//! Redis/ValKey operations related to visas.
//!
//! `VisaRepo` is a **write-through store**: an in-memory image is authoritative
//! for all reads/iteration; Redis is the persistence backing. Every mutation
//! writes Redis first, then applies to memory, both under the store write lock.
//! At startup the image is loaded from Redis in one pass. The service holds an
//! exclusive DB instance lock (see `db_worker`), so nothing else mutates visa
//! keys.
//!
//! Redis schema (one key per visa):
//! - `visa:next_visa_id` a counter for the next visa ID (INCR).
//! - `visa:<ID>` a JSON `VisaRecord` (visa blob + metadata + per-node states),
//!   with TTL = visa expiry.
//!
//! TODO: At some point more of the redis stored state will be moved to write-through
//! schemes like this, which may involve some refactoring.

use capnp;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use ::zpr::vsapi::v1 as vsapi;
use libeval::eval_result::Direction;
use serde_with::{TimestampSeconds, serde_as};
use zpr::vsapi_types::{PacketDesc, Visa, VsapiFiveTuple};
use zpr::write_to::WriteTo;

use crate::db::{DbConnection, DbOp, ZAddr, gen_timestamp};
use crate::error::StoreError;
use crate::logging::targets::DB;

const KEY_VISA: &str = "visa";
const KEY_NEXT_VISA_ID: &str = "visa:next_visa_id";

/// Minimum wall-gap between actual purge scans. Housekeeping calls
/// `purge_expired` once per node per heartbeat, so with N nodes it fires N× per
/// interval; this collapses those to one real scan and spares readers the extra
/// store-write-lock acquisitions.
const PURGE_MIN_INTERVAL: Duration = Duration::from_millis(800);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeVisaState {
    PendingInstall,
    Installed,
    PendingRevoke,
    Revoked,
}

/// Metadata around an issued visa.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisaMetadata {
    /// The node this visa was issued to. NOT necessarily the node the flow ingresses at --
    /// the visa service also mints visas pre-emptively for flows it originates itself -- so
    /// do not derive path geometry from it. Use `path` ordering for that.
    pub requesting_node: IpAddr,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub policy_version: u64, // from policy.get_version
    pub created_vinst: u64,  // service vinst active when the visa was issued
    pub checked_vinst: u64,  // latest vinst this visa has been evaluated against
    pub zpl: String,
    pub signal_msgs: Vec<String>, // note we do not keep the signal destination
    pub direction: Direction,
    /// ZPR addresses of the nodes on the path, in flow order: ingress node first, egress node
    /// last. Only set if a link needs to be traversed. Actualization reads each node's role
    /// off this ordering, so whoever builds one must keep it in flow order.
    pub path: Option<Vec<IpAddr>>,
    pub five_tuple: VsapiFiveTuple,
}

/// Persisted per-node state within a `VisaRecord` (keyed by ZAddr string).
/// This is the persisted [NodeState].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNodeState {
    state: NodeVisaState,
    utime: String,
    revoke_vinst: Option<u64>,
}

/// The single JSON value persisted at `visa:<id>`. Redis's only jobs are
/// persisting and expiring whole visas, so everything a visa needs lives here.
/// Expiry lives in the capnp blob (`visa.expires`) and is recovered on decode.
///
/// This is the persisted [VisaEntry].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VisaRecord {
    blob: String, // base64 capnp visa bytes (Visa is not serde)
    metadata: VisaMetadata,
    node_states: HashMap<String, StoredNodeState>, // keyed by ZAddr string
}

/// In-memory, authoritative per-node state for a visa.
#[derive(Debug, Clone)]
struct NodeState {
    state: NodeVisaState,
    revoke_vinst: Option<u64>, // policy `vinst` stamped when the node was marked PendingRevoke
}

/// In-memory, authoritative copy of one visa.
struct VisaEntry {
    visa: Visa,
    metadata: VisaMetadata,
    // Expiry moment as a tokio Instant, derived from `visa.expires` at insert /
    // state_load time. The tokio (monotonic) clock, not SystemTime, is deliberate:
    // it lets paused-clock tests drive expiry with tokio::time::advance().
    //
    // NOTE: Monotonic deadline can diverge from Redis's wall-clock TTL if the
    // host suspends or NTP steps the clock — CLOCK_MONOTONIC freezes/ignores those.
    // Memory may then serve a visa Redis has already dropped, and a rewrite can
    // resurrect the key with a fresh TTL. Bounded and self-healing: restart
    // re-hydrates from Redis. If suspend/NTP-step becomes a real deployment
    // concern, AND-guard liveness with `seconds_until(visa.expires) > 0`.
    deadline: Instant,
    node_states: HashMap<IpAddr, NodeState>,
}

/// The in-memory store guarded by a single `RwLock`.
///
/// INVARIANT C: `visas`, `by_node`, and `by_actor` must be updated under the
/// same `store` write guard; a reader must never see one without the others.
/// Today the single `store` lock gives this for free (all live behind one guard).
#[derive(Default)]
struct VisaStoreInner {
    visas: HashMap<u64, VisaEntry>,
    by_node: HashMap<IpAddr, HashSet<u64>>, // secondary index for per-node queries
    by_actor: HashMap<IpAddr, HashSet<u64>>, // five-tuple src/dst endpoints
}

/// Cheap cloneable handle. `VisaRepo` owns the in-memory store, so it cannot be
/// value-`Clone` (the locks are not `Clone`, and duplicating the store would be
/// wrong). Instead every clone shares one `Arc<VisaRepoInner>` — callers
/// (`VisaMgr`, workers) hold the repo by value and clone the handle freely.
#[derive(Clone)]
pub struct VisaRepo {
    inner: Arc<VisaRepoInner>,
}

struct VisaRepoInner {
    db: Arc<dyn DbConnection>,
    /// Serializes ALL write paths (store/update/clear/clean_up). Held across the
    /// Redis I/O so writes commit to Redis and then to memory in one global
    /// order. Readers never take this lock. `purge_expired` is the sole writer
    /// exempt (Invariant D: memory-only, no Redis write to order).
    ///
    /// INVARIANT A: every mutation that writes Redis must take `backing` before
    /// touching Redis or the memory image.
    backing: Mutex<()>,
    /// Guards the in-memory image. Taken briefly and NEVER held across an
    /// `.await` — it is a `std::sync::RwLock`, so its `!Send` guard makes holding
    /// it across `.await` a compile error.
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/246
    store: RwLock<VisaStoreInner>,
    /// Last time `purge_expired` actually scanned. `None` until the first purge.
    /// Throttles the per-node housekeeping stampede (see `PURGE_MIN_INTERVAL`).
    last_purge: std::sync::Mutex<Option<Instant>>,
}

impl VisaMetadata {
    /// Create a non-link-traversing metadata.
    ///
    /// `requesting_node` is the node that requested the visa.
    /// `pver` is the policy version that was in effect at the time of the visa request.
    /// `vinst` is the service policy-install generation active at issuance; it
    /// seeds both `created_vinst` and `checked_vinst`.
    /// `zpl` is the ZPL is a copy of the ZPL line that matched in policy.
    /// `direction` is the direction of the match as reported by the hit.
    pub fn new(
        requesting_node: IpAddr,
        pver: u64,
        vinst: u64,
        zpl: String,
        direction: Direction,
        path: Option<Vec<IpAddr>>,
        pdesc: &PacketDesc,
    ) -> Self {
        VisaMetadata {
            requesting_node,
            ctime: SystemTime::now(),
            policy_version: pver,
            created_vinst: vinst,
            checked_vinst: vinst,
            zpl,
            signal_msgs: Vec::new(),
            direction,
            path,
            five_tuple: pdesc.five_tuple.clone(),
        }
    }
}

impl VisaRepo {
    /// Set up and initialize the visa store, loading the in-memory image from
    /// Redis. We set `initial_visa_id` only if the key is not already present.
    pub async fn new(db: Arc<dyn DbConnection>, initial_visa_id: u64) -> Result<Self, StoreError> {
        // Only set the initial visa id if the key is not ready present.
        if !db.exists(KEY_NEXT_VISA_ID).await? {
            db.set(KEY_NEXT_VISA_ID, &initial_visa_id.to_string())
                .await?;
        }
        let store = restore_from_state(&db).await?;
        Ok(VisaRepo {
            inner: Arc::new(VisaRepoInner {
                db,
                backing: Mutex::new(()),
                store: RwLock::new(store),
                last_purge: std::sync::Mutex::new(None),
            }),
        })
    }

    pub async fn get_next_visa_id(&self) -> Result<u64, StoreError> {
        let next_id: u64 = self.inner.db.incr(KEY_NEXT_VISA_ID, 1).await?;
        Ok(next_id)
    }

    /// Remove all references to a visa: DEL the Redis key, then drop it from
    /// memory (Redis first so memory never claims state persistence lacks).
    ///
    pub async fn remove_visa(&self, visa_id: u64) -> Result<(), StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        let key = visa_key_for_visa(visa_id);
        // Redis first. On an ApplyThenError-style ambiguous DEL we still return
        // the error and keep the memory entry; a later rewrite recreates the key.
        self.inner.db.del(&key).await?;
        // Memory second. `remove_entry` is a no-op on a missing row, so a
        // concurrent `purge_expired` that already dropped the entry is harmless.
        let mut store = self.inner.store.write().unwrap();
        remove_entry(&mut store, visa_id);
        Ok(())
    }

    /// Force remove the node's state from every visa record that references it.
    ///
    /// The node is dropped from each record's `node_states` and from the
    /// `by_node` index, but the visa record itself is never deleted, even if
    /// `node_states` becomes empty.
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        // Snapshot the work under a short read guard: for each visa referencing
        // the node, its id and the rewritten JSON to persist (None if the entry
        // is effectively expired — its TTL has fired / is about to, so we skip
        // the rewrite but still drop the node from memory below).
        //
        // INVARIANT B: dropping this read guard is safe — backing blocks other
        // writers, so these entries can't change under us before the apply.
        let writes: Vec<(u64, Option<(String, u64)>)> = {
            let store = self.inner.store.read().unwrap();
            let ids: Vec<u64> = store
                .by_node
                .get(node_addr)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            let mut writes = Vec::new();
            for id in ids {
                let Some(entry) = store.visas.get(&id) else {
                    continue;
                };
                if !entry.node_states.contains_key(node_addr) {
                    continue;
                }
                let ttl = remaining_secs(entry.deadline);
                let json = if ttl > 0 {
                    let mut new_states = entry.node_states.clone();
                    new_states.remove(node_addr);
                    let record = build_record(&entry.visa, &entry.metadata, &new_states)?;
                    Some((serde_json::to_string(&record)?, ttl))
                } else {
                    None
                };
                writes.push((id, json));
            }
            writes
        };

        // Redis first, as one atomic pipeline: all rewrites land or none do, so a
        // mid-flight failure can no longer half-clear Redis while memory keeps the
        // node (SetBin + Expire per record, matching set_ex semantics).
        let mut ops = Vec::new();
        for (id, json) in &writes {
            if let Some((json, ttl)) = json {
                let key = visa_key_for_visa(*id);
                ops.push(DbOp::SetBin {
                    key: key.clone(),
                    value: json.clone().into_bytes(),
                });
                ops.push(DbOp::Expire {
                    key,
                    seconds: *ttl as i64,
                });
            }
        }
        if !ops.is_empty() {
            self.inner.db.atomic_pipeline(&ops).await?;
        }

        // Memory second. A concurrent purge may have dropped an entry during the
        // I/O gap; `get_mut` and `unindex_node` both no-op on a missing row.
        let mut store = self.inner.store.write().unwrap();
        for (id, _) in &writes {
            if let Some(entry) = store.visas.get_mut(id) {
                entry.node_states.remove(node_addr);
            }
            unindex_node(&mut store, node_addr, *id);
        }
        Ok(())
    }

    /// Store a new visa, setting its state w.r.t. the requesting node to `nstate`
    /// and any other path nodes to `PendingInstall`.
    ///
    /// If the visa is already expired, this is a NOP and returns `Ok`.
    ///
    /// ### Errrors
    /// - Errors if there is a problem writing to Redis or serializing the record.
    pub async fn store_visa(
        &self,
        visa: &Visa,
        metadata: VisaMetadata,
        nstate: NodeVisaState,
    ) -> Result<(), StoreError> {
        let visa_id = visa.issuer_id;
        let ttl = seconds_until(visa.expires);
        if ttl == 0 {
            // already expired.
            return Ok(());
        }

        // Build the per-node state map: requesting node gets `nstate`, other path
        // nodes get PendingInstall.
        let mut node_states = HashMap::new();
        node_states.insert(
            metadata.requesting_node,
            NodeState {
                state: nstate,
                revoke_vinst: None,
            },
        );
        if let Some(path) = &metadata.path {
            for node in path {
                if node == &metadata.requesting_node {
                    continue;
                }
                node_states.insert(
                    *node,
                    NodeState {
                        state: NodeVisaState::PendingInstall,
                        revoke_vinst: None,
                    },
                );
            }
        }

        let record = build_record(visa, &metadata, &node_states)?;
        let json = serde_json::to_string(&record)?;
        let key = visa_key_for_visa(visa_id);

        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;
        // Redis first.
        if let Err(e) = self.inner.db.set_ex(&key, &json, ttl).await {
            // The write may have applied but the reply was lost (ambiguous
            // commit) — issue one best-effort DEL so an unknown visa is not left
            // behind. If that also fails the TTL bounds the orphan; one restart
            // may resurrect it (documented residual risk).
            let _ = self.inner.db.del(&key).await;
            return Err(e.into());
        }
        // Memory second. Pure insert: the id does not exist until now and purge
        // only removes, so there is nothing to re-check.
        let entry = VisaEntry {
            visa: visa.clone(),
            metadata,
            deadline: Instant::now() + Duration::from_secs(ttl),
            node_states,
        };
        let mut store = self.inner.store.write().unwrap();
        insert_entry(&mut store, visa_id, entry);

        debug!(target: DB, "stored visa {visa_id} expires in {ttl} seconds");
        Ok(())
    }

    /// Snapshot of `(visa_id, metadata)` for all live entries, cloned under the
    /// read lock. Used by policy-update sweep (when new policy installed).
    pub async fn list_visa_metadata(&self) -> Vec<(u64, VisaMetadata)> {
        let store = self.inner.store.read().unwrap();
        store
            .visas
            .iter()
            .filter(|(_, e)| remaining_secs(e.deadline) > 0)
            .map(|(id, e)| (*id, e.metadata.clone()))
            .collect()
    }

    /// Apply an allow verdict at policy generation `vinst`. This happens after a policy
    /// update and we are checking all existing visas.
    ///
    /// No-ops (`Ok(false)`) when the visa is absent/expired or `vinst` is not
    /// newer than `checked_vinst` (never lowered). Otherwise bumps
    /// `checked_vinst` and cancels any queued revoke whose stamp predates
    /// `vinst` (`PendingRevoke -> PendingInstall`, stamp cleared) in one rewrite.
    pub async fn record_allow_verdict(&self, visa_id: u64, vinst: u64) -> Result<bool, StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        // Snapshot + decide under a short read guard, then drop it for the Redis
        // I/O. INVARIANT B: backing blocks other writers, so the entry can't
        // change between this check and the apply below.
        let (json, ttl, new_metadata, new_states) = {
            let store = self.inner.store.read().unwrap();
            let Some(entry) = live_entry(&store, visa_id) else {
                return Ok(false);
            };
            if vinst <= entry.metadata.checked_vinst {
                return Ok(false);
            }
            let ttl = remaining_secs(entry.deadline);
            let mut new_metadata = entry.metadata.clone();
            new_metadata.checked_vinst = vinst;
            let mut new_states = entry.node_states.clone();
            for ns in new_states.values_mut() {
                if ns.state == NodeVisaState::PendingRevoke
                    && ns.revoke_vinst.is_some_and(|rv| rv < vinst)
                {
                    // Was marked for revocation but now is allowed, flip it.
                    ns.state = NodeVisaState::PendingInstall;
                    ns.revoke_vinst = None;
                }
            }
            let record = build_record(&entry.visa, &new_metadata, &new_states)?;
            (
                serde_json::to_string(&record)?,
                ttl,
                new_metadata,
                new_states,
            )
        };
        // Redis first.
        self.inner
            .db
            .set_ex(&visa_key_for_visa(visa_id), &json, ttl)
            .await?;
        // Memory second. If purge_expired dropped the entry during the set_ex
        // gap the visa expired mid-update; skipping the apply is correct.
        if let Some(entry) = self.inner.store.write().unwrap().visas.get_mut(&visa_id) {
            entry.metadata = new_metadata;
            entry.node_states = new_states;
        }
        debug!(target: DB, "recorded allow verdict visa={visa_id} vinst={vinst}");
        Ok(true)
    }

    /// Apply a deny verdict at policy generation `vinst`. This happens after a
    /// policy update and we are checking all existing visas.
    ///
    /// No-ops (`Ok(false)`) when the visa is absent/expired or `vinst` is not
    /// newer than `checked_vinst`. Otherwise marks every node `PendingRevoke`,
    /// stamping `revoke_vinst = vinst` only where it exceeds the existing stamp
    /// (a revoke decision overwrites `PendingInstall`/`Installed` freely). A node
    /// already revoked unconditionally (`PendingRevoke`, no stamp) stays unstamped,
    /// so a later allow cannot cancel it. One
    /// rewrite. `checked_vinst` is not bumped (only allow bumps it).
    pub async fn record_deny_verdict(&self, visa_id: u64, vinst: u64) -> Result<bool, StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        // Snapshot + decide under a short read guard, then drop it for the Redis
        // I/O. INVARIANT B: backing blocks other writers, so the entry can't
        // change between this check and the apply below.
        let (json, ttl, new_states) = {
            let store = self.inner.store.read().unwrap();
            let Some(entry) = live_entry(&store, visa_id) else {
                return Ok(false);
            };
            if vinst <= entry.metadata.checked_vinst {
                return Ok(false);
            }
            let ttl = remaining_secs(entry.deadline);
            let mut new_states = entry.node_states.clone();
            for ns in new_states.values_mut() {
                // Already revoked unconditionally (PendingRevoke with no stamp, see
                // mark_visa_revoked): keep it unstamped, so no later allow can
                // cancel it.
                if ns.state == NodeVisaState::PendingRevoke && ns.revoke_vinst.is_none() {
                    continue;
                }
                ns.state = NodeVisaState::PendingRevoke;
                if ns.revoke_vinst.is_none_or(|rv| vinst > rv) {
                    ns.revoke_vinst = Some(vinst); // still revoked!
                }
            }
            let record = build_record(&entry.visa, &entry.metadata, &new_states)?;
            (serde_json::to_string(&record)?, ttl, new_states)
        };
        // Redis first.
        self.inner
            .db
            .set_ex(&visa_key_for_visa(visa_id), &json, ttl)
            .await?;
        // Memory second. If purge_expired dropped the entry during the set_ex
        // gap the visa expired mid-update; skipping the apply is correct.
        if let Some(entry) = self.inner.store.write().unwrap().visas.get_mut(&visa_id) {
            entry.node_states = new_states;
        }
        Ok(true)
    }

    /// Mark every node of a live visa `PendingRevoke`, unconditionally (no vinst
    /// gate, no `checked_vinst` bump). For actor/node departure, a link going down
    /// or an attribute change: the visa is invalid regardless of policy, so clear each
    /// node's `revoke_vinst` to `None`, which `record_allow_verdict`'s `rv < vinst`
    /// test can never cancel -- a later allow cannot resurrect it, even when an
    /// earlier policy deny had stamped it.
    /// No-ops (`Ok(false)`) when the visa is absent/expired.
    pub async fn mark_visa_revoked(&self, visa_id: u64) -> Result<bool, StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        let (json, ttl, new_states) = {
            let store = self.inner.store.read().unwrap();
            let Some(entry) = live_entry(&store, visa_id) else {
                return Ok(false);
            };
            let ttl = remaining_secs(entry.deadline);
            let mut new_states = entry.node_states.clone();
            for ns in new_states.values_mut() {
                ns.state = NodeVisaState::PendingRevoke;
                ns.revoke_vinst = None; // not cancellable by a later allow
            }
            let record = build_record(&entry.visa, &entry.metadata, &new_states)?;
            (serde_json::to_string(&record)?, ttl, new_states)
        };
        // Redis first.
        self.inner
            .db
            .set_ex(&visa_key_for_visa(visa_id), &json, ttl)
            .await?;
        // Memory second. A purge during the I/O gap means the visa expired;
        // skipping the apply is correct.
        if let Some(entry) = self.inner.store.write().unwrap().visas.get_mut(&visa_id) {
            entry.node_states = new_states;
        }
        Ok(true)
    }

    /// Compare-and-swap one node's state: apply `new` only if the node is
    /// currently in `expected`. Not-found/expired or state mismatch -> `Ok(false)`.
    pub async fn transition_node_visa_state(
        &self,
        node_addr: IpAddr,
        visa_id: u64,
        expected: NodeVisaState,
        new: NodeVisaState,
    ) -> Result<bool, StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        // Snapshot + CAS-check under a short read guard, then drop it for the
        // Redis I/O. INVARIANT B: backing blocks other writers, so the entry
        // can't change between this check and the apply below.
        let (json, ttl, new_states) = {
            let store = self.inner.store.read().unwrap();
            let Some(entry) = live_entry(&store, visa_id) else {
                return Ok(false);
            };
            if entry
                .node_states
                .get(&node_addr)
                .is_none_or(|ns| ns.state != expected)
            {
                return Ok(false);
            }
            let ttl = remaining_secs(entry.deadline);
            let mut new_states = entry.node_states.clone();
            new_states.get_mut(&node_addr).unwrap().state = new;
            let record = build_record(&entry.visa, &entry.metadata, &new_states)?;
            (serde_json::to_string(&record)?, ttl, new_states)
        };
        // Redis first.
        self.inner
            .db
            .set_ex(&visa_key_for_visa(visa_id), &json, ttl)
            .await?;
        // Memory second. If purge_expired dropped the entry during the set_ex
        // gap the visa expired mid-update; skipping the apply is correct.
        if let Some(entry) = self.inner.store.write().unwrap().visas.get_mut(&visa_id) {
            entry.node_states = new_states;
        }
        debug!(target: DB, "transitioned node={node_addr} visa={visa_id} {expected:?} -> {new:?}");
        Ok(true)
    }

    /// Conditional teardown: drop `node_addr` from the visa's `node_states` (and
    /// the `by_node` index) only if its state is `PendingRevoke`. Rewrites the
    /// record. Returns true if node was removed.
    pub async fn remove_node_if_pending_revoke(
        &self,
        node_addr: IpAddr,
        visa_id: u64,
    ) -> Result<bool, StoreError> {
        // INVARIANT A: backing held for the whole write.
        let _backing = self.inner.backing.lock().await;

        // Snapshot + check under a short read guard, then drop it for the Redis
        // I/O. INVARIANT B: backing blocks other writers, so the entry can't
        // change between this check and the apply below.
        let (json, ttl, new_states) = {
            let store = self.inner.store.read().unwrap();
            let Some(entry) = live_entry(&store, visa_id) else {
                return Ok(false);
            };
            if entry
                .node_states
                .get(&node_addr)
                .is_none_or(|ns| ns.state != NodeVisaState::PendingRevoke)
            {
                return Ok(false);
            }
            let ttl = remaining_secs(entry.deadline);
            let mut new_states = entry.node_states.clone();
            new_states.remove(&node_addr);
            let record = build_record(&entry.visa, &entry.metadata, &new_states)?;
            (serde_json::to_string(&record)?, ttl, new_states)
        };
        // Redis first.
        self.inner
            .db
            .set_ex(&visa_key_for_visa(visa_id), &json, ttl)
            .await?;
        // Memory second. If purge_expired dropped the entry during the set_ex
        // gap the visa expired mid-update; skipping the apply is correct.
        let mut store = self.inner.store.write().unwrap();
        if let Some(entry) = store.visas.get_mut(&visa_id) {
            entry.node_states = new_states;
        }
        unindex_node(&mut store, &node_addr, visa_id);
        debug!(target: DB, "removed pending-revoke node={node_addr} from visa={visa_id}");
        Ok(true)
    }

    /// Whether a given live visa still references any node.
    pub async fn visa_has_node_refs(&self, visa_id: u64) -> bool {
        let store = self.inner.store.read().unwrap();
        live_entry(&store, visa_id).is_some_and(|e| !e.node_states.is_empty())
    }

    /// All visas for a node in the given state (blobs cloned from memory).
    pub fn get_visas_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<Vec<Visa>, StoreError> {
        let store = self.inner.store.read().unwrap();
        let mut visas = Vec::new();
        for_each_node_visa_in_state(&store, node_addr, state, |_, e| visas.push(e.visa.clone()));
        Ok(visas)
    }

    /// The state a live visa is in on one node, or `None` when the visa is unknown/expired or
    /// was never staged for that node. Read-only, for explaining a failed state transition.
    pub fn get_node_visa_state(&self, visa_id: u64, node_addr: &IpAddr) -> Option<NodeVisaState> {
        let store = self.inner.store.read().unwrap();
        let entry = live_entry(&store, visa_id)?;
        entry.node_states.get(node_addr).map(|ns| ns.state)
    }

    /// The visa IDs for a node filtered by state, without cloning the visas.
    pub fn get_visa_ids_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<Vec<u64>, StoreError> {
        let store = self.inner.store.read().unwrap();
        let mut ids = Vec::new();
        for_each_node_visa_in_state(&store, node_addr, state, |id, _| ids.push(id));
        Ok(ids)
    }

    /// Live visa IDs having any of `actor_addrs` as a five-tuple endpoint.
    /// O(matched visas), not O(all visas). Returns `Result` for signature
    /// consistency with the `get_*` query family though it never errors.
    pub fn get_visa_ids_for_actors(&self, actor_addrs: &[IpAddr]) -> Result<Vec<u64>, StoreError> {
        let store = self.inner.store.read().unwrap();
        // HashSet: a src/dst pair or overlapping input addrs can hit one id twice.
        let mut ids = HashSet::new();
        for addr in actor_addrs {
            if let Some(set) = store.by_actor.get(addr) {
                ids.extend(
                    set.iter()
                        .copied()
                        .filter(|&id| live_entry(&store, id).is_some()),
                );
            }
        }
        Ok(ids.into_iter().collect())
    }

    /// All live visa IDs referencing this node, in any per-node state.
    /// O(matched visas), not O(all visas).
    pub fn get_all_visa_ids_for_node(&self, node_addr: &IpAddr) -> Result<Vec<u64>, StoreError> {
        let store = self.inner.store.read().unwrap();
        let ids = store
            .by_node
            .get(node_addr)
            .map(|set| {
                set.iter()
                    .copied()
                    .filter(|&id| live_entry(&store, id).is_some())
                    .collect()
            })
            .unwrap_or_default();
        Ok(ids)
    }

    /// Count the visas for a node that are in the given state.
    pub fn get_count_visas_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<u32, StoreError> {
        let store = self.inner.store.read().unwrap();
        let mut count = 0u32;
        for_each_node_visa_in_state(&store, node_addr, state, |_, _| count += 1);
        Ok(count)
    }

    /// Get the visa by ID.
    ///
    /// ## Errors
    /// - [StoreError::NotFound] if the visa does not exist (or has expired).
    pub fn get_visa_by_id(&self, visa_id: u64) -> Result<Visa, StoreError> {
        let store = self.inner.store.read().unwrap();
        live_entry(&store, visa_id)
            .map(|e| e.visa.clone())
            .ok_or_else(|| StoreError::NotFound(format!("visa not found for ID {visa_id}")))
    }

    /// Get the metadata for the visa by ID.
    ///
    /// ## Errors
    /// - [StoreError::NotFound] if the visa metadata does not exist (or has expired).
    pub fn get_visa_metadata_by_id(&self, visa_id: u64) -> Result<VisaMetadata, StoreError> {
        let store = self.inner.store.read().unwrap();
        live_entry(&store, visa_id)
            .map(|e| e.metadata.clone())
            .ok_or_else(|| {
                StoreError::NotFound(format!("visa metadata not found for ID {visa_id}"))
            })
    }

    /// Copy all the live visa IDs into a vec.
    pub fn list_visa_ids(&self) -> Result<Vec<u64>, StoreError> {
        let store = self.inner.store.read().unwrap();
        Ok(store
            .visas
            .iter()
            .filter(|(_, e)| e.is_live())
            .map(|(id, _)| *id)
            .collect())
    }

    /// Drop expired entries and their `by_node` index rows. Redis needs no
    /// matching delete since the TTL should have already fired. Called by housekeeping.
    pub fn purge_expired(&self) -> Result<(), StoreError> {
        // Throttle: skip if the last real scan was under PURGE_MIN_INTERVAL ago,
        // so N node workers ticking together don't each take the store write
        // lock. Stamped before the scan; a purge at most one interval stale is
        // fine since reads already filter expired entries.
        {
            let mut last = self.inner.last_purge.lock().unwrap();
            if let Some(t) = *last {
                if Instant::now().saturating_duration_since(t) < PURGE_MIN_INTERVAL {
                    return Ok(());
                }
            }
            *last = Some(Instant::now());
        }
        // INVARIANT D: memory-only writer. purge does NOT take `backing` — it
        // writes no Redis key (the keys expire on their own TTL), so there is no
        // Redis/memory order to enforce, and it is exempt from Invariant A.
        // Because it skips `backing`, it is the one writer that can interleave
        // inside a read-modify-write's Redis-I/O gap; that is why every writer's
        // memory-apply tolerates a vanished entry.
        let mut store = self.inner.store.write().unwrap();
        let expired: Vec<u64> = store
            .visas
            .iter()
            .filter(|(_, e)| !e.is_live())
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            remove_entry(&mut store, id);
        }
        Ok(())
    }
}

/// Build the in-memory image by scanning `visa:[0-9]*`, decoding each value as
/// a `VisaRecord`. Undecodable or already-expired values are DELeted and
/// skipped so they are never rescanned.
async fn restore_from_state(db: &Arc<dyn DbConnection>) -> Result<VisaStoreInner, StoreError> {
    let mut inner = VisaStoreInner::default();
    let keys = db.scan_match_all(format!("{KEY_VISA}:[0-9]*")).await?;
    let mut node_count = 0usize;
    let mut deleted = 0usize;

    for key in &keys {
        let Some(raw) = db.get(key).await? else {
            continue; // vanished (TTL) between scan and get.
        };
        let visa_id = match key
            .rsplit_once(':')
            .and_then(|(_, id)| id.parse::<u64>().ok())
        {
            Some(id) => id,
            None => {
                warn!(target: DB, "malformed visa key {key}, deleting");
                db.del(key).await?;
                deleted += 1;
                continue;
            }
        };
        match decode_record(&raw) {
            Ok(entry) if entry.is_live() => {
                node_count += entry.node_states.len();
                insert_entry(&mut inner, visa_id, entry);
            }
            // Expired or undecodable/legacy: delete so it is not rescanned.
            Ok(_) => {
                db.del(key).await?;
                deleted += 1;
            }
            Err(e) => {
                warn!(target: DB, "deleting undecodable visa record {key}: {e}");
                db.del(key).await?;
                deleted += 1;
            }
        }
    }

    info!(
        target: DB,
        "loaded {} visas, {} node entries, deleted {} broken/legacy keys",
        inner.visas.len(),
        node_count,
        deleted
    );
    Ok(inner)
}

/// Decode a JSON `VisaRecord` string into a `VisaEntry`.
fn decode_record(raw: &str) -> Result<VisaEntry, StoreError> {
    let record: VisaRecord = serde_json::from_str(raw)?;
    let bytes = BASE64
        .decode(record.blob.as_bytes())
        .map_err(|e| StoreError::InvalidData(format!("visa blob base64 decode: {e}")))?;
    let visa = Visa::from_capnp_bytes(&bytes)?;
    let deadline = Instant::now() + Duration::from_secs(seconds_until(visa.expires));

    let mut node_states = HashMap::new();
    for (zaddr_str, sns) in record.node_states {
        let addr = IpAddr::try_from(ZAddr::new_from_encoded(&zaddr_str))
            .map_err(|e| StoreError::InvalidData(format!("bad zaddr {zaddr_str}: {e}")))?;
        node_states.insert(
            addr,
            NodeState {
                state: sns.state,
                revoke_vinst: sns.revoke_vinst,
            },
        );
    }
    Ok(VisaEntry {
        visa,
        metadata: record.metadata,
        deadline,
        node_states,
    })
}

/// Serialize the components of a visa into a persistable `VisaRecord`.
fn build_record(
    visa: &Visa,
    metadata: &VisaMetadata,
    node_states: &HashMap<IpAddr, NodeState>,
) -> Result<VisaRecord, StoreError> {
    let blob = BASE64.encode(visa_to_capnp_bytes(visa)?);
    let stored: HashMap<String, StoredNodeState> = node_states
        .iter()
        .map(|(addr, ns)| {
            (
                ZAddr::from(addr).to_string(),
                StoredNodeState {
                    state: ns.state,
                    utime: gen_timestamp(),
                    revoke_vinst: ns.revoke_vinst,
                },
            )
        })
        .collect();
    Ok(VisaRecord {
        blob,
        metadata: metadata.clone(),
        node_states: stored,
    })
}

/// Encode a Visa to its capnp wire bytes.
fn visa_to_capnp_bytes(visa: &Visa) -> Result<Vec<u8>, StoreError> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut visa_bldr = msg.init_root::<vsapi::visa::Builder>();
        visa.write_to(&mut visa_bldr);
    }
    let mut words: Vec<u8> = Vec::new();
    capnp::serialize::write_message(&mut words, &msg)?;
    Ok(words)
}

impl VisaEntry {
    /// True while the visa has not yet reached its expiry deadline. The single
    /// liveness rule used by every read/iteration site.
    fn is_live(&self) -> bool {
        remaining_secs(self.deadline) > 0
    }
}

/// Return the entry only if it is still live (`deadline` in the future).
/// All reads go through this so expired entries read as absent.
fn live_entry(inner: &VisaStoreInner, id: u64) -> Option<&VisaEntry> {
    inner.visas.get(&id).filter(|e| e.is_live())
}

/// Visit each live visa referencing `node_addr` whose per-node state == `state`,
/// calling `f(id, entry)`. Backs the per-node get/ids/count query methods.
fn for_each_node_visa_in_state<F: FnMut(u64, &VisaEntry)>(
    inner: &VisaStoreInner,
    node_addr: &IpAddr,
    state: NodeVisaState,
    mut f: F,
) {
    if let Some(ids) = inner.by_node.get(node_addr) {
        for &id in ids {
            if let Some(entry) = live_entry(inner, id) {
                if entry
                    .node_states
                    .get(node_addr)
                    .is_some_and(|ns| ns.state == state)
                {
                    f(id, entry);
                }
            }
        }
    }
}

/// Insert an entry and index it in `by_node` (path nodes) and `by_actor`
/// (five-tuple endpoints).
fn insert_entry(inner: &mut VisaStoreInner, id: u64, entry: VisaEntry) {
    let nodes: Vec<IpAddr> = entry.node_states.keys().copied().collect();
    let ft = &entry.metadata.five_tuple;
    let actors = [ft.source_addr, ft.dest_addr];
    inner.visas.insert(id, entry);
    for node in nodes {
        inner.by_node.entry(node).or_default().insert(id);
    }
    for actor in actors {
        inner.by_actor.entry(actor).or_default().insert(id);
    }
}

/// Remove an entry and unindex it from both `by_node` and `by_actor`.
fn remove_entry(inner: &mut VisaStoreInner, id: u64) {
    if let Some(entry) = inner.visas.remove(&id) {
        let ft = &entry.metadata.five_tuple;
        for actor in [ft.source_addr, ft.dest_addr] {
            unindex(&mut inner.by_actor, &actor, id);
        }
        let nodes: Vec<IpAddr> = entry.node_states.keys().copied().collect();
        for node in nodes {
            unindex(&mut inner.by_node, &node, id);
        }
    }
}

/// Drop `id` from `index[key]`, removing the row if it empties.
fn unindex(index: &mut HashMap<IpAddr, HashSet<u64>>, key: &IpAddr, id: u64) {
    if let Some(set) = index.get_mut(key) {
        set.remove(&id);
        if set.is_empty() {
            index.remove(key);
        }
    }
}

/// Drop `id` from the `by_node` row for `node`. Thin wrapper over `unindex` so
/// the state-mutation call sites (`clear_node_state`, `remove_node_if_pending_revoke`)
/// don't churn.
fn unindex_node(inner: &mut VisaStoreInner, node: &IpAddr, id: u64) {
    unindex(&mut inner.by_node, node, id);
}

// Get number of seconds until the given SystemTime or zero if in the past.
fn seconds_until(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// Remaining whole seconds until a tokio deadline, zero if reached.
fn remaining_secs(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_secs()
}

fn visa_key_for_visa(visa_id: u64) -> String {
    format!("{KEY_VISA}:{visa_id}")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::{FakeDb, FaultMode, ZAddr};
    use crate::test_helpers::{make_pdesc, make_visa};

    /// Build a default no-path metadata for `node`.
    fn md(node: IpAddr) -> VisaMetadata {
        VisaMetadata::new(
            node,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        )
    }

    /// Read and JSON-decode the persisted VisaRecord for `id`.
    async fn read_record(db: &FakeDb, id: u64) -> VisaRecord {
        let raw = db.get(&visa_key_for_visa(id)).await.unwrap().unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    /// Assert the persisted VisaRecord for `id` matches the in-memory entry.
    async fn assert_memory_matches_redis(repo: &VisaRepo, db: &FakeDb, id: u64) {
        let record = read_record(db, id).await;
        let store = repo.inner.store.read().unwrap();
        let entry = store.visas.get(&id).unwrap();
        assert_eq!(record.node_states.len(), entry.node_states.len());
        for (addr, ns) in &entry.node_states {
            let sns = record
                .node_states
                .get(&ZAddr::from(addr).to_string())
                .expect("node missing from persisted record");
            assert_eq!(sns.state, ns.state);
            assert_eq!(sns.revoke_vinst, ns.revoke_vinst);
        }
        assert_eq!(
            record.metadata.requesting_node,
            entry.metadata.requesting_node
        );
    }

    // --- retargeted behavioral tests ---

    #[tokio::test]
    async fn test_store_and_get_visas_by_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::1".parse().unwrap();
        let visa = make_visa(42, Duration::from_secs(60));

        repo.store_visa(&visa, md(node_addr), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        // The single record persists the requesting node's state.
        let record = read_record(&db, 42).await;
        let sns = record
            .node_states
            .get(&ZAddr::from(&node_addr).to_string())
            .unwrap();
        assert_eq!(sns.state, NodeVisaState::PendingInstall);

        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].issuer_id, 42);

        assert!(
            repo.transition_node_visa_state(
                node_addr,
                42,
                NodeVisaState::PendingInstall,
                NodeVisaState::Installed
            )
            .await
            .unwrap()
        );
        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .unwrap();
        assert!(pending.is_empty());

        let installed = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::Installed)
            .unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].issuer_id, 42);
    }

    /// clear_node_state drops the node from a visa's states and the by_node
    /// index, but keeps the visa record itself (and both Redis and memory agree).
    #[tokio::test]
    async fn test_clear_node_state_only_removes_node_from_record() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::3".parse().unwrap();
        let visa = make_visa(7, Duration::from_secs(60));

        repo.store_visa(&visa, md(node_addr), NodeVisaState::Installed)
            .await
            .unwrap();

        repo.clear_node_state(&node_addr).await.unwrap();

        // The visa record still exists but no longer references the node.
        let record = read_record(&db, 7).await;
        assert!(
            record
                .node_states
                .get(&ZAddr::from(&node_addr).to_string())
                .is_none()
        );
        // Memory agrees.
        let store = repo.inner.store.read().unwrap();
        assert!(store.visas.contains_key(&7));
        assert!(!store.by_node.contains_key(&node_addr));
    }

    /// Regression for the partial-clear divergence (issue #1): a failed Redis
    /// write must leave Redis and memory consistent. The atomic pipeline rejects
    /// as a whole, so nothing is cleared on either side — no half-cleared state.
    #[tokio::test]
    async fn test_clear_node_state_write_failure_stays_consistent() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::30".parse().unwrap();

        // One node referenced by two visas.
        for id in [70u64, 71] {
            let visa = make_visa(id, Duration::from_secs(60));
            repo.store_visa(&visa, md(node_addr), NodeVisaState::Installed)
                .await
                .unwrap();
        }

        // The clear's pipeline fails atomically.
        db.set_set_ex_fault(FaultMode::Reject);
        assert!(repo.clear_node_state(&node_addr).await.is_err());

        // Redis kept the node on both records (pipeline applied nothing)...
        db.set_set_ex_fault(FaultMode::None);
        let node_str = ZAddr::from(&node_addr).to_string();
        for id in [70u64, 71] {
            assert!(
                read_record(&db, id)
                    .await
                    .node_states
                    .contains_key(&node_str),
                "Redis record {id} should be untouched",
            );
        }

        // ...and so did memory: the two agree, no divergence.
        let store = repo.inner.store.read().unwrap();
        assert!(store.by_node.contains_key(&node_addr));
        assert!(store.visas[&70].node_states.contains_key(&node_addr));
        assert!(store.visas[&71].node_states.contains_key(&node_addr));
    }

    /// Storing an already-expired visa is a NOP (not an error): it returns Ok
    /// but writes nothing to memory (nor Redis, since ttl==0 short-circuits).
    #[tokio::test]
    async fn test_store_visa_nop_expired() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let mut visa = make_visa(8, Duration::from_secs(1));
        visa.expires = SystemTime::now() - Duration::from_secs(1);

        let _res = repo
            .store_visa(&visa, md(node_addr), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        // Not written
        let store = repo.inner.store.read().unwrap();
        assert!(!store.visas.contains_key(&8));
    }

    #[tokio::test]
    async fn test_list_visa_ids_after_store() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        for id in [1u64, 5, 42] {
            let visa = make_visa(id, Duration::from_secs(60));
            repo.store_visa(&visa, md(node_addr), NodeVisaState::PendingInstall)
                .await
                .unwrap();
        }

        let mut ids = repo.list_visa_ids().unwrap();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 5, 42]);
    }

    #[tokio::test]
    async fn test_get_visa_by_id() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::8".parse().unwrap();
        let visa = make_visa(77, Duration::from_secs(60));

        repo.store_visa(&visa, md(node_addr), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let loaded = repo.get_visa_by_id(77).unwrap();
        assert_eq!(loaded.issuer_id, 77);
        assert_eq!(
            loaded.dock_pep.as_ref().unwrap().source_addr,
            visa.dock_pep.as_ref().unwrap().source_addr
        );
        assert_eq!(
            loaded.dock_pep.as_ref().unwrap().dest_addr,
            visa.dock_pep.as_ref().unwrap().dest_addr
        );
    }

    #[tokio::test]
    async fn test_get_visa_by_id_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let err = repo.get_visa_by_id(1234).unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_get_visa_metadata_by_id() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::9".parse().unwrap();
        let visa = make_visa(88, Duration::from_secs(60));

        repo.store_visa(&visa, md(node_addr), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let metadata = repo.get_visa_metadata_by_id(88).unwrap();
        assert_eq!(metadata.requesting_node, node_addr);
        assert!(metadata.ctime > SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn test_get_visa_metadata_by_id_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let err = repo.get_visa_metadata_by_id(999).unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    /// A VisaMetadata with non-default values survives a serialize round-trip.
    #[test]
    fn test_visa_metadata_round_trip() {
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let original = VisaMetadata {
            requesting_node: node_addr,
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            policy_version: 42,
            created_vinst: 7,
            checked_vinst: 9,
            zpl: "permit src any dst any".to_string(),
            signal_msgs: vec!["sig-a".to_string(), "sig-b".to_string()],
            direction: Direction::Reverse,
            path: None,
            five_tuple: make_pdesc().five_tuple,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.requesting_node, original.requesting_node);
        assert_eq!(decoded.ctime, original.ctime);
        assert_eq!(decoded.policy_version, original.policy_version);
        assert_eq!(decoded.zpl, original.zpl);
        assert_eq!(decoded.signal_msgs, original.signal_msgs);
        assert_eq!(decoded.direction, original.direction);
        assert_eq!(decoded.created_vinst, original.created_vinst);
        assert_eq!(decoded.checked_vinst, original.checked_vinst);
    }

    /// signal_msgs is preserved when non-empty across a serialize round-trip.
    #[test]
    fn test_visa_metadata_signal_msgs_preserved() {
        let node_addr: IpAddr = "fd5a:5052::12".parse().unwrap();
        let signals = vec!["msg-1".to_string(), "msg-2".to_string()];
        let original = VisaMetadata {
            requesting_node: node_addr,
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            policy_version: 1,
            created_vinst: 0,
            checked_vinst: 0,
            zpl: String::new(),
            signal_msgs: signals.clone(),
            direction: Direction::Forward,
            path: None,
            five_tuple: make_pdesc().five_tuple,
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signal_msgs, signals);
    }

    /// Both Direction variants survive a serialize round-trip.
    #[test]
    fn test_visa_metadata_direction_round_trip_both_variants() {
        let node_addr: IpAddr = "fd5a:5052::13".parse().unwrap();
        for direction in [Direction::Forward, Direction::Reverse] {
            let original = VisaMetadata {
                requesting_node: node_addr,
                ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_002),
                policy_version: 0,
                created_vinst: 0,
                checked_vinst: 0,
                zpl: String::new(),
                signal_msgs: Vec::new(),
                direction,
                path: None,
                five_tuple: make_pdesc().five_tuple,
            };
            let json = serde_json::to_string(&original).unwrap();
            let decoded: VisaMetadata = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.direction, direction);
        }
    }

    /// With a path, the requesting node gets the passed state (Installed) and
    /// every other node on the path gets PendingInstall.
    #[tokio::test]
    async fn test_store_visa_with_path_sets_path_nodes_pending() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let requesting: IpAddr = "fd5a:5052::30".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052::31".parse().unwrap();
        let node_c: IpAddr = "fd5a:5052::32".parse().unwrap();
        let visa = make_visa(100, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, node_b, node_c]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        let record = read_record(&db, 100).await;
        assert_eq!(
            record
                .node_states
                .get(&ZAddr::from(&requesting).to_string())
                .unwrap()
                .state,
            NodeVisaState::Installed
        );
        for node in [node_b, node_c] {
            assert_eq!(
                record
                    .node_states
                    .get(&ZAddr::from(&node).to_string())
                    .unwrap()
                    .state,
                NodeVisaState::PendingInstall
            );
        }
    }

    /// When the requesting node also appears in the path, it keeps its passed
    /// state (Installed) rather than being downgraded to PendingInstall.
    #[tokio::test]
    async fn test_store_visa_requesting_node_in_path_not_overwritten() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let requesting: IpAddr = "fd5a:5052::40".parse().unwrap();
        let other: IpAddr = "fd5a:5052::41".parse().unwrap();
        let visa = make_visa(101, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, other]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        let record = read_record(&db, 101).await;
        assert_eq!(
            record
                .node_states
                .get(&ZAddr::from(&requesting).to_string())
                .unwrap()
                .state,
            NodeVisaState::Installed,
            "requesting node state should not be overwritten"
        );
        assert_eq!(
            record
                .node_states
                .get(&ZAddr::from(&other).to_string())
                .unwrap()
                .state,
            NodeVisaState::PendingInstall
        );
    }

    #[tokio::test]
    async fn test_store_visa_path_nodes_queryable_by_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let requesting: IpAddr = "fd5a:5052::50".parse().unwrap();
        let path_node: IpAddr = "fd5a:5052::51".parse().unwrap();
        let visa = make_visa(102, Duration::from_secs(60));

        let metadata = VisaMetadata::new(
            requesting,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![requesting, path_node]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let ids = repo
            .get_visa_ids_for_node_by_state(&path_node, NodeVisaState::PendingInstall)
            .unwrap();
        assert_eq!(ids, vec![102]);
        assert!(
            repo.get_visa_ids_for_node_by_state(&path_node, NodeVisaState::Installed)
                .unwrap()
                .is_empty()
        );
    }

    /// With no path, only the requesting node gets a state entry; unrelated
    /// nodes are absent from the record.
    #[tokio::test]
    async fn test_store_visa_no_path_only_requesting_node_gets_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let requesting: IpAddr = "fd5a:5052::60".parse().unwrap();
        let unrelated: IpAddr = "fd5a:5052::61".parse().unwrap();
        let visa = make_visa(103, Duration::from_secs(60));

        repo.store_visa(&visa, md(requesting), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let record = read_record(&db, 103).await;
        assert!(
            record
                .node_states
                .contains_key(&ZAddr::from(&requesting).to_string())
        );
        assert!(
            !record
                .node_states
                .contains_key(&ZAddr::from(&unrelated).to_string())
        );
    }

    #[tokio::test]
    async fn test_get_visa_ids_for_node_by_state_filters_correctly() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node_addr: IpAddr = "fd5a:5052::20".parse().unwrap();

        let visa_a = make_visa(10, Duration::from_secs(60));
        repo.store_visa(&visa_a, md(node_addr), NodeVisaState::PendingInstall)
            .await
            .unwrap();
        let visa_b = make_visa(11, Duration::from_secs(60));
        repo.store_visa(&visa_b, md(node_addr), NodeVisaState::Installed)
            .await
            .unwrap();

        let pending_ids = repo
            .get_visa_ids_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .unwrap();
        assert_eq!(pending_ids, vec![10]);
        assert_eq!(
            repo.get_count_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
                .unwrap(),
            1
        );

        let installed_ids = repo
            .get_visa_ids_for_node_by_state(&node_addr, NodeVisaState::Installed)
            .unwrap();
        assert_eq!(installed_ids, vec![11]);
    }

    // --- new store tests ---

    /// Store visas via one repo, load a second repo on the same DB, and check
    /// the ids, metadata, node states, and by_node index all round-trip.
    #[tokio::test]
    async fn test_state_load_round_trip() {
        let db = Arc::new(FakeDb::new());
        let repo1 = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::70".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052::71".parse().unwrap();

        let visa = make_visa(200, Duration::from_secs(60));
        let metadata = VisaMetadata::new(
            req,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![req, node_b]),
            &make_pdesc(),
        );
        repo1
            .store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        let repo2 = VisaRepo::new(db.clone(), 1).await.unwrap();
        let s1 = repo1.inner.store.read().unwrap();
        let s2 = repo2.inner.store.read().unwrap();
        assert_eq!(
            s1.visas.keys().collect::<HashSet<_>>(),
            s2.visas.keys().collect::<HashSet<_>>()
        );
        let e2 = s2.visas.get(&200).unwrap();
        assert_eq!(e2.metadata.requesting_node, req);
        assert_eq!(
            e2.node_states.get(&req).unwrap().state,
            NodeVisaState::Installed
        );
        assert_eq!(
            e2.node_states.get(&node_b).unwrap().state,
            NodeVisaState::PendingInstall
        );
        assert!(s2.by_node.get(&req).unwrap().contains(&200));
        assert!(s2.by_node.get(&node_b).unwrap().contains(&200));
    }

    /// State load DELetes records it cannot use (undecodable, expired) rather than
    /// silently skipping — a second state load then finds nothing.
    #[tokio::test]
    async fn test_state_load_deletes_broken_and_expired() {
        let db = Arc::new(FakeDb::new());
        let node: IpAddr = "fd5a:5052::80".parse().unwrap();

        // Undecodable value at a visa key.
        db.set_ex("visa:900", "not-a-json-record", 100)
            .await
            .unwrap();

        // Expired record: a visa whose embedded expiry is already in the past,
        // persisted with a still-live Redis TTL.
        let mut visa = make_visa(901, Duration::from_secs(60));
        visa.expires = SystemTime::now() - Duration::from_secs(10);
        let node_states = HashMap::from([(
            node,
            NodeState {
                state: NodeVisaState::Installed,
                revoke_vinst: None,
            },
        )]);
        let record = build_record(&visa, &md(node), &node_states).unwrap();
        db.set_ex("visa:901", &serde_json::to_string(&record).unwrap(), 100)
            .await
            .unwrap();

        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        assert!(repo.inner.store.read().unwrap().visas.is_empty());
        assert!(!db.exists("visa:900").await.unwrap());
        assert!(!db.exists("visa:901").await.unwrap());

        // A second load has nothing to drop.
        let repo2 = VisaRepo::new(db.clone(), 1).await.unwrap();
        assert!(repo2.inner.store.read().unwrap().visas.is_empty());
    }

    /// After each mutator the persisted record matches the in-memory image.
    #[tokio::test]
    async fn test_write_through_matches_memory() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::90".parse().unwrap();
        let visa = make_visa(300, Duration::from_secs(60));

        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_memory_matches_redis(&repo, &db, 300).await;

        assert!(
            repo.transition_node_visa_state(
                node,
                300,
                NodeVisaState::PendingInstall,
                NodeVisaState::Installed
            )
            .await
            .unwrap()
        );
        assert_memory_matches_redis(&repo, &db, 300).await;
    }

    /// Reject-mode set_ex: the write fails and nothing is applied anywhere.
    #[tokio::test]
    async fn test_store_visa_reject_mode_leaves_nothing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::91".parse().unwrap();
        let visa = make_visa(400, Duration::from_secs(60));

        db.set_set_ex_fault(FaultMode::Reject);
        let err = repo
            .store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Redis(_)));

        assert!(!db.exists("visa:400").await.unwrap());
        assert!(repo.inner.store.read().unwrap().visas.is_empty());
    }

    /// Ambiguous store_visa: set_ex applies but errors → the compensating DEL
    /// removes the orphan key; no memory entry either.
    #[tokio::test]
    async fn test_store_visa_apply_then_error_compensating_del() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::92".parse().unwrap();
        let visa = make_visa(401, Duration::from_secs(60));

        db.set_set_ex_fault(FaultMode::ApplyThenError);
        let err = repo
            .store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Redis(_)));

        assert!(!db.exists("visa:401").await.unwrap());
        assert!(repo.inner.store.read().unwrap().visas.is_empty());
    }

    /// Ambiguous store_visa where the compensating DEL also fails: the key
    /// survives and a later reload resurrects it (documented residual).
    #[tokio::test]
    async fn test_store_visa_apply_then_error_del_also_fails_resurrects() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::93".parse().unwrap();
        let visa = make_visa(402, Duration::from_secs(60));

        db.set_set_ex_fault(FaultMode::ApplyThenError);
        db.set_del_fault(FaultMode::Reject);
        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap_err();

        assert!(db.exists("visa:402").await.unwrap());
        assert!(repo.inner.store.read().unwrap().visas.is_empty());

        // Reset faults and reload — the orphan comes back.
        db.set_set_ex_fault(FaultMode::None);
        db.set_del_fault(FaultMode::None);
        let repo2 = VisaRepo::new(db.clone(), 1).await.unwrap();
        assert!(repo2.inner.store.read().unwrap().visas.contains_key(&402));
    }

    /// Ambiguous record rewrite: Redis takes the new state, memory keeps the old
    /// and the caller errors; the next successful mutation converges both.
    #[tokio::test]
    async fn test_record_rewrite_apply_then_error_converges() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::94".parse().unwrap();
        let visa = make_visa(403, Duration::from_secs(60));
        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        db.set_set_ex_fault(FaultMode::ApplyThenError);
        repo.transition_node_visa_state(
            node,
            403,
            NodeVisaState::PendingInstall,
            NodeVisaState::Installed,
        )
        .await
        .unwrap_err();

        // Memory kept the old state; Redis diverged to the new one.
        {
            let store = repo.inner.store.read().unwrap();
            assert_eq!(
                store
                    .visas
                    .get(&403)
                    .unwrap()
                    .node_states
                    .get(&node)
                    .unwrap()
                    .state,
                NodeVisaState::PendingInstall
            );
        }
        let record = read_record(&db, 403).await;
        assert_eq!(
            record
                .node_states
                .get(&ZAddr::from(&node).to_string())
                .unwrap()
                .state,
            NodeVisaState::Installed
        );

        // A clean mutation converges both.
        db.set_set_ex_fault(FaultMode::None);
        assert!(
            repo.transition_node_visa_state(
                node,
                403,
                NodeVisaState::PendingInstall,
                NodeVisaState::Installed
            )
            .await
            .unwrap()
        );
        assert_memory_matches_redis(&repo, &db, 403).await;
    }

    /// Ambiguous DEL (remove path): Redis drops the key but errors → memory keeps
    /// the entry; a subsequent rewrite recreates the key with a (finite) TTL.
    #[tokio::test(start_paused = true)]
    async fn test_del_apply_then_error_recreated_with_ttl() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::95".parse().unwrap();
        let visa = make_visa(404, Duration::from_secs(60));
        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        db.set_del_fault(FaultMode::ApplyThenError);
        repo.remove_visa(404).await.unwrap_err();
        // Redis key gone, memory keeps the entry.
        assert!(!db.exists("visa:404").await.unwrap());
        assert!(repo.inner.store.read().unwrap().visas.contains_key(&404));

        // A rewrite recreates the key.
        db.set_del_fault(FaultMode::None);
        assert!(
            repo.transition_node_visa_state(
                node,
                404,
                NodeVisaState::PendingInstall,
                NodeVisaState::Installed
            )
            .await
            .unwrap()
        );
        assert!(db.exists("visa:404").await.unwrap());

        // The recreated key has a finite TTL: advancing past expiry removes it.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(!db.exists("visa:404").await.unwrap());
    }

    /// by_node index stays consistent through store / clear_node_state / remove.
    #[tokio::test]
    async fn test_by_node_index_consistency() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::a0".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052::a1".parse().unwrap();
        let node_c: IpAddr = "fd5a:5052::a2".parse().unwrap();
        let visa = make_visa(500, Duration::from_secs(60));
        let metadata = VisaMetadata::new(
            req,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![req, node_b, node_c]),
            &make_pdesc(),
        );
        repo.store_visa(&visa, metadata, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        {
            let store = repo.inner.store.read().unwrap();
            for n in [req, node_b, node_c] {
                assert!(store.by_node.get(&n).unwrap().contains(&500));
            }
        }

        repo.clear_node_state(&node_b).await.unwrap();
        {
            let store = repo.inner.store.read().unwrap();
            assert!(!store.by_node.contains_key(&node_b));
            assert!(store.by_node.get(&req).unwrap().contains(&500));
            assert!(store.by_node.get(&node_c).unwrap().contains(&500));
        }

        repo.remove_visa(500).await.unwrap();
        {
            let store = repo.inner.store.read().unwrap();
            assert!(store.visas.is_empty());
            assert!(store.by_node.is_empty());
        }
    }

    /// Expired entries are invisible to reads before purge; purge_expired drops
    /// them and their index rows.
    #[tokio::test(start_paused = true)]
    async fn test_expired_invisible_then_purged() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::b0".parse().unwrap();
        let visa = make_visa(600, Duration::from_secs(5));
        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(6)).await;

        // Invisible to reads, but still resident until purge.
        assert!(repo.list_visa_ids().unwrap().is_empty());
        assert!(matches!(
            repo.get_visa_by_id(600).unwrap_err(),
            StoreError::NotFound(_)
        ));
        assert!(repo.inner.store.read().unwrap().visas.contains_key(&600));

        repo.purge_expired().unwrap();
        let store = repo.inner.store.read().unwrap();
        assert!(store.visas.is_empty());
        assert!(store.by_node.is_empty());
    }

    // --- Visa "sweep" (from policy update) / teardown tests ---

    /// Store a three-node visa (requesting + two path nodes): requesting node is
    /// `Installed`, path nodes `PendingInstall`. `vinst` seeds created/checked.
    async fn store_three_node(
        repo: &VisaRepo,
        id: u64,
        req: IpAddr,
        b: IpAddr,
        c: IpAddr,
        vinst: u64,
    ) {
        let metadata = VisaMetadata::new(
            req,
            0,
            vinst,
            String::new(),
            Direction::Forward,
            Some(vec![req, b, c]),
            &make_pdesc(),
        );
        let visa = make_visa(id, Duration::from_secs(60));
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();
    }

    /// An allow verdict cancels a queued revoke on every holder node
    /// (`PendingRevoke -> PendingInstall`, stamp cleared) and bumps checked_vinst.
    #[tokio::test]
    async fn test_record_allow_cancels_queued_revokes() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::c0".parse().unwrap();
        let b: IpAddr = "fd5a:5052::c1".parse().unwrap();
        let c: IpAddr = "fd5a:5052::c2".parse().unwrap();
        store_three_node(&repo, 700, req, b, c, 5).await;

        // Deny at 6 marks all nodes PendingRevoke (stamp 6).
        assert!(repo.record_deny_verdict(700, 6).await.unwrap());
        // Allow at 7 cancels them (6 < 7) and bumps checked_vinst.
        assert!(repo.record_allow_verdict(700, 7).await.unwrap());

        let store = repo.inner.store.read().unwrap();
        let e = store.visas.get(&700).unwrap();
        for n in [req, b, c] {
            let ns = e.node_states.get(&n).unwrap();
            assert_eq!(ns.state, NodeVisaState::PendingInstall);
            assert_eq!(ns.revoke_vinst, None);
        }
        assert_eq!(e.metadata.checked_vinst, 7);
    }

    /// Stale verdicts no-op at the store boundary: checked_vinst is never lowered,
    /// a stale revoke is not stamped, and a stale allow cannot cancel a newer revoke.
    #[tokio::test]
    async fn test_verdict_stale_guards() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::d0".parse().unwrap();
        let metadata = VisaMetadata::new(
            node,
            0,
            5,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        let visa = make_visa(710, Duration::from_secs(60));
        repo.store_visa(&visa, metadata, NodeVisaState::Installed)
            .await
            .unwrap();

        // Allow at 6 bumps checked to 6.
        assert!(repo.record_allow_verdict(710, 6).await.unwrap());
        // Not-newer allow (6) and stale deny (5) both no-op.
        assert!(!repo.record_allow_verdict(710, 6).await.unwrap());
        assert!(!repo.record_deny_verdict(710, 5).await.unwrap());
        {
            let store = repo.inner.store.read().unwrap();
            let e = store.visas.get(&710).unwrap();
            assert_eq!(e.metadata.checked_vinst, 6);
            assert_eq!(
                e.node_states.get(&node).unwrap().state,
                NodeVisaState::Installed
            );
        }

        // Deny at 7 stamps PendingRevoke; a stale allow (6) does not cancel it.
        assert!(repo.record_deny_verdict(710, 7).await.unwrap());
        assert!(!repo.record_allow_verdict(710, 6).await.unwrap());
        let store = repo.inner.store.read().unwrap();
        let ns = store
            .visas
            .get(&710)
            .unwrap()
            .node_states
            .get(&node)
            .unwrap();
        assert_eq!(ns.state, NodeVisaState::PendingRevoke);
        assert_eq!(ns.revoke_vinst, Some(7));
    }

    /// CAS transition applies only when the current state matches `expected`;
    /// conditional teardown fires only on `PendingRevoke`.
    #[tokio::test]
    async fn test_transition_cas_and_conditional_teardown() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::e0".parse().unwrap();
        let visa = make_visa(720, Duration::from_secs(60));
        repo.store_visa(&visa, md(node), NodeVisaState::PendingInstall)
            .await
            .unwrap();

        // CAS PendingInstall -> Installed succeeds, then a repeat misses.
        assert!(
            repo.transition_node_visa_state(
                node,
                720,
                NodeVisaState::PendingInstall,
                NodeVisaState::Installed
            )
            .await
            .unwrap()
        );
        assert!(
            !repo
                .transition_node_visa_state(
                    node,
                    720,
                    NodeVisaState::PendingInstall,
                    NodeVisaState::Installed
                )
                .await
                .unwrap()
        );

        // Not PendingRevoke → teardown misses.
        assert!(!repo.remove_node_if_pending_revoke(node, 720).await.unwrap());

        // Deny → PendingRevoke, then teardown fires and clears the ref + index.
        assert!(repo.record_deny_verdict(720, 1).await.unwrap());
        assert!(repo.remove_node_if_pending_revoke(node, 720).await.unwrap());
        assert!(!repo.visa_has_node_refs(720).await);
        let store = repo.inner.store.read().unwrap();
        assert!(!store.by_node.contains_key(&node));
        assert!(store.visas.get(&720).unwrap().node_states.is_empty());
    }

    /// Expired visas are invisible to every Phase 2 method (before purge).
    #[tokio::test(start_paused = true)]
    async fn test_phase2_methods_ignore_expired() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::f0".parse().unwrap();
        let visa = make_visa(730, Duration::from_secs(5));
        repo.store_visa(&visa, md(node), NodeVisaState::Installed)
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(6)).await;

        assert!(!repo.visa_has_node_refs(730).await);
        assert!(
            !repo
                .transition_node_visa_state(
                    node,
                    730,
                    NodeVisaState::Installed,
                    NodeVisaState::PendingRevoke
                )
                .await
                .unwrap()
        );
        assert!(!repo.record_allow_verdict(730, 99).await.unwrap());
        assert!(!repo.record_deny_verdict(730, 99).await.unwrap());
        assert!(repo.list_visa_metadata().await.is_empty());
        // Still resident until purge.
        assert!(repo.inner.store.read().unwrap().visas.contains_key(&730));
    }

    /// Verdict mutators write through (record matches memory) and a second repo
    /// hydrated from the same DB reproduces states and revoke_vinst stamps.
    #[tokio::test]
    async fn test_verdict_write_through_and_hydration() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::1a0".parse().unwrap();
        let b: IpAddr = "fd5a:5052::1a1".parse().unwrap();
        let c: IpAddr = "fd5a:5052::1a2".parse().unwrap();
        store_three_node(&repo, 740, req, b, c, 0).await;

        assert!(repo.record_deny_verdict(740, 3).await.unwrap());
        assert_memory_matches_redis(&repo, &db, 740).await;
        assert!(repo.remove_node_if_pending_revoke(b, 740).await.unwrap());
        assert_memory_matches_redis(&repo, &db, 740).await;

        let repo2 = VisaRepo::new(db.clone(), 1).await.unwrap();
        let store = repo2.inner.store.read().unwrap();
        let e = store.visas.get(&740).unwrap();
        assert!(e.node_states.get(&b).is_none());
        for n in [req, c] {
            let ns = e.node_states.get(&n).unwrap();
            assert_eq!(ns.state, NodeVisaState::PendingRevoke);
            assert_eq!(ns.revoke_vinst, Some(3));
        }
    }

    /// Reject-mode fault on a verdict rewrite → error returned, memory unchanged.
    #[tokio::test]
    async fn test_verdict_reject_fault_leaves_memory() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::1b0".parse().unwrap();
        let visa = make_visa(750, Duration::from_secs(60));
        repo.store_visa(&visa, md(node), NodeVisaState::Installed)
            .await
            .unwrap();

        db.set_set_ex_fault(FaultMode::Reject);
        let err = repo.record_deny_verdict(750, 5).await.unwrap_err();
        assert!(matches!(err, StoreError::Redis(_)));

        // Memory untouched: still Installed, checked_vinst still 0.
        db.set_set_ex_fault(FaultMode::None);
        let store = repo.inner.store.read().unwrap();
        let e = store.visas.get(&750).unwrap();
        assert_eq!(
            e.node_states.get(&node).unwrap().state,
            NodeVisaState::Installed
        );
        assert_eq!(e.metadata.checked_vinst, 0);
    }

    /// Build metadata whose five-tuple uses the given src/dst endpoint strings.
    fn md_ft(node: IpAddr, src: &str, dst: &str) -> VisaMetadata {
        let pdesc = PacketDesc::new_tcp(src, dst, 1234, 443).unwrap();
        VisaMetadata::new(node, 0, 0, String::new(), Direction::Forward, None, &pdesc)
    }

    /// Two visas sharing the same endpoints both resolve for either endpoint;
    /// removing one leaves the other resolvable and the removed id gone.
    #[tokio::test]
    async fn test_get_visa_ids_for_actors_shared_endpoint() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::100".parse().unwrap();
        // md() five-tuple endpoints are ::10 (src) and ::20 (dst).
        let src: IpAddr = "fd5a:5052::10".parse().unwrap();
        let dst: IpAddr = "fd5a:5052::20".parse().unwrap();

        for id in [200u64, 201] {
            let visa = make_visa(id, Duration::from_secs(60));
            repo.store_visa(&visa, md(node), NodeVisaState::Installed)
                .await
                .unwrap();
        }

        for actor in [src, dst] {
            let mut ids = repo.get_visa_ids_for_actors(&[actor]).unwrap();
            ids.sort_unstable();
            assert_eq!(ids, vec![200, 201]);
        }

        repo.remove_visa(200).await.unwrap();
        assert_eq!(repo.get_visa_ids_for_actors(&[src]).unwrap(), vec![201]);
    }

    /// An expired entry still sitting in `by_actor` (purge not yet run) is
    /// filtered out of the query by the liveness check.
    #[tokio::test(start_paused = true)]
    async fn test_get_visa_ids_for_actors_filters_expired() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::101".parse().unwrap();
        let src: IpAddr = "fd5a:5052::10".parse().unwrap();
        let visa = make_visa(210, Duration::from_secs(60));
        repo.store_visa(&visa, md(node), NodeVisaState::Installed)
            .await
            .unwrap();

        assert_eq!(repo.get_visa_ids_for_actors(&[src]).unwrap(), vec![210]);

        // Age past expiry without running purge; the id lingers in by_actor.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(repo.get_visa_ids_for_actors(&[src]).unwrap().is_empty());
    }

    /// When one actor is both src and dst of a visa, it resolves to a single id
    /// (no duplicate from the two by_actor rows collapsing to one).
    #[tokio::test]
    async fn test_get_visa_ids_for_actors_dedup() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db, 1).await.unwrap();
        let node: IpAddr = "fd5a:5052::102".parse().unwrap();
        let actor: IpAddr = "fd5a:5052::10".parse().unwrap();
        let visa = make_visa(220, Duration::from_secs(60));
        repo.store_visa(
            &visa,
            md_ft(node, "fd5a:5052::10", "fd5a:5052::10"),
            NodeVisaState::Installed,
        )
        .await
        .unwrap();

        // Same actor passed twice as well: still exactly one id.
        assert_eq!(
            repo.get_visa_ids_for_actors(&[actor, actor]).unwrap(),
            vec![220]
        );
    }

    /// `mark_visa_revoked` flips every node PendingRevoke (with no revoke_vinst
    /// stamp), keeps Redis and memory in agreement, and no-ops on a missing
    /// id.
    #[tokio::test]
    async fn test_mark_visa_revoked_write_through() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::f0".parse().unwrap();
        let b: IpAddr = "fd5a:5052::f1".parse().unwrap();
        let c: IpAddr = "fd5a:5052::f2".parse().unwrap();
        store_three_node(&repo, 800, req, b, c, 5).await;

        assert!(repo.mark_visa_revoked(800).await.unwrap());
        {
            let store = repo.inner.store.read().unwrap();
            let e = store.visas.get(&800).unwrap();
            for n in [req, b, c] {
                let ns = e.node_states.get(&n).unwrap();
                assert_eq!(ns.state, NodeVisaState::PendingRevoke);
                assert_eq!(ns.revoke_vinst, None); // no vinst stamp
            }
            // checked_vinst untouched (not a policy event).
            assert_eq!(e.metadata.checked_vinst, 5);
        }
        assert_memory_matches_redis(&repo, &db, 800).await;

        // Missing id is a no-op.
        assert!(!repo.mark_visa_revoked(999).await.unwrap());
    }

    /// An unconditional revocation (link down, departure) is not cancelled by a later
    /// allow verdict, even on a visa an earlier policy deny had stamped (round 13,
    /// Copilot): `mark_visa_revoked` clears the stamp, so `record_allow_verdict`'s
    /// `rv < vinst` test can never match.
    #[tokio::test]
    async fn test_mark_visa_revoked_is_not_cancelled_by_a_later_allow() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::f0".parse().unwrap();
        let b: IpAddr = "fd5a:5052::f1".parse().unwrap();
        let c: IpAddr = "fd5a:5052::f2".parse().unwrap();
        store_three_node(&repo, 810, req, b, c, 5).await;

        assert!(repo.record_deny_verdict(810, 6).await.unwrap());
        assert!(repo.mark_visa_revoked(810).await.unwrap());
        assert!(repo.record_allow_verdict(810, 7).await.unwrap());
        {
            let store = repo.inner.store.read().unwrap();
            let e = store.visas.get(&810).unwrap();
            for n in [req, b, c] {
                let ns = e.node_states.get(&n).unwrap();
                assert_eq!(ns.state, NodeVisaState::PendingRevoke);
                assert_eq!(ns.revoke_vinst, None);
            }
        }
        assert_memory_matches_redis(&repo, &db, 810).await;
    }

    /// Round 14 (Copilot): an unconditional revocation also survives a policy deny
    /// followed by an allow. The deny must not stamp a `revoke_vinst` onto it, or the
    /// newer allow could cancel it.
    #[tokio::test]
    async fn test_unconditional_revocation_survives_deny_then_allow() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone(), 1).await.unwrap();
        let req: IpAddr = "fd5a:5052::f0".parse().unwrap();
        let b: IpAddr = "fd5a:5052::f1".parse().unwrap();
        let c: IpAddr = "fd5a:5052::f2".parse().unwrap();
        store_three_node(&repo, 820, req, b, c, 5).await;

        assert!(repo.mark_visa_revoked(820).await.unwrap());
        assert!(repo.record_deny_verdict(820, 6).await.unwrap());
        assert!(repo.record_allow_verdict(820, 7).await.unwrap());
        {
            let store = repo.inner.store.read().unwrap();
            let e = store.visas.get(&820).unwrap();
            for n in [req, b, c] {
                let ns = e.node_states.get(&n).unwrap();
                assert_eq!(ns.state, NodeVisaState::PendingRevoke);
                assert_eq!(ns.revoke_vinst, None);
            }
        }
        assert_memory_matches_redis(&repo, &db, 820).await;
    }
}
