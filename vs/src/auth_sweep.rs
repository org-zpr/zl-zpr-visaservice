//! Periodic authentication-expiry sweep: find connected adapter actors whose
//! authentication has expired, revoke their authentications on the docking
//! node's VSS, and drop them from the actor store — but only after the node
//! positively acks the revocation, so a VSS outage just defers the removal to
//! the next pass.
//!
//! Like `visa_reconciler::revalidate_visas`, the pass is a plain async fn the
//! spawned loop calls, so tests drive single passes directly — no timers in
//! tests. Node actors are out of scope (operator decision on zipline#44):
//! expired nodes are culled at startup by `actor_mgr::refresh_state`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use libeval::actor::Actor;
use libeval::attribute::key;
use zpr::vsapi::v1::DisconnectReason;

use crate::assembly::Assembly;
use crate::config;
use crate::db;
use crate::logging::targets::ACTOR;

/// What one sweep pass did, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepStats {
    /// Actors examined.
    pub checked: usize,
    /// Actors revoked on their docking node and removed from the store.
    pub revoked: usize,
    /// Expired actors left in place for the next pass (no VSS handle, or the
    /// revocation was not positively acked).
    pub deferred: usize,
}

/// What one reauth-obligation sweep pass did (zipline#123), for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReauthSweepStats {
    /// Pending obligations considered.
    pub obligations: usize,
    /// Obligations pruned as satisfied (every connected actor at or past V).
    pub pruned: usize,
    /// Actors still inside their window that were asked (again) to re-auth.
    pub requested: usize,
    /// Actors revoked for missing the deadline (nodes disconnected, adapters
    /// revoked-and-removed).
    pub revoked: usize,
    /// Overdue actors left in place for the next pass (no VSS handle, or the
    /// revocation was not positively acked).
    pub deferred: usize,
}

/// What one denylist enforcement pass did (zipline#136), for logging, tests,
/// and the admin `Revokes` response.
#[derive(Debug, Default)]
pub(crate) struct DenylistSweepStats {
    /// Connected actors examined.
    pub checked: usize,
    /// Actors revoked, with the denylisted CN that matched each: nodes
    /// disconnected (their docked adapters cascade), adapters revoked on
    /// their docking node and removed only on a positive ack.
    pub revoked: Vec<(IpAddr, String)>,
    /// Matched actors left in place for the next pass (no VSS handle, or the
    /// revocation was not positively acked).
    pub deferred: usize,
}

/// Enforce the bootstrap-key denylist (zipline#136): every connected actor
/// whose `device.zpr.authority` is `zpr-bootstrap` and whose authenticated CN
/// is denylisted is revoked immediately — no policy install, no
/// `reauth_deadline` wait — through the zipline#123 revoke machinery. Nodes
/// admitted under a denylisted CN are disconnected (`cc.disconnect(.., Admin)`),
/// which also drops their docked adapters (operator answer Q2 on zipline#136);
/// adapters go through the batched per-node `revokeAuthentication` and are
/// removed only on a positive ack, so a VSS outage defers the removal to the
/// next pass. Runs on every add to the denylist and on the periodic sweep
/// tick (to retry deferrals).
pub(crate) async fn sweep_denylisted_actors(asm: &Arc<Assembly>) -> DenylistSweepStats {
    let mut stats = DenylistSweepStats::default();

    let denylist = db::BootstrapDenylist::new(asm.state_db.clone());
    let denied: std::collections::HashSet<String> = match denylist.list().await {
        Ok(entries) => entries.into_iter().map(|(_, cn)| cn).collect(),
        Err(e) => {
            warn!(target: ACTOR, "denylist sweep: failed to list denylist: {e}");
            return stats;
        }
    };
    if denied.is_empty() {
        return stats;
    }

    /// A matched actor: its address, the denylisted CN that admitted it,
    /// whether it is a node, and (for adapters) its docking node.
    struct Entry {
        addr: IpAddr,
        cn: String,
        is_node: bool,
        dock: Option<IpAddr>,
    }

    // Snapshot every connected actor and keep the bootstrap-admitted ones
    // whose authenticated CN is denylisted. The VS's own actor is exempt for
    // the same reason as in the reauth sweep — and its CN is not policy data
    // anyway.
    let listed = match asm.actor_mgr.list_actors(None).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(target: ACTOR, "denylist sweep: failed to list actors: {e}");
            return stats;
        }
    };
    let mut matched: Vec<Entry> = Vec::new();
    for (addr, _cn) in listed {
        let actor = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
            Ok(Some(actor)) => actor,
            Ok(None) => continue, // Removed between list and fetch.
            Err(e) => {
                warn!(target: ACTOR, "denylist sweep: failed to load actor {addr}: {e}");
                continue;
            }
        };
        stats.checked += 1;
        if actor.get_cn() == Some(config::VS_CN)
            && addr == std::net::IpAddr::V6(config::VS_ZPR_ADDR)
        {
            continue;
        }
        // Only a bootstrap-admitted device authority is subject to the
        // bootstrap-key denylist: the CN of an OIDC-only actor is a display
        // label, not an authenticated key binding.
        let bootstrap_admitted = actor
            .get_attribute(key::DEVICE_AUTHORITY)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|method| method == key::AUTHORITY_METHOD_BOOTSTRAP);
        if !bootstrap_admitted {
            continue;
        }
        let Some(cn) = actor.get_cn() else { continue };
        if !denied.contains(cn) {
            continue;
        }
        matched.push(Entry {
            addr,
            cn: cn.to_string(),
            is_node: actor.is_node(),
            dock: asm.actor_mgr.get_docking_node_for_actor(&actor),
        });
    }
    if matched.is_empty() {
        return stats;
    }

    // Nodes first — `cc.disconnect` also drops their docked adapters
    // (operator answer Q2 on zipline#136), so those adapters never need
    // their own revoke.
    let mut disconnected_nodes: Vec<IpAddr> = Vec::new();
    for entry in matched.iter().filter(|e| e.is_node) {
        info!(
            target: ACTOR,
            "denylist sweep: node {} was admitted under revoked bootstrap CN {}; disconnecting it (and its adapters)",
            entry.addr, entry.cn
        );
        match asm
            .cc
            .disconnect(asm.clone(), entry.addr, DisconnectReason::Admin)
            .await
        {
            Ok(()) => {
                disconnected_nodes.push(entry.addr);
                stats.revoked.push((entry.addr, entry.cn.clone()));
            }
            Err(e) => {
                warn!(target: ACTOR, "denylist sweep: failed to disconnect node {}: {e}; deferring", entry.addr);
                stats.deferred += 1;
            }
        }
    }

    // Matched adapters, batched per docking node — skipping adapters whose
    // node was just disconnected (the cascade already removed them).
    let mut by_node: BTreeMap<IpAddr, Vec<(IpAddr, String)>> = BTreeMap::new();
    for entry in matched.iter().filter(|e| !e.is_node) {
        let Some(dock) = entry.dock else {
            warn!(target: ACTOR, "denylist sweep: no docking node for denylisted adapter {}; deferring", entry.addr);
            stats.deferred += 1;
            continue;
        };
        if disconnected_nodes.contains(&dock) {
            continue;
        }
        by_node
            .entry(dock)
            .or_default()
            .push((entry.addr, entry.cn.clone()));
    }
    for (node_addr, entries) in by_node {
        let addrs: Vec<IpAddr> = entries.iter().map(|(a, _)| *a).collect();
        let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
            warn!(
                target: ACTOR,
                "denylist sweep: no VSS handle for node {node_addr} ({} denylisted adapter(s)); deferring",
                addrs.len()
            );
            stats.deferred += addrs.len();
            continue;
        };
        match vss_handle.revoke_auths(addrs.clone()).await {
            Ok(processed) => {
                // Same partial-success contract as the reauth sweep (PR #41
                // review): the VSS processes the batch in order and stops
                // counting at the first failure. Remove only the processed
                // prefix; the rest keep their node-side auth and are
                // deferred to the next pass.
                if processed < entries.len() {
                    warn!(
                        target: ACTOR,
                        "denylist sweep: node {node_addr} revoked {processed} of {} denylisted adapter(s); deferring the rest",
                        entries.len()
                    );
                    stats.deferred += entries.len() - processed;
                }
                for (addr, cn) in entries.into_iter().take(processed) {
                    info!(
                        target: ACTOR,
                        "denylist sweep: adapter {addr} was admitted under revoked bootstrap CN {cn}; revoked on node {node_addr}, removing actor"
                    );
                    if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await {
                        warn!(target: ACTOR, "denylist sweep: revoked {addr} but failed to remove actor: {e}");
                        continue;
                    }
                    stats.revoked.push((addr, cn));
                }
            }
            Err(e) => {
                warn!(
                    target: ACTOR,
                    "denylist sweep: failed to revoke {} denylisted adapter(s) on node {node_addr}: {e}; deferring",
                    addrs.len()
                );
                stats.deferred += addrs.len();
            }
        }
    }

    if !stats.revoked.is_empty() || stats.deferred > 0 {
        debug!(
            target: ACTOR,
            "denylist sweep: checked {}, revoked {}, deferred {}",
            stats.checked,
            stats.revoked.len(),
            stats.deferred
        );
    }
    stats
}

/// Enforce pending policy-install re-authentication obligations (zipline#123):
/// for every recorded `(V, T)`, an actor whose `zpr.vinst` is below `V` is
/// re-asked to authenticate while `now <= T` and revoked once `now > T` —
/// adapters through the batched per-node `revokeAuthentication` (removed only
/// on a positive ack), nodes through `cc.disconnect(.., Admin)`, which also
/// drops their docked adapters. With several obligations the earliest unmet
/// deadline applies (an actor is revoked as soon as ANY obligation it has not
/// met is overdue), authenticating under the newest generation satisfies all
/// older ones (the checks compare `zpr.vinst` against each obligation's own
/// `V`), and satisfied obligations are pruned.
pub(crate) async fn sweep_reauth_obligations(asm: &Arc<Assembly>) -> ReauthSweepStats {
    let mut stats = ReauthSweepStats::default();

    let repo = db::ReauthRepo::new(asm.state_db.clone());
    let obligations = match repo.list_obligations().await {
        Ok(o) => o,
        Err(e) => {
            warn!(target: ACTOR, "reauth sweep: failed to list obligations: {e}");
            return stats;
        }
    };
    if obligations.is_empty() {
        return stats;
    }
    stats.obligations = obligations.len();

    /// A connected actor as the sweep sees it: its address, the policy
    /// generation it was last authenticated under, whether it is a node, and
    /// (for adapters) its docking node.
    struct Entry {
        addr: IpAddr,
        vinst: u64,
        is_node: bool,
        dock: Option<IpAddr>,
    }

    // Snapshot every connected actor (nodes and adapters) with its vinst.
    let listed = match asm.actor_mgr.list_actors(None).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(target: ACTOR, "reauth sweep: failed to list actors: {e}");
            return stats;
        }
    };
    let mut entries: Vec<Entry> = Vec::new();
    for (addr, _cn) in listed {
        let actor = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
            Ok(Some(actor)) => actor,
            Ok(None) => continue, // Removed between list and fetch.
            Err(e) => {
                warn!(target: ACTOR, "reauth sweep: failed to load actor {addr}: {e}");
                continue;
            }
        };
        // The visa service's own adapter authenticates by construction at
        // startup (authenticate_visa_service), not through a node, so no
        // requestAuthentication can ever renew its vinst — enforcing the
        // obligation on it would make every install revoke the VS itself.
        // It is exempt for the same reason its authentication never expires.
        if actor.get_cn() == Some(config::VS_CN)
            && addr == std::net::IpAddr::V6(config::VS_ZPR_ADDR)
        {
            continue;
        }
        entries.push(Entry {
            addr,
            vinst: actor_vinst(&actor),
            is_node: actor.is_node(),
            dock: asm.actor_mgr.get_docking_node_for_actor(&actor),
        });
    }

    // Prune obligations every connected actor already satisfies. With the
    // stale actors gone (below), the remaining obligations are pruned by a
    // later pass.
    let mut unmet = Vec::new();
    for ob in obligations {
        if entries.iter().all(|e| e.vinst >= ob.vinst) {
            info!(target: ACTOR, "reauth sweep: obligation vinst={} satisfied by all connected actors, pruning", ob.vinst);
            if let Err(e) = repo.remove_obligation(ob.vinst).await {
                warn!(target: ACTOR, "reauth sweep: failed to prune obligation vinst={}: {e}", ob.vinst);
            } else {
                stats.pruned += 1;
            }
        } else {
            unmet.push(ob);
        }
    }

    // The generation each phase enforces: an actor owes a re-auth when its
    // vinst is below an unmet obligation's V; it is revoked when that
    // obligation is also overdue. Taking the max V per phase implements both
    // rules at once — earliest unmet deadline (any overdue obligation
    // suffices) and newest-satisfies-older (one comparison per phase).
    let now = SystemTime::now();
    let overdue_v = unmet
        .iter()
        .filter(|ob| now > ob.deadline)
        .map(|ob| ob.vinst)
        .max();
    let pending_v = unmet.iter().map(|ob| ob.vinst).max();

    // Phase 1: revoke actors that missed an overdue deadline. Nodes first —
    // `cc.disconnect` also drops their docked adapters, so those adapters
    // never need their own revoke.
    let mut disconnected_nodes: Vec<IpAddr> = Vec::new();
    if let Some(required_v) = overdue_v {
        for entry in entries.iter().filter(|e| e.is_node && e.vinst < required_v) {
            // Serialize against a concurrent re-auth: re-load and re-check the
            // stored vinst right before disconnecting, so a node that made the
            // deadline while this pass ran is kept.
            match asm.actor_mgr.get_actor_by_zpr_addr(&entry.addr).await {
                Ok(Some(actor)) if actor_vinst(&actor) >= required_v => {
                    info!(target: ACTOR, "reauth sweep: node {} re-authenticated while the sweep ran; keeping it", entry.addr);
                    continue;
                }
                Ok(Some(_)) => {}
                Ok(None) => continue, // Already gone.
                Err(e) => {
                    warn!(target: ACTOR, "reauth sweep: failed to re-load node {}: {e}; deferring", entry.addr);
                    stats.deferred += 1;
                    continue;
                }
            }
            info!(
                target: ACTOR,
                "reauth sweep: node {} did not re-authenticate under vinst {} by the deadline; disconnecting it (and its adapters)",
                entry.addr, required_v
            );
            match asm
                .cc
                .disconnect(asm.clone(), entry.addr, DisconnectReason::Admin)
                .await
            {
                Ok(()) => {
                    disconnected_nodes.push(entry.addr);
                    stats.revoked += 1;
                }
                Err(e) => {
                    warn!(target: ACTOR, "reauth sweep: failed to disconnect node {}: {e}; deferring", entry.addr);
                    stats.deferred += 1;
                }
            }
        }

        // Overdue adapters, batched per docking node — skipping adapters whose
        // node was just disconnected (the cascade already removed them).
        let mut by_node: BTreeMap<IpAddr, Vec<IpAddr>> = BTreeMap::new();
        for entry in entries
            .iter()
            .filter(|e| !e.is_node && e.vinst < required_v)
        {
            let Some(dock) = entry.dock else {
                warn!(target: ACTOR, "reauth sweep: no docking node for stale adapter {}; deferring", entry.addr);
                stats.deferred += 1;
                continue;
            };
            if disconnected_nodes.contains(&dock) {
                continue;
            }
            by_node.entry(dock).or_default().push(entry.addr);
        }
        for (node_addr, addrs) in by_node {
            let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
                warn!(
                    target: ACTOR,
                    "reauth sweep: no VSS handle for node {node_addr} ({} stale adapter(s)); deferring",
                    addrs.len()
                );
                stats.deferred += addrs.len();
                continue;
            };
            match vss_handle.revoke_auths(addrs.clone()).await {
                Ok(processed) => {
                    // A short count is PARTIAL success (PR #41 review, Codex
                    // P2): the VSS processes the batch in order and stops
                    // counting at the first failure, so exactly the first
                    // `processed` entries had their node-side auth revoked.
                    // Remove only those; the rest keep their node-side auth
                    // and are deferred to the next sweep tick.
                    if processed < addrs.len() {
                        warn!(
                            target: ACTOR,
                            "reauth sweep: node {node_addr} revoked {processed} of {} stale adapter(s); deferring the rest",
                            addrs.len()
                        );
                        stats.deferred += addrs.len() - processed;
                    }
                    for addr in addrs.into_iter().take(processed) {
                        // Same re-check as above: a concurrent reauthorize that
                        // landed while the revoke was in flight wins, and the
                        // renewed actor's node-side auth is re-established by
                        // its own reauth flow.
                        match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
                            Ok(Some(actor)) if actor_vinst(&actor) >= required_v => {
                                info!(target: ACTOR, "reauth sweep: adapter {addr} re-authenticated while the revoke was in flight; keeping it");
                                continue;
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => continue, // Already removed concurrently.
                            Err(e) => {
                                warn!(target: ACTOR, "reauth sweep: revoked {addr} but failed to re-load actor: {e}; deferring");
                                stats.deferred += 1;
                                continue;
                            }
                        }
                        info!(
                            target: ACTOR,
                            "reauth sweep: adapter {addr} did not re-authenticate under vinst {required_v} by the deadline; revoked on node {node_addr}, removing actor"
                        );
                        if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await {
                            warn!(target: ACTOR, "reauth sweep: revoked {addr} but failed to remove actor: {e}");
                            continue;
                        }
                        stats.revoked += 1;
                    }
                }
                Err(e) => {
                    warn!(
                        target: ACTOR,
                        "reauth sweep: failed to revoke {} stale adapter(s) on node {node_addr}: {e}; deferring",
                        addrs.len()
                    );
                    stats.deferred += addrs.len();
                }
            }
        }
    }

    // Phase 2: re-send requestAuthentication to actors that still owe a
    // re-auth inside their window (the node dedups via `renewal_in_flight`).
    // Actors already revoked above are gone from the store, but the snapshot
    // may still list them — the node skips unknown addresses (K1), so a stale
    // entry costs nothing.
    if let Some(required_v) = pending_v {
        let mut by_node: BTreeMap<IpAddr, Vec<IpAddr>> = BTreeMap::new();
        for entry in entries.iter().filter(|e| e.vinst < required_v) {
            let Some(dock) = entry.dock else {
                continue; // Logged in phase 1 when overdue; nothing to send to.
            };
            if disconnected_nodes.contains(&dock) {
                continue;
            }
            by_node.entry(dock).or_default().push(entry.addr);
        }
        for (node_addr, addrs) in by_node {
            let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
                debug!(target: ACTOR, "reauth sweep: no VSS handle for node {node_addr}; re-send skipped this pass");
                continue;
            };
            let count = addrs.len();
            match vss_handle.request_auths(addrs).await {
                Ok(_accepted) => stats.requested += count,
                Err(e) => {
                    warn!(target: ACTOR, "reauth sweep: failed to request_auths on node {node_addr}: {e}");
                }
            }
        }
    }

    if stats.revoked > 0 || stats.deferred > 0 || stats.requested > 0 || stats.pruned > 0 {
        debug!(
            target: ACTOR,
            "reauth sweep: obligations {}, pruned {}, requested {}, revoked {}, deferred {}",
            stats.obligations, stats.pruned, stats.requested, stats.revoked, stats.deferred
        );
    }
    stats
}

/// The policy generation the actor was last authenticated under: its
/// `zpr.vinst` attribute, stamped by `approve_connection` on connect and
/// reauthorize. A missing or unparseable value is 0 — such an actor owes a
/// re-auth against every obligation (fail closed).
pub(crate) fn actor_vinst(actor: &Actor) -> u64 {
    actor
        .get_attribute(key::VINST)
        .and_then(|a| a.get_single_value().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// One sweep pass over the connected adapters, in two phases. Phase 1 walks
/// the adapters and collects every one whose authentication expiration has
/// passed, grouped by docking node. Phase 2 sends **one batched**
/// `revokeAuthentication` per docking node (PR #20 review: N expired adapters
/// behind one unresponsive node cost the pass one RPC timeout, not N), and —
/// **only on a positive ack** — logs (with the gate: the credential that drove
/// the expiry) and removes the batch's actors from the store. A missing VSS
/// handle, an error, or a timeout leaves the batch untouched for the next pass.
pub(crate) async fn sweep_expired_auths(asm: &Arc<Assembly>) -> SweepStats {
    let mut stats = SweepStats::default();

    let entries = match asm.actor_mgr.list_actors(Some(db::Role::Adapter)).await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(target: ACTOR, "auth sweep: failed to list actors: {e}");
            return stats;
        }
    };

    /// An adapter phase 1 found expired: its snapshot expiry and the gate
    /// (credential key) that drove it. The expiry snapshot is re-checked
    /// against the store after the revoke ack, so a concurrent renewal wins;
    /// the gate is for logging at removal time.
    struct Expired {
        addr: IpAddr,
        expiry: SystemTime,
        gate: String,
    }

    // Phase 1: collect expired adapters per docking node.
    let now = SystemTime::now();
    let mut by_node: BTreeMap<IpAddr, Vec<Expired>> = BTreeMap::new();
    for (addr, _cn) in entries {
        let actor = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
            Ok(Some(actor)) => actor,
            Ok(None) => continue, // Removed between list and fetch.
            Err(e) => {
                warn!(target: ACTOR, "auth sweep: failed to load actor {addr}: {e}");
                continue;
            }
        };
        stats.checked += 1;

        // No expiration means no authentication to expire; in-window means fine.
        let Some((expiry, gate)) = actor.get_authentication_expiration_with_gate() else {
            continue;
        };
        if expiry > now {
            continue;
        }

        let Some(node_addr) = asm.actor_mgr.get_docking_node_for_actor(&actor) else {
            warn!(target: ACTOR, "auth sweep: no docking node for expired actor {addr}; deferring to next pass");
            stats.deferred += 1;
            continue;
        };
        by_node
            .entry(node_addr)
            .or_default()
            .push(Expired { addr, expiry, gate });
    }

    // Phase 2: one batched revoke per docking node; drop the batch's actors
    // only on a positive ack, so a VSS outage leaves them for the next pass
    // rather than half-removing them.
    for (node_addr, expired) in by_node {
        let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) else {
            warn!(
                target: ACTOR,
                "auth sweep: no VSS handle for node {node_addr} ({} expired actor(s)); deferring to next pass",
                expired.len()
            );
            stats.deferred += expired.len();
            continue;
        };

        let addrs: Vec<IpAddr> = expired.iter().map(|e| e.addr).collect();
        match vss_handle.revoke_auths(addrs).await {
            Ok(_processed) => {
                for Expired { addr, expiry, gate } in expired {
                    // Serialize against a concurrent reauthorization (PR #20
                    // review): the expiry decision was made on a pre-RPC
                    // snapshot, and `reauthorize_actor` may have renewed the
                    // actor while the revoke ack was in flight. Re-load the
                    // stored actor and remove it only if its authentication
                    // expiration still matches the expired snapshot; a renewed
                    // actor stays, and its (revoked-then-renewed) node-side
                    // auth is re-established by its own reauth flow.
                    let stored_expiry = match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
                        Ok(Some(actor)) => actor
                            .get_authentication_expiration_with_gate()
                            .map(|(exp, _gate)| exp),
                        Ok(None) => continue, // Already removed concurrently.
                        Err(e) => {
                            warn!(target: ACTOR, "auth sweep: revoked {addr} but failed to re-load actor: {e}; deferring to next pass");
                            stats.deferred += 1;
                            continue;
                        }
                    };
                    if stored_expiry != Some(expiry) {
                        info!(
                            target: ACTOR,
                            "auth sweep: actor {addr} was reauthorized while the revoke was in flight (stored expiration changed); keeping actor"
                        );
                        continue;
                    }
                    info!(
                        target: ACTOR,
                        "authentication expired for actor {addr} (gate: {gate}); revoked on node {node_addr}, removing actor"
                    );
                    if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await {
                        warn!(target: ACTOR, "auth sweep: revoked {addr} but failed to remove actor: {e}");
                        continue;
                    }
                    stats.revoked += 1;
                }
            }
            Err(e) => {
                warn!(
                    target: ACTOR,
                    "auth sweep: failed to revoke auths for {} actor(s) on node {node_addr}: {e}; deferring to next pass",
                    expired.len()
                );
                stats.deferred += expired.len();
            }
        }
    }

    if stats.revoked > 0 || stats.deferred > 0 {
        debug!(
            target: ACTOR,
            "auth sweep: checked {} actors, revoked {}, deferred {}",
            stats.checked, stats.revoked, stats.deferred
        );
    }
    stats
}

/// Run [sweep_expired_auths], [sweep_reauth_obligations] and
/// [sweep_denylisted_actors] every `period` in
/// a background task, mirroring `KeySource::spawn_refresher` (`oidc/jwks.rs`).
/// A pass never fails as such — per-actor trouble is logged and deferred
/// inside each sweep — so the loop just sleeps and sweeps. Callers pass
/// [crate::config::MIN_VISA_LIFETIME]: fine-grained enough that a revocation
/// lands inside the shortest visa lifetime, and well inside any sane
/// `reauth_deadline`. The denylist pass here is the retry path for
/// revocations the admin add deferred (zipline#136).
pub(crate) fn spawn_auth_expiry_sweeper(asm: Arc<Assembly>, period: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            sweep_expired_auths(&asm).await;
            sweep_reauth_obligations(&asm).await;
            sweep_denylisted_actors(&asm).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::Assembly;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::config;
    use crate::test_helpers::make_adapter_actor;
    use crate::vss::VssCmd;
    use libeval::attribute::{Attribute, key};
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc;

    const NODE: &str = "fd5a:5052:3000::1";
    const ADAPTER: &str = "fd5a:5052:4000::a";

    /// Add an adapter docked at `node` whose device authority expires in
    /// `auth_expires_in` (zero = already expired by sweep time).
    async fn add_adapter_with_auth(
        asm: &Arc<Assembly>,
        zpr_addr: &str,
        node: &IpAddr,
        auth_expires_in: Duration,
    ) {
        let mut actor = make_adapter_actor(zpr_addr, "sweep-test", Duration::from_secs(3600));
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(auth_expires_in)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, node, &Default::default())
            .await
            .unwrap();
    }

    /// Install a fake VSS handle for `node` whose worker answers every
    /// `RevokeAuthsByZprAddr` per `ok`, recording the addr batches it saw.
    fn install_fake_vss(
        asm: &Arc<Assembly>,
        node: IpAddr,
        ok: bool,
    ) -> Arc<Mutex<Vec<Vec<IpAddr>>>> {
        let (revokes, _requests) = install_fake_vss_with_requests(asm, node, ok);
        revokes
    }

    /// As [install_fake_vss], but also recording (and acking) the
    /// `RequestAuthsByZprAddr` batches — returns `(revokes, requests)`.
    fn install_fake_vss_with_requests(
        asm: &Arc<Assembly>,
        node: IpAddr,
        ok: bool,
    ) -> (Arc<Mutex<Vec<Vec<IpAddr>>>>, Arc<Mutex<Vec<Vec<IpAddr>>>>) {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let revokes = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let revokes_task = revokes.clone();
        let requests_task = requests.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) => {
                        revokes_task.lock().unwrap().push(addrs.clone());
                        let resp = if ok {
                            Ok(addrs.len())
                        } else {
                            Err(crate::error::VssSyncError::Timeout("test".to_string()))
                        };
                        let _ = resp_tx.send(resp);
                    }
                    VssCmd::RequestAuthsByZprAddr(addrs, resp_tx) => {
                        requests_task.lock().unwrap().push(addrs.clone());
                        let resp = if ok {
                            Ok(addrs.len())
                        } else {
                            Err(crate::error::VssSyncError::Timeout("test".to_string()))
                        };
                        let _ = resp_tx.send(resp);
                    }
                    _ => {}
                }
            }
        });
        (revokes, requests)
    }

    /// An adapter past its authentication expiry is revoked by one pass —
    /// the docking node's VSS sees the revoke — and is gone afterwards.
    #[tokio::test]
    async fn test_sweep_revokes_and_drops_expired_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 1, "one expired actor must be revoked");
        assert_eq!(stats.deferred, 0);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[vec![adapter]],
            "the docking node's VSS must see exactly the expired addr"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_none(),
            "the actor must be gone after a positive ack"
        );
    }

    /// An adapter still inside its authentication window is untouched: no
    /// revoke sent, actor still present.
    #[tokio::test]
    async fn test_sweep_leaves_in_window_actor_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::from_secs(3600)).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 0);
        assert!(seen.lock().unwrap().is_empty(), "no revoke may be sent");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A VSS outage during a sweep leaves the actor for the next pass rather
    /// than half-removing it: no handle for the docking node, and a handle
    /// answering Err, both defer; a later pass with an acking handle removes it.
    #[tokio::test]
    async fn test_sweep_vss_outage_leaves_actor_for_next_pass() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;

        // Pass 1: no handle at all for the docking node.
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 1, "missing handle must defer, not remove");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "actor must survive a missing-handle pass"
        );

        // Pass 2: a handle that answers Err.
        let seen_err = install_fake_vss(&asm, node, false);
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 1, "an Err ack must defer, not remove");
        assert_eq!(
            seen_err.lock().unwrap().len(),
            1,
            "the revoke was attempted"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "actor must survive an Err pass"
        );

        // Pass 3: an acking handle finally removes it.
        let seen_ok = install_fake_vss(&asm, node, true);
        let stats = sweep_expired_auths(&asm).await;
        assert_eq!(stats.revoked, 1);
        assert_eq!(seen_ok.lock().unwrap().as_slice(), &[vec![adapter]]);
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// zipline#119: an adapter whose device authority carries the far-future
    /// bootstrap stamp is NEVER revoked by the sweep — bootstrap
    /// authentication does not expire, so revocation is a policy change (key
    /// removal), not a timer.
    #[tokio::test]
    async fn test_sweep_never_revokes_bootstrap_far_future_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, config::VS_AUTH_EXPIRATION).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 0, "a bootstrap actor must never be revoked");
        assert_eq!(stats.deferred, 0);
        assert!(seen.lock().unwrap().is_empty(), "no revoke may be sent");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "the bootstrap actor must survive the sweep"
        );
    }

    /// An actor with no authentication expiration at all (no authority and no
    /// identity attributes) is skipped entirely.
    #[tokio::test]
    async fn test_sweep_skips_actor_without_expiration() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        // Plain adapter: role/CN/zpr-addr only — get_authentication_expiration() is None.
        let actor = make_adapter_actor(ADAPTER, "no-auth", Duration::ZERO);
        asm.actor_mgr
            .add_adapter_via_node(&actor, &node, &Default::default())
            .await
            .unwrap();
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 0);
        assert!(seen.lock().unwrap().is_empty());
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Two expired adapters docked at the same node are revoked with ONE
    /// batched `revokeAuthentication` RPC (PR #20 review): an unresponsive
    /// node costs the pass one RPC timeout, not one per expired adapter.
    #[tokio::test]
    async fn test_sweep_batches_expired_actors_per_node() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter_a: IpAddr = ADAPTER.parse().unwrap();
        let adapter_b: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        add_adapter_with_auth(&asm, "fd5a:5052:4000::b", &node, Duration::ZERO).await;
        let seen = install_fake_vss(&asm, node, true);

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(stats.revoked, 2, "both expired actors must be revoked");
        assert_eq!(stats.deferred, 0);
        let batches = seen.lock().unwrap().clone();
        assert_eq!(
            batches.len(),
            1,
            "one docking node must see exactly one batched revoke, got {batches:?}"
        );
        let mut batch = batches[0].clone();
        batch.sort();
        let mut expected = vec![adapter_a, adapter_b];
        expected.sort();
        assert_eq!(batch, expected, "the batch must carry both expired addrs");
        for addr in [adapter_a, adapter_b] {
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&addr)
                    .await
                    .unwrap()
                    .is_none(),
                "actor {addr} must be gone after the batched ack"
            );
        }
    }

    /// A renewal that lands while the sweep is awaiting the revoke ack wins
    /// (PR #20 review): the sweep re-checks the stored authentication
    /// expiration against its pre-RPC snapshot and must NOT remove an actor
    /// whose authentication was concurrently renewed by `reauthorize_actor`.
    #[tokio::test]
    async fn test_sweep_skips_actor_renewed_during_revoke() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;

        // Fake VSS that renews the actor's device authority *while the sweep
        // awaits the revoke ack*, then acks OK — the reauthorize race.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let asm_task = asm.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if let VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) = cmd {
                    let renewed_addr: IpAddr = ADAPTER.parse().unwrap();
                    let mut actor = asm_task
                        .actor_mgr
                        .get_actor_by_zpr_addr(&renewed_addr)
                        .await
                        .unwrap()
                        .expect("actor must still exist during the revoke");
                    actor
                        .add_attribute(
                            Attribute::builder(key::DEVICE_AUTHORITY)
                                .expires_in(Duration::from_secs(3600))
                                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
                        )
                        .unwrap();
                    asm_task
                        .actor_mgr
                        .update_actor(&actor, &Default::default())
                        .await
                        .unwrap();
                    let _ = resp_tx.send(Ok(addrs.len()));
                }
            }
        });

        let stats = sweep_expired_auths(&asm).await;

        assert_eq!(
            stats.revoked, 0,
            "a concurrently renewed actor must not be counted revoked"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&adapter)
                .await
                .unwrap()
                .is_some(),
            "the renewed actor must survive the sweep"
        );
    }

    /// The spawned periodic task removes an expired actor without any direct
    /// call to the sweep: spawn with a millisecond period against the fake-VSS
    /// assembly and await removal with a bounded timeout (two-ish periods).
    #[tokio::test]
    async fn test_sweeper_task_removes_expired_actor_within_two_periods() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_auth(&asm, ADAPTER, &node, Duration::ZERO).await;
        let _seen = install_fake_vss(&asm, node, true);

        let handle = spawn_auth_expiry_sweeper(asm.clone(), Duration::from_millis(20));

        let removed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if asm
                    .actor_mgr
                    .get_actor_by_zpr_addr(&adapter)
                    .await
                    .unwrap()
                    .is_none()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        handle.abort();
        assert!(
            removed.is_ok(),
            "the periodic sweeper must remove the expired actor within the timeout"
        );
    }

    // ---- policy-install reauth obligation sweep (zipline#123) ----

    use crate::db::{ReauthObligation, ReauthRepo};
    use crate::test_helpers::make_node_actor_defexp;
    use std::time::SystemTime;

    /// Add an adapter docked at `node` with far-future bootstrap auth (so the
    /// expiry sweep never touches it) and `zpr.vinst = vinst` — the shape of a
    /// bootstrap actor authenticated under policy generation `vinst`.
    async fn add_adapter_with_vinst(
        asm: &Arc<Assembly>,
        zpr_addr: &str,
        node: &IpAddr,
        vinst: u64,
    ) {
        let mut actor = make_adapter_actor(zpr_addr, "reauth-test", Duration::from_secs(3600));
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::VINST).value(vinst.to_string()))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, node, &Default::default())
            .await
            .unwrap();
    }

    /// Record the obligation `(vinst, now + offset)`; a negative offset is a
    /// deadline already in the past.
    async fn record_obligation(asm: &Arc<Assembly>, vinst: u64, offset_secs: i64) {
        let deadline = if offset_secs >= 0 {
            SystemTime::now() + Duration::from_secs(offset_secs as u64)
        } else {
            SystemTime::now() - Duration::from_secs((-offset_secs) as u64)
        };
        ReauthRepo::new(asm.state_db.clone())
            .add_obligation(&ReauthObligation { vinst, deadline })
            .await
            .unwrap();
    }

    /// The stored actor at `addr` exists.
    async fn actor_exists(asm: &Arc<Assembly>, addr: &IpAddr) -> bool {
        asm.actor_mgr
            .get_actor_by_zpr_addr(addr)
            .await
            .unwrap()
            .is_some()
    }

    /// STEP-1 end-to-end (zipline#123): an adapter whose bootstrap key was
    /// removed by a policy install — so it cannot re-authenticate and its
    /// `zpr.vinst` stays below the new generation — is revoked once
    /// `reauth_deadline` has passed: the docking node's VSS sees the batched
    /// `revokeAuthentication`, and the actor is removed from the store.
    /// This fails today because nothing enforces the obligation.
    #[tokio::test]
    async fn test_reauth_stale_actor_revoked_after_deadline() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        // Authenticated under generation 1; obligation demands generation 2
        // and its deadline has already passed.
        add_adapter_with_vinst(&asm, ADAPTER, &node, 1).await;
        record_obligation(&asm, 2, -5).await;
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_reauth_obligations(&asm).await;

        assert_eq!(stats.revoked, 1, "the stale actor must be revoked");
        assert_eq!(
            revokes.lock().unwrap().as_slice(),
            &[vec![adapter]],
            "the docking node's VSS must see the batched revoke"
        );
        assert!(
            !actor_exists(&asm, &adapter).await,
            "the actor must be gone after the deadline"
        );
    }

    /// An actor already re-authenticated under V is never revoked and never
    /// re-asked, and the satisfied obligation is pruned from the store.
    #[tokio::test]
    async fn test_reauth_satisfied_actor_never_revoked_and_obligation_pruned() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_vinst(&asm, ADAPTER, &node, 2).await;
        record_obligation(&asm, 2, -5).await; // Overdue, but already satisfied.
        let (revokes, requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_reauth_obligations(&asm).await;

        assert_eq!(stats.revoked, 0, "a satisfied actor must never be revoked");
        assert_eq!(stats.pruned, 1, "the satisfied obligation must be pruned");
        assert!(revokes.lock().unwrap().is_empty(), "no revoke may be sent");
        assert!(requests.lock().unwrap().is_empty(), "no re-ask may be sent");
        assert!(actor_exists(&asm, &adapter).await);
        assert!(
            ReauthRepo::new(asm.state_db.clone())
                .list_obligations()
                .await
                .unwrap()
                .is_empty(),
            "the obligation must be gone from the store"
        );
    }

    /// A silent actor inside its window is re-asked (requestAuthentication),
    /// not revoked; only once the deadline passes is it revoked.
    #[tokio::test]
    async fn test_reauth_silent_actor_revoked_after_deadline_not_before() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_vinst(&asm, ADAPTER, &node, 1).await;
        record_obligation(&asm, 2, 3600).await; // Deadline well in the future.
        let (revokes, requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_reauth_obligations(&asm).await;
        assert_eq!(stats.revoked, 0, "inside the window no one is revoked");
        assert_eq!(stats.requested, 1, "the laggard must be re-asked");
        assert!(revokes.lock().unwrap().is_empty());
        assert_eq!(
            requests.lock().unwrap().as_slice(),
            &[vec![adapter]],
            "the docking node must see the re-ask for the laggard"
        );
        assert!(
            actor_exists(&asm, &adapter).await,
            "still inside the window"
        );

        // The deadline passes (rewrite the obligation into the past).
        record_obligation(&asm, 2, -5).await;
        let stats = sweep_reauth_obligations(&asm).await;
        assert_eq!(stats.revoked, 1, "past the deadline the laggard is revoked");
        assert!(!actor_exists(&asm, &adapter).await);
    }

    /// Two installs V2 then V3: re-authenticating under V3 (the newest)
    /// satisfies both obligations, while a laggard still on V1 is revoked by
    /// the earlier deadline.
    #[tokio::test]
    async fn test_reauth_newest_generation_satisfies_older_obligations() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let good: IpAddr = ADAPTER.parse().unwrap();
        let laggard: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        // `good` re-authenticated under the newest generation; `laggard` never did.
        add_adapter_with_vinst(&asm, ADAPTER, &node, 3).await;
        add_adapter_with_vinst(&asm, "fd5a:5052:4000::b", &node, 1).await;
        // V2's deadline has passed; V3's is still open — the earliest unmet
        // deadline (V2's) applies to the laggard anyway.
        record_obligation(&asm, 2, -5).await;
        record_obligation(&asm, 3, 3600).await;
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_reauth_obligations(&asm).await;

        assert_eq!(
            stats.revoked, 1,
            "only the laggard is revoked; newest-generation auth satisfies both"
        );
        assert_eq!(revokes.lock().unwrap().as_slice(), &[vec![laggard]]);
        assert!(actor_exists(&asm, &good).await, "the good actor is kept");
        assert!(!actor_exists(&asm, &laggard).await);
    }

    /// A node that re-authenticated is kept; a node that did not is
    /// disconnected past the deadline — and its docked adapters go with it
    /// (cc.disconnect cascade), with no separate adapter revoke needed.
    #[tokio::test]
    async fn test_reauth_stale_node_disconnected_with_its_adapters() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let good_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let bad_node: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let bad_adapter: IpAddr = ADAPTER.parse().unwrap();

        // Node actors: `good` re-authenticated under generation 2, `bad` did not.
        let mut good = make_node_actor_defexp(
            "fd5a:5052:3000::1",
            "node-good",
            "[fd5a:5052:3000::101]:1234",
        );
        good.add_attribute(Attribute::builder(key::VINST).value("2"))
            .unwrap();
        asm.actor_mgr
            .add_node(&good, false, &Default::default())
            .await
            .unwrap();
        let mut bad = make_node_actor_defexp(
            "fd5a:5052:3000::2",
            "node-bad",
            "[fd5a:5052:3000::102]:1234",
        );
        bad.add_attribute(Attribute::builder(key::VINST).value("1"))
            .unwrap();
        asm.actor_mgr
            .add_node(&bad, false, &Default::default())
            .await
            .unwrap();
        // An adapter docked at the bad node, also stale.
        add_adapter_with_vinst(&asm, ADAPTER, &bad_node, 1).await;

        record_obligation(&asm, 2, -5).await;
        let (good_revokes, _) = install_fake_vss_with_requests(&asm, good_node, true);
        let (bad_revokes, _) = install_fake_vss_with_requests(&asm, bad_node, true);

        let stats = sweep_reauth_obligations(&asm).await;

        assert_eq!(
            stats.revoked, 1,
            "one node disconnect counts as one revocation"
        );
        assert!(
            actor_exists(&asm, &good_node).await,
            "the node that answered must be kept"
        );
        assert!(
            !actor_exists(&asm, &bad_node).await,
            "the silent node must be disconnected"
        );
        assert!(
            !actor_exists(&asm, &bad_adapter).await,
            "the disconnected node's adapters must cascade away"
        );
        assert!(
            bad_revokes.lock().unwrap().is_empty(),
            "no separate adapter revoke may be sent through the disconnected node"
        );
        assert!(good_revokes.lock().unwrap().is_empty());
    }

    /// Revocation waits for a positive ack: an erroring VSS defers the stale
    /// adapter to the next pass rather than half-removing it, and a later
    /// acking pass removes it.
    #[tokio::test]
    async fn test_reauth_revocation_waits_for_positive_ack() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_vinst(&asm, ADAPTER, &node, 1).await;
        record_obligation(&asm, 2, -5).await;

        // Pass 1: the VSS answers Err — the actor must survive.
        let (revokes_err, _) = install_fake_vss_with_requests(&asm, node, false);
        let stats = sweep_reauth_obligations(&asm).await;
        assert_eq!(stats.revoked, 0);
        assert_eq!(stats.deferred, 1, "an Err ack must defer, not remove");
        assert_eq!(
            revokes_err.lock().unwrap().len(),
            1,
            "the revoke was attempted"
        );
        assert!(
            actor_exists(&asm, &adapter).await,
            "actor must survive an unacked revoke"
        );

        // Pass 2: an acking handle finally removes it.
        let (revokes_ok, _) = install_fake_vss_with_requests(&asm, node, true);
        let stats = sweep_reauth_obligations(&asm).await;
        assert_eq!(stats.revoked, 1);
        assert_eq!(revokes_ok.lock().unwrap().as_slice(), &[vec![adapter]]);
        assert!(!actor_exists(&asm, &adapter).await);
    }

    /// Pending `(V, T)` survives a VS restart: a fresh repo over the same
    /// state DB — what a restarted VS constructs — still sees the obligation,
    /// and the sweep enforces it.
    #[tokio::test]
    async fn test_reauth_obligation_survives_restart() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter: IpAddr = ADAPTER.parse().unwrap();
        add_adapter_with_vinst(&asm, ADAPTER, &node, 1).await;
        record_obligation(&asm, 2, -5).await;

        // "Restart": a brand-new repo instance over the same state DB reads
        // the persisted obligation back.
        let fresh = ReauthRepo::new(asm.state_db.clone());
        let obligations = fresh.list_obligations().await.unwrap();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].vinst, 2);

        // And the sweep — which builds its own repo from asm.state_db, as the
        // restarted process would — enforces it.
        let (revokes, _) = install_fake_vss_with_requests(&asm, node, true);
        let stats = sweep_reauth_obligations(&asm).await;
        assert_eq!(
            stats.revoked, 1,
            "the persisted obligation must be enforced"
        );
        assert_eq!(revokes.lock().unwrap().as_slice(), &[vec![adapter]]);
        assert!(!actor_exists(&asm, &adapter).await);
    }

    /// PR #41 review (Codex P2, zipline#123): `revoke_auths` represents
    /// partial success as `Ok(processed)` with `processed < addrs.len()`,
    /// and the VSS processes the batch in order. The sweep must remove only
    /// the first `processed` actors — deleting an actor whose node-side auth
    /// was NOT revoked leaves the two sides inconsistent. The remainder is
    /// deferred to the next tick.
    #[tokio::test]
    async fn test_reauth_partial_revoke_ack_removes_only_processed() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let adapter_a: IpAddr = ADAPTER.parse().unwrap();
        let adapter_b: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        add_adapter_with_vinst(&asm, ADAPTER, &node, 1).await;
        add_adapter_with_vinst(&asm, "fd5a:5052:4000::b", &node, 1).await;
        record_obligation(&asm, 2, -5).await;

        // A VSS that acks only ONE item of whatever batch it receives.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let batches = Arc::new(Mutex::new(Vec::new()));
        let batches_task = batches.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) => {
                        batches_task.lock().unwrap().push(addrs.clone());
                        let _ = resp_tx.send(Ok(1)); // partial: first item only
                    }
                    VssCmd::RequestAuthsByZprAddr(addrs, resp_tx) => {
                        let _ = resp_tx.send(Ok(addrs.len()));
                    }
                    _ => {}
                }
            }
        });

        let stats = sweep_reauth_obligations(&asm).await;

        assert_eq!(stats.revoked, 1, "only the acked entry may be revoked");
        assert_eq!(stats.deferred, 1, "the unacked entry must be deferred");
        let batch = batches.lock().unwrap()[0].clone();
        assert_eq!(batch.len(), 2, "both stale adapters were in the batch");
        // VSS processes in order: the first batch entry was revoked, the
        // second was not. Exactly the unprocessed one must survive.
        let (revoked_addr, kept_addr) = (batch[0], batch[1]);
        assert!(
            !actor_exists(&asm, &revoked_addr).await,
            "the acked adapter must be removed"
        );
        assert!(
            actor_exists(&asm, &kept_addr).await,
            "an adapter beyond the processed count must survive for the next tick"
        );
        // Sanity: the two are the adapters we added.
        let mut both = vec![revoked_addr, kept_addr];
        both.sort();
        let mut expected = vec![adapter_a, adapter_b];
        expected.sort();
        assert_eq!(both, expected);
    }

    // ---- bootstrap-key denylist enforcement (zipline#136) ----

    use crate::db::BootstrapDenylist;

    /// Add an adapter docked at `node`, admitted by bootstrap under `cn`
    /// (`device.zpr.authority = zpr-bootstrap`, authenticated CN = `cn`).
    async fn add_bootstrap_adapter(asm: &Arc<Assembly>, zpr_addr: &str, node: &IpAddr, cn: &str) {
        let mut actor = make_adapter_actor(zpr_addr, cn, Duration::from_secs(3600));
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, node, &Default::default())
            .await
            .unwrap();
    }

    /// A denylisted CN's adapters are revoked in one pass — the docking
    /// node's VSS sees the batched revoke, the actors are gone — while an
    /// adapter under a different CN survives untouched.
    #[tokio::test]
    async fn test_denylist_sweep_revokes_adapters_under_cn() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let bad_a: IpAddr = ADAPTER.parse().unwrap();
        let bad_b: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        let good: IpAddr = "fd5a:5052:4000::c".parse().unwrap();
        add_bootstrap_adapter(&asm, ADAPTER, &node, "laptop-7.zpr").await;
        add_bootstrap_adapter(&asm, "fd5a:5052:4000::b", &node, "laptop-7.zpr").await;
        add_bootstrap_adapter(&asm, "fd5a:5052:4000::c", &node, "innocent.zpr").await;
        BootstrapDenylist::new(asm.state_db.clone())
            .add("laptop-7.zpr")
            .await
            .unwrap();
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_denylisted_actors(&asm).await;

        assert_eq!(
            stats.revoked.len(),
            2,
            "both actors under the denylisted CN must be revoked"
        );
        assert!(
            stats.revoked.iter().all(|(_, cn)| cn == "laptop-7.zpr"),
            "every revocation must be attributed to the denylisted CN"
        );
        let mut revoked_addrs: Vec<IpAddr> = stats.revoked.iter().map(|(a, _)| *a).collect();
        revoked_addrs.sort();
        assert_eq!(revoked_addrs, vec![bad_a, bad_b]);
        let batch = {
            let seen = revokes.lock().unwrap();
            assert_eq!(seen.len(), 1, "one batched revoke per docking node");
            seen[0].clone()
        };
        assert_eq!(batch.len(), 2, "the batch carries both denylisted actors");
        assert!(!actor_exists(&asm, &bad_a).await);
        assert!(!actor_exists(&asm, &bad_b).await);
        assert!(
            actor_exists(&asm, &good).await,
            "an actor under another CN must survive"
        );
    }

    /// A NODE admitted under a denylisted CN is disconnected — and its docked
    /// adapters go with it (operator answer Q2 on zipline#136), with no
    /// separate adapter revoke needed.
    #[tokio::test]
    async fn test_denylist_sweep_disconnects_node_with_its_adapters() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let bad_node: IpAddr = NODE.parse().unwrap();
        let docked: IpAddr = ADAPTER.parse().unwrap();

        let mut node_actor =
            make_node_actor_defexp(NODE, "node-bad.zpr", "[fd5a:5052:3000::101]:1234");
        node_actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        // The docked adapter is under a DIFFERENT, innocent CN: it goes down
        // with its node anyway (the cascade), which is the Q2 blast radius.
        add_bootstrap_adapter(&asm, ADAPTER, &bad_node, "innocent.zpr").await;
        BootstrapDenylist::new(asm.state_db.clone())
            .add("node-bad.zpr")
            .await
            .unwrap();
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, bad_node, true);

        let stats = sweep_denylisted_actors(&asm).await;

        assert_eq!(
            stats.revoked,
            vec![(bad_node, "node-bad.zpr".to_string())],
            "the node is revoked under the denylisted CN"
        );
        assert!(
            !actor_exists(&asm, &bad_node).await,
            "the node must be gone"
        );
        assert!(
            !actor_exists(&asm, &docked).await,
            "the docked adapter must cascade with its node"
        );
        assert!(
            revokes.lock().unwrap().is_empty(),
            "no separate adapter revoke: the disconnect cascade covers it"
        );
    }

    /// The denylist gates on the BOOTSTRAP authority: an actor with the same
    /// CN whose device authority is not `zpr-bootstrap` (e.g. an OIDC-only
    /// actor with a display CN) is untouched.
    #[tokio::test]
    async fn test_denylist_sweep_ignores_non_bootstrap_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let addr: IpAddr = ADAPTER.parse().unwrap();
        // Same CN, but NO bootstrap device authority.
        let actor = make_adapter_actor(ADAPTER, "laptop-7.zpr", Duration::from_secs(3600));
        asm.actor_mgr
            .add_adapter_via_node(&actor, &node, &Default::default())
            .await
            .unwrap();
        BootstrapDenylist::new(asm.state_db.clone())
            .add("laptop-7.zpr")
            .await
            .unwrap();
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_denylisted_actors(&asm).await;

        assert!(
            stats.revoked.is_empty(),
            "a non-bootstrap actor must not match the bootstrap denylist"
        );
        assert!(revokes.lock().unwrap().is_empty());
        assert!(actor_exists(&asm, &addr).await);
    }

    /// No positive ack, no removal: a VSS that fails the revoke leaves the
    /// denylisted adapter in place for the next pass (deferred), exactly like
    /// the zipline#123 sweep.
    #[tokio::test]
    async fn test_denylist_sweep_defers_without_positive_ack() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        let addr: IpAddr = ADAPTER.parse().unwrap();
        add_bootstrap_adapter(&asm, ADAPTER, &node, "laptop-7.zpr").await;
        BootstrapDenylist::new(asm.state_db.clone())
            .add("laptop-7.zpr")
            .await
            .unwrap();
        let (_revokes, _requests) = install_fake_vss_with_requests(&asm, node, false);

        let stats = sweep_denylisted_actors(&asm).await;

        assert!(stats.revoked.is_empty(), "no ack, no revocation");
        assert_eq!(stats.deferred, 1, "the failure must be deferred, not lost");
        assert!(
            actor_exists(&asm, &addr).await,
            "the actor survives until a positive ack"
        );
    }

    /// An empty denylist is a no-op pass: nothing revoked, nothing deferred.
    #[tokio::test]
    async fn test_denylist_sweep_empty_is_noop() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = NODE.parse().unwrap();
        add_bootstrap_adapter(&asm, ADAPTER, &node, "laptop-7.zpr").await;
        let (revokes, _requests) = install_fake_vss_with_requests(&asm, node, true);

        let stats = sweep_denylisted_actors(&asm).await;

        assert!(stats.revoked.is_empty());
        assert_eq!(stats.deferred, 0);
        assert!(revokes.lock().unwrap().is_empty());
    }
}
