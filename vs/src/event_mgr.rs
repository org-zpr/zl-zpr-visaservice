//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::future::join_all;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1::DisconnectReason;

use libeval::eval::EvalContext;

use crate::actor_attributes::{refresh_actors, restamp_node_services};
use crate::assembly::Assembly;
use crate::db::{Obligation, ObligationKind};
use crate::error::ServiceError;
use crate::logging::targets::EVENT;
use crate::policy_mgr::PolicySnapshot;
use crate::topology_mgr::TopoOps;
use crate::visa_reconciler::revalidate_visas;

#[derive(Debug)]
pub enum VsEvent {
    /// Use _after_ actor has been authenticated and the datastore updated.
    ActorJoins(IpAddr),

    /// Use when we get a signal from remote that actor is disconnected/disconnecting.
    /// EventManager takes care of state updates.
    ActorLeaves(IpAddr, DisconnectReason),

    /// Revocation obligations may be pending (zl-zipline#289): run one reconciler pass,
    /// [reconcile_obligations]. Queued after every write that records an obligation, by
    /// the auth-expiry sweeper's loop and at startup. It carries nothing: the pass reads
    /// the obligations from the state DB, so a lost or duplicate kick is harmless.
    Reconcile,
}

#[derive(Clone)]
pub struct EventMgr {
    event_queue: mpsc::Sender<VsEvent>,
}

impl EventMgr {
    pub fn new(event_queue: mpsc::Sender<VsEvent>) -> Self {
        EventMgr { event_queue }
    }

    /// Non-blocking enqueue; false when the queue is full. Test-only: lets a
    /// test fill the bounded queue.
    #[cfg(test)]
    pub fn try_record_event_for_tests(&self, event: VsEvent) -> bool {
        self.event_queue.try_send(event).is_ok()
    }

    /// Ask the event worker for a reconciler pass ([VsEvent::Reconcile]) without
    /// waiting: safe under any lock and from the event worker itself. A full queue
    /// drops the kick, which is harmless -- the obligations stay in the state DB and
    /// the auth-expiry sweeper's loop kicks again.
    pub fn kick_reconcile(&self) {
        if self.event_queue.try_send(VsEvent::Reconcile).is_err() {
            debug!(target: EVENT, "event queue full; the next sweeper tick re-kicks the reconciler");
        }
    }

    pub async fn record_event(&self, event: VsEvent) -> Result<(), ServiceError> {
        if let Err(e) = self.event_queue.send(event).await {
            error!(target: EVENT, "failed to send to event-queue: {}", e);
            Err(ServiceError::QueueFull("event-queue".into()))
        } else {
            Ok(())
        }
    }
}

pub async fn launch(asm: Arc<Assembly>, mut event_rx: mpsc::Receiver<VsEvent>) {
    debug!(target: EVENT, "event manager worker started");
    while let Some(event) = event_rx.recv().await {
        match event {
            VsEvent::ActorJoins(actor) => {
                if let Err(e) = handle_actor_joins(&asm, actor).await {
                    error!(target: EVENT, "failed to handle actor join event: {}", e);
                }
            }
            VsEvent::ActorLeaves(actor, reason) => {
                if let Err(e) = handle_actor_leaves(&asm, actor, reason).await {
                    error!(target: EVENT, "failed to handle actor leave event: {}", e);
                }
            }
            VsEvent::Reconcile => reconcile_obligations(&asm).await,
        }
    }
    info!(target: EVENT, "event manager shutting down");
}

/// One reconciler pass (zl-zipline#289; see [crate::revocation] for the invariant).
///
/// Starts a pass on the ledger (waiting out every writer holding an obligation
/// guard, so every listed obligation's write has landed), then satisfies the
/// listed obligations with one sweep under the current state, and deletes them only
/// if every step completed. Anything short of that leaves them all pending; the
/// auth-expiry sweeper's loop kicks the next pass. Runs on the event worker only,
/// so passes never overlap.
pub(crate) async fn reconcile_obligations(asm: &Arc<Assembly>) {
    let pending = match asm.revocations.start_pass().await {
        Ok(pending) => pending,
        Err(e) => {
            error!(target: EVENT, "failed to list revocation obligations: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    if satisfy_obligations(asm, &pending).await {
        let seqs: Vec<u64> = pending.iter().map(|(seq, _)| *seq).collect();
        if let Err(e) = asm.revocations.complete(&seqs).await {
            // Harmless: the next pass repeats the sweep and deletes them then.
            error!(target: EVENT, "failed to delete satisfied revocation obligations: {e}");
        }
    } else {
        warn!(target: EVENT, "{} revocation obligation(s) left pending; the next sweeper tick retries", pending.len());
    }
}

/// The work of one pass over `pending`, in order. Returns whether all of it
/// completed:
/// 1. if any obligation is a policy install, the policy pass ([policy_pass]) against
///    the current policy;
/// 2. the attribute refresh of the actors behind live visas, then the sweep of every
///    live visa ([revalidate_visas]) -- an actor without a live visa is re-checked
///    lazily, by the revision check on its next visa request; the sweep must record
///    every verdict under a policy
///    generation that did not move meanwhile (a sweep under a superseded generation
///    applies no revocations, so a newer install's pass has to decide);
/// 3. every visa of an actor an obligation names that no longer exists is revoked:
///    the sweep skips visas whose actor it cannot resolve, and an actor is gone when
///    a failed write cleaned it up or an undo removed it.
async fn satisfy_obligations(asm: &Arc<Assembly>, pending: &[(u64, Obligation)]) -> bool {
    if pending
        .iter()
        .any(|(_, ob)| ob.kind == ObligationKind::Policy)
    {
        match policy_pass(asm).await {
            Ok(true) => {}
            // A newer install committed during the refresh; its pass applies.
            Ok(false) => return false,
            Err(e) => {
                error!(target: EVENT, "policy pass failed: {e}");
                return false;
            }
        }
    }

    // One snapshot for the refresh and the sweep. The refresh writes the actors'
    // attributes back before the sweep re-reads them; after a policy pass it costs
    // nothing more (only stale actors are fetched).
    let psnap = asm.policy_mgr.get_current_snapshot();
    let (refreshed, unresolved, failed) =
        refresh_actors(asm, live_visa_actor_addrs(asm).await).await;
    info!(
        target: EVENT,
        "reconcile: actors refreshed={refreshed} unresolved={unresolved} failed={}",
        failed.len()
    );
    // ponytail: a full sweep of every live visa per pass; sweep only the visas
    // touching the obligations' actors if sweeps get costly.
    let failures = revalidate_visas(asm, &psnap).await;
    if failures > 0 || asm.policy_mgr.get_current_snapshot().vinst() != psnap.vinst() {
        return false;
    }

    revoke_visas_of_vanished_actors(asm, pending).await
}

/// Step 3 of [satisfy_obligations]: revoke every visa of each actor named in
/// `pending` that no longer exists. False if an actor lookup or the visa listing
/// failed.
async fn revoke_visas_of_vanished_actors(
    asm: &Arc<Assembly>,
    pending: &[(u64, Obligation)],
) -> bool {
    let mut vanished = Vec::new();
    for addr in pending.iter().flat_map(|(_, ob)| ob.actors.iter()) {
        match asm.actor_mgr.get_actor_by_zpr_addr(addr).await {
            Ok(Some(_)) => {}
            Ok(None) => vanished.push(*addr),
            Err(e) => {
                warn!(target: EVENT, "reconcile: failed to look up actor {addr}: {e}");
                return false;
            }
        }
    }
    vanished.sort();
    vanished.dedup();
    if vanished.is_empty() {
        return true;
    }
    info!(target: EVENT, "reconcile: revoking the visas of vanished actors {vanished:?}");
    // A visa whose revoke cannot be recorded is quarantined in memory for retry
    // ([crate::visa_mgr::VisaMgr::revoke_visa_ids]), as everywhere else.
    match asm.visa_mgr.remove_visas_for_actors(&vanished).await {
        Ok(()) => true,
        Err(e) => {
            warn!(target: EVENT, "reconcile: failed to revoke the visas of vanished actors: {e}");
            false
        }
    }
}

/// TODO: Does not do anything yet.
async fn handle_actor_joins(_asm: &Arc<Assembly>, actor_addr: IpAddr) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor joined: {}", actor_addr);
    Ok(())
}

/// TODO: Does not do anything yet.
async fn handle_actor_leaves(
    _asm: &Arc<Assembly>,
    actor_addr: IpAddr,
    _reason: DisconnectReason,
) -> Result<(), ServiceError> {
    info!(target: EVENT, "actor left: {}", actor_addr);
    Ok(())
}

/// Send `setTopology` from `psnap` to every node in `nodes` that has a VSS worker, in
/// parallel. A node without one is skipped (it gets topology when its worker starts).
/// Failures are logged. Never call this under a [TopoOps]: it waits on node RPCs.
pub(crate) async fn send_topology_to(asm: &Assembly, psnap: &PolicySnapshot, nodes: &[IpAddr]) {
    let futs = nodes.iter().filter_map(|naddr| {
        asm.vss_mgr.get_handle(naddr).map(|vss_handle| async move {
            if let Err(e) = vss_handle.set_topology(psnap.clone()).await {
                error!(target: EVENT, "failed to set topology for node {}: {}", naddr, e);
            }
        })
    });
    join_all(futs).await;
}

/// Push a policy pass's results to each of `node_addrs` over its VSS: the node's
/// topology under `psnap`, then the current auth-services list (OIDC providers are
/// declared in policy, so it can change with it), then -- if `request_reauth` -- the
/// request to re-authenticate the node and its docked adapters (zipline#123).
///
/// One detached task per node (g101): a node whose VSS is slow or unreachable, where
/// every call waits out its RPC timeout, delays only its own pushes, never the policy
/// pass or the install queued behind it. A node's calls keep their order. Two passes'
/// tasks for one node may interleave, which is harmless: a `setTopology` or
/// `setServices` command makes the node's worker re-send the current topology and
/// services list at its next heartbeat, and a second re-auth request only repeats
/// the first.
///
/// Failures are logged. The deadline rule in `auth_sweep` re-sends a re-auth request
/// to whoever still owes, so a missed one costs one sweep period, not the obligation.
async fn push_policy_to_nodes(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
    node_addrs: &[IpAddr],
    request_reauth: bool,
) {
    if node_addrs.is_empty() {
        return;
    }
    let services = match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => Some(services),
        Err(e) => {
            error!(target: EVENT, "failed to refresh auth services after policy update: {e}");
            None
        }
    };
    for &naddr in node_addrs {
        // A node without a worker gets all of this when its worker starts.
        let Some(vss) = asm.vss_mgr.get_handle(&naddr) else {
            continue;
        };
        let psnap = psnap.clone();
        let services = services.clone();
        let asm = asm.clone();
        tokio::spawn(async move {
            if let Err(e) = vss.set_topology(psnap).await {
                error!(target: EVENT, "failed to set topology for node {naddr}: {e}");
            }
            if let Some(services) = services {
                if let Err(e) = vss.set_services(services).await {
                    error!(target: EVENT, "failed to set_services on node {naddr}: {e}");
                }
            }
            if request_reauth {
                let mut addrs = vec![naddr];
                match asm.actor_mgr.get_adapters_connected_to_node(&naddr).await {
                    Ok(adapters) => addrs.extend(adapters),
                    Err(e) => {
                        error!(target: EVENT, "failed to list adapters of node {naddr}: {e}");
                    }
                }
                debug!(target: EVENT, "requesting re-authentication of {} actor(s) via node {naddr}", addrs.len());
                if let Err(e) = vss.request_auths(addrs).await {
                    error!(target: EVENT, "failed to request_auths on node {naddr}: {e}");
                }
            }
        });
    }
}

/// The policy step of a reconciler pass ([satisfy_obligations]): bring nodes,
/// links, transit and the re-authentication obligation in line with the current
/// policy. Returns `Ok(false)` when a newer policy was installed during the
/// attribute refresh (nothing applied; that install's own obligation drives the
/// next pass). The visa sweep is not part of it: the caller runs it next.
async fn policy_pass(asm: &Arc<Assembly>) -> Result<bool, ServiceError> {
    /*
    When we get here we have already updated policy.

    - clear revocation list? May make more sense to keep it and make admin clear manually.

    - services -> ensure all services being offered are still allowed by policy.
       - What if an already connected adapter has a new service -> will need to re-connect?
       - We can do a basic check to see that all the services we have do exist in policy.
          - But that won't detect if a service has altered its provider.
          - TO BE SAFE: expire auth from all services - force re-auth of all existing services (after removing non-existing ones)
     */

    // Which nodes may pass traffic through comes from the current policy
    // (zl-zipline#255). Transit the policy takes away is withdrawn first, under its own
    // short topology guard, before anything fallible or slow: an error below leaves
    // the rest to the next pass, the actor refresh can take long, and until this runs the
    // router would keep routing through a node the policy no longer lets carry
    // traffic. Transit the policy grants waits for the link reconciliation in
    // `policy_pass_locked`. A newer policy's own pass applies its set again, so a
    // superseded pass does no harm here.
    {
        let ops = asm.topo_mgr.ops().await;
        withdraw_policy_transit(asm, &ops, &asm.policy_mgr.get_current_snapshot()).await;
    }

    // The snapshot for the attribute and hostname reconciliation below. The
    // topology part of the pass re-reads it under the topology operation lock, and
    // everything from there on (node validity, links, re-auth obligation, visa sweep)
    // uses that one consistent view.
    let psnap = asm.policy_mgr.get_current_snapshot();
    let snapshot_vinst = psnap.vinst();

    // Reconcile attributes before anything reads them. Both consumers below --
    // node revalidation and the visa sweep -- evaluate actors exactly as stored, so
    // a stale actor is judged on the previous store's data. Nothing between here and
    // the sweep mutates attributes, so this one pass covers both.
    //
    // Only actors that are actually stale cost a fetch: `PolicyMgr::build_state`
    // carries unchanged trusted-service stores (and their revisions) across a policy
    // install, so this is a no-op unless the policy changed a trusted-service.
    //
    // TODO: When a declaration does change, this refetches every source for every
    // actor in the set, sequentially -- an N x M synchronous fan-out on the event
    // handler's critical path. Once services are network-backed and actor/visa counts
    // are large this is going to be an issue.
    // (The live-node set used for topology is read again under the topology lock below.)
    let mut refresh_set = live_visa_actor_addrs(asm).await;
    refresh_set.extend(asm.actor_mgr.list_node_addrs().await?);
    let (refreshed, unresolved, unrefreshed) = refresh_actors(asm, refresh_set).await;
    info!(
        target: EVENT,
        "policy pass vinst={snapshot_vinst}: actors refreshed={refreshed} unresolved={unresolved} failed={}",
        unrefreshed.len()
    );

    // Reconcile hostname claims against the new policy's service-name set
    // (zipline#53, PR #24 review): a newly named policy service evicts a
    // matching held `host:<name>` claim. The attribute refresh above cannot
    // cover this — it only persists actors whose trusted attributes changed,
    // and a hostname/service collision changes no attribute. The set comes
    // from the same snapshot the rest of this pass reconciles against.
    let policy_service_names: HashSet<String> = psnap
        .policy_arc()
        .list_services()
        .iter()
        .map(|svc| svc.id.clone())
        .collect();
    if let Err(e) = asm
        .actor_mgr
        .reconcile_hostname_claims(&policy_service_names)
        .await
    {
        error!(target: EVENT, "failed to reconcile hostname claims after policy update: {e}");
    }

    // Topology operation (TopoOps invariant): one guard spans every read that
    // decides this pass's topology writes -- the policy generation, the live-node set
    // and node validity -- through the disconnects, the link reconciliation and the
    // revocations it calls for. A node that disconnects or connects meanwhile is
    // either fully before or fully after it.
    let ops = asm.topo_mgr.ops().await;
    let locked = policy_pass_locked(asm, &ops, snapshot_vinst, &unrefreshed).await;
    drop(ops);
    let LockedPass::Applied {
        psnap,
        valid_node_addrs,
        stopped_workers,
        reconciled,
    } = locked?
    else {
        return Ok(false);
    };
    // The VSS workers of the nodes disconnected, or cut off, under the guard are
    // stopped now that it is released, before any reconciliation error is returned:
    // those nodes are gone either way. The stop does not wait on the worker (g101).
    for (vss, naddr) in stopped_workers {
        crate::connection_control::ConnectionControl::stop_vss_worker(vss, &naddr);
    }
    reconciled?;

    // Policy install obliges every connected actor to re-authenticate under
    // the new generation (zipline#123). Record the obligation `(V, T)` durably
    // FIRST — it must survive a VS restart — then ask every surviving node to
    // start re-authentication for itself and its docked adapters. The ack only
    // means "started" (contract K1); outcomes are judged by each actor's
    // `zpr.vinst`, and enforcement is the deadline rule in
    // `auth_sweep::sweep_reauth_obligations`.
    //
    // A failed obligation write is FATAL to this handler (PR #41 review,
    // Codex P1): the sweep discovers obligations only from the state DB, so
    // an unrecorded obligation means non-reauthenticating actors would never
    // be revoked for this generation. Propagating the error means the update
    // is not reported as successfully enforced: the revocation obligation stays
    // pending, and the next reconciler pass (or a restart's) retries the write
    // against the then-current snapshot. The nodes still get the new topology and
    // services list, but no re-auth request.
    let deadline_secs = asm
        .config
        .core
        .reauth_deadline
        .unwrap_or(crate::config::DEFAULT_REAUTH_DEADLINE_SECS);
    let obligation = crate::db::ReauthObligation {
        vinst: snapshot_vinst,
        deadline: SystemTime::now() + Duration::from_secs(deadline_secs),
    };
    let recorded = crate::db::ReauthRepo::new(asm.state_db.clone())
        .add_obligation(&obligation)
        .await;
    if let Err(e) = &recorded {
        error!(target: EVENT, "failed to record reauth obligation for vinst {snapshot_vinst}: {e}");
    }
    push_policy_to_nodes(asm, &psnap, &valid_node_addrs, recorded.is_ok()).await;
    recorded?;

    // The visa sweep the caller runs next re-checks every live visa against this
    // policy, including one requested between the install and this pass: it was
    // judged on the services its endpoints stored under the previous policy, which
    // this pass may since have recalculated (zl-zipline#273).
    Ok(true)
}

/// What the guarded part of a policy pass ([policy_pass_locked]) did.
enum LockedPass {
    /// A newer policy was installed during the attribute refresh; nothing applied.
    Deferred,
    /// Applied under the current policy `psnap`.
    Applied {
        psnap: PolicySnapshot,
        /// Connected nodes still valid under `psnap` and still reachable by the visa
        /// service: the nodes the caller pushes the new policy to.
        valid_node_addrs: Vec<IpAddr>,
        /// VSS workers of the nodes disconnected or cut off under the guard, for the
        /// caller to stop once it has released it.
        stopped_workers: Vec<(Option<crate::vss_mgr::VssHandle>, IpAddr)>,
        /// Link reconciliation result, returned after the workers are stopped.
        reconciled: Result<(), ServiceError>,
    },
}

/// The topology part of a policy pass, under the caller's [TopoOps]: re-read the
/// policy (installs commit under the same lock, so it stays current until the guard
/// is dropped), read the live-node set, recalculate each node's services under the
/// policy ([restamp_node_services]), judge each node on it, disconnect the
/// invalid ones, reconcile links, revoke visas over links taken down and set apart
/// the nodes those links cut off from the visa service ([nodes_cut_off]).
///
/// `unrefreshed` are the actors whose attribute refresh failed: their claims are
/// indeterminate, so their services are not recalculated (a policy condition a
/// missing key satisfies must not grant one) and they are judged on their stored
/// services.
///
/// `refreshed_vinst` is the policy the caller refreshed actor attributes for. If a
/// newer policy has been installed since, the actors are stale for it: judging nodes
/// on them could disconnect one the new policy admits. Then this applies nothing and
/// returns [LockedPass::Deferred]; the pass that follows for the newer install
/// (it records a revocation obligation before it commits and kicks after), refreshes
/// first and applies.
async fn policy_pass_locked(
    asm: &Arc<Assembly>,
    ops: &TopoOps<'_>,
    refreshed_vinst: u64,
    unrefreshed: &HashSet<IpAddr>,
) -> Result<LockedPass, ServiceError> {
    let psnap = asm.policy_mgr.get_current_snapshot();
    if psnap.vinst() != refreshed_vinst {
        info!(target: EVENT, "policy pass for vinst={refreshed_vinst} superseded by vinst={} during the attribute refresh: deferring to its pass", psnap.vinst());
        return Ok(LockedPass::Deferred);
    }
    let vinst = psnap.vinst();

    // The new policy may invalidate some existing nodes. Read the live-node set
    // under the guard, so the pass cannot re-add a node that has disconnected.
    let connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;

    // Recalculate each node's services under the new policy before judging it
    // (zl-zipline#273): a node still offering a service the policy deleted would
    // otherwise be judged invalid and disconnected. If the recalculation fails, the
    // node is judged on its stored services -- at worst it is disconnected, never kept
    // with more than the policy grants. A node whose attribute refresh failed is
    // judged on its stored services the same way: its claims are indeterminate.
    let policy = psnap.policy_arc();
    for naddr in &connected_node_addrs {
        if unrefreshed.contains(naddr) {
            warn!(target: EVENT, "policy updated vinst={vinst}: the attributes of node {naddr} could not be refreshed, judging it on its stored services");
            continue;
        }
        if let Err(e) = restamp_node_services(asm, &policy, naddr).await {
            warn!(target: EVENT, "policy updated vinst={vinst}: failed to recalculate the services of node {naddr}, judging it on its stored services: {e}");
        }
    }

    let (mut valid_node_addrs, invalid_node_addrs) =
        revalidate_nodes(asm, &psnap, connected_node_addrs).await;

    // Disconnect the nodes that are no longer approved by the new policy, under the
    // guard. Their VSS workers are stopped by the caller after it is released.
    let mut stopped_workers = Vec::new();
    for naddr in &invalid_node_addrs {
        info!(target: EVENT, "connected node {naddr} is no longer approved by policy, disconnecting");
        let (vss, result) = asm
            .cc
            .disconnect_locked(ops, asm, *naddr, DisconnectReason::Admin)
            .await;
        stopped_workers.push((vss, *naddr));
        if let Err(e) = result {
            error!(target: EVENT, "error processing disconnect of {naddr}: {e}");
            // In this case we do not send an actor-leaves event.
            // What is the state of our topology manager now?
            // Visa service is porbably hosed.
        }
    }

    // Only reconcile links if there are connected nodes. If there are none at the
    // moment, then topology should have been (or will soon be) updated via other
    // code paths. The purpose of updating the topology when presented with a new
    // policy is to verify that existing links are still allowed.
    let mut reconciled: Result<(), ServiceError> = Ok(());
    if !valid_node_addrs.is_empty() {
        info!(target: EVENT, "policy updated vinst={vinst}: revalidating topology ({} nodes)", valid_node_addrs.len());
        match asm
            .topo_mgr
            .revalidate_against_policy(ops, &psnap, &valid_node_addrs, &|| {
                asm.policy_mgr.get_current_snapshot()
            })
            .await
        {
            Ok(report) => {
                info!(
                    target: EVENT,
                    "topology revalidated vinst={vinst}: removed={} updated={} repaired={} orphaned={}",
                    report.links_removed,
                    report.links_updated,
                    report.links_repaired,
                    report.orphaned_nodes.len()
                );

                // The links now match the policy, so its full transit set is applied,
                // granting what the early step withheld -- before the cut-off check
                // below, so a node reached through a newly transit-capable node is not
                // taken for cut off.
                apply_policy_transit(asm, ops, &psnap).await;

                // Links the reconciliation took down or removed: revoke the visas
                // crossing them through the ungated link path (zl-zipline#224). The
                // policy sweep would skip a visa committed under this policy before the
                // link went down, because its generation gate considers it current. A
                // visa whose revocation write fails is quarantined and retried per visa.
                for (a, b) in &report.links_down {
                    let _ = crate::visa_reconciler::revoke_visas_over_link(asm, a, b).await;
                }

                // A node those links cut off from the visa service gets nothing more
                // over them (g101): every call would wait out its RPC timeout. Its VSS
                // worker is stopped instead. Its VS-API session ran over the same
                // link, so it rejoins (J10), and the rejoin starts a new worker.
                let cut_off = nodes_cut_off(asm, &psnap, &report.links_down, &valid_node_addrs);
                valid_node_addrs.retain(|naddr| {
                    if !cut_off.contains(naddr) {
                        return true;
                    }
                    info!(target: EVENT, "policy updated vinst={vinst}: node {naddr} is cut off from the visa service, stopping its VSS worker");
                    stopped_workers.push((asm.vss_mgr.get_handle(naddr), *naddr));
                    false
                });
            }
            Err(e) => {
                // Fail closed: the grant is withheld until a later pass (or a restart)
                // reconciles the links.
                warn!(target: EVENT, "policy updated vinst={vinst}: link reconciliation failed; transit the policy grants is not applied");
                reconciled = Err(e);
            }
        }
    } else {
        // No node is connected, so there are no links to reconcile: apply the policy's
        // full transit set for the nodes that connect later.
        apply_policy_transit(asm, ops, &psnap).await;
    }

    Ok(LockedPass::Applied {
        psnap,
        valid_node_addrs,
        stopped_workers,
        reconciled,
    })
}

/// The early transit step of a policy pass: take transit away from every node `psnap`'s
/// policy no longer lists, and revoke the visas through a node that is not
/// transit-capable, under the caller's [TopoOps]. A node the policy newly lists is
/// **not** made transit-capable here: the router still has the old links, and the new
/// policy may remove or change one of that node's links, so a route through it could
/// use a link the policy no longer has. [policy_pass_locked] grants it, through
/// [apply_policy_transit], once the links are reconciled (visaservice#68 review r3).
async fn withdraw_policy_transit(asm: &Arc<Assembly>, ops: &TopoOps<'_>, psnap: &PolicySnapshot) {
    asm.topo_mgr.withdraw_transit_nodes(ops, psnap);
    let _ = crate::visa_reconciler::revoke_visas_through_non_transit(asm).await;
}

/// Make the router's transit set `psnap`'s (`Policy.transitNodes`, zl-zipline#255) and
/// revoke every live visa whose path passes through a node that is not
/// transit-capable, under the caller's [TopoOps]. Applied whether or not any node is
/// connected, so nodes that connect later route under it.
///
/// The revocation checks every visa against the transit set as it now is, not against
/// what this call changed, so it does not depend on the change being seen once: a
/// pass that stopped early, or a restart, leaves nothing a later call cannot find.
/// The revocations go through the ungated path, like `links_down`: the policy sweep
/// skips a visa committed under this policy before the pass ran. The flag is cleared
/// before the visas are listed, so a visa committed concurrently is either listed or
/// fails its commit-time route check. Failed revocations are quarantined and retried
/// per visa.
async fn apply_policy_transit(asm: &Arc<Assembly>, ops: &TopoOps<'_>, psnap: &PolicySnapshot) {
    asm.topo_mgr.apply_transit_nodes(ops, psnap);
    let _ = crate::visa_reconciler::revoke_visas_through_non_transit(asm).await;
}

/// The connected nodes the visa service can no longer reach: those with no route from
/// the node it docks on (the relay). Candidates are the ends of `links_down`, which the
/// policy pass just took down, and every node of `connected` with a link up: a transit
/// withdrawal (zl-zipline#255) cuts a node off without taking any link down. A node
/// with no link up is not a candidate unless a link of it just went down: it is still
/// joining, or restored and not yet reported (R14), and is not reached over links yet.
/// If the visa service is not docked, it reaches no node and none is set apart.
fn nodes_cut_off(
    asm: &Assembly,
    psnap: &PolicySnapshot,
    links_down: &[(IpAddr, IpAddr)],
    connected: &[IpAddr],
) -> HashSet<IpAddr> {
    let Some(dock) = asm
        .actor_mgr
        .get_docking_node_for_adapter(&asm.config.get_vs_addr())
    else {
        return HashSet::new();
    };
    let has_link_up = |naddr: &IpAddr| {
        psnap
            .policy()
            .get_peers_for_node(naddr)
            .unwrap_or_default()
            .iter()
            .any(|peer| asm.topo_mgr.link_up(naddr, &peer.remote_zpr_addr))
    };
    links_down
        .iter()
        .flat_map(|&(a, b)| [a, b])
        .chain(connected.iter().copied().filter(has_link_up))
        .filter(|naddr| *naddr != dock && asm.topo_mgr.get_best_route(&dock, naddr).is_none())
        .collect()
}

/// The distinct actor addresses referenced by a live visa (both ends of every visa's
/// five-tuple). The reconcile set for a sweep that only re-checks visas.
async fn live_visa_actor_addrs(asm: &Arc<Assembly>) -> HashSet<IpAddr> {
    let mut zpr_addrs: HashSet<IpAddr> = HashSet::new();
    for (_, md) in asm.visa_mgr.list_visa_metadata().await {
        zpr_addrs.insert(md.five_tuple.source_addr);
        zpr_addrs.insert(md.five_tuple.dest_addr);
    }
    zpr_addrs
}

/// When we get a new policy, some nodes may no longer be valid. This checks each of
/// `connected_node_addrs` against the policy and partitions them into `(valid, invalid)`
/// addresses. It has no side effects -- disconnecting the invalid nodes is left to
/// the caller.
///
/// The caller supplies the address list because it also needs it to reconcile those
/// nodes' attributes first; the evaluation below reads the actors as stored.
///
/// This is the attribute-side check only. The authentication side is handled by
/// the policy-install re-auth obligation (zipline#123): `policy_pass`
/// records `(V, T)` and fans out `requestAuthentication`, and `auth_sweep`
/// revokes whoever has not re-authenticated under the new generation by `T`.
async fn revalidate_nodes(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
    connected_node_addrs: Vec<IpAddr>,
) -> (Vec<IpAddr>, Vec<IpAddr>) {
    // Check existing nodes against policy.
    let ectx = EvalContext::new(psnap.policy_arc());

    let keep_flags = join_all(
        connected_node_addrs
            .iter()
            .map(|naddr| node_still_valid(asm, &ectx, naddr)),
    )
    .await;

    // Partition into still-valid and no-longer-valid nodes.
    let (valid, invalid): (Vec<_>, Vec<_>) = connected_node_addrs
        .into_iter()
        .zip(keep_flags)
        .partition(|(_, keep)| *keep);

    let valid = valid.into_iter().map(|(naddr, _)| naddr).collect();
    let invalid = invalid.into_iter().map(|(naddr, _)| naddr).collect();

    (valid, invalid)
}

/// Pure predicate helper for [revalidate_nodes].
/// Loads the node `Actor` from the `actor_mgr` and uses the `EvalContext` to check that
/// the actor is still permitted by policy. Note this does not check authentication -- just
/// attributes that were authenticated under the previous policy.
///
/// Returns `true` if the node looks valid (including on any query/eval error, where we
/// optimistically keep the node), and `false` only if policy affirmatively rejects it.
async fn node_still_valid(asm: &Arc<Assembly>, ectx: &EvalContext, naddr: &IpAddr) -> bool {
    match asm.actor_mgr.get_actor_by_zpr_addr(naddr).await {
        Ok(Some(node_actor)) => match ectx.approve_connected(&node_actor) {
            Ok(approved) => approved,
            Err(e) => {
                warn!(target: EVENT, "failed to evaluate connected node {naddr} against policy: {e}");
                true
            }
        },
        // No actor came back for this address, or the query failed. Optimistically keep it.
        Ok(None) => true,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::config;
    use crate::test_helpers::{
        TS_KEY, TS_SOURCE, build_sweep_asm, create_routed_sweep_visa, create_sweep_visa,
        make_attr_hosted_service_policy, make_container_bytes, make_node_actor_defexp, register_ts,
        seed_source_attr, stored_attr,
    };
    use libeval::attribute::{Attribute, key};
    use std::time::Duration;
    use zpr::policy::v1 as capnp_policy;
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
    use zpr::write_to::WriteTo;

    /// The pending obligations, read without starting a pass.
    async fn pending(asm: &Assembly) -> Vec<crate::db::Obligation> {
        crate::db::RevocationRepo::new(asm.state_db.clone())
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|(_, ob)| ob)
            .collect()
    }

    /// What a trusted-service change sets off: an attribute obligation, then a pass.
    /// The obligations the test's setup left (its policy installs) are dropped first,
    /// so the pass runs the attribute step only.
    async fn attribute_pass(asm: &Arc<Assembly>) {
        let setup: Vec<u64> = asm
            .revocations
            .start_pass()
            .await
            .unwrap()
            .iter()
            .map(|(seq, _)| *seq)
            .collect();
        asm.revocations.complete(&setup).await.unwrap();
        record_attribute_obligation(asm, vec![]).await;
        reconcile_obligations(asm).await;
    }

    /// Record an attribute obligation for `actors`, as a writer does before its write.
    async fn record_attribute_obligation(asm: &Assembly, actors: Vec<IpAddr>) {
        drop(
            asm.revocations
                .begin(crate::db::ObligationKind::Attributes, actors)
                .await
                .unwrap(),
        );
    }

    /// zl-zipline#289, replacing p61's `test_failed_reconcile_sweep_is_retried`
    /// (#63 review, Copilot): a pass whose sweep could not record every verdict
    /// leaves the obligation pending, and the next pass completes it -- no
    /// in-memory retry task, nothing to lose on a restart.
    #[tokio::test]
    async fn test_failed_sweep_keeps_the_obligation() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let (asm, node_a) = crate::test_helpers::build_sweep_asm_on(asm, false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await; // the empty policy denies it
        record_attribute_obligation(&asm, vec![]).await;

        db.set_set_ex_fault(crate::db::FaultMode::Reject);
        reconcile_obligations(&asm).await;
        db.set_set_ex_fault(crate::db::FaultMode::None);
        assert!(
            !pending(&asm).await.is_empty(),
            "a sweep that failed must leave its obligation pending"
        );

        reconcile_obligations(&asm).await;
        assert!(pending(&asm).await.is_empty(), "the retry completes it");
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .contains(&id)
        );
    }

    /// zl-zipline#289, replacing p60's
    /// `test_policy_pass_failed_ungated_sweep_is_retried_off_the_worker`: a policy
    /// install whose sweep could not record a revoke leaves its obligation pending;
    /// the next pass revokes the visa issued on stale services and deletes it.
    #[tokio::test]
    async fn test_policy_pass_failed_sweep_keeps_the_obligation() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let (asm, node_a, node_b, id) = issue_visa_on_stale_services_on(asm).await;

        // ApplyThenError: the visa write errors, link writes are unaffected.
        db.set_set_ex_fault(crate::db::FaultMode::ApplyThenError);
        reconcile_obligations(&asm).await;
        db.set_set_ex_fault(crate::db::FaultMode::None);
        assert!(
            pending(&asm)
                .await
                .iter()
                .any(|ob| ob.kind == crate::db::ObligationKind::Policy),
            "the install's obligation must stay pending"
        );

        assert_pass_revokes(&asm, &node_a, &node_b, id).await;
    }

    /// zl-zipline#289: a policy pass that fails before its sweep (here the
    /// re-authentication obligation write) is not lost: the obligation stays
    /// pending, and once the store recovers the next pass runs the policy step again.
    #[tokio::test]
    async fn test_failed_policy_pass_keeps_the_obligation() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let asm = Arc::new(asm);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();

        // The re-authentication obligation write fails (hset); the revocation
        // obligation itself is already recorded.
        db.set_hset_fault(crate::db::FaultMode::Reject);
        reconcile_obligations(&asm).await;
        db.set_hset_fault(crate::db::FaultMode::None);
        assert!(
            !pending(&asm).await.is_empty(),
            "a failed policy pass must leave the obligation pending"
        );

        reconcile_obligations(&asm).await;
        assert!(pending(&asm).await.is_empty());
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        assert!(
            crate::db::ReauthRepo::new(asm.state_db.clone())
                .list_obligations()
                .await
                .unwrap()
                .iter()
                .any(|ob| ob.vinst == vinst),
            "the retried policy pass records the re-authentication obligation"
        );
    }

    /// zl-zipline#289 (VS#77 declined P2): an obligation names an actor that no
    /// longer exists -- a failed Reset whose replacing add cleaned the old actor
    /// up, or an undo -- so the sweep cannot judge its visas (it skips unresolved
    /// actors). The reconciler revokes every visa of that actor instead.
    #[tokio::test]
    async fn test_visas_of_a_vanished_actor_are_revoked() {
        use crate::connection_control::tests::{create_zode_files_visa, zode_fixture, zode_login};
        let cn = "zode-289a.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let id = create_zode_files_visa(&asm, addr).await;
        reconcile_obligations(&asm).await; // settle the fixture's own obligations

        record_attribute_obligation(&asm, vec![addr]).await;
        asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await.unwrap();
        reconcile_obligations(&asm).await;

        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap(),
            vec![id],
            "the vanished actor's visa must be revoked"
        );
        assert!(pending(&asm).await.is_empty());
    }

    /// zl-zipline#289: obligations are durable. A logout that recorded its
    /// obligation and wrote, then the visa service stopped before any pass: a new
    /// assembly over the same state DB (a restart) reconciles it.
    #[tokio::test]
    async fn test_restart_reconciles_a_pending_obligation() {
        use crate::connection_control::tests::{
            create_zode_files_visa, zode_fixture_on, zode_login, zode_logout,
        };
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let cn = "zode-289b.zpr";
        let (asm, cc, addr, privkey) = zode_fixture_on(Arc::new(asm), cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let id = create_zode_files_visa(&asm, addr).await;
        reconcile_obligations(&asm).await;
        zode_logout(&asm, &cc, addr, &privkey, cn).await;
        drop(asm); // the "crash": no pass ran after the logout

        let (restarted, _event_rx) = crate::assembly::tests::new_assembly_on_db(db).await;
        let restarted = Arc::new(restarted);
        assert!(
            !pending(&restarted).await.is_empty(),
            "the obligation survived"
        );
        reconcile_obligations(&restarted).await;
        assert!(pending(&restarted).await.is_empty());
        assert!(
            restarted
                .visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap()
                .contains(&id),
            "the restarted visa service must revoke the visa"
        );
    }

    /// Build a policy container whose single join policy marks connections as
    /// nodes. `provides` is the set of services a node must offer to stay valid
    /// (`None` = no service requirement). Conditions are empty, so the policy
    /// matches any actor's claims.
    fn make_node_join_policy(provides: Option<Vec<Service>>) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            let mut jp_list = policy_bldr.reborrow().init_join_policies(1);
            let mut jp_bldr = jp_list.reborrow().get(0);
            let jp = JoinPolicy {
                conditions: Vec::new(),
                flags: PFlags::node(false),
                provides,
            };
            jp.write_to(&mut jp_bldr);
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    /// Build a single-endpoint regular [Service] with the given id, for use as a
    /// policy-required service.
    fn svc(id: &str) -> Service {
        Service {
            id: id.to_string(),
            endpoints: vec![Scope {
                protocol: 0,
                flag: None,
                port: Some(4000),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        }
    }

    /// Sort a vec of addrs so results can be compared order-independently
    /// (`list_node_addrs` order is not guaranteed).
    fn sorted(mut addrs: Vec<IpAddr>) -> Vec<IpAddr> {
        addrs.sort();
        addrs
    }

    /// All connected nodes satisfy the policy: all are returned and none disconnected.
    #[tokio::test]
    async fn test_revalidate_nodes_all_valid() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        // Any node is valid: node flag set, no required services.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();

        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::2", "node-b", "[fd5a:5052::102]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

        assert_eq!(sorted(valid), sorted(vec![a, b]));
        assert!(invalid.is_empty());
    }

    /// No node satisfies the default (join-policy-free) policy: the returned set is
    /// empty and every node is disconnected/removed.
    #[tokio::test]
    async fn test_revalidate_nodes_all_invalid() {
        // The default test-assembly policy has no join policies, so no node matches.
        let asm = Arc::new(new_assembly_for_tests(None).await);

        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::2", "node-b", "[fd5a:5052::102]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

        assert!(valid.is_empty());
        assert_eq!(sorted(invalid), sorted(vec![a, b]));
    }

    /// Mixed set under one snapshot: policy allows service "svc-x". A node whose
    /// services are a subset of the policy survives; a node offering an unlisted
    /// service ("svc-y") is disconnected. Guards the keep-flag/retain index alignment.
    #[tokio::test]
    async fn test_revalidate_nodes_mixed() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();

        let good: IpAddr = "fd5a:5052::1".parse().unwrap();
        let bad: IpAddr = "fd5a:5052::2".parse().unwrap();
        // Node that provides the required service → stays valid.
        let mut good_actor =
            make_node_actor_defexp("fd5a:5052::1", "node-good", "[fd5a:5052::101]:1234");
        good_actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(3600))
                    .value("svc-x"),
            )
            .unwrap();
        asm.actor_mgr
            .add_node(&good_actor, false, &Default::default())
            .await
            .unwrap();
        // Node offering a service the policy does not allow → invalid → disconnected.
        let mut bad_actor =
            make_node_actor_defexp("fd5a:5052::2", "node-bad", "[fd5a:5052::102]:1234");
        bad_actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(3600))
                    .value("svc-y"),
            )
            .unwrap();
        asm.actor_mgr
            .add_node(&bad_actor, false, &Default::default())
            .await
            .unwrap();

        let psnap = asm.policy_mgr.get_current_snapshot();
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;

        assert_eq!(valid, vec![good]);
        assert_eq!(invalid, vec![bad]);
    }

    /// No connected nodes at all: returns an empty set without error.
    #[tokio::test]
    async fn test_revalidate_nodes_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let psnap = asm.policy_mgr.get_current_snapshot();
        let node_addrs = asm.actor_mgr.list_node_addrs().await.unwrap();
        let (valid, invalid) = revalidate_nodes(&asm, &psnap, node_addrs).await;
        assert!(valid.is_empty());
        assert!(invalid.is_empty());
    }

    /// Phase A: handling the event refreshes the stored actors behind live visas from the
    /// changed service -- replacing a changed value and dropping an attribute the service
    /// no longer vends.
    #[tokio::test]
    async fn test_trusted_service_change_refreshes_stored_actors() {
        let (asm, node_a) = build_sweep_asm(false).await;
        create_sweep_visa(&asm, &node_a, 0).await;
        let svc = register_ts(&asm, &[(TS_KEY, "engineering")]);
        // What the actor holds from the old data: one value that changes, one that goes away.
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;
        seed_source_attr(&asm, "fd5a:5052:4000::a", "user.badge", "b-1").await;

        // The external data changed and the service was reloaded.
        *svc.attrs.lock().unwrap() = vec![(TS_KEY.to_string(), "engineering".to_string())];
        {
            use crate::trusted_services::TrustedServiceInterface;
            svc.flush().await.unwrap();
        }

        attribute_pass(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("engineering".to_string()),
            "changed value must be refreshed in the store"
        );
        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", "user.badge").await,
            None,
            "attribute no longer vended must be pruned"
        );
    }

    /// Phase A fails closed: if the changed service cannot be reached, its attributes are
    /// stripped from the stored actor rather than left to satisfy a policy on their
    /// unexpired TTL.
    #[tokio::test]
    async fn test_trusted_service_change_strips_attrs_when_service_fails() {
        let (asm, node_a) = build_sweep_asm(false).await;
        create_sweep_visa(&asm, &node_a, 0).await;
        let svc = register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        svc.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        attribute_pass(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            None,
            "unreachable service must not leave stale attributes in place"
        );
    }

    /// A policy update revalidates the topology and revokes visas over links it takes
    /// down under the topology operation lock (TopoOps), so it cannot interleave with a
    /// link-state report, disconnect or authentication.
    #[tokio::test]
    async fn test_policy_update_waits_for_the_topology_operation_lock() {
        let (asm, _node_a) = build_sweep_asm(false).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let update = tokio::task::spawn_local({
                    let asm = asm.clone();
                    async move { policy_pass(&asm).await }
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                assert!(!update.is_finished(), "policy pass must wait for the lock");
                drop(held);
                update.await.unwrap().unwrap();
            })
            .await;
    }

    /// A policy install commits under the topology operation lock (round 13, Codex
    /// P1): while a topology operation holds it, the current policy cannot change, so
    /// a policy pass that reads the policy under the lock judges nodes and links on the
    /// policy that is current for its whole run -- it can never disconnect a node, or
    /// remove a link, on a policy superseded mid-pass.
    #[tokio::test]
    async fn test_policy_install_waits_for_the_topology_operation_lock() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let before = asm.policy_mgr.get_current_snapshot().vinst();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let install = tokio::task::spawn_local({
                    let asm = asm.clone();
                    async move {
                        asm.policy_mgr
                            .update_policy_from_container_bytes(make_node_join_policy(None))
                            .await
                    }
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                assert!(!install.is_finished(), "install must wait for the lock");
                assert_eq!(asm.policy_mgr.get_current_snapshot().vinst(), before);
                drop(held);
                install.await.unwrap().unwrap();
            })
            .await;

        assert_eq!(asm.policy_mgr.get_current_snapshot().vinst(), before + 1);
    }

    /// Round 14 (Copilot): a policy installed during the pass's attribute refresh
    /// makes the guarded part defer -- it judges no node and disconnects nothing --
    /// because the actors were refreshed for the old policy. The newer policy's own
    /// pass, queued behind it, refreshes and applies.
    #[tokio::test]
    async fn test_policy_pass_superseded_during_refresh_defers() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        // A offers "svc-y": fine under the first policy, not under the second.
        let mut node_a = make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234");
        node_a
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(3600))
                    .value("svc-y"),
            )
            .unwrap();
        asm.actor_mgr
            .add_node(&node_a, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(a).unwrap();
        // The pass refreshed under this policy...
        let refreshed_vinst = asm.policy_mgr.get_current_snapshot().vinst();
        // ...and a newer one, under which A is invalid, landed before its guard.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();

        let outcome = {
            let ops = asm.topo_mgr.ops().await;
            policy_pass_locked(&asm, &ops, refreshed_vinst, &HashSet::new())
                .await
                .unwrap()
        };
        assert!(matches!(outcome, LockedPass::Deferred));
        assert_eq!(asm.actor_mgr.list_node_addrs().await.unwrap(), vec![a]);
        assert!(asm.topo_mgr.has_node(&a));
    }

    /// The live-node set is read under the topology operation lock (round 13, Codex
    /// P2): a node that disconnects before the pass takes the lock is not put back
    /// into the router by the pass.
    #[tokio::test]
    async fn test_policy_pass_does_not_resurrect_a_disconnected_node() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::1", "node-a", "[fd5a:5052::101]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.topo_mgr.add_node(a).unwrap();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let pass = tokio::task::spawn_local({
                    let asm = asm.clone();
                    async move { policy_pass(&asm).await }
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                // A disconnects while the pass waits: the same steps as
                // ConnectionControl::disconnect, under the lock this test holds.
                asm.actor_mgr.remove_actor_by_zpr_addr(&a).await.unwrap();
                asm.actor_mgr.remove_node(&a).await.unwrap();
                asm.topo_mgr.remove_node(&held, &a).await;
                drop(held);
                pass.await.unwrap().unwrap();
            })
            .await;

        assert!(
            !asm.topo_mgr.has_node(&a),
            "disconnected node must stay out of the router"
        );
    }

    // ---- zl-zipline#273: a policy install recalculates a node's services. ----

    /// Store a connected node at `addr` (CN `cn`) providing `services`, in both the
    /// actor store and the router: the state a connect leaves behind.
    async fn add_live_node_with_services(
        asm: &Assembly,
        addr: &str,
        cn: &str,
        services: &[&str],
    ) -> IpAddr {
        let mut node = make_node_actor_defexp(addr, cn, "[fd5a:5052::101]:1234");
        node.set_services(services.iter().map(|s| s.to_string()).collect());
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let naddr: IpAddr = addr.parse().unwrap();
        asm.topo_mgr.add_node(naddr).unwrap();
        naddr
    }

    /// The services the stored actor at `naddr` provides.
    async fn stored_services(asm: &Assembly, naddr: &IpAddr) -> HashSet<String> {
        let actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(naddr)
            .await
            .unwrap()
            .expect("the actor must still be stored");
        actor.services_iter().map(str::to_string).collect()
    }

    /// Run the guarded part of a policy pass under the current policy, as
    /// `policy_pass` does once its attribute refresh is done, and return
    /// the nodes it judged valid. Panics if the pass deferred.
    async fn run_locked_pass(asm: &Arc<Assembly>) -> Vec<IpAddr> {
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        let ops = asm.topo_mgr.ops().await;
        match policy_pass_locked(asm, &ops, vinst, &HashSet::new())
            .await
            .unwrap()
        {
            LockedPass::Applied {
                valid_node_addrs, ..
            } => valid_node_addrs,
            LockedPass::Deferred => panic!("the pass must apply under the current policy"),
        }
    }

    /// The set of service names in `names`.
    fn service_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// Deleting a service a node hosts must not disconnect the node: the pass
    /// recalculates the node's services from the new policy before judging it, so it
    /// stays connected, provides nothing, and no longer owns the service entry.
    #[tokio::test]
    async fn test_policy_pass_keeps_a_node_whose_hosted_service_was_deleted() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a = add_live_node_with_services(&asm, "fd5a:5052::1", "node-a", &["svc-x"]).await;
        assert!(
            asm.actor_mgr
                .get_service_detail("svc-x")
                .await
                .unwrap()
                .is_some(),
            "setup: the node owns the svc-x entry"
        );
        // The new policy still admits the node but grants it no service.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();

        let valid = run_locked_pass(&asm).await;

        assert_eq!(valid, vec![a], "the node must be judged valid");
        assert_eq!(asm.actor_mgr.list_node_addrs().await.unwrap(), vec![a]);
        assert!(
            asm.topo_mgr.has_node(&a),
            "the node must stay in the router"
        );
        assert!(stored_services(&asm, &a).await.is_empty());
        assert!(
            asm.actor_mgr
                .get_service_detail("svc-x")
                .await
                .unwrap()
                .is_none(),
            "the deleted service's entry must no longer name the node"
        );
    }

    /// Only the service the new policy dropped is removed; the one it still grants
    /// stays.
    #[tokio::test]
    async fn test_policy_pass_prunes_only_the_deleted_service() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a =
            add_live_node_with_services(&asm, "fd5a:5052::1", "node-a", &["svc-x", "svc-y"]).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();

        let valid = run_locked_pass(&asm).await;

        assert_eq!(valid, vec![a]);
        assert_eq!(stored_services(&asm, &a).await, service_set(&["svc-x"]));
    }

    /// A service the new policy grants a node is added to it by the pass, as a
    /// connect or re-authentication under that policy would.
    #[tokio::test]
    async fn test_policy_pass_adds_a_newly_granted_service() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a = add_live_node_with_services(&asm, "fd5a:5052::1", "node-a", &[]).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();

        let valid = run_locked_pass(&asm).await;

        assert_eq!(valid, vec![a]);
        assert_eq!(stored_services(&asm, &a).await, service_set(&["svc-x"]));
    }

    /// A node whose attribute refresh failed is not recalculated (Copilot on
    /// zl-zpr-visaservice#76): its claims are indeterminate, and a policy condition a
    /// missing key satisfies must not grant it a service. It is judged on its stored
    /// services instead.
    #[tokio::test]
    async fn test_policy_pass_does_not_recalculate_a_node_whose_refresh_failed() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a = add_live_node_with_services(&asm, "fd5a:5052::1", "node-a", &[]).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();
        // A trusted service the node has never been refreshed from, and it is down.
        let ts = register_ts(&asm, &[]);
        ts.fail.store(true, std::sync::atomic::Ordering::SeqCst);

        policy_pass(&asm).await.unwrap();

        assert_eq!(
            stored_services(&asm, &a).await,
            service_set(&[]),
            "indeterminate claims must not grant a service"
        );
        assert!(
            asm.topo_mgr.has_node(&a),
            "the node is judged on its stored services"
        );
    }

    /// The recalculation does not save a node the new policy no longer admits at
    /// all: one whose CN no join policy matches is still disconnected.
    #[tokio::test]
    async fn test_policy_pass_still_disconnects_a_node_no_join_policy_matches() {
        use crate::test_helpers::policy_with_peerings_and_node_cns;
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a = add_live_node_with_services(&asm, "fd5a:5052::1", "node-a", &["svc-x"]).await;
        // The only join policy admits another node.
        let other: IpAddr = "fd5a:5052::2".parse().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(policy_with_peerings_and_node_cns(
                &[],
                &[(other, "node-other")],
            ))
            .await
            .unwrap();

        let valid = run_locked_pass(&asm).await;

        assert!(valid.is_empty(), "the node must be judged invalid");
        assert!(asm.actor_mgr.list_node_addrs().await.unwrap().is_empty());
        assert!(!asm.topo_mgr.has_node(&a), "the node must leave the router");
    }

    /// The pass that keeps a node whose hosted service was deleted still revokes the
    /// visas to that service: the visa sweep runs last in the same pass.
    #[tokio::test]
    async fn test_policy_pass_revokes_visas_to_a_deleted_service() {
        use libeval::eval_result::{Direction, Hit};
        use libeval::route::Route;
        use zpr::vsapi_types::PacketDesc;

        let (asm, node_a) = build_sweep_asm(false).await;
        // Node B hosts "web" on TCP 80, and adapter `::4000::a` holds a visa to it.
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let mut host = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&node_b)
            .await
            .unwrap()
            .unwrap();
        host.set_services(service_set(&["web"]));
        asm.actor_mgr
            .update_actor(&host, &Default::default())
            .await
            .unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:3000::2", 1234, 80).unwrap();
        let id = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_a,
                &pdesc,
                &Hit::new_no_signal(0, Direction::Forward),
                &Route::new_direct(node_a.into()),
                "",
                0,
                0,
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await
            .unwrap()
            .visa
            .issuer_id;

        // "web" is deleted: the new policy admits every node and grants no service.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        reconcile_obligations(&asm).await;

        assert!(
            asm.actor_mgr
                .list_node_addrs()
                .await
                .unwrap()
                .contains(&node_b),
            "the host must stay connected"
        );
        assert!(stored_services(&asm, &node_b).await.is_empty());
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .contains(&id),
            "the visa to the deleted service must be revoked"
        );
    }

    /// Set up the window between a policy install and its pass (local Codex P1 on
    /// zl-zipline#273): node B stores "web" on TCP 80 from the previous policy; the new
    /// policy keeps both nodes and the A--B link (reported up by both ends, R14) and
    /// keeps allowing access to "web", but grants it to nobody. A visa from adapter
    /// `::4000::a` to B on port 80 is then requested through the real request path:
    /// it is allowed on B's stale services and carries the new generation. Returns
    /// (asm, A, B, the visa's id).
    async fn issue_visa_on_stale_services() -> (Arc<Assembly>, IpAddr, IpAddr, u64) {
        // The assembly build_sweep_asm uses: its event queue stays open.
        let (asm, event_rx, _db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        std::mem::forget(event_rx);
        issue_visa_on_stale_services_on(asm).await
    }

    /// [issue_visa_on_stale_services] on the given assembly.
    async fn issue_visa_on_stale_services_on(
        asm: Assembly,
    ) -> (Arc<Assembly>, IpAddr, IpAddr, u64) {
        use crate::test_helpers::{make_peering, policy_with_peerings_cns_and_tcp_services};
        use crate::visareq_worker::{VisaDecision, process_visa_request_for_test};
        use zpr::vsapi_types::{LinkState, LinkStateReport, PacketDesc};

        let (asm, node_a) = crate::test_helpers::build_sweep_asm_on(asm, true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let mut host = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&node_b)
            .await
            .unwrap()
            .unwrap();
        host.set_services(service_set(&["web"]));
        asm.actor_mgr
            .update_actor(&host, &Default::default())
            .await
            .unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(policy_with_peerings_cns_and_tcp_services(
                &[make_peering(node_a, node_b, "l", vec![])],
                &[(node_a, "na"), (node_b, "nb")],
                &[("web", 80)],
            ))
            .await
            .unwrap();

        let cn_of = |n: &IpAddr| {
            [(node_a, "na"), (node_b, "nb")]
                .iter()
                .find(|(addr, _)| addr == n)
                .map(|(_, cn)| cn.to_string())
        };
        for (reporter, peer_cn) in [(node_a, "nb"), (node_b, "na")] {
            asm.topo_mgr.record_link_states_with_cns(
                &asm.topo_mgr.ops_now(),
                &reporter,
                None,
                vec![LinkStateReport {
                    peer_cn: peer_cn.to_string(),
                    state: LinkState::Up,
                }],
                &cn_of,
            );
        }

        let pkt = PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:3000::2", 1234, 80).unwrap();
        let VisaDecision::Allow(visa, _) =
            process_visa_request_for_test(asm.clone(), node_a, pkt).await
        else {
            panic!("precondition: the stale services allow the visa");
        };
        (asm, node_a, node_b, visa.issuer_id)
    }

    /// Run the policy pass for the current policy and assert that it kept the A--B
    /// link and that the visa `id` held by `node_a` is revoked.
    async fn assert_pass_revokes(asm: &Arc<Assembly>, node_a: &IpAddr, node_b: &IpAddr, id: u64) {
        reconcile_obligations(asm).await;
        assert!(
            pending(asm).await.is_empty(),
            "the pass completes the obligation"
        );
        assert!(
            asm.topo_mgr.link_up(node_a, node_b),
            "the A--B link stays up"
        );
        assert!(stored_services(asm, node_b).await.is_empty());
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(node_a)
                .await
                .unwrap()
                .contains(&id),
            "the visa issued on stale services must be revoked"
        );
    }

    /// The pass that recalculates the host's services revokes a visa issued on its
    /// stale services, although the generation-gated policy sweep skips that visa.
    #[tokio::test]
    async fn test_policy_pass_revokes_a_visa_issued_on_stale_services() {
        let (asm, node_a, node_b, id) = issue_visa_on_stale_services().await;
        assert_pass_revokes(&asm, &node_a, &node_b, id).await;
    }

    /// Local Codex P2 on zl-zipline#273: a pass that recalculated the host's services
    /// and then failed leaves nothing for its retry to recalculate. The retry must
    /// still revoke the visa issued on the stale services. The failed pass's
    /// recalculation is played here by recalculating B directly.
    #[tokio::test]
    async fn test_policy_pass_retry_revokes_a_visa_issued_on_stale_services() {
        let (asm, node_a, node_b, id) = issue_visa_on_stale_services().await;
        let policy = asm.policy_mgr.get_current();
        assert!(restamp_node_services(&asm, &policy, &node_b).await.unwrap());
        assert_pass_revokes(&asm, &node_a, &node_b, id).await;
    }

    /// zl-zipline#255: the policy pass sets the router's transit set from the policy,
    /// and revokes a visa through a node that lost transit -- including one committed
    /// under the new policy before the pass ran, which the sweep's generation gate
    /// would skip.
    #[tokio::test]
    async fn test_policy_pass_applies_transit_and_revokes_visas_through_lost_nodes() {
        use crate::test_helpers::{
            build_transit_asm, create_sweep_visa_on_route, report_transit_asm_links, transit_policy,
        };
        let (asm, a, b, c) = build_transit_asm().await;
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[c]))
            .await
            .unwrap();
        policy_pass(&asm).await.unwrap();
        // Under R14 the links are up once both ends report them.
        report_transit_asm_links(&asm, true);
        let via_c = asm
            .topo_mgr
            .get_routes(&a, &b, None)
            .into_iter()
            .find(|r| r.links.len() == 2)
            .expect("the pass made C transit-capable");

        // C loses transit. In the window between the install and its pass the router
        // still has the old flags, so a visa through C commits under the new policy.
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[]))
            .await
            .unwrap();
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        let id = create_sweep_visa_on_route(&asm, &a, vinst, &via_c).await;
        policy_pass(&asm).await.unwrap();

        assert!(
            asm.topo_mgr
                .get_routes(&a, &b, None)
                .iter()
                .all(|r| r.links.len() == 1),
            "no route through C any more"
        );
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&a)
                .await
                .unwrap()
                .contains(&id),
            "the visa through C is revoked"
        );
    }

    /// visaservice#68 review r3 (Codex P1): the early transit step of a policy pass only
    /// takes transit away. A node the new policy makes transit-capable becomes so only
    /// once the pass has reconciled the links, so no route is built through it over a
    /// link the new policy may have removed.
    #[tokio::test]
    async fn test_the_early_transit_step_withdraws_but_never_grants() {
        use crate::test_helpers::{build_transit_asm, transit_policy};
        let (asm, a, b, c) = build_transit_asm().await;

        // C is not transit-capable; the new policy grants it: not yet.
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[c]))
            .await
            .unwrap();
        withdraw_policy_transit(
            &asm,
            &asm.topo_mgr.ops().await,
            &asm.policy_mgr.get_current_snapshot(),
        )
        .await;
        assert!(!asm.topo_mgr.interior_is_transit(&[a, c, b]), "no grant");

        // C is transit-capable; the new policy takes it away: at once.
        asm.topo_mgr.set_transit_nodes(&[c]);
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[]))
            .await
            .unwrap();
        withdraw_policy_transit(
            &asm,
            &asm.topo_mgr.ops().await,
            &asm.policy_mgr.get_current_snapshot(),
        )
        .await;
        assert!(!asm.topo_mgr.interior_is_transit(&[a, c, b]), "withdrawn");
    }

    /// Review r2 (Codex): the policy's transit set is applied, and the visas through a
    /// node that lost it revoked, before any fallible step of the handler. Here the
    /// live-node read fails (the event worker only logs that, with no retry); the
    /// router must still stop routing through C.
    #[tokio::test]
    async fn test_policy_update_applies_transit_before_any_fallible_step() {
        use crate::test_helpers::{
            build_transit_asm_with_db, create_sweep_visa_on_route, transit_policy,
        };
        let (asm, a, b, c, db) = build_transit_asm_with_db().await;
        asm.topo_mgr.set_transit_nodes(&[c]);
        let via_c = asm
            .topo_mgr
            .get_routes(&a, &b, None)
            .into_iter()
            .find(|r| r.links.len() == 2)
            .unwrap();
        let id = create_sweep_visa_on_route(&asm, &a, 0, &via_c).await;

        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[]))
            .await
            .unwrap();
        db.set_scan_fault(crate::db::FaultMode::Reject);
        assert!(policy_pass(&asm).await.is_err());
        db.set_scan_fault(crate::db::FaultMode::None);

        assert!(
            asm.topo_mgr
                .get_routes(&a, &b, None)
                .iter()
                .all(|r| r.links.len() == 1),
            "no route through C any more"
        );
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&a)
                .await
                .unwrap()
                .contains(&id),
            "the visa through C is revoked"
        );
    }

    /// Review r1 (Copilot): applying a policy's transit set and revoking the visas
    /// through the nodes that lost transit is one step, so no later failure in the
    /// pass (the node list read, link reconciliation) can consume the transit change
    /// without the revocations.
    #[tokio::test]
    async fn test_apply_policy_transit_revokes_in_the_same_step() {
        use crate::test_helpers::{build_transit_asm, create_sweep_visa_on_route};
        let (asm, a, b, c) = build_transit_asm().await;
        asm.topo_mgr.set_transit_nodes(&[c]);
        let via_c = asm
            .topo_mgr
            .get_routes(&a, &b, None)
            .into_iter()
            .find(|r| r.links.len() == 2)
            .unwrap();
        let id = create_sweep_visa_on_route(&asm, &a, 0, &via_c).await;

        // The current (empty) policy lists no transit node.
        let psnap = asm.policy_mgr.get_current_snapshot();
        apply_policy_transit(&asm, &asm.topo_mgr.ops().await, &psnap).await;
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&a)
                .await
                .unwrap()
                .contains(&id)
        );
    }

    /// zl-zipline#255: the pass applies the transit set even when no node is connected
    /// (it then skips link reconciliation), so nodes that connect later route under it.
    #[tokio::test]
    async fn test_policy_pass_applies_transit_without_connected_nodes() {
        use crate::test_helpers::{TRANSIT_NODE_C, transit_policy};
        use libeval::route::LinkId;
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let c: IpAddr = TRANSIT_NODE_C.parse().unwrap();
        for n in [a, b, c] {
            asm.topo_mgr.add_node(n).unwrap();
        }
        asm.topo_mgr
            .add_link(a, c, LinkId("ac".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(c, b, LinkId("cb".into()), vec![], 1)
            .unwrap();
        assert!(asm.topo_mgr.get_best_route(&a, &b).is_none());

        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[c]))
            .await
            .unwrap();
        policy_pass(&asm).await.unwrap();
        assert!(asm.topo_mgr.get_best_route(&a, &b).is_some());
    }

    /// A policy update reconciles the actors behind live visas before it sweeps them.
    /// The actor here is revision-stale against the registered store (it has no recorded
    /// revision for it); the sweep re-reads actors from the store, and would otherwise
    /// judge them on the attributes seeded below.
    #[tokio::test]
    async fn test_policy_update_refreshes_stored_actors_before_sweep() {
        let (asm, node_a) = build_sweep_asm(false).await;
        // A policy the connected nodes still satisfy, so revalidation keeps them (and
        // their docked adapters) rather than disconnecting everything out from under us.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        create_sweep_visa(&asm, &node_a, 0).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        // What the actor holds from the previous store's data.
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        policy_pass(&asm).await.unwrap();

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("engineering".to_string()),
            "policy update must reconcile attributes before the visa sweep reads actors"
        );
    }

    /// A connected node is reconciled even though it holds no visa: `revalidate_nodes`
    /// judges it on its stored attributes, so those have to be current first. The
    /// live-visa refresh alone did not cover this (item 1 in ts-followups.md).
    #[tokio::test]
    async fn test_policy_update_refreshes_connected_nodes_without_visas() {
        let (asm, _node_a) = build_sweep_asm(false).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(None))
            .await
            .unwrap();
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        // No visa anywhere, so the node is in scope only via the node-address list.
        seed_source_attr(&asm, "fd5a:5052:3000::1", TS_KEY, "sales").await;

        policy_pass(&asm).await.unwrap();

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:3000::1", TS_KEY).await,
            Some("engineering".to_string()),
            "policy update must reconcile connected nodes before revalidating them"
        );
    }

    /// End-to-end for the targeted change notification (zipline#79): after
    /// `forget_source_revision(listed_actor, source)` — what
    /// `POST /admin/services/{id}/changed` with an identities body does — the
    /// event handler re-queries exactly the listed actor from the source,
    /// while an unlisted actor (whose recorded revision still matches) keeps
    /// its stored data untouched.
    #[tokio::test]
    async fn test_trusted_service_change_requeries_only_forgotten_actor() {
        let (asm, node_a) = build_sweep_asm(false).await;
        // A visa whose five-tuple covers both adapters, so BOTH are in the
        // handler's refresh set — what distinguishes them below is revision
        // staleness alone.
        create_sweep_visa(&asm, &node_a, 0).await;
        let svc = register_ts(&asm, &[(TS_KEY, "engineering")]);
        // Both actors hold unexpired data from the source's previous state.
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;
        seed_source_attr(&asm, "fd5a:5052:4000::b", TS_KEY, "sales").await;
        // Both are fully caught up on the source's current revision.
        let rev = {
            use crate::trusted_services::TrustedServiceInterface;
            svc.current_revision()
        };
        let listed: IpAddr = "fd5a:5052:4000::a".parse().unwrap();
        let unlisted: IpAddr = "fd5a:5052:4000::b".parse().unwrap();
        asm.ts_mgr.record_revision(&listed, TS_SOURCE, rev);
        asm.ts_mgr.record_revision(&unlisted, TS_SOURCE, rev);

        // The notification endpoint's targeted body does exactly this for
        // every connected actor carrying a listed identity pair.
        asm.ts_mgr.forget_source_revision(&listed, TS_SOURCE);

        attribute_pass(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("engineering".to_string()),
            "listed actor must be re-queried from the source"
        );
        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::b", TS_KEY).await,
            Some("sales".to_string()),
            "unlisted actor must not be re-queried"
        );
    }

    /// An actor with no live visa is left alone: it reconciles lazily on its next visa
    /// request instead.
    #[tokio::test]
    async fn test_trusted_service_change_ignores_actors_without_visas() {
        let (asm, _node_a) = build_sweep_asm(false).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, "fd5a:5052:4000::a", TS_KEY, "sales").await;

        // No visa created, so no actor is in scope for the refresh.
        attribute_pass(&asm).await;

        assert_eq!(
            stored_attr(&asm, "fd5a:5052:4000::a", TS_KEY).await,
            Some("sales".to_string())
        );
    }

    // ---- zipline#181: the services an actor provides follow its attributes. ----

    /// Service and port hosted by attribute in the zipline#181 tests; the flow
    /// `create_sweep_visa` makes (`::4000::a` -> `::4000::b`, TCP 80) targets it.
    const HOSTED_SVC: &str = "web";
    const HOSTED_PORT: u16 = 80;
    /// The hosting attribute: `::4000::b` hosts [HOSTED_SVC] while it holds it.
    const HOST_KEY: &str = "device.tags";
    const HOST_VALUE: &str = "server";
    const HOST_ADDR: &str = "fd5a:5052:4000::b";

    /// Install the attribute-hosted service policy and register a trusted service
    /// vending the hosting attribute, then give the stored host the attribute and the
    /// service it implies -- the state a connect under this policy leaves behind.
    async fn setup_attr_hosted_service(
        asm: &Arc<Assembly>,
    ) -> Arc<crate::test_helpers::MutableTrustedService> {
        asm.policy_mgr
            .update_policy_from_container_bytes(make_attr_hosted_service_policy(
                HOSTED_SVC,
                HOSTED_PORT,
                HOST_KEY,
                HOST_VALUE,
                PFlags::default(),
            ))
            .await
            .unwrap();
        let svc = register_ts(asm, &[(HOST_KEY, HOST_VALUE)]);
        seed_source_attr(asm, HOST_ADDR, HOST_KEY, HOST_VALUE).await;
        let addr: IpAddr = HOST_ADDR.parse().unwrap();
        let mut host = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        host.set_services(HashSet::from([HOSTED_SVC.to_string()]));
        asm.actor_mgr
            .update_actor(&host, &Default::default())
            .await
            .unwrap();
        assert!(
            stored_provides(asm, HOST_ADDR, HOSTED_SVC).await,
            "setup: host must provide"
        );
        svc
    }

    /// Whether the stored actor at `zpr_addr` provides `service_id`.
    async fn stored_provides(asm: &Arc<Assembly>, zpr_addr: &str, service_id: &str) -> bool {
        let addr: IpAddr = zpr_addr.parse().unwrap();
        let actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        actor.provides(service_id)
    }

    /// Change the hosting data the trusted service vends, and reload it.
    async fn change_host_attrs(
        svc: &crate::test_helpers::MutableTrustedService,
        attrs: &[(&str, &str)],
    ) {
        use crate::trusted_services::TrustedServiceInterface;
        *svc.attrs.lock().unwrap() = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        svc.flush().await.unwrap();
    }

    /// While the host keeps its hosting attribute, a change sweep recomputes the same
    /// services and the visa to it survives.
    #[tokio::test]
    async fn test_trusted_service_change_keeps_visa_while_host_keeps_attr() {
        let (asm, node_a) = build_sweep_asm(true).await;
        let svc = setup_attr_hosted_service(&asm).await;
        create_routed_sweep_visa(&asm, &node_a, 0).await;

        change_host_attrs(&svc, &[(HOST_KEY, HOST_VALUE)]).await;
        attribute_pass(&asm).await;

        assert!(stored_provides(&asm, HOST_ADDR, HOSTED_SVC).await);
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty(),
            "a host that keeps its attribute must keep its visas"
        );
    }

    /// A host that loses its hosting attribute stops providing the service, and the
    /// change sweep revokes the visa to it -- without a reconnect or a policy push.
    #[tokio::test]
    async fn test_trusted_service_change_revokes_visa_when_host_loses_attr() {
        let (asm, node_a) = build_sweep_asm(true).await;
        let svc = setup_attr_hosted_service(&asm).await;
        let id = create_routed_sweep_visa(&asm, &node_a, 0).await;

        change_host_attrs(&svc, &[]).await;
        attribute_pass(&asm).await;

        assert!(
            !stored_provides(&asm, HOST_ADDR, HOSTED_SVC).await,
            "losing the hosting attribute must drop the service"
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id]
        );
    }

    /// An actor that gains the hosting attribute starts providing the service on its
    /// next refresh (the visa-request path refreshes the destination actor).
    #[tokio::test]
    async fn test_refresh_grants_service_when_host_gains_attr() {
        let (asm, _node_a) = build_sweep_asm(true).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_attr_hosted_service_policy(
                HOSTED_SVC,
                HOSTED_PORT,
                HOST_KEY,
                HOST_VALUE,
                PFlags::default(),
            ))
            .await
            .unwrap();
        // The host connected before it had the attribute, so it provides nothing.
        let svc = register_ts(&asm, &[]);
        assert!(!stored_provides(&asm, HOST_ADDR, HOSTED_SVC).await);

        change_host_attrs(&svc, &[(HOST_KEY, HOST_VALUE)]).await;
        let addr: IpAddr = HOST_ADDR.parse().unwrap();
        refresh_actors(&asm, HashSet::from([addr])).await;

        assert!(stored_provides(&asm, HOST_ADDR, HOSTED_SVC).await);
    }

    /// An adapter that gains the attribute of a node-only hosting policy does not start
    /// providing that service: the refresh cannot make it a node, so it must not get a
    /// node's services either (Codex P1 on PR #50).
    #[tokio::test]
    async fn test_refresh_withholds_node_service_from_adapter() {
        let (asm, _node_a) = build_sweep_asm(true).await;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_attr_hosted_service_policy(
                HOSTED_SVC,
                HOSTED_PORT,
                HOST_KEY,
                HOST_VALUE,
                PFlags::node(false),
            ))
            .await
            .unwrap();
        let svc = register_ts(&asm, &[]);

        change_host_attrs(&svc, &[(HOST_KEY, HOST_VALUE)]).await;
        let addr: IpAddr = HOST_ADDR.parse().unwrap();
        refresh_actors(&asm, HashSet::from([addr])).await;

        assert_eq!(
            stored_attr(&asm, HOST_ADDR, HOST_KEY).await,
            Some(HOST_VALUE.to_string()),
            "the attribute itself is refreshed"
        );
        assert!(
            !stored_provides(&asm, HOST_ADDR, HOSTED_SVC).await,
            "an adapter must not pick up a node-only service"
        );
    }

    /// zipline#53 (PR #24 review, finding 2): installing a policy that
    /// introduces a service ID matching an already-held hostname must
    /// reconcile the claim — `host:<name>` is released (policy services win,
    /// retroactively) while the actor's other names stay held. The
    /// attribute-refresh pass alone cannot do this: it only persists actors
    /// whose trusted attributes changed, and this actor's did not.
    #[tokio::test]
    async fn test_policy_update_reconciles_hostname_claims() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        // A node whose device.hostname claims "svc-x" before any policy names it.
        let mut actor = make_node_actor_defexp("fd5a:5052::7", "node-h", "[fd5a:5052::107]:1234");
        actor
            .add_attribute(
                Attribute::builder("device.hostname")
                    .expires_in(Duration::from_secs(3600))
                    .values(&["svc-x", "keep-name"]),
            )
            .unwrap();
        asm.actor_mgr
            .add_node(&actor, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(addr).unwrap();

        let repo = crate::db::ActorRepo::new(asm.state_db.clone());
        assert_eq!(
            repo.get_zpr_addr_for_hostname("svc-x").await.unwrap(),
            Some(addr),
            "precondition: the hostname is held before the policy names it"
        );

        // Install a policy introducing service "svc-x" (the node offers no
        // services, so it remains valid) and run the update handler.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_node_join_policy(Some(vec![svc("svc-x")])))
            .await
            .unwrap();
        policy_pass(&asm).await.unwrap();

        assert_eq!(
            repo.get_zpr_addr_for_hostname("svc-x").await.unwrap(),
            None,
            "policy install must release a held hostname matching a new policy service"
        );
        assert_eq!(
            repo.get_zpr_addr_for_hostname("keep-name").await.unwrap(),
            Some(addr),
            "reconciliation must not cost the actor its other names"
        );
    }

    /// The next command a test VSS handle receives, or `None` if none arrives within
    /// a second (or the channel closed).
    async fn next_cmd(rx: &mut mpsc::Receiver<crate::vss::VssCmd>) -> Option<crate::vss::VssCmd> {
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// g101 (zl-zipline#252): a node whose VSS never answers -- here a test handle
    /// nobody serves, standing in for a node behind a dead link, whose every RPC waits
    /// out its timeout -- must not hold up the policy pass. Otherwise the next
    /// install's pass, queued behind it on the event queue, never applies. The pass
    /// still pushes to that node, per node and off the policy path.
    #[tokio::test]
    async fn test_policy_pass_does_not_wait_on_a_hung_vss() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<crate::vss::VssCmd>(16);
        asm.vss_mgr.insert_test_handle(node_a, cmd_tx);

        let mut applied = Vec::new();
        for _ in 0..2 {
            asm.policy_mgr
                .update_policy_from_container_bytes(make_node_join_policy(None))
                .await
                .unwrap();
            let vinst = asm.policy_mgr.get_current_snapshot().vinst();
            tokio::time::timeout(Duration::from_secs(5), policy_pass(&asm))
                .await
                .expect("the policy pass must not wait on a node's VSS")
                .unwrap();
            applied.push(vinst);
        }

        // Both passes ran to the end: each recorded its re-auth obligation.
        let mut recorded: Vec<u64> = crate::db::ReauthRepo::new(asm.state_db.clone())
            .list_obligations()
            .await
            .unwrap()
            .iter()
            .map(|o| o.vinst)
            .collect();
        recorded.sort();
        assert_eq!(recorded, applied);
        // The hung node still got its topology push.
        let first = tokio::time::timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .expect("the node's push runs off the policy path")
            .unwrap();
        assert!(matches!(first, crate::vss::VssCmd::SetTopology(..)));
    }

    /// g101 (zl-zipline#252): a policy that removes the only link between the node the
    /// visa service docks on (the relay) and a Zode cuts the Zode off from the visa
    /// service. The pass sends it nothing over the link it just removed -- no
    /// topology, services or re-auth request -- and stops its VSS worker; the Zode
    /// rejoins (J10). The relay, still reachable, gets its pushes.
    #[tokio::test]
    async fn test_policy_pass_sends_nothing_to_a_node_it_cut_off() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let relay: IpAddr = "fd5a:5052::2".parse().unwrap();
        let zode: IpAddr = "fd5a:5052::3".parse().unwrap();
        let cns = [(relay, "relay"), (zode, "zb")];
        for (addr, cn) in cns {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(&addr.to_string(), cn, "10.0.0.1:1"),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
            asm.topo_mgr.add_node(addr).unwrap();
        }
        asm.actor_mgr
            .hack_set_vs_docking_node(&relay)
            .await
            .unwrap();
        // The link is up in the router; the new policy no longer describes it.
        asm.topo_mgr
            .add_link(
                relay,
                zode,
                libeval::route::LinkId("relay-zb".into()),
                vec![],
                1,
            )
            .unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(
                crate::test_helpers::policy_with_peerings_and_node_cns(&[], &cns),
            )
            .await
            .unwrap();
        let (relay_tx, mut relay_rx) = mpsc::channel::<crate::vss::VssCmd>(16);
        asm.vss_mgr.insert_test_handle(relay, relay_tx);
        let (zode_tx, mut zode_rx) = mpsc::channel::<crate::vss::VssCmd>(16);
        asm.vss_mgr.insert_test_handle(zode, zode_tx);

        tokio::time::timeout(Duration::from_secs(5), policy_pass(&asm))
            .await
            .expect("the policy pass must not wait on a node's VSS")
            .unwrap();

        assert!(
            matches!(
                next_cmd(&mut zode_rx).await,
                Some(crate::vss::VssCmd::Stop())
            ),
            "the cut-off Zode's VSS worker is stopped"
        );
        assert!(
            next_cmd(&mut zode_rx).await.is_none(),
            "and nothing is pushed to it over the removed link"
        );
        assert!(
            matches!(
                next_cmd(&mut relay_rx).await,
                Some(crate::vss::VssCmd::SetTopology(..))
            ),
            "the relay, still reachable, gets its topology"
        );
    }

    /// A relay (docking the visa service), a Zode `zb` and a node `zc`, all connected,
    /// with the links `relay_links` (pairs of indices into [relay, zb, zc]) in the
    /// router, reported up by both ends (R14). The Zode's VSS is captured. Returns
    /// (asm, [relay, zb, zc], the Zode's command receiver).
    async fn relay_zb_zc_asm(
        relay_links: &[(usize, usize)],
    ) -> (
        Arc<Assembly>,
        [IpAddr; 3],
        mpsc::Receiver<crate::vss::VssCmd>,
    ) {
        use libeval::route::LinkId;
        use zpr::vsapi_types::{LinkState, LinkStateReport};
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let nodes: [IpAddr; 3] =
            ["fd5a:5052::2", "fd5a:5052::3", "fd5a:5052::4"].map(|n| n.parse().unwrap());
        let cns = ["relay", "zb", "zc"];
        for (addr, cn) in nodes.iter().zip(cns) {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(&addr.to_string(), cn, "10.0.0.1:1"),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
            asm.topo_mgr.add_node(*addr).unwrap();
        }
        asm.actor_mgr
            .hack_set_vs_docking_node(&nodes[0])
            .await
            .unwrap();
        for &(i, j) in relay_links {
            let id = format!("{}-{}", cns[i], cns[j]);
            asm.topo_mgr
                .add_link(nodes[i], nodes[j], LinkId(id), vec![], 1)
                .unwrap();
        }
        // Under R14 a link is up while both ends report it up.
        let cn_of = move |n: &IpAddr| {
            nodes
                .iter()
                .position(|a| a == n)
                .map(|i| cns[i].to_string())
        };
        for (i, reporter) in nodes.iter().enumerate() {
            let peers = relay_links
                .iter()
                .filter_map(|&(a, b)| match (a == i, b == i) {
                    (true, _) => Some(b),
                    (_, true) => Some(a),
                    _ => None,
                })
                .map(|k| LinkStateReport {
                    peer_cn: cns[k].to_string(),
                    state: LinkState::Up,
                })
                .collect();
            asm.topo_mgr.record_link_states_with_cns(
                &asm.topo_mgr.ops_now(),
                reporter,
                None,
                peers,
                &cn_of,
            );
        }
        let (zode_tx, zode_rx) = mpsc::channel::<crate::vss::VssCmd>(16);
        asm.vss_mgr.insert_test_handle(nodes[1], zode_tx);
        (asm, nodes, zode_rx)
    }

    /// The policy for [relay_zb_zc_asm]: the peerings `links` (index pairs, link ids as
    /// there), a CN per node, and `transitNodes` = `transit`.
    fn relay_zb_zc_policy(
        nodes: [IpAddr; 3],
        links: &[(usize, usize)],
        transit: &[IpAddr],
    ) -> Vec<u8> {
        let cns = ["relay", "zb", "zc"];
        let peerings: Vec<_> = links
            .iter()
            .map(|&(i, j)| {
                crate::test_helpers::make_peering(
                    nodes[i],
                    nodes[j],
                    &format!("{}-{}", cns[i], cns[j]),
                    vec![],
                )
            })
            .collect();
        let node_cns: Vec<(IpAddr, &str)> = nodes.iter().copied().zip(cns).collect();
        crate::test_helpers::policy_with_peerings_cns_services_and_transit(
            &peerings,
            &node_cns,
            &[],
            transit,
        )
    }

    /// Local review (Codex P2) of visaservice#68 r3: a policy that removes the relay's
    /// link to a Zode while making C transit-capable, with relay-C and C-Zode up, does
    /// not cut the Zode off: the grant is applied before the pass asks which nodes the
    /// removed links cut off, so the Zode is still reached through C.
    #[tokio::test]
    async fn test_a_transit_grant_counts_before_the_cut_off_check() {
        let (asm, nodes, mut zode_rx) = relay_zb_zc_asm(&[(0, 1), (0, 2), (2, 1)]).await;
        // The new policy drops relay-zb, keeps the other two, and makes C transit.
        asm.policy_mgr
            .update_policy_from_container_bytes(relay_zb_zc_policy(
                nodes,
                &[(0, 2), (2, 1)],
                &[nodes[2]],
            ))
            .await
            .unwrap();
        policy_pass(&asm).await.unwrap();

        assert!(
            matches!(
                next_cmd(&mut zode_rx).await,
                Some(crate::vss::VssCmd::SetTopology(..))
            ),
            "the Zode is still reached through C: it gets its topology, not a Stop"
        );
    }

    /// Local review (Codex P2): a policy that takes transit away from C, with the Zode
    /// reached only through C and no link changed, cuts the Zode off as surely as a
    /// removed link: its VSS worker is stopped and it is sent nothing more.
    #[tokio::test]
    async fn test_a_transit_withdrawal_can_cut_a_node_off() {
        let links = [(0, 2), (2, 1)];
        let (asm, nodes, mut zode_rx) = relay_zb_zc_asm(&links).await;
        asm.topo_mgr.set_transit_nodes(&[nodes[2]]);
        assert!(asm.topo_mgr.get_best_route(&nodes[0], &nodes[1]).is_some());
        asm.policy_mgr
            .update_policy_from_container_bytes(relay_zb_zc_policy(nodes, &links, &[]))
            .await
            .unwrap();
        policy_pass(&asm).await.unwrap();

        assert!(
            matches!(
                next_cmd(&mut zode_rx).await,
                Some(crate::vss::VssCmd::Stop())
            ),
            "the cut-off Zode's VSS worker is stopped"
        );
        assert!(
            next_cmd(&mut zode_rx).await.is_none(),
            "and nothing is pushed to it"
        );
    }

    /// PR #41 review (Codex P1, zipline#123): a policy update whose reauth
    /// obligation cannot be persisted must FAIL, not return Ok. The sweep
    /// discovers obligations only from the state DB, so an unrecorded
    /// obligation means non-reauthenticating actors are never revoked for
    /// that generation — the update must not be treated as enforced.
    #[tokio::test]
    async fn test_policy_update_fails_when_obligation_persist_fails() {
        use crate::assembly::tests::new_assembly_with_event_rx_and_db;
        use crate::db::FaultMode;

        let (asm, event_rx, db) = new_assembly_with_event_rx_and_db(None).await;
        std::mem::forget(event_rx);
        let asm = Arc::new(asm);

        // No nodes connected: everything before the obligation write is a
        // no-op, so the injected hset fault hits exactly the obligation add.
        db.set_hset_fault(FaultMode::Reject);
        let result = policy_pass(&asm).await;
        db.set_hset_fault(FaultMode::None);

        assert!(
            result.is_err(),
            "a policy update whose reauth obligation was not persisted must not report success"
        );
        assert!(
            crate::db::ReauthRepo::new(asm.state_db.clone())
                .list_obligations()
                .await
                .unwrap()
                .is_empty(),
            "precondition check: the obligation must not have been recorded"
        );
    }
}
