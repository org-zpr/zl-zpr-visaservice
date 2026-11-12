//! Event Manager handles high-level events that have repurcussions around the
//! visa service system such as actor joins/leaves. Operations in here
//! are not able to report back success/failure to the "caller".

use futures::future::join_all;
use futures::stream::{self, StreamExt};

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1::DisconnectReason;
use zpr::vsapi_types::ServiceDescriptor;

use libeval::eval::EvalContext;

use crate::actor_attributes::refresh_actors;
use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::EVENT;
use crate::policy_mgr::PolicySnapshot;
use crate::topology_mgr::TopoOps;
use crate::visa_reconciler::{SweepReason, revalidate_visas};

#[derive(Debug)]
pub enum VsEvent {
    /// Use _after_ actor has been authenticated and the datastore updated.
    ActorJoins(IpAddr),

    /// Use when we get a signal from remote that actor is disconnected/disconnecting.
    /// EventManager takes care of state updates.
    ActorLeaves(IpAddr, DisconnectReason),

    /// Indicates that policy has been successfully updated. Pass the new `vinst`.
    PolicyUpdated(u64),

    /// The attribute data behind a trusted service changed (an admin refreshed it).
    /// Handler reconciles *all* stale or TTL-expired trusted attributes on the actors
    /// behind live visas, then re-checks those visas. Deliberately not scoped to the
    /// source that changed: `stale_sources_for_actor` already narrows the fetch to
    /// sources whose revision actually moved, so a source id would buy nothing.
    TrustedServiceChange,
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
            VsEvent::PolicyUpdated(vinst) => {
                if let Err(e) = handle_policy_updated(&asm, vinst).await {
                    error!(target: EVENT, "failed to handle policy updated event: {}", e);
                }
            }
            VsEvent::TrustedServiceChange => {
                handle_trusted_service_change(&asm).await;
            }
        }
    }
    info!(target: EVENT, "event manager shutting down");
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

/// Re-push the current auth-services list to all connected nodes. The list is the
/// policy's OIDC identity providers (see `ActorMgr::get_auth_services_list`), so it
/// can only change when policy does.
async fn push_auth_services_all_nodes(asm: &Arc<Assembly>) -> Result<(), ServiceError> {
    let auth_services = asm.actor_mgr.get_auth_services_list(asm.clone()).await?;
    set_services_all_nodes(asm, &auth_services).await
}

/// Helper to use the VSS on all connected nodes to update the auth services list.
async fn set_services_all_nodes(
    asm: &Arc<Assembly>,
    service_set: &[ServiceDescriptor],
) -> Result<(), ServiceError> {
    let node_list = asm.actor_mgr.list_node_addrs().await.unwrap_or_default();

    // Make RPC calls to the nodes in parallel.

    stream::iter(node_list)
        .for_each_concurrent(None, |naddr| {
            let asm = asm.clone();
            let service_list: Vec<ServiceDescriptor> = service_set.to_vec();
            async move {
                debug!(
                    target: EVENT,
                    "attempting to use VSS to set_services on node {naddr}"
                );
                if let Some(vss_h) = asm.vss_mgr.get_handle(&naddr) {
                    if let Err(e) = vss_h.set_services(service_list).await {
                        error!(
                            target: EVENT,
                            "failed to set_services on node {}: {}",
                            naddr,
                            e
                        );
                    }
                }
            }
        })
        .await;
    Ok(())
}

async fn handle_policy_updated(asm: &Arc<Assembly>, vinst: u64) -> Result<(), ServiceError> {
    /*
    When we get here we have already updated policy.

    - clear revocation list? May make more sense to keep it and make admin clear manually.

    - services -> ensure all services being offered are still allowed by policy.
       - What if an already connected adapter has a new service -> will need to re-connect?
       - We can do a basic check to see that all the services we have do exist in policy.
          - But that won't detect if a service has altered its provider.
          - TO BE SAFE: expire auth from all services - force re-auth of all existing services (after removing non-existing ones)
     */

    // The snapshot for the attribute and hostname reconciliation below. The
    // topology part of the pass re-reads it under the topology operation lock, and
    // everything from there on (node validity, links, re-auth obligation, visa sweep)
    // uses that one consistent view.
    let psnap = asm.policy_mgr.get_current_snapshot();

    // PolicyUpdated(vinst) is a trigger, not a guarantee that this handler reconciles that
    // exact revision. If updates queue faster than we process them we reconcile against the
    // latest snapshot.
    let snapshot_vinst = psnap.vinst();
    if snapshot_vinst != vinst {
        info!(
            target: EVENT,
            "policy update event called with vinst={vinst}, using current snapshot vinst={snapshot_vinst}"
        );
    }

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
    let (refreshed, unresolved, failed) = refresh_actors(asm, refresh_set).await;
    info!(
        target: EVENT,
        "policy updated vinst={vinst}: actors refreshed={refreshed} unresolved={unresolved} failed={failed}"
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
    let locked = policy_pass_locked(asm, &ops, snapshot_vinst).await;
    drop(ops);
    let LockedPass::Applied {
        psnap,
        valid_node_addrs,
        stopped_workers,
        reconciled,
    } = locked?
    else {
        return Ok(());
    };
    // Disconnected nodes' VSS workers are stopped now that the guard is released
    // (stopping waits on the worker), before any reconciliation error is returned:
    // those nodes are gone either way.
    for (vss, naddr) in stopped_workers {
        crate::connection_control::ConnectionControl::stop_vss_worker(vss, &naddr).await;
    }
    reconciled?;

    if !valid_node_addrs.is_empty() {
        // Queue up setTopology messages in parallel.
        let futs = valid_node_addrs.iter().filter_map(|naddr| {
            let peers = psnap.resolved_peers_for_node(naddr);
            // Same snapshot the peers came from: the worker builds the wire Links and
            // mints bootstrap visas off it.
            let policy = psnap.policy_arc();
            asm.vss_mgr.get_handle(naddr).map(|vss_handle| async move {
                if let Err(e) = vss_handle.set_topology(peers, policy).await {
                    error!(target: EVENT, "failed to set topology for node {}: {}", naddr, e);
                }
            })
        });
        join_all(futs).await;

        // A policy update can change the auth-services list (OIDC providers are
        // declared in policy). Re-push the current list so surviving nodes stay in
        // sync.
        if let Err(e) = push_auth_services_all_nodes(asm).await {
            error!(target: EVENT, "failed to refresh auth services after policy update: {e}");
        }
    }

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
    // is not reported as successfully enforced; the event worker logs it, and
    // the next policy-updated event (or VS restart, which replays the current
    // policy) retries the write against the same snapshot vinst.
    let deadline_secs = asm
        .config
        .core
        .reauth_deadline
        .unwrap_or(crate::config::DEFAULT_REAUTH_DEADLINE_SECS);
    let obligation = crate::db::ReauthObligation {
        vinst: snapshot_vinst,
        deadline: SystemTime::now() + Duration::from_secs(deadline_secs),
    };
    if let Err(e) = crate::db::ReauthRepo::new(asm.state_db.clone())
        .add_obligation(&obligation)
        .await
    {
        error!(target: EVENT, "failed to record reauth obligation for vinst {snapshot_vinst}: {e}");
        return Err(e.into());
    }
    request_auths_all_nodes(asm, &valid_node_addrs).await;

    // Re-check existing visas against the new policy. Runs last so route checks
    // and the nodes' own link state already reflect the updated topology.
    revalidate_visas(asm, &psnap, SweepReason::PolicyUpdate).await;

    Ok(())
}

/// What the guarded part of a policy pass ([policy_pass_locked]) did.
enum LockedPass {
    /// A newer policy was installed during the attribute refresh; nothing applied.
    Deferred,
    /// Applied under the current policy `psnap`.
    Applied {
        psnap: PolicySnapshot,
        /// Connected nodes still valid under `psnap`.
        valid_node_addrs: Vec<IpAddr>,
        /// VSS workers of the nodes disconnected under the guard, for the caller to
        /// stop once it has released it.
        stopped_workers: Vec<(Option<crate::vss_mgr::VssHandle>, IpAddr)>,
        /// Link reconciliation result, returned after the workers are stopped.
        reconciled: Result<(), ServiceError>,
    },
}

/// The topology part of a policy pass, under the caller's [TopoOps]: re-read the
/// policy (installs commit under the same lock, so it stays current until the guard
/// is dropped), read the live-node set and judge each node on it, disconnect the
/// invalid ones, reconcile links and revoke visas over links taken down.
///
/// `refreshed_vinst` is the policy the caller refreshed actor attributes for. If a
/// newer policy has been installed since, the actors are stale for it: judging nodes
/// on them could disconnect one the new policy admits. Then this applies nothing and
/// returns [LockedPass::Deferred]; the newer policy's own pass, queued behind this
/// one (every install records a PolicyUpdated event after it commits), refreshes
/// first and applies.
async fn policy_pass_locked(
    asm: &Arc<Assembly>,
    ops: &TopoOps<'_>,
    refreshed_vinst: u64,
) -> Result<LockedPass, ServiceError> {
    let psnap = asm.policy_mgr.get_current_snapshot();
    if psnap.vinst() != refreshed_vinst {
        info!(target: EVENT, "policy pass for vinst={refreshed_vinst} superseded by vinst={} during the attribute refresh: deferring to its pass", psnap.vinst());
        return Ok(LockedPass::Deferred);
    }
    let vinst = psnap.vinst();

    // Which nodes may pass traffic through comes from this policy (zl-zipline#227).
    // Applied whether or not any node is connected, so nodes that connect later route
    // under it. The flag is cleared before the revocations below list visas.
    let transit_lost = asm.topo_mgr.apply_transit_nodes(ops, &psnap);

    // The new policy may invalidate some existing nodes. Read the live-node set
    // under the guard, so the pass cannot re-add a node that has disconnected.
    let connected_node_addrs = asm.actor_mgr.list_node_addrs().await?;
    let (valid_node_addrs, invalid_node_addrs) =
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

                // Links the reconciliation took down or removed: revoke the visas
                // crossing them through the ungated link path (zl-zipline#224). The
                // policy sweep would skip a visa committed under this policy before the
                // link went down, because its generation gate considers it current. A
                // visa whose revocation write fails is quarantined and retried per visa.
                for (a, b) in &report.links_down {
                    let _ = crate::visa_reconciler::revoke_visas_over_link(asm, a, b).await;
                }
            }
            Err(e) => reconciled = Err(e),
        }
    }

    // Visas through a node that lost transit: revoked through the ungated path, for
    // the same reason as `links_down` above -- the sweep skips a visa committed under
    // this policy before the pass ran (zl-zipline#227). Failures are quarantined and
    // retried per visa.
    for node in &transit_lost {
        let _ = crate::visa_reconciler::revoke_visas_through_node(asm, node).await;
    }

    Ok(LockedPass::Applied {
        psnap,
        valid_node_addrs,
        stopped_workers,
        reconciled,
    })
}

/// Fan the `requestAuthentication` VSS call out to every listed node
/// (zipline#123), mirroring [set_services_all_nodes]. Each node's address list
/// is its own address (meaning "re-authenticate yourself to the VS") plus its
/// docked adapters. Failures are logged: the deadline rule in `auth_sweep`
/// re-sends to whoever still owes, so a missed request costs one sweep period,
/// not the obligation.
async fn request_auths_all_nodes(asm: &Arc<Assembly>, node_addrs: &[IpAddr]) {
    stream::iter(node_addrs)
        .for_each_concurrent(None, |naddr| {
            let asm = asm.clone();
            async move {
                let mut addrs = vec![*naddr];
                match asm.actor_mgr.get_adapters_connected_to_node(naddr).await {
                    Ok(adapters) => addrs.extend(adapters),
                    Err(e) => {
                        error!(target: EVENT, "failed to list adapters of node {naddr} for reauth fan-out: {e}");
                    }
                }
                debug!(target: EVENT, "requesting re-authentication of {} actor(s) via node {naddr}", addrs.len());
                if let Some(vss_h) = asm.vss_mgr.get_handle(naddr) {
                    if let Err(e) = vss_h.request_auths(addrs).await {
                        error!(target: EVENT, "failed to request_auths on node {naddr}: {e}");
                    }
                }
            }
        })
        .await;
}

/// A trusted service's attribute data changed (eg, an admin refreshed it). The
/// new data may invalidate visas that were issued under the old data, so
/// reconcile in two phases: refresh and persist the actors behind live visas,
/// then re-check those visas.
///
/// Phase order matters: the sweep re-reads actors from the store, so their
/// attributes have to be reconciled and written back first.
///
/// Note this only reconciles actors that hold a live visa. Everyone else is
/// handled lazily on their next visa request by the revision check in
/// `refresh_expired_attributes`.
async fn handle_trusted_service_change(asm: &Arc<Assembly>) {
    // One snapshot for the whole pass, same as the policy handler.
    let psnap = asm.policy_mgr.get_current_snapshot();

    let (refreshed, unresolved, failed) =
        refresh_actors(asm, live_visa_actor_addrs(asm).await).await;
    info!(
        target: EVENT,
        "trusted service changed: actors refreshed={refreshed} unresolved={unresolved} failed={failed}"
    );

    let failures = revalidate_visas(asm, &psnap, SweepReason::AttributeChange).await;
    if failures > 0 {
        // A verdict that could not be recorded must not be dropped -- after a
        // Zode logout it is a visa that should be revoked (#63 review). Run
        // the whole reconcile again later; it repeats while the sweep fails.
        // ponytail: fixed interval; add backoff if long store outages make the
        // retries noisy.
        warn!(target: EVENT, "attribute-change sweep left {failures} visa(s) undecided; retrying in {:?}", crate::config::RECONCILE_RETRY);
        let asm = asm.clone();
        tokio::spawn(async move {
            tokio::time::sleep(crate::config::RECONCILE_RETRY).await;
            if let Err(e) = asm
                .event_mgr
                .record_event(VsEvent::TrustedServiceChange)
                .await
            {
                error!(target: EVENT, "failed to re-queue the attribute-change reconcile: {e}");
            }
        });
    }
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
/// the policy-install re-auth obligation (zipline#123): `handle_policy_updated`
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

    /// #63 review (Copilot): a reconcile whose sweep could not record every
    /// verdict re-queues itself after `RECONCILE_RETRY` instead of dropping
    /// the work.
    #[tokio::test(start_paused = true)]
    async fn test_failed_reconcile_sweep_is_retried() {
        let (asm, mut event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let (asm, node_a) = crate::test_helpers::build_sweep_asm_on(asm, false).await;
        create_sweep_visa(&asm, &node_a, 0).await; // the empty policy denies it
        while event_rx.try_recv().is_ok() {}
        db.set_set_ex_fault(crate::db::FaultMode::ApplyThenError);

        handle_trusted_service_change(&asm).await;
        assert!(
            event_rx.try_recv().is_err(),
            "the retry waits RECONCILE_RETRY"
        );
        // Let the spawned retry task start its sleep before the clock moves.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(crate::config::RECONCILE_RETRY + Duration::from_secs(1)).await;
        let evt = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("the retry must be queued")
            .unwrap();
        assert!(matches!(evt, VsEvent::TrustedServiceChange));
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

        handle_trusted_service_change(&asm).await;

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
        handle_trusted_service_change(&asm).await;

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
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let update = tokio::task::spawn_local({
                    let asm = asm.clone();
                    async move { handle_policy_updated(&asm, vinst).await }
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
            policy_pass_locked(&asm, &ops, refreshed_vinst)
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
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let pass = tokio::task::spawn_local({
                    let asm = asm.clone();
                    async move { handle_policy_updated(&asm, vinst).await }
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

    /// zl-zipline#227: the policy pass sets the router's transit set from the policy,
    /// and revokes a visa through a node that lost transit -- including one committed
    /// under the new policy before the pass ran, which the sweep's generation gate
    /// would skip.
    #[tokio::test]
    async fn test_policy_pass_applies_transit_and_revokes_visas_through_lost_nodes() {
        use crate::test_helpers::{build_transit_asm, create_sweep_visa_on_route, transit_policy};
        let (asm, a, b, c) = build_transit_asm().await;
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[c]))
            .await
            .unwrap();
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();
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
        handle_policy_updated(&asm, vinst).await.unwrap();

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

    /// zl-zipline#227: the pass applies the transit set even when no node is connected
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
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();
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

        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();

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

        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();

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

        handle_trusted_service_change(&asm).await;

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
        handle_trusted_service_change(&asm).await;

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
        handle_trusted_service_change(&asm).await;

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
        handle_trusted_service_change(&asm).await;

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
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        handle_policy_updated(&asm, vinst).await.unwrap();

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
        let vinst = asm.policy_mgr.get_current_snapshot().vinst();
        let result = handle_policy_updated(&asm, vinst).await;
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
