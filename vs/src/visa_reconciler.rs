//! Visa reconciliation: re-evaluate live visas against a policy snapshot and queue
//! revocations for the ones that no longer hold.
//!
//! Split out of `event_mgr` because this is visa lifecycle policy, not event
//! coordination -- the operation spans actors, policy, topology, and visa
//! persistence. `event_mgr` still owns the *ordering* of a reconcile pass (refresh
//! attributes, then sweep); this module owns the sweep itself.

use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::assembly::Assembly;
use crate::logging::targets::VISA;
use crate::policy_mgr::PolicySnapshot;
use crate::visa_mgr::VisaRecheck;

/// Why a visa sweep is running. The two reasons need different handling because
/// an attribute change does not move the policy generation, so the
/// `checked_vinst` gates that make the policy sweep idempotent (ie, do not do
/// anything if the `vinst` has not changed) would make an attribute sweep a
/// complete no-op.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SweepReason {
    /// A new policy was installed.
    PolicyUpdate,
    /// A trusted service's attribute data changed.
    AttributeChange,
}

/// Sweep every live visa and re-evaluate it against the given policy snapshot.
/// Denied visas (and visas whose route moved) are marked `PendingRevoke` on all
/// their nodes so VSS housekeeping revokes them.
///
/// Visas whose actors can't be resolved are skipped (not revoked). A verdict is
/// only applied while `target_vinst` is still the live policy generation —
/// otherwise a newer policy sweep is coming and it will decide when it runs.
///
/// [SweepReason::PolicyUpdate] skips any visa already checked at/after
/// `target_vinst`, bumps `checked_vinst` on allow (canceling any older queued
/// revoke), and denies through the vinst-gated verdict recorder.
///
/// [SweepReason::AttributeChange] cannot use those gates: the policy generation has
/// not moved, so every visa looks "current". It checks every visa, revokes through
/// the ungated [VisaMgr::mark_visa_revoked], and does nothing at all on allow —
/// a revoke queued by an earlier attribute sweep stays queued, and the node simply
/// re-requests to get a fresh decision.
///
/// Returns the number of visas the sweep could not decide or record (a
/// re-check error, or a failed verdict write). Those are logged either way; a
/// caller that must not lose them (a node's logout, zl-zipline#232) retries.
pub(crate) async fn revalidate_visas(
    asm: &Arc<Assembly>,
    psnap: &PolicySnapshot,
    reason: SweepReason,
) -> u32 {
    let target_vinst = psnap.vinst();
    let snapshot = asm.visa_mgr.list_visa_metadata().await;

    // Some numbers for logging purposes.
    let total = snapshot.len();
    let mut allowed = 0u32;
    let mut revoked = 0u32;
    let mut skipped_stale = 0u32;
    let mut skipped_unresolved = 0u32;
    let mut skipped_current = 0u32;
    let mut failed = 0u32;

    for (visa_id, metadata) in snapshot {
        // Only a policy sweep can skip on generation: an attribute change leaves the
        // generation alone, so this would skip everything.
        if reason == SweepReason::PolicyUpdate && metadata.checked_vinst >= target_vinst {
            skipped_current += 1;
            continue;
        }
        match asm
            .visa_mgr
            .recheck_visa_allowed(asm, &metadata, psnap)
            .await
        {
            Ok(VisaRecheck::SkipUnresolvedActor) => {
                skipped_unresolved += 1;
                debug!(target: VISA, "visa sweep: visa {visa_id} actor unresolved, skipping");
            }
            Ok(VisaRecheck::AllowSameRoute) => {
                // An attribute sweep records nothing on allow: it must not bump
                // checked_vinst (that would make a later policy sweep skip the visa)
                // and it deliberately leaves any queued revoke in place.
                if reason == SweepReason::AttributeChange {
                    allowed += 1;
                    continue;
                }
                // Allowed. Only apply while target_vinst is still the live policy;
                // otherwise an older sweep could cancel a newer revoke verdict.
                if asm.policy_mgr.get_current_snapshot().vinst() != target_vinst {
                    skipped_stale += 1;
                    continue;
                }
                match asm
                    .visa_mgr
                    .record_allow_verdict(visa_id, target_vinst)
                    .await
                {
                    Ok(_) => allowed += 1,
                    Err(e) => {
                        failed += 1;
                        warn!(target: VISA, "visa sweep: failed to record allow for visa {visa_id}: {e}")
                    }
                }
            }
            Ok(VisaRecheck::Revoke) => {
                // Denied, or allowed but rerouted. Only apply while target_vinst
                // is still the live policy; otherwise a newer sweep is coming and
                // will make the decision.
                if asm.policy_mgr.get_current_snapshot().vinst() != target_vinst {
                    skipped_stale += 1;
                    continue;
                }
                // The verdict recorder is vinst-gated, so an attribute sweep has to
                // revoke through the ungated path.
                let res = match reason {
                    SweepReason::PolicyUpdate => {
                        asm.visa_mgr
                            .record_deny_verdict(visa_id, target_vinst)
                            .await
                    }
                    SweepReason::AttributeChange => asm.visa_mgr.mark_visa_revoked(visa_id).await,
                };
                match res {
                    Ok(_) => revoked += 1,
                    Err(e) => {
                        failed += 1;
                        warn!(target: VISA, "visa sweep: failed to record deny for visa {visa_id}: {e}")
                    }
                }
            }
            Err(e) => {
                failed += 1;
                warn!(target: VISA, "visa sweep: error re-checking visa {visa_id}: {e}");
            }
        }
    }

    // Note that this sweep just manipulates the desired state of the visas. The
    // actual revocations happen asynchronously in VSS housekeeping.
    info!(
        target: VISA,
        "visa sweep reason={reason:?} vinst={target_vinst}: total={total} allowed={allowed} revoked={revoked} skipped_stale={skipped_stale} skipped_unresolved={skipped_unresolved} skipped_current={skipped_current} failed={failed}"
    );
    failed
}

/// Revoke every live visa whose path crosses the link between nodes `a` and `b` (either
/// direction), because link-state reports say that link is down (zl-zipline#224).
///
/// A visa crosses the link when `a` and `b` are adjacent in its recorded node path
/// (`VisaMetadata.path`). A visa with no path (both actors on one node) never crosses a
/// link. See [revoke_visas_on_paths] for how each visa is revoked and what is returned.
pub(crate) async fn revoke_visas_over_link(
    asm: &Arc<Assembly>,
    a: &std::net::IpAddr,
    b: &std::net::IpAddr,
) -> Result<usize, usize> {
    revoke_visas_on_paths(asm, &format!("link {a} <-> {b} down"), |path| {
        path.windows(2)
            .any(|hop| (hop[0] == *a && hop[1] == *b) || (hop[0] == *b && hop[1] == *a))
    })
    .await
}

/// Revoke every live visa whose path passes *through* `node` -- `node` is an interior
/// hop, neither its first nor its last node -- because policy no longer lists it as
/// transit-capable (zl-zipline#227). A visa that only starts or ends at `node` is kept.
/// See [revoke_visas_on_paths] for how each visa is revoked and what is returned.
pub(crate) async fn revoke_visas_through_node(
    asm: &Arc<Assembly>,
    node: &std::net::IpAddr,
) -> Result<usize, usize> {
    revoke_visas_on_paths(asm, &format!("node {node} no longer transit"), |path| {
        path.len() > 2 && path[1..path.len() - 1].contains(node)
    })
    .await
}

/// Revoke every live visa whose recorded path has an interior node the router does not
/// hold transit-capable ([crate::topology_mgr::TopologyMgr::interior_is_transit]).
///
/// Startup runs this right after the topology restore (review on visaservice#65). The
/// visas come back from the store, but the revocations a policy pass owed them do not:
/// if the service stopped after installing a policy that took a node's transit flag
/// away and before that pass revoked the visas through it, the restored router already
/// has the new transit set and reports no change, so nothing else would revoke them.
/// The caller holds [crate::topology_mgr::TopoOps], so the transit set cannot change
/// while the paths are checked. See [revoke_visas_on_paths] for how each visa is
/// revoked and what is returned.
pub(crate) async fn revoke_visas_through_non_transit(asm: &Arc<Assembly>) -> Result<usize, usize> {
    revoke_visas_on_paths(asm, "restored route through a non-transit node", |path| {
        !asm.topo_mgr.interior_is_transit(path)
    })
    .await
}

/// Revoke every live visa whose recorded node path (`VisaMetadata.path`) satisfies
/// `affected`. `why` names the cause in the logs.
///
/// Each such visa is marked `PendingRevoke` on all its nodes through the ungated
/// [VisaMgr::mark_visa_revoked] -- the same path the attribute sweep uses -- so VSS
/// housekeeping revokes it and the flow re-requests, getting a route that avoids the
/// cause. A visa with no recorded path is never affected.
///
/// Every affected visa is attempted even if some writes fail. A visa whose write fails
/// is quarantined ([VisaMgr::quarantine]): withheld from distribution and retried on
/// every pending-visa read. Returns `Ok(marked)` when every write succeeded, or
/// `Err(failed)` with the number quarantined.
///
/// [VisaMgr::quarantine]: crate::visa_mgr::VisaMgr::quarantine
///
/// [VisaMgr::mark_visa_revoked]: crate::visa_mgr::VisaMgr::mark_visa_revoked
async fn revoke_visas_on_paths(
    asm: &Arc<Assembly>,
    why: &str,
    affected: impl Fn(&[std::net::IpAddr]) -> bool,
) -> Result<usize, usize> {
    let mut revoked = 0;
    let mut failed = 0;
    for (visa_id, metadata) in asm.visa_mgr.list_visa_metadata().await {
        let Some(path) = &metadata.path else {
            continue;
        };
        if !affected(path) {
            continue;
        }
        match asm.visa_mgr.mark_visa_revoked(visa_id).await {
            Ok(true) => revoked += 1,
            Ok(false) => {} // already being revoked
            Err(e) => {
                failed += 1;
                // Retried per visa from now on, independent of what caused it.
                asm.visa_mgr.quarantine(visa_id);
                warn!(target: VISA, "{why}: failed to revoke visa {visa_id}, quarantined for retry: {e}")
            }
        }
    }
    info!(target: VISA, "{why}: revoked {revoked} visa(s) on it, {failed} failed");
    if failed == 0 {
        Ok(revoked)
    } else {
        Err(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::{make_policy, new_assembly_for_tests};
    use crate::test_helpers::{build_sweep_asm, create_sweep_visa};
    use std::net::IpAddr;

    /// #63 review: an actor-store read error is a sweep failure, not an
    /// unresolved actor -- otherwise a logout's sweep could report success and
    /// stop retrying while a visa it should revoke stays live.
    #[tokio::test]
    async fn test_actor_read_error_counts_as_sweep_failure() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let (asm, node_a) = crate::test_helpers::build_sweep_asm_on(asm, false).await;
        create_sweep_visa(&asm, &node_a, 0).await;
        db.set_exists_fault(crate::db::FaultMode::Reject);

        let psnap = asm.policy_mgr.get_current_snapshot();
        let failures = revalidate_visas(&asm, &psnap, SweepReason::AttributeChange).await;
        assert_eq!(failures, 1, "the unreadable actor must count as a failure");
    }

    /// A denied visa is marked PendingRevoke on its holder node (target policy
    /// still live). Uses the no-route assembly so eval falls out as a deny.
    #[tokio::test]
    async fn test_sweep_denied_visa_marked_pending_revoke() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        assert!(
            psnap.vinst() > 0,
            "target must exceed the visa's checked_vinst"
        );
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        let revoke_ids = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoke_ids, vec![id]);
    }

    /// A visa already checked at/after target_vinst is skipped before re-eval:
    /// even on the deny (no-route) assembly it is NOT marked PendingRevoke.
    #[tokio::test]
    async fn test_sweep_skips_already_checked() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let target = asm.policy_mgr.get_current_snapshot().vinst();
        // checked_vinst == target, so the guard skips before recheck.
        let id = create_sweep_visa(&asm, &node_a, target).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty(),
            "already-checked visa must not be re-evaluated/revoked"
        );
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
    }

    /// An unresolvable actor leaves the visa untouched (skipped, not revoked).
    #[tokio::test]
    async fn test_sweep_unresolved_actor_leaves_visa_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        // Five-tuple addrs (::4000::a/b) have no actors in the DB → unresolved.
        let id = create_sweep_visa(&asm, &node, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::PolicyUpdate).await;

        // Still held as PendingInstall (untouched); nothing marked for revoke.
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A deny whose target vinst is no longer the live policy generation is
    /// skipped (a newer sweep is coming): no revoke is marked.
    #[tokio::test]
    async fn test_sweep_denied_but_stale_target_skips() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        // Snapshot the current (stale) generation, then bump the live policy so
        // get_current_snapshot().vinst() moves past the snapshot's vinst.
        let stale_psnap = asm.policy_mgr.get_current_snapshot();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy("2024-01-02T00:00:00Z", 2, Some("m")))
            .await
            .unwrap();
        assert!(asm.policy_mgr.get_current_snapshot().vinst() > stale_psnap.vinst());

        revalidate_visas(&asm, &stale_psnap, SweepReason::PolicyUpdate).await;

        // No revoke marked; the visa stays PendingInstall.
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty()
        );
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(pending, vec![id]);
    }

    /// The core case: an attribute sweep re-checks (and revokes) a visa whose
    /// `checked_vinst` already equals the live generation -- exactly what the policy
    /// sweep skips, at both the sweep and the store layer.
    #[tokio::test]
    async fn test_attr_sweep_revokes_visa_at_current_vinst() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let target = asm.policy_mgr.get_current_snapshot().vinst();
        let id = create_sweep_visa(&asm, &node_a, target).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::AttributeChange).await;

        let revoke_ids = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoke_ids, vec![id]);

        // The attribute sweep must not touch the policy generation it was checked at.
        let md = asm.visa_mgr.list_visa_metadata().await;
        assert_eq!(md.len(), 1);
        assert_eq!(md[0].1.checked_vinst, target);
    }

    /// An attribute sweep holding a snapshot older than the live policy applies nothing:
    /// a policy sweep is already coming and will decide.
    #[tokio::test]
    async fn test_attr_sweep_stale_target_skips() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let id = create_sweep_visa(&asm, &node_a, 0).await;

        let stale_psnap = asm.policy_mgr.get_current_snapshot();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy("2024-01-02T00:00:00Z", 2, Some("m")))
            .await
            .unwrap();

        revalidate_visas(&asm, &stale_psnap, SweepReason::AttributeChange).await;

        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id]
        );
    }

    /// An unresolvable actor is skipped by the attribute sweep too, never revoked.
    #[tokio::test]
    async fn test_attr_sweep_unresolved_actor_leaves_visa_untouched() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let id = create_sweep_visa(&asm, &node, 0).await;

        let psnap = asm.policy_mgr.get_current_snapshot();
        revalidate_visas(&asm, &psnap, SweepReason::AttributeChange).await;

        assert_eq!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&node)
                .await
                .unwrap(),
            vec![id]
        );
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // --- Revoke on link down (zl-zipline#224) ---

    /// A visa whose path crosses the downed link is marked PendingRevoke; a visa that
    /// does not cross it is left alone.
    #[tokio::test]
    async fn test_revoke_visas_over_link_hits_only_crossing_visas() {
        use crate::test_helpers::create_routed_sweep_visa;
        let (asm, node_a) = build_sweep_asm(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let crossing = create_routed_sweep_visa(&asm, &node_a, 0).await;
        let local = create_sweep_visa(&asm, &node_a, 0).await; // direct, no path

        // Either argument order names the same undirected link.
        assert_eq!(revoke_visas_over_link(&asm, &node_b, &node_a).await, Ok(1));

        let revoked = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoked, vec![crossing]);
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert!(pending.contains(&local), "a visa off the link stays");
    }

    /// zl-zipline#227: a node that lost transit revokes the visas whose path passes
    /// through it, and not the visas that only start or end there.
    #[tokio::test]
    async fn test_revoke_visas_through_node_hits_only_interior_hops() {
        use crate::test_helpers::{build_transit_asm, create_sweep_visa_on_route};
        let (asm, a, b, c) = build_transit_asm().await;
        asm.topo_mgr.set_transit_nodes(&[c]);
        let via_c = asm.topo_mgr.get_routes(&a, &b, None);
        let via_c = via_c
            .iter()
            .find(|r| r.links.len() == 2)
            .expect("a route through C");
        let through = create_sweep_visa_on_route(&asm, &a, 0, via_c).await;
        let direct = asm.topo_mgr.get_best_route(&a, &b).unwrap();
        assert_eq!(direct.links.len(), 1);
        let direct = create_sweep_visa_on_route(&asm, &a, 0, &direct).await;

        // A and B are ends of both paths: nothing passes through them.
        assert_eq!(revoke_visas_through_node(&asm, &a).await, Ok(0));
        assert_eq!(revoke_visas_through_node(&asm, &b).await, Ok(0));
        assert_eq!(revoke_visas_through_node(&asm, &c).await, Ok(1));

        let revoked = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&a)
            .await
            .unwrap();
        assert_eq!(revoked, vec![through]);
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&a)
            .await
            .unwrap();
        assert!(pending.contains(&direct), "the direct visa stays");
    }

    /// zl-zipline#227: a visa routed through a node whose transit flag is cleared
    /// between route selection and commit is revoked at commit.
    #[tokio::test]
    async fn test_visa_through_a_node_that_lost_transit_is_revoked_at_commit() {
        use crate::test_helpers::{build_transit_asm, try_create_sweep_visa_on_route};
        let (asm, a, b, c) = build_transit_asm().await;
        asm.topo_mgr.set_transit_nodes(&[c]);
        let route = asm
            .topo_mgr
            .get_routes(&a, &b, None)
            .into_iter()
            .find(|r| r.links.len() == 2)
            .expect("a route through C");

        asm.topo_mgr.set_transit_nodes(&[]);
        assert!(
            try_create_sweep_visa_on_route(&asm, &a, 0, &route)
                .await
                .is_err(),
            "a visa through a node that lost transit is not issued"
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&a)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// A link between two other nodes revokes nothing.
    #[tokio::test]
    async fn test_revoke_visas_over_unrelated_link_revokes_nothing() {
        use crate::test_helpers::create_routed_sweep_visa;
        let (asm, node_a) = build_sweep_asm(true).await;
        create_routed_sweep_visa(&asm, &node_a, 0).await;
        let x: IpAddr = "fd5a:5052:3000::8".parse().unwrap();
        let y: IpAddr = "fd5a:5052:3000::9".parse().unwrap();
        assert_eq!(revoke_visas_over_link(&asm, &x, &y).await, Ok(0));
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A visa issued on a route whose link went down after the route was chosen is
    /// revoked as it is committed, not left for a sweep that already ran.
    #[tokio::test]
    async fn test_visa_on_a_route_that_went_down_is_revoked_at_commit() {
        use crate::test_helpers::try_create_sweep_visa_on_route;
        let (asm, node_a) = build_sweep_asm(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let route = asm.topo_mgr.get_best_route(&node_a, &node_b).unwrap();

        // The link goes down between route selection and commit.
        let down = asm.topo_mgr.record_link_states_with_cns(
            &asm.topo_mgr.ops_now(),
            &node_a,
            None,
            vec![],
            &|_: &IpAddr| None,
        );
        assert_eq!(down, vec![(node_a, node_b)]);
        assert!(
            try_create_sweep_visa_on_route(&asm, &node_a, 0, &route)
                .await
                .is_err(),
            "a visa on a route that went down is not issued, even once revoked"
        );

        let revoked = asm
            .visa_mgr
            .get_pending_revoke_visa_ids_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(revoked.len(), 1, "the stored visa is revoked");
    }

    /// A link revocation whose state write fails quarantines the visa: it is not
    /// handed out while the write keeps failing, and the next pending-visa read
    /// revokes it once writes work again -- whatever happens to the link meanwhile.
    #[tokio::test]
    async fn test_failed_link_revocation_quarantines_the_visa() {
        use crate::db::FaultMode;
        use crate::test_helpers::{build_sweep_asm_with_db, create_routed_sweep_visa};
        let (asm, node_a, db) = build_sweep_asm_with_db(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let id = create_routed_sweep_visa(&asm, &node_a, 0).await;

        db.set_set_ex_fault(FaultMode::Reject);
        assert_eq!(revoke_visas_over_link(&asm, &node_a, &node_b).await, Err(1));
        let pending = asm
            .visa_mgr
            .get_pending_visas_for_node(&node_a)
            .await
            .unwrap();
        assert!(pending.iter().all(|v| v.issuer_id != id), "quarantined");

        db.set_set_ex_fault(FaultMode::None);
        asm.visa_mgr
            .get_pending_visas_for_node(&node_a)
            .await
            .unwrap();
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id],
            "the quarantine retry revoked it"
        );
    }

    /// A commit-time revocation whose state write fails quarantines the visa: the
    /// issuance fails, the visa is not handed out, and its revocation is retried.
    #[tokio::test]
    async fn test_commit_time_revocation_failure_is_retained_for_retry() {
        use crate::db::FaultMode;
        use crate::test_helpers::{build_sweep_asm_with_db, create_routed_sweep_visa};
        let (asm, node_a, db) = build_sweep_asm_with_db(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let route = asm.topo_mgr.get_best_route(&node_a, &node_b).unwrap();
        let id = create_routed_sweep_visa(&asm, &node_a, 0).await;

        // The link goes down; the commit-time check runs and its revocation fails.
        // (Same for a route link that was removed outright: no endpoints needed.)
        asm.topo_mgr.record_link_states_with_cns(
            &asm.topo_mgr.ops_now(),
            &node_a,
            None,
            vec![],
            &|_: &IpAddr| None,
        );
        db.set_set_ex_fault(FaultMode::Reject);
        assert!(
            asm.visa_mgr
                .revoke_if_route_down(&asm, id, &route.links, None, None)
                .await
                .is_err(),
            "a stale visa that could not be revoked must not be issued"
        );
        // Quarantined: not handed out while its revocation keeps failing.
        let pending = asm
            .visa_mgr
            .get_pending_visas_for_node(&node_a)
            .await
            .unwrap();
        assert!(
            pending.iter().all(|v| v.issuer_id != id),
            "an unrevoked stale visa must not be distributed"
        );

        // Once the write works again, the next pending-visa read revokes it.
        db.set_set_ex_fault(FaultMode::None);
        let pending = asm
            .visa_mgr
            .get_pending_visas_for_node(&node_a)
            .await
            .unwrap();
        assert!(pending.iter().all(|v| v.issuer_id != id));
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id],
            "the retry revoked it"
        );

        // A live visa whose route is still up is left alone (the revoked one above
        // stays unissuable whatever its route does).
        let live = crate::test_helpers::create_sweep_visa(&asm, &node_a, 1).await;
        assert!(
            asm.visa_mgr
                .revoke_if_route_down(&asm, live, &[], None, None)
                .await
                .is_ok()
        );
    }

    /// Round 16 (Copilot): `register_vss` prepares its visas outside the topology
    /// lock and filters them under it with `still_grantable`: a visa revoked or
    /// quarantined meanwhile, or no longer staged for the node, is not granted.
    #[tokio::test]
    async fn test_still_grantable_filters_revoked_and_quarantined_visas() {
        let (asm, node_a) = build_sweep_asm(true).await;
        let fresh = crate::test_helpers::create_sweep_visa(&asm, &node_a, 0).await;
        assert!(asm.visa_mgr.still_grantable(fresh, &node_a));

        let revoked = crate::test_helpers::create_sweep_visa(&asm, &node_a, 1).await;
        assert!(asm.visa_mgr.mark_visa_revoked(revoked).await.unwrap());
        assert!(!asm.visa_mgr.still_grantable(revoked, &node_a));

        let quarantined = crate::test_helpers::create_sweep_visa(&asm, &node_a, 2).await;
        asm.visa_mgr.quarantine(quarantined);
        assert!(!asm.visa_mgr.still_grantable(quarantined, &node_a));

        let elsewhere: IpAddr = "fd5a:5052:3000::99".parse().unwrap();
        assert!(!asm.visa_mgr.still_grantable(fresh, &elsewhere));
    }

    /// Round 16 (Copilot): a visa revoked between being stored and the commit-time
    /// check -- the link went down, its revocation pass marked the visa, and the link
    /// came back up -- is not issued, although its route looks valid again. Link
    /// recovery must not make a revoked visa issuable.
    #[tokio::test]
    async fn test_visa_revoked_during_issuance_is_not_issued_after_recovery() {
        use crate::test_helpers::create_routed_sweep_visa;
        let (asm, node_a) = build_sweep_asm(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let route = asm.topo_mgr.get_best_route(&node_a, &node_b).unwrap();
        let id = create_routed_sweep_visa(&asm, &node_a, 0).await;
        // The link-down pass revoked it; the link is up again now.
        assert!(asm.visa_mgr.mark_visa_revoked(id).await.unwrap());

        assert!(
            asm.visa_mgr
                .revoke_if_route_down(&asm, id, &route.links, None, None)
                .await
                .is_err(),
            "a revoked visa must not be issued"
        );
    }

    /// A path that no longer ends at the destination's docking node is stale even if
    /// every route link is up and joins the path's hops (a link id moved before the
    /// path was derived from the router): the visa is revoked and not issued.
    #[tokio::test]
    async fn test_path_not_ending_at_the_egress_node_is_rejected() {
        use crate::test_helpers::create_routed_sweep_visa;
        let (asm, node_a) = build_sweep_asm(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let elsewhere: IpAddr = "fd5a:5052:3000::9".parse().unwrap();
        let route = asm.topo_mgr.get_best_route(&node_a, &node_b).unwrap();
        let id = create_routed_sweep_visa(&asm, &node_a, 0).await;
        let path = [node_a, node_b];

        assert!(
            asm.visa_mgr
                .revoke_if_route_down(&asm, id, &route.links, Some(&path), Some(node_b))
                .await
                .is_ok(),
            "path ends at the egress node: valid"
        );
        assert!(
            asm.visa_mgr
                .revoke_if_route_down(&asm, id, &route.links, Some(&path), Some(elsewhere))
                .await
                .is_err(),
            "path ends somewhere else: stale"
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![id]
        );
    }
}
