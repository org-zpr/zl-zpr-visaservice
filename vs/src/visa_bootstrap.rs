//! Bootstrap visas: the visas that let a joining Zode reach VSAPI *before* it has a VS-API
//! session (ZODE_LINKS.md "Joining through the relay", J1-J8).
//!
//! A Zode joining through the relay has no VS-API session, and maybe no actor, until it has
//! authenticated, and it authenticates by reaching the visa service over VSAPI. Policy
//! evaluation cannot answer for it, so these visas are minted directly from the
//! policy-declared peering, which *is* the authorization (J3).
//!
//! **They are requested on demand** (J2, J8). The relay asks for them over its own VS-API
//! session, with `requestBootstrapVisas(peerCn)`, when the joiner's initial link comes up.
//! Topology carries none, and nothing is minted ahead of time or from traffic. The narrow
//! rule, checked by [request_bootstrap_visas]:
//! - **Only the relay may ask**: the node the visa service docks on, one hop from it
//!   (operator, pd g44 q3). A Zode reached over any other link never qualifies, so an
//!   endpoint never carries a joiner's traffic (the non-transit rule).
//! - **Only for a peer in the relay's topology**, named by the CN the relay verified on the
//!   link. The joiner's ZPR address is the one the relay's topology names for that CN, never
//!   anything the joiner claims (J2).
//! - **Only the joiner's VS-API flow**: `joiner:any -> vs:VSAPI` and its reply, one visa
//!   each, short-lived ([BOOTSTRAP_VISA_LIFETIME]).
//!
//! **Every request is a join** (J6). Each one mints new visas, and the relay's request is
//! the proof that the joiner's previous link is gone (one link per peer, rule 5): whatever
//! carried the previous join is torn down first ([end_previous_join]).
//!
//! The minting itself is `VisaMgr::mint_bootstrap_visa`, in [crate::visa_mgr] because it
//! needs the visa store's internals.

use std::net::IpAddr;
use std::sync::Arc;

use libeval::eval_result::Direction;
use libeval::policy::Policy;
use tracing::{info, warn};
use zpr::vsapi_types::BootstrapVisas;

use crate::assembly::Assembly;
use crate::connection_control::ConnectionControl;
use crate::core_visas::{self, IssueGuard};
use crate::db::VisaMetadata;
use crate::error::ServiceError;
use crate::logging::targets::API;
use crate::policy_mgr::PolicySnapshot;
use crate::topology_mgr::TopoOps;
use crate::visa_reconciler::revoke_visas_over_link;

/// Stands in for the ZPL source on a bootstrap visa, which has no matching com policy.
/// The core-visa code reads it to tell a bootstrap visa from a core visa (J5c).
pub const BOOTSTRAP_VISA_ZPL: &str = "<bootstrap: policy peering>";

/// How long a bootstrap visa lives (gate g89 q3, J3). It only has to carry the joiner's
/// authentication: the joiner moves onto its own VSAPI visas once it has authenticated
/// (J5a) and lets these expire (J5c). Five minutes covers the hand-off, the
/// `connect`/`authenticate` exchange and the J5a push with a wide margin.
pub const BOOTSTRAP_VISA_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Why [request_bootstrap_visas] refused. The VS-API handler answers each with its vs.capnp
/// error code.
pub(crate) enum Refusal {
    /// The caller's VS-API session is no longer current (`authRequired`).
    StaleSession,
    /// The caller is not the relay (`invalidOperation`, J3).
    NotRelay,
    /// The CN names no peer in the caller's topology (`notFound`, J3).
    UnknownPeer,
    /// The teardown of the previous join or the mint failed (`internal`).
    Failed(ServiceError),
}

/// Whether `node` is the relay: the node the visa service docks on, the only node that may
/// ask for a joining peer's bootstrap visas (see the module rules).
pub(crate) fn is_relay(asm: &Assembly, node: &IpAddr) -> bool {
    asm.actor_mgr
        .get_docking_node_for_adapter(&asm.config.get_vs_addr())
        .is_some_and(|dock| dock == *node)
}

/// The ZPR address `relay`'s topology names for `peer_cn`, or `None` if no link of its
/// topology names that CN.
///
/// This is exactly the topology the visa service sends the relay
/// ([crate::vss_worker::topology_links] over `psnap`; every one of those is a relay link,
/// which `proposed_links` always sends): the CN-to-address mapping comes from policy, and
/// a peer that topology leaves out (no CN, a failed pair) is not found.
fn topology_peer_addr(
    asm: &Assembly,
    psnap: &PolicySnapshot,
    relay: &IpAddr,
    peer_cn: &str,
) -> Option<IpAddr> {
    crate::vss_worker::topology_links(
        asm,
        psnap.policy(),
        relay,
        psnap.resolved_peers_for_node(relay),
    )
    .into_iter()
    .find(|link| link.peer_cn == peer_cn)
    .map(|link| link.zpr_addr)
}

/// Whether policy still authorises the bootstrap visa `metadata` describes (g94 q1): the node
/// it was issued to is still the relay, and that relay's topology under `psnap` still names
/// the joiner, by the CN policy gives the joiner's address. These are the checks
/// [request_bootstrap_visas] mints on ([is_relay], [topology_peer_addr]), and nothing else.
///
/// A policy or attribute sweep rechecks a bootstrap visa with this instead of evaluating it
/// as ordinary traffic (`VisaMgr::recheck_visa_allowed`): the visa was minted from the
/// peering, not from policy evaluation, so the route and the joiner's link state play no
/// part. They cannot: a live peer's rejoin forgets the joiner's link reports
/// ([end_previous_join]), so the joiner has no route until it reports again, and a routed
/// recheck would revoke the very pair that rejoin needs.
///
/// ponytail: the visa does not record the CN it was minted for, so the joiner's CN is read
/// from `psnap`, and a policy that only renames the joiner keeps the pair. It carries only
/// the joiner's unauthenticated VS-API flow and expires within [BOOTSTRAP_VISA_LIFETIME];
/// record the CN on the visa if that ever matters.
pub(crate) fn bootstrap_visa_authorized(
    asm: &Assembly,
    psnap: &PolicySnapshot,
    metadata: &VisaMetadata,
) -> bool {
    // A bootstrap visa is issued to the relay (`VisaMgr::mint_bootstrap_visa`).
    let relay = metadata.requesting_node;
    // The joiner is the client of its VS-API flow: the source of the forward visa and the
    // destination of the reverse one.
    let joiner = match metadata.direction {
        Direction::Forward => metadata.five_tuple.source_addr,
        Direction::Reverse => metadata.five_tuple.dest_addr,
    };
    let Some(joiner_cn) = psnap.policy().node_cn_for_addr(&joiner) else {
        return false;
    };
    is_relay(asm, &relay) && topology_peer_addr(asm, psnap, &relay, joiner_cn) == Some(joiner)
}

/// `requestBootstrapVisas` (J2, J3, J6): `relay`, whose VS-API session is `relay_session`,
/// asks for the bootstrap visas of the peer its topology names `peer_cn`.
///
/// Refused unless the session is still current, the caller is the relay and `peer_cn` names
/// a peer in its topology (see [Refusal]). Otherwise the joiner's previous join is torn
/// down ([end_previous_join]) and both directions of its VS-API flow are minted, and the
/// answer holds the joiner's copies (`peer`) and the relay's (`relay`), forward first.
///
/// `peer_cn` is the raw bytes off the wire, decoded only once the session and relay checks
/// have passed (g94 q3): a caller that may not ask is refused the same way whatever it
/// sent, and bytes that are not UTF-8 name no peer.
///
/// The checks, the teardown and the mint run as one step under the issuance lock and the
/// topology lock, so they are atomic against connect, disconnect, core-visa issuance and
/// policy passes, and the visas record the policy generation the peering was read from.
/// Stopping the old session's VSS worker waits on that worker, so it runs after both locks
/// are released.
pub(crate) async fn request_bootstrap_visas(
    asm: &Arc<Assembly>,
    relay: &IpAddr,
    relay_session: Option<&str>,
    peer_cn: &[u8],
) -> Result<BootstrapVisas, Refusal> {
    // Lock order: issuance lock, then topology lock (see core_visas::lock_issuance).
    let issuing = core_visas::lock_issuance().await;
    let ops = asm.topo_mgr.ops().await;
    if let Err(e) = core_visas::require_current_session(asm, relay, relay_session).await {
        warn!(target: API, "requestBootstrapVisas from {relay}: {e}");
        return Err(Refusal::StaleSession);
    }
    if !is_relay(asm, relay) {
        return Err(Refusal::NotRelay);
    }
    let Ok(peer_cn) = std::str::from_utf8(peer_cn) else {
        return Err(Refusal::UnknownPeer);
    };
    // Policy installs commit under the topology lock, so this snapshot stays current until
    // the guard is dropped.
    let psnap = asm.policy_mgr.get_current_snapshot();
    let Some(peer) = topology_peer_addr(asm, &psnap, relay, peer_cn) else {
        return Err(Refusal::UnknownPeer);
    };
    // Any VSS worker the joiner has belongs to its previous join, which this request proves
    // is over. It is stopped whatever happens below, once both locks are released.
    let old_vss = asm.vss_mgr.get_handle(&peer);
    let minted = match end_previous_join(asm, &ops, &issuing, &peer).await {
        Ok(()) => mint_pair(asm, psnap.policy(), &peer, relay).await,
        Err(e) => Err(e),
    };
    drop(ops);
    drop(issuing);
    ConnectionControl::stop_vss_worker(old_vss, &peer);
    match &minted {
        Ok(bv) => {
            info!(target: API, "relay {relay}: bootstrap visas {:?} for joiner {peer_cn} at {peer}", bv.peer.iter().map(|v| v.issuer_id).collect::<Vec<_>>());
        }
        Err(e) => {
            warn!(target: API, "relay {relay}: minting bootstrap visas for {peer_cn} at {peer} failed: {e}")
        }
    }
    minted.map_err(Refusal::Failed)
}

/// Tear down whatever carried `peer`'s previous join. The relay's new request is the proof
/// that it is gone: a peer has one link at a time (rule 5), so the relay holds no other live
/// link for it, and the peer's links were wiped (R9).
///
/// - Every visa of the previous join is revoked: every visa between the peer and the visa
///   service ([core_visas::revoke_previous_join]).
/// - If the peer still has a VS-API session (its node actor is stored), the session is
///   ended: a new session id is stamped on the actor, so every handle of the old session
///   fails its liveness check (the caller stops its VSS worker). Its link-state reports
///   are forgotten, so its links are down until it reports again (R14), and the visas
///   crossing a link that went down are revoked. Every other visa installed on the peer is
///   marked pending install, so it
///   is pushed again after a `reconnect` (`VisaMgr::forget_installs_on_node`). The node
///   actor and its adapters stay, so the visa service can still accept a `reconnect` (R16).
///
/// Only install state, link-state reports and revocation change here; no visa is edited.
/// Runs under the caller's issuance lock and topology lock (`ops`); takes the node commit
/// lock for the actor write, as every writer of a node's own actor does.
async fn end_previous_join(
    asm: &Arc<Assembly>,
    ops: &TopoOps<'_>,
    issuing: &IssueGuard,
    peer: &IpAddr,
) -> Result<(), ServiceError> {
    let has_session = {
        let _commit = asm.policy_mgr.node_commit_lock.lock().await;
        match asm.actor_mgr.get_actor_by_zpr_addr(peer).await? {
            Some(mut actor) if actor.is_node() => {
                crate::vsapi_worker::stamp_new_session(&mut actor);
                asm.actor_mgr
                    .update_actor(&actor, &asm.policy_service_names())
                    .await?;
                true
            }
            _ => false,
        }
    };
    core_visas::revoke_previous_join(asm, issuing, peer).await?;
    if !has_session {
        return Ok(());
    }
    // Its links are gone too (R9): forget its link reports, so they are down until it
    // reports again (R14), and revoke the visas crossing any that just went down, as a
    // link-down report would.
    let went_down = asm
        .topo_mgr
        .forget_link_states(ops, peer, &|| asm.policy_mgr.get_current_snapshot());
    for (a, b) in went_down {
        let _ = revoke_visas_over_link(asm, &a, &b).await;
    }
    // ponytail: an install ack of the old session still in flight can land after this and
    // mark one visa installed again although the node lost it. The node then re-requests
    // that flow on its next packet (F6). Fence acks by session if that ever matters.
    let repush = asm.visa_mgr.forget_installs_on_node(peer).await?;
    info!(target: API, "joiner {peer} rejoins: its VS-API session is ended; visas {repush:?} will be pushed again");
    Ok(())
}

/// Mint both directions of `peer`'s VS-API flow through `relay`, forward first, and return
/// the peer's copies and the relay's. `policy` is the view the peering was read from.
///
/// If the reverse mint fails after the forward one succeeded, the forward visa is simply
/// never handed out: it expires within [BOOTSTRAP_VISA_LIFETIME], and the relay's next
/// request revokes it anyway (J6).
async fn mint_pair(
    asm: &Assembly,
    policy: &Policy,
    peer: &IpAddr,
    relay: &IpAddr,
) -> Result<BootstrapVisas, ServiceError> {
    let mut peer_copies = Vec::with_capacity(BootstrapVisas::VISAS_PER_LIST);
    let mut relay_copies = Vec::with_capacity(BootstrapVisas::VISAS_PER_LIST);
    for direction in [Direction::Forward, Direction::Reverse] {
        let visa = asm
            .visa_mgr
            .mint_bootstrap_visa(asm, policy, peer, relay, direction)
            .await?;
        peer_copies.push(
            asm.visa_mgr
                .actualize_visa_for_target_node(visa.clone(), peer)
                .await?,
        );
        relay_copies.push(
            asm.visa_mgr
                .actualize_visa_for_target_node(visa, relay)
                .await?,
        );
    }
    Ok(BootstrapVisas {
        peer: peer_copies,
        relay: relay_copies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::config;
    use crate::visareq_worker::{VisaDecision, process_visa_request_for_test};
    use zpr::vsapi_types::PacketDesc;

    /// Assembly for the bootstrap tests: policy declares one `via_node`<->`future_peer`
    /// peering, and `via_node` is connected and docks the visa service. The peer is left
    /// unconnected (no actor, no route) -- callers that want it connected add its actor.
    async fn build_bootstrap_test_asm(via_node: IpAddr, future_peer: IpAddr) -> Assembly {
        build_bootstrap_test_asm_with_cns(via_node, &[future_peer], &[]).await
    }

    /// As [build_bootstrap_test_asm], with one peering from `via_node` to each of
    /// `future_peers` (link ids `link-vp`, `link-vp1`, ...), and node join policies declaring
    /// the given node CNs (what `Policy::node_cn_for_addr` reads).
    async fn build_bootstrap_test_asm_with_cns(
        via_node: IpAddr,
        future_peers: &[IpAddr],
        node_cns: &[(IpAddr, &str)],
    ) -> Assembly {
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::{FakeResolver, make_peering, policy_with_peerings_and_node_cns};
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let mut asm = new_assembly_for_tests(None).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            policy_with_peerings_and_node_cns(
                &future_peers
                    .iter()
                    .enumerate()
                    .map(|(i, peer)| {
                        let link_id = if i == 0 {
                            "link-vp".to_string()
                        } else {
                            format!("link-vp{i}")
                        };
                        make_peering(via_node, *peer, &link_id, vec![])
                    })
                    .collect::<Vec<_>>(),
                node_cns,
            ),
            PolicyRepo::new(asm.state_db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(crate::db::ActorRepo::new(asm.state_db.clone())),
            None,
            crate::config::VSConfig::default().get_vs_addr(),
        )
        .await
        .unwrap();
        asm.topo_mgr.add_node(via_node).unwrap();
        asm.actor_mgr
            .hack_set_vs_docking_node(&via_node)
            .await
            .unwrap();
        asm
    }

    /// The two directions of a future peer's VSAPI flow, as a node's dataplane would ask about
    /// them: the peer's own SYN, and the visa service's reply to it.
    fn bootstrap_flow_packets(asm: &Assembly, future_peer: &IpAddr) -> (PacketDesc, PacketDesc) {
        let vs_addr = asm.config.get_vs_addr().to_string();
        let peer = future_peer.to_string();
        let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);
        (
            PacketDesc::new_tcp(&peer, &vs_addr, 40000, vsapi_port).unwrap(),
            PacketDesc::new_tcp(&vs_addr, &peer, vsapi_port, 40000).unwrap(),
        )
    }

    /// J8: a topology send carries no bootstrap visas. Building the relay's links for a peer
    /// that has not connected mints nothing for it: its bootstrap visas come only from the
    /// relay's on-demand `requestBootstrapVisas` (J2, J3).
    #[tokio::test]
    async fn topology_links_mint_no_bootstrap_visas_for_an_unconnected_peer() {
        let relay: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
        let joiner: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = Arc::new(
            build_bootstrap_test_asm_with_cns(
                relay,
                &[joiner],
                &[(relay, "relay.zpr"), (joiner, "joiner.zpr")],
            )
            .await,
        );

        let links = crate::vss_worker::topology_links(
            &asm,
            &asm.policy_mgr.get_current(),
            &relay,
            resolved_peers(&asm, &relay),
        );

        assert_eq!(links.len(), 1, "the link to the joiner is still proposed");
        assert!(
            asm.visa_mgr
                .get_visa_ids_for_actors(&[joiner])
                .await
                .unwrap()
                .is_empty(),
            "nothing is minted for the joiner by a topology send"
        );
    }

    /// J8: there is no traffic-triggered bootstrap path. The relay asking about either
    /// direction of an actor-less peer's VSAPI flow goes through normal evaluation, which
    /// denies it: the peer has no actor.
    #[tokio::test]
    async fn vsapi_request_about_an_actorless_peer_is_denied() {
        let relay: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
        let joiner: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = Arc::new(build_bootstrap_test_asm(relay, joiner).await);
        let (syn_pkt, reply_pkt) = bootstrap_flow_packets(&asm, &joiner);

        for pkt in [syn_pkt, reply_pkt] {
            assert!(
                matches!(
                    process_visa_request_for_test(asm.clone(), relay, pkt).await,
                    VisaDecision::Deny(_)
                ),
                "no bootstrap visa is minted from traffic"
            );
        }
        assert!(
            asm.visa_mgr
                .get_visa_ids_for_actors(&[joiner])
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The `(link_id, substrate)` pairs `send_topology` would resolve for `node`, read the same
    /// way: from the current snapshot.
    fn resolved_peers(asm: &Assembly, node: &IpAddr) -> Vec<crate::policy_mgr::ResolvedPeer> {
        asm.policy_mgr
            .get_current_snapshot()
            .resolved_peers_for_node(node)
    }

    /// Every link of a topology send names its peer's CN, read from the peer's node join
    /// policy (zl-zipline#221): the CN the peer's link certificate must carry.
    #[tokio::test]
    async fn topology_links_carry_the_peer_cn_from_policy() {
        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();
        let asm = Arc::new(
            build_bootstrap_test_asm_with_cns(
                via_node,
                &[future_peer],
                &[(via_node, "relay.zpr"), (future_peer, "laptop-a.zpr")],
            )
            .await,
        );
        let links = crate::vss_worker::topology_links(
            &asm,
            &asm.policy_mgr.get_current(),
            &via_node,
            resolved_peers(&asm, &via_node),
        );
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].zpr_addr, future_peer);
        assert_eq!(links[0].peer_cn, "laptop-a.zpr");
    }

    /// A peer whose CN policy does not declare is left out of the topology send (operator,
    /// pd g44 q2): its node would refuse an unnamed peer anyway (zl-zipline#220), and its
    /// bootstrap visas would have no CN to be bound to.
    #[tokio::test]
    async fn topology_links_skip_a_peer_without_a_cn() {
        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();
        let asm = Arc::new(
            build_bootstrap_test_asm_with_cns(via_node, &[future_peer], &[(via_node, "relay.zpr")])
                .await,
        );
        let links = crate::vss_worker::topology_links(
            &asm,
            &asm.policy_mgr.get_current(),
            &via_node,
            resolved_peers(&asm, &via_node),
        );
        assert!(
            links.is_empty(),
            "no CN for {future_peer}: link skipped, got {links:?}"
        );
    }

    /// R13a (ZODE_LINKS.md): once the owner reports a link `failed`, the visa service leaves
    /// it out of both ends' topology until the pair is cleared (a (re)connect of either end),
    /// and proposes it again after that. Other links of the same node are unaffected.
    #[tokio::test]
    async fn topology_links_leave_out_a_failed_pair_until_it_is_cleared() {
        use zpr::vsapi_types::{LinkState, LinkStateReport};
        let relay: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let a: IpAddr = "fd5a:5052:3000::a".parse().unwrap();
        let b: IpAddr = "fd5a:5052:3000::b".parse().unwrap();
        let asm = Arc::new(
            build_bootstrap_test_asm_with_cns(
                relay,
                &[a, b],
                &[(relay, "relay.zpr"), (a, "a.zpr"), (b, "b.zpr")],
            )
            .await,
        );
        // The peers each end's topology names, by ZPR address.
        let peers_of = |node: IpAddr| {
            let asm = asm.clone();
            async move {
                let mut peers: Vec<IpAddr> = crate::vss_worker::topology_links(
                    &asm,
                    &asm.policy_mgr.get_current(),
                    &node,
                    resolved_peers(&asm, &node),
                )
                .iter()
                .map(|l| l.zpr_addr)
                .collect();
                peers.sort();
                peers
            }
        };
        assert_eq!(peers_of(relay).await, vec![a, b]);
        assert_eq!(peers_of(a).await, vec![relay]);

        // The relay reports its link to A failed.
        asm.topo_mgr.record_link_states(
            &asm.topo_mgr.ops().await,
            &relay,
            None,
            vec![LinkStateReport {
                peer_cn: "a.zpr".to_string(),
                state: LinkState::Failed,
            }],
            &|| asm.policy_mgr.get_current_snapshot(),
        );
        assert_eq!(
            peers_of(relay).await,
            vec![b],
            "left out of the reporter's topology"
        );
        assert!(
            peers_of(a).await.is_empty(),
            "and out of the peer's topology"
        );

        // A (re)connects: the pair is cleared and proposed again.
        assert_eq!(
            asm.topo_mgr
                .clear_failed_pairs_for(&asm.topo_mgr.ops().await, &a),
            vec![relay]
        );
        assert_eq!(peers_of(relay).await, vec![a, b]);
        assert_eq!(peers_of(a).await, vec![relay]);
    }
}
