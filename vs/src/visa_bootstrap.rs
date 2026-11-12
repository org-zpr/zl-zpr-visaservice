//! Bootstrap visas: the visas that let a node reach VSAPI *before* it has connected.
//!
//! A node declared in policy as a peer of an already-connected node has no actor and no route
//! until its link comes up, and the way it brings that link up is by reaching the visa service
//! over VSAPI. Policy evaluation cannot answer for it, so these visas are minted directly from
//! the policy-declared peering, which *is* the authorization.
//!
//! This is the defined v1 join path for a Zode (Zodes plan §5.6, zl-zipline#221), not a
//! stopgap. Three rules keep it narrow:
//! - **Only the visa service mints them**, here and in
//!   `VisaMgr::vsapi_bootstrap_visa_for_future_peer`. Nothing a peer says is ever a bootstrap
//!   visa (the dataplane accepts none from Hello; zl-zipline#222).
//! - **Only the relay receives them**: the node the visa service docks on, which is one hop
//!   from it (operator, pd g44 q3). Any other neighbour of a joining node gets its link but no
//!   bootstrap visas, so an endpoint never carries a joiner's traffic (the non-transit rule).
//!   Joining across more than one hop is deferred until the visa service runs on its own Zode.
//! - **They travel next to the joiner's name**: only inside the `Link.visas` of the topology
//!   link whose `zprAddr`/`peerCn` name the joining peer, so the relay can bind them to the
//!   link whose certificate carries that CN (zl-zipline#220, #222).
//!
//! There are two ways a bootstrap visa gets to the relay, and both live here:
//! - [visas_for_link] mints the peer's own visas for a topology send, which carries them to the
//!   relay inside `Link.visas` for hand-off when the peer shows up. These have to be
//!   pushed: the peer cannot ask for a visa until it has a VSAPI session, and these are what let
//!   it open one.
//! - [visa_for_future_peer_request] answers the relay when it sees the peer's traffic -- the
//!   SYN it relays, or the visa service's reply to it -- before its own queued copy landed.
//!
//! Each direction of the session is its own visa -- see
//! `VisaMgr::vsapi_bootstrap_visa_for_future_peer`, which does the actual minting and stays in
//! [crate::visa_mgr] because it needs the visa store's internals.
//!
//! The topology send that carries them is [crate::vss_worker::topology_links].

use std::net::IpAddr;
use std::sync::Arc;

use libeval::actor::Actor;
use libeval::eval_result::Direction;
use libeval::policy::Policy;
use libeval::route::{LinkId, NodeId, Route, RouteKind};
use tracing::{debug, warn};
use zpr::vsapi_types::Visa;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use crate::assembly::Assembly;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::{VREQ, VSS};
use crate::visareq_worker::{VisaDecision, VisaRequestJob};

/// Stands in for the ZPL source on a bootstrap visa, which has no matching com policy.
pub const BOOTSTRAP_VISA_ZPL: &str = "<bootstrap: policy peering>";

/// Whether `node` is the relay: the node the visa service docks on, the only neighbour a
/// joining peer's bootstrap visas may go to (see the module rules). Read at run time, the same
/// way [vs_segment] finds the visa service's path.
fn is_relay(asm: &Assembly, node: &IpAddr) -> bool {
    asm.actor_mgr
        .get_docking_node_for_adapter(&asm.config.get_vs_addr())
        .is_some_and(|dock| dock == *node)
}

/// Both directions of the peer's VSAPI flow, actualized for `future_peer`, for `via_node` to
/// carry in the `Link.visas` of its topology message.
///
/// The visas belong to the peer, not to `via_node`: it holds them and hands them off when the
/// peer connects. Actualizing for the peer gives it the copy for its end of each path -- the SYN
/// visa ingresses at the peer, so it gets a fwd_pep handing its VSAPI traffic to `via_node`,
/// while on the reply visa the peer is egress and forwards nothing. Nodes further along either
/// path get their own copies via the pending-install queue.
///
/// Both directions are pushed because the peer needs both before it has a session to ask over:
/// the SYN visa to reach VSAPI, and the reply visa so the visa service's answer is admitted. A
/// visa carries one dock PEP and one path orientation, so neither can stand in for the other --
/// see `VisaMgr::vsapi_bootstrap_visa_for_future_peer`.
///
/// Returns no visas for a peer that has already connected: it has an actor and a route, so it
/// asks for what it needs over its own VSAPI session. Minting for it is not just redundant but
/// wrong -- [path_for_future_peer] stitches the peer on in front of `via_node`'s route to the
/// visa service, and for a connected peer that route can run back through the peer itself,
/// producing a path that revisits it (`[peer, via_node, peer]`). Actualization then reads
/// `via_node` as an intermediary and pushes it a forwarding-only visa for a flow it terminates.
///
/// Returns no visas when `via_node` is not the relay: a joining peer reaches the visa service
/// only through the relay, never through another neighbour (module rules).
///
/// Minting is idempotent, so calling this on every topology send is free after the first.
///
/// `policy` is the view the caller picked the link out of, threaded through so the minted
/// visas record the generation that actually authorized them.
pub async fn visas_for_link(
    asm: &Arc<Assembly>,
    policy: &Arc<Policy>,
    future_peer: &IpAddr,
    via_node: &IpAddr,
) -> Result<Vec<Visa>, ServiceError> {
    if !is_relay(asm, via_node) {
        debug!(target: VSS, "node {via_node} is not the relay: no bootstrap visas for its peer {future_peer}");
        return Ok(Vec::new());
    }
    if asm
        .actor_mgr
        .get_actor_by_zpr_addr(future_peer)
        .await?
        .is_some()
    {
        debug!(target: VSS, "peer {future_peer} of node {via_node} is already connected: no bootstrap visas needed");
        return Ok(Vec::new());
    }

    let mut visas = Vec::new();
    for direction in [Direction::Forward, Direction::Reverse] {
        let visa = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(asm, policy, future_peer, via_node, direction)
            .await?;
        let visa = asm
            .visa_mgr
            .actualize_visa_for_target_node(visa, future_peer)
            .await?;
        debug!(target: VSS, "created {direction:?} bootstrap visa for future peer {future_peer}: {}", visa.issuer_id);
        visas.push(visa);
    }
    Ok(visas)
}

/// Answer a request for a not-yet-connected peer's VSAPI bootstrap flow from the visa we
/// already minted, instead of from policy.
///
/// Policy cannot answer: the peer has no actor and no route until it connects, and reaching
/// VSAPI is how it connects. A peering declared in policy *is* the authorization -- the same
/// argument that justifies [visas_for_link] minting at topology-send time -- so hand a visa back.
///
/// Either orientation counts, and both really happen -- this node saw the traffic before the copy
/// [visas_for_link] staged for it was installed:
/// - `peer:any -> vs:VSAPI`, the SYN this node relays.
/// - `vs:VSAPI -> peer:any`, the visa service's reply to it.
///
/// They are two visas, not one: a visa's dock PEP names a source and a destination, and its path
/// has an ingress end, so the forward visa matches neither the reply's addresses nor its
/// direction of travel. The direction detected here is what selects the right one. Minting is
/// idempotent, so a repeated ask returns the same visa.
///
/// Returns `None` when this is not that flow, when the requesting node is not the relay, or on
/// a mint failure, leaving the request to normal evaluation.
pub async fn visa_for_future_peer_request(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
    source_actor: &Option<Actor>,
    dest_actor: &Option<Actor>,
) -> Option<VisaDecision> {
    let ft = &job.packet_desc.five_tuple;
    if ft.l4_protocol != ip_proto::TCP {
        return None;
    }
    let vs_addr = asm.config.get_vs_addr();
    let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);

    // Which end is the peer, which direction of the flow is this, and is the peer's actor the
    // missing one? A connected peer's VSAPI traffic must go through policy like anything else.
    let (peer_addr, direction, peer_actor_missing) =
        if ft.dest_addr == vs_addr && ft.dest_port == vsapi_port {
            (ft.source_addr, Direction::Forward, source_actor.is_none())
        } else if ft.source_addr == vs_addr && ft.source_port == vsapi_port {
            (ft.dest_addr, Direction::Reverse, dest_actor.is_none())
        } else {
            return None;
        };
    if !peer_actor_missing {
        return None;
    }
    // Only the relay may relay a joiner's VSAPI traffic (module rules).
    if !is_relay(asm, &job.requesting_node) {
        debug!(target: VREQ, "node {} asked about VSAPI flow with unconnected {peer_addr} but is not the relay: not a bootstrap request", job.requesting_node);
        return None;
    }

    // Only for a peer the requesting node is declared to link with: that node is the one
    // that would be handed the visa by a topology send, so it is the one allowed to pull it.
    //
    // This is the only policy read on this path: the peer selection here, the minted visa's
    // recorded generation, and the route's link_id all have to agree, so `policy` is threaded
    // into both calls below rather than re-read in each.
    let policy = asm.policy_mgr.get_current();
    let peers = policy
        .get_peers_for_node(&job.requesting_node)
        .unwrap_or(&[]);
    if !peers.iter().any(|p| p.remote_zpr_addr == peer_addr) {
        debug!(target: VREQ, "node {} asked about VSAPI flow with {peer_addr}, which is not one of its {} declared peers: not a bootstrap request", job.requesting_node, peers.len());
        return None;
    }

    // The requesting node relays for the peer, so it is `via_node` of the minted path, and
    // what it needs is its own actualized copy (forwarding-only, or full if it is an end of
    // the path) -- not the copy the peer gets pushed in `Link.visas`.
    let visa = match asm
        .visa_mgr
        .vsapi_bootstrap_visa_for_future_peer(
            asm,
            &policy,
            &peer_addr,
            &job.requesting_node,
            direction,
        )
        .await
    {
        Ok(visa) => visa,
        Err(e) => {
            warn!(target: VREQ, "failed to mint bootstrap visa for future peer {peer_addr} requested by node {}: {e}", job.requesting_node);
            return None;
        }
    };
    let route = match bootstrap_route(asm, &policy, &peer_addr, &job.requesting_node, direction) {
        Ok(route) => route,
        Err(e) => {
            warn!(target: VREQ, "failed to build the bootstrap route for future peer {peer_addr} via node {}: {e}", job.requesting_node);
            return None;
        }
    };
    match asm
        .visa_mgr
        .actualize_visa_for_target_node(visa, &job.requesting_node)
        .await
    {
        Ok(visa) => {
            debug!(target: VREQ, "node {} requested the bootstrap visa for future peer {peer_addr}: returning visa {}", job.requesting_node, visa.issuer_id);
            Some(VisaDecision::Allow(visa, route))
        }
        Err(e) => {
            warn!(target: VREQ, "failed to actualize bootstrap visa for node {} relaying future peer {peer_addr}: {e}", job.requesting_node);
            None
        }
    }
}

/// The routed part of a future peer's path to VSAPI: `via_node` to the node the visa service
/// docks on. The peer's own link is not in the router until it connects, so it is not in here --
/// [path_for_future_peer] and [bootstrap_route] each stitch it on.
fn vs_segment(
    asm: &Assembly,
    future_peer: &IpAddr,
    via_node: &IpAddr,
) -> Result<Route, ServiceError> {
    let vs_addr = asm.config.get_vs_addr();
    let vs_dock = asm
        .actor_mgr
        .get_docking_node_for_adapter(&vs_addr)
        .ok_or_else(|| {
            ServiceError::Internal(format!(
                "visa service {vs_addr} is not docked to a node: cannot path bootstrap visa for {future_peer}"
            ))
        })?;
    asm.topo_mgr
        .get_best_route(via_node, &vs_dock)
        .ok_or_else(|| {
            ServiceError::Internal(format!(
                "no route from {via_node} to visa service docking node {vs_dock}"
            ))
        })
}

/// Node path a future peer's VSAPI traffic will take: the peer itself, then
/// `via_node` (the neighbour carrying the peer's topology message, hence its
/// first hop), then `via_node`'s route to the node the visa service docks on.
///
/// The peer's own link is not in the router yet -- it only comes up when the
/// peer connects -- so the first hop is stitched on from the peering rather
/// than routed.
///
/// The routed part is read from the live router: the path names the nodes
/// actualization pushes a copy to, so they have to be nodes whose links are up.
/// See the comment at the mint site in
/// `VisaMgr::vsapi_bootstrap_visa_for_future_peer` for why a `PolicySnapshot`
/// cannot supply this and what does come from policy.
pub fn path_for_future_peer(
    asm: &Assembly,
    future_peer: &IpAddr,
    via_node: &IpAddr,
) -> Result<Vec<IpAddr>, ServiceError> {
    let segment = vs_segment(asm, future_peer, via_node)?;
    let mut path = vec![*future_peer];
    path.extend(
        asm.topo_mgr
            .route_to_path(&segment, &NodeId(*via_node))?
            .into_iter()
            .map(IpAddr::from),
    );
    Ok(path)
}

/// The route a future peer's VSAPI traffic takes in the given direction: its own link to
/// `via_node`, then the routed segment on to the visa service's docking node.
///
/// It is always [RouteKind::Multihop] -- at least the peer's link is crossed -- and that link
/// is described by `policy` rather than by the router, which does not know it yet. The caller's
/// view is threaded in so the link id here matches the peering the caller selected.
/// [Direction::Reverse] walks the same links from the far end, so the order flips.
fn bootstrap_route(
    asm: &Assembly,
    policy: &Arc<Policy>,
    future_peer: &IpAddr,
    via_node: &IpAddr,
    direction: Direction,
) -> Result<Route, ServiceError> {
    let segment = vs_segment(asm, future_peer, via_node)?;
    let peer_link = policy.describe_link(via_node, future_peer).map_err(|e| {
        ServiceError::Internal(format!(
            "no policy link between {via_node} and future peer {future_peer}: {e}"
        ))
    })?;
    let mut links = vec![LinkId(peer_link.link_id)];
    links.extend(segment.links);
    if direction == Direction::Reverse {
        links.reverse();
    }
    Ok(Route {
        kind: RouteKind::Multihop,
        links,
        cost: segment.cost.saturating_add(peer_link.cost),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::make_node_actor_defexp;
    use crate::visareq_worker::process_visa_request_for_test;
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

    /// A visa request from a connected node on behalf of a policy-declared peer that has not
    /// connected yet is answered from the pre-minted bootstrap visa. Policy cannot answer it:
    /// the peer has no actor and no route, which is exactly what reaching VSAPI would fix.
    #[tokio::test]
    async fn bootstrap_visa_request_for_future_peer_is_allowed() {
        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = Arc::new(build_bootstrap_test_asm(via_node, future_peer).await);
        let (syn_pkt, _reply_pkt) = bootstrap_flow_packets(&asm, &future_peer);

        let visa = match process_visa_request_for_test(asm.clone(), via_node, syn_pkt).await {
            VisaDecision::Allow(visa, _) => visa,
            VisaDecision::Deny(code) => panic!("expected allow, got deny {code:?}"),
        };

        // It is the peer's own visa, held pending-install until the peer connects.
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&future_peer)
            .await
            .unwrap();
        assert_eq!(pending, vec![visa.issuer_id]);
    }

    /// The reply direction gets its own visa. One visa carries one dock PEP and one path
    /// orientation, so the forward visa (`peer -> vs:VSAPI`, pathed peer-first) cannot answer
    /// `vs:VSAPI -> peer`: its PEP would not match the packet and no node on its path would
    /// forward the reply. The reverse visa must be a distinct visa, addressed and pathed the
    /// other way, with the requesting node forwarding towards the peer.
    #[tokio::test]
    async fn bootstrap_visa_reply_direction_gets_its_own_reverse_visa() {
        use zpr::vsapi_types::{DockPepType, EndpointT};

        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = Arc::new(build_bootstrap_test_asm(via_node, future_peer).await);
        let vs_addr = asm.config.get_vs_addr();
        let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);
        let (syn_pkt, reply_pkt) = bootstrap_flow_packets(&asm, &future_peer);

        let syn_visa = match process_visa_request_for_test(asm.clone(), via_node, syn_pkt).await {
            VisaDecision::Allow(visa, _) => visa,
            VisaDecision::Deny(code) => panic!("expected allow for SYN direction, got {code:?}"),
        };
        let reply_visa = match process_visa_request_for_test(asm.clone(), via_node, reply_pkt).await
        {
            VisaDecision::Allow(visa, _) => visa,
            VisaDecision::Deny(code) => panic!("expected allow for reply direction, got {code:?}"),
        };

        assert_ne!(
            reply_visa.issuer_id, syn_visa.issuer_id,
            "the reply direction needs its own visa, not the forward one"
        );

        // The dock PEP must describe the reply packet: vs:VSAPI -> peer:any, server side.
        let dock_pep = reply_visa.dock_pep.expect("reverse visa must be full");
        assert_eq!(dock_pep.source_addr, vs_addr);
        assert_eq!(dock_pep.dest_addr, future_peer);
        match dock_pep.pep {
            DockPepType::TCP(tpep) => {
                assert_eq!(tpep.source_port, vsapi_port);
                assert_eq!(tpep.dest_port, 0, "reply direction allows any dest port");
                assert_eq!(tpep.endpoint, EndpointT::Server);
            }
            other => panic!("expected a TCP dock PEP, got {other:?}"),
        }

        // The requesting node is where the reply ingresses, so it must forward to the peer.
        let fwd_pep = reply_visa
            .fwd_pep
            .expect("reply ingress node needs a forwarding PEP towards the peer");
        assert_eq!(fwd_pep.next_hop, future_peer);

        // Both directions are held for the peer until it connects.
        let mut pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&future_peer)
            .await
            .unwrap();
        pending.sort();
        let mut expected = vec![syn_visa.issuer_id, reply_visa.issuer_id];
        expected.sort();
        assert_eq!(pending, expected);
    }

    /// The bootstrap route is the joiner's own link to the relay, in both directions. Before
    /// zl-zipline#221 it could also run on from a non-relay neighbour to the docking node;
    /// that join path is gone (see `no_bootstrap_visas_through_a_neighbour_that_is_not_the_relay`).
    #[tokio::test]
    async fn bootstrap_visa_route_is_the_peers_link_to_the_relay() {
        let relay: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // docks the VS
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();
        let asm = Arc::new(build_bootstrap_test_asm(relay, future_peer).await);
        let (syn_pkt, reply_pkt) = bootstrap_flow_packets(&asm, &future_peer);

        for (pkt, what) in [(syn_pkt, "SYN"), (reply_pkt, "reply")] {
            let route = match process_visa_request_for_test(asm.clone(), relay, pkt).await {
                VisaDecision::Allow(_, route) => route,
                VisaDecision::Deny(code) => panic!("expected allow for {what}, got {code:?}"),
            };
            assert!(
                matches!(route.kind, RouteKind::Multihop),
                "the peer's own link is always crossed, so this is never a direct route"
            );
            assert_eq!(
                route.links,
                vec![LinkId("link-vp".into())],
                "{what}: only the peer's link"
            );
            assert_eq!(route.cost, 1, "{what}: one policy link");
        }
    }

    /// A topology send carries both directions of the peer's VSAPI flow, and re-sending
    /// topology reuses them rather than minting a fresh pair every heartbeat.
    #[tokio::test]
    async fn topology_send_carries_both_bootstrap_directions_and_dedups() {
        use zpr::vsapi_types::DockPepType;

        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = Arc::new(build_bootstrap_test_asm(via_node, future_peer).await);
        let vs_addr = asm.config.get_vs_addr();
        let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);

        let visas = visas_for_link(&asm, &asm.policy_mgr.get_current(), &future_peer, &via_node)
            .await
            .unwrap();
        assert_eq!(visas.len(), 2, "one visa per direction of the flow");
        assert_ne!(
            visas[0].issuer_id, visas[1].issuer_id,
            "the two directions are distinct visas"
        );

        // The dock PEPs are the two orientations, with the wildcard on the peer's side: it is
        // the client, so its port is unknown until it picks one.
        let peps: Vec<_> = visas
            .iter()
            .map(|v| {
                let pep = v.dock_pep.as_ref().expect("bootstrap visas are full visas");
                let DockPepType::TCP(tpep) = &pep.pep else {
                    panic!("expected a TCP dock PEP, got {:?}", pep.pep)
                };
                (
                    pep.source_addr,
                    tpep.source_port,
                    pep.dest_addr,
                    tpep.dest_port,
                )
            })
            .collect();
        assert_eq!(
            peps,
            vec![
                (future_peer, 0, vs_addr, vsapi_port),
                (vs_addr, vsapi_port, future_peer, 0),
            ],
            "the peer's SYN to VSAPI, then the visa service's reply"
        );

        // Both are held for the peer until it connects, and a second send reuses them.
        let mut pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&future_peer)
            .await
            .unwrap();
        pending.sort();
        let mut ids: Vec<u64> = visas.iter().map(|v| v.issuer_id).collect();
        ids.sort();
        assert_eq!(pending, ids);

        let resent = visas_for_link(&asm, &asm.policy_mgr.get_current(), &future_peer, &via_node)
            .await
            .unwrap();
        let mut resent_ids: Vec<u64> = resent.iter().map(|v| v.issuer_id).collect();
        resent_ids.sort();
        assert_eq!(
            resent_ids, ids,
            "re-sending topology must not mint duplicates"
        );
    }

    /// A topology send to a node whose peer has already connected carries no bootstrap visas.
    /// Minting them is not merely redundant: here the connected peer is also the node the visa
    /// service docks on, so the peer's path would run back through itself
    /// (`[peer, via_node, peer]`) and stage `via_node` a forwarding-only visa for a flow it is
    /// an endpoint of -- which its dataplane rejects.
    #[tokio::test]
    async fn no_bootstrap_visas_for_an_already_connected_peer() {
        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let peer: IpAddr = "fd5a:5052:3000::2".parse().unwrap(); // connected, docks the VS

        let asm = build_bootstrap_test_asm(via_node, peer).await;
        asm.topo_mgr.add_node(peer).unwrap();
        asm.topo_mgr
            .add_link(via_node, peer, LinkId("link-vp".into()), vec![], 1)
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp(&peer.to_string(), "peer-node", "10.0.0.2:5001"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr.hack_set_vs_docking_node(&peer).await.unwrap();
        let asm = Arc::new(asm);

        assert!(
            visas_for_link(&asm, &asm.policy_mgr.get_current(), &peer, &via_node)
                .await
                .unwrap()
                .is_empty(),
            "a connected peer needs no bootstrap visas"
        );
        assert!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&via_node)
                .await
                .unwrap()
                .is_empty(),
            "nothing may be staged for the relaying node either"
        );
    }

    /// A connected peer's VSAPI traffic is not a bootstrap request: it has an actor, so it
    /// goes through policy like anything else.
    #[tokio::test]
    async fn bootstrap_visa_request_declined_for_connected_peer() {
        let via_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();

        let asm = build_bootstrap_test_asm(via_node, peer).await;
        // The peer is connected now, so it has an actor.
        let peer_actor = make_node_actor_defexp(&peer.to_string(), "peer-node", "10.0.0.7:5001");
        asm.actor_mgr
            .add_node(&peer_actor, false, &Default::default())
            .await
            .unwrap();
        let asm = Arc::new(asm);
        let (syn_pkt, _reply_pkt) = bootstrap_flow_packets(&asm, &peer);

        // Reaches policy evaluation (which has no matching comm policy) rather than being
        // short-circuited into an allow.
        assert!(
            matches!(
                process_visa_request_for_test(asm, via_node, syn_pkt).await,
                VisaDecision::Deny(_)
            ),
            "a connected peer must not get a bootstrap visa"
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
        )
        .await
        .unwrap();
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
        )
        .await
        .unwrap();
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
                .await
                .unwrap()
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

    /// Bootstrap visas go only to the node the visa service docks on -- the relay (plan §5.6,
    /// operator pd g44 q3). A connected node that is not the relay but is declared to link
    /// with an unconnected peer (an endpoint with a direct link to a laptop that has not
    /// joined yet) gets neither the pushed visas nor the pulled ones: carrying the joiner's
    /// VSAPI traffic would make it a transit node.
    #[tokio::test]
    async fn no_bootstrap_visas_through_a_neighbour_that_is_not_the_relay() {
        let endpoint: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, not the relay
        let relay: IpAddr = "fd5a:5052:3000::9".parse().unwrap(); // connected, docks the VS
        let joiner: IpAddr = "fd5a:5052:3000::7".parse().unwrap(); // no actor, no route
        let asm = build_bootstrap_test_asm(endpoint, joiner).await;
        asm.topo_mgr.add_node(relay).unwrap();
        asm.topo_mgr
            .add_link(endpoint, relay, LinkId("link-er".into()), vec![], 1)
            .unwrap();
        asm.actor_mgr
            .hack_set_vs_docking_node(&relay)
            .await
            .unwrap();
        let asm = Arc::new(asm);

        assert!(
            visas_for_link(&asm, &asm.policy_mgr.get_current(), &joiner, &endpoint)
                .await
                .unwrap()
                .is_empty(),
            "a non-relay neighbour must not be pushed bootstrap visas"
        );
        assert!(
            asm.visa_mgr
                .get_pending_visa_ids_for_node(&joiner)
                .await
                .unwrap()
                .is_empty(),
            "nothing may be minted for the joiner on a non-relay link"
        );
        let (syn_pkt, reply_pkt) = bootstrap_flow_packets(&asm, &joiner);
        for pkt in [syn_pkt, reply_pkt] {
            assert!(
                matches!(
                    process_visa_request_for_test(asm.clone(), endpoint, pkt).await,
                    VisaDecision::Deny(_)
                ),
                "a non-relay neighbour must not pull a bootstrap visa"
            );
        }
    }

    /// CN-mismatch guard (zl-zipline#221): with two joiners behind the relay, each link's
    /// bootstrap visas belong to that link's own peer -- the one its `zprAddr` and `peerCn`
    /// name -- so the relay can bind them to the link whose certificate carries that CN, and
    /// no joiner's visas ever ride on another joiner's link.
    #[tokio::test]
    async fn bootstrap_visas_ride_only_on_their_own_peers_link() {
        let relay: IpAddr = "fd5a:5052:3000::1".parse().unwrap(); // connected, docks the VS
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
        let links = crate::vss_worker::topology_links(
            &asm,
            &asm.policy_mgr.get_current(),
            &relay,
            resolved_peers(&asm, &relay),
        )
        .await
        .unwrap();
        assert_eq!(links.len(), 2);
        for link in &links {
            let expected_cn = if link.zpr_addr == a { "a.zpr" } else { "b.zpr" };
            assert_eq!(
                link.peer_cn, expected_cn,
                "link {} names the wrong CN",
                link.link_id
            );
            assert_eq!(link.visas.len(), 2, "both directions for {}", link.zpr_addr);
            for visa in &link.visas {
                let pep = visa
                    .dock_pep
                    .as_ref()
                    .expect("bootstrap visas are full visas");
                assert!(
                    pep.source_addr == link.zpr_addr || pep.dest_addr == link.zpr_addr,
                    "visa {} on the link to {} is for another peer",
                    visa.issuer_id,
                    link.zpr_addr
                );
            }
        }
    }
}
