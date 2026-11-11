//! Manage the creating, storage and retrieval of visas for the visa service.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, warn};

use crate::assembly::Assembly;
use crate::config;
use crate::db;
use crate::db::VisaMetadata;
use crate::error::{ServiceError, StoreError};
use crate::logging::targets::VISA;
use crate::packet::make_fivetuple_tcp;
use crate::policy_mgr::PolicySnapshot;
use crate::visa_bootstrap::{BOOTSTRAP_VISA_ZPL, path_for_future_peer};
use crate::visa_policy::{
    PolicyOutcome, docking_node_for_addr, evaluate_against_policy, route_for_allow,
};
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

use libeval::eval_result::{Direction, Hit};
use libeval::policy::Policy;
use libeval::route::{NodeId, Route};
use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, DockPepType, EndpointT, FwdPep, FwdPepStyle, IcmpPep, KeySet, PacketDesc,
    TcpUdpPep, Visa, VisaType, VsapiFiveTuple,
};

use tracing::info;

#[derive(Clone)]
pub struct VisaMgr {
    repo: db::VisaRepo,
    /// Serializes the check-then-create in [VisaMgr::vsapi_bootstrap_visa_for_future_peer].
    /// Behind an `Arc` so every clone of the manager shares the one lock.
    bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
}

pub struct VisaWithMetadata {
    pub visa: Visa,
    pub metadata: db::VisaMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VCtx {
    Ingress,
    Intermediary,
    Egress,
}

/// Outcome of re-checking an existing visa against a newer policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisaRecheck {
    /// An actor could not be resolved; skip without bumping `checked_vinst`.
    SkipUnresolvedActor,
    /// Still allowed and the selected route is unchanged.
    AllowSameRoute,
    /// Denied, or allowed but the selected route changed -- revoke.
    Revoke,
}

/// Node path for `route` in flow order: the node the packets enter the fabric at first,
/// then every node they traverse, ending at the node serving the destination. `None` for a
/// direct route -- nothing is forwarded, so there is no path worth recording.
///
/// Anchored on the docking node of `source_addr` (the actor sending the packets this visa
/// authorizes), NOT on the node that asked for the visa. Those coincide for an ordinary
/// request -- a node asks about a packet its own docked actor sent -- but not for visas the
/// visa service mints pre-emptively on another node's behalf, e.g.
/// [VisaMgr::post_register_vss_visas_for_node]. Actualization reads each node's role
/// straight off this ordering, so getting the anchor wrong hands the destination node a
/// next hop pointing back the way the packets came.
///
/// Mirrors exactly what `create_visa` stores in `metadata.path`, so a re-derived path can
/// be compared against a stored one.
async fn path_for_flow(
    asm: &Assembly,
    source_addr: &IpAddr,
    route: &Route,
) -> Result<Option<Vec<IpAddr>>, ServiceError> {
    if !matches!(route.kind, libeval::route::RouteKind::Multihop) {
        return Ok(None);
    }
    let Some(ingress) = docking_node_for_addr(asm, source_addr).await else {
        return Err(ServiceError::Internal(format!(
            "cannot orient visa path: source {source_addr} is not docked to any node"
        )));
    };
    let node_id_path = asm.topo_mgr.route_to_path(route, &NodeId(ingress))?;
    Ok(Some(node_id_path.into_iter().map(|id| id.into()).collect()))
}

/// Node path a future peer's VSAPI traffic will take: the peer itself, then `via_node`
/// (the neighbour carrying the peer's topology message, hence its first hop), then
/// `via_node`'s route to the node the visa service docks on.
///
/// The peer's own link is not in the router yet -- it only comes up when the peer
/// connects -- so the first hop is stitched on from the peering rather than routed.
/// True if the visa's dock PEP is for exactly this five-tuple: both addresses and both TCP
/// ports. A visa with no dock PEP cannot match -- only full visas are stored, so that is a bug
/// worth logging.
fn dock_pep_matches_five_tuple(visa: &Visa, ft: &VsapiFiveTuple) -> bool {
    let Some(dock_pep) = visa.dock_pep.as_ref() else {
        warn!(target: VISA, "found visa in store with no dock_pep ID={}", visa.issuer_id);
        return false;
    };
    if dock_pep.source_addr != ft.source_addr || dock_pep.dest_addr != ft.dest_addr {
        return false;
    }
    match &dock_pep.pep {
        DockPepType::TCP(tpep) => {
            tpep.dest_port == ft.dest_port && tpep.source_port == ft.source_port
        }
        _ => false,
    }
}

/// The node `node_addr` hands off to on `path`, given that it is one of the path's two ends.
/// `None` if it is not an end (an intermediary has two neighbours, so the question is
/// ambiguous). Bootstrap dedup asks "does this visa use the peer's link to that relay?", and
/// the peer is always an end, so this answers it whichever way the path is oriented.
fn path_neighbour_of_endpoint(path: &[IpAddr], node_addr: &IpAddr) -> Option<IpAddr> {
    if path.first()? == node_addr {
        path.get(1).copied()
    } else if path.last()? == node_addr {
        path.get(path.len().checked_sub(2)?).copied()
    } else {
        None
    }
}

impl VisaWithMetadata {
    pub fn new(visa: Visa, metadata: db::VisaMetadata) -> Self {
        VisaWithMetadata { visa, metadata }
    }
}

impl VisaMgr {
    pub fn new(db: db::VisaRepo) -> Self {
        VisaMgr {
            repo: db,
            bootstrap_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// To "actualize" a visa means to adjust it for the context in which it is deployed.
    /// The contexts are:
    /// - On an ingress node we send a full visa which may also have forwarding instuctions
    ///   when there are links that need to be traversed.
    /// - On an intermediary node we send a very truncated visa: just the ID and forwarding
    ///   instructions.
    /// - On an egress node we send a full visa, no forwarding info.
    ///
    pub async fn actualize_visa_for_target_node(
        &self,
        mut visa: Visa,
        target_node: &IpAddr,
    ) -> Result<Visa, ServiceError> {
        let md = self.repo.get_visa_metadata_by_id(visa.issuer_id)?;

        let Some(path) = md.path.as_ref() else {
            return Ok(visa);
        };
        if path.len() < 2 {
            // should not happen but just in case, treat as no path.
            return Ok(visa);
        }

        // The path is in flow order (see [path_for_flow]), so a node's role is its position
        // on it: packets enter at the front and leave at the back. Deliberately NOT keyed off
        // `md.requesting_node` -- the requester is not always the ingress node, and treating
        // it as one told the destination node to forward the flow back towards its source.
        let vctx = if path.first().unwrap() == target_node {
            VCtx::Ingress
        } else if path.last().unwrap() == target_node {
            VCtx::Egress
        } else {
            VCtx::Intermediary
        };

        match vctx {
            // The flow terminates here, so there is nothing to forward: full visa as-is.
            VCtx::Egress => Ok(visa),

            // Both other roles forward one hop further along the path -- given [A, B, C, D],
            // A forwards to B, B to C, C to D. Only the visa contents differ: the ingress
            // node also docks the flow, an intermediary purely relays it.
            VCtx::Ingress | VCtx::Intermediary => {
                let Some(next_hop) = next_hop_in_path(path, target_node) else {
                    error!(target: VISA, "error actualizing visa for node {target_node} on path {path:?}: no next_hop found");
                    return Err(ServiceError::Internal(format!("failed to actualize visa")));
                };
                let fpep = FwdPep {
                    next_hop: *next_hop,
                    style: FwdPepStyle::OneWay, // TODO: Not sure when to set this to symmetric.
                };
                if vctx == VCtx::Ingress {
                    visa.fwd_pep = Some(fpep);
                    Ok(visa)
                } else {
                    Ok(to_forwarding_visa(visa, fpep))
                }
            }
        }
    }

    /// Used when a node has already connected to the VS via the VSAPI and has called
    /// `register_vss`.
    ///
    /// Creates visas for:
    /// - allow visa service to talk to node VSS.
    ///
    /// `node_addr` - The node, already connected and has just called `register_vss` over
    /// VSAPI.  The idea is that the VS is next going to open a connection back to the node's
    /// VSS so this can preempt the visa request.
    ///
    /// The visas returned here are any pending visas that should be installed on the
    /// node `node_addr` which has just called to initialize vss.  If there are intermediary
    /// nodes between the VS and `node_addr` those other visas are also created and set
    /// PENDING on the relevant nodes -- but are not returned here.
    ///
    pub async fn post_register_vss_visas_for_node(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let mut visas = Vec::new();

        // Start with any visas that may already be pending.
        if let Ok(pendings) = self.get_pending_visas_for_node(node_addr).await {
            for v in pendings {
                let av = self.actualize_visa_for_target_node(v, node_addr).await?;
                visas.push(av);
            }
        }

        // The node may be reconnecting, in which case it may already have the core visas installed.
        let vs_node_ft = make_fivetuple_tcp(
            asm.config.get_vs_addr(),
            node_addr.clone(),
            0,
            vss_addr.port(),
        )?;
        let has_vs_to_node_visa = self
            .get_node_visa_by_five_tuple(node_addr, &vs_node_ft)
            .await?
            .is_some();

        if !has_vs_to_node_visa {
            let cres = self
                .create_vs_to_node_vss_visa(asm.clone(), node_addr, vss_addr.port())
                .await?;
            let cres = self.actualize_visa_for_target_node(cres, node_addr).await?;
            visas.push(cres);
        } else {
            debug!(
                target: VISA,
                "node {node_addr} already has VS->VSS visa installed, skipping creation"
            );
        }
        Ok(visas)
    }

    /// Mint (or reuse) one direction of the bootstrap flow that lets a not-yet-connected peer
    /// reach the visa service's VSAPI port, which is how it connects in the first place.
    ///
    /// The rest of the bootstrap machinery lives in [crate::visa_bootstrap]; only the minting
    /// is here, because it needs this module's private store and lookup helpers.
    ///
    /// The visa belongs to `future_peer` and is stored pending-install against it.
    /// `via_node` is the already-connected neighbour whose topology message carries the
    /// copy handed off when the peer shows up; it is also the peer's first hop, so the
    /// path is anchored on it (see [crate::visa_bootstrap::path_for_future_peer]).
    ///
    /// `direction` picks which half of the flow this visa is for. A visa carries exactly one
    /// dock PEP and one path orientation, so the two halves cannot share one:
    /// - [Direction::Forward] is the peer's own SYN, `peer:any -> vs:VSAPI`, ingressing at the
    ///   peer and forwarded towards the node the visa service docks on.
    /// - [Direction::Reverse] is the visa service's reply, `vs:VSAPI -> peer:any`, ingressing
    ///   at the docking node and forwarded towards the peer.
    ///
    /// Call it once per direction: with only the forward visa the reply is dropped, because no
    /// dock PEP matches it and no node on the forward path has a route back.
    ///
    /// This deliberately bypasses policy evaluation. The peer cannot be evaluated --
    /// it has no actor and no route until the link comes up -- and it needs none: a
    /// peering declared in policy *is* the authorization for that peer to reach VSAPI.
    ///
    /// `policy` is the caller's view, not a fresh read: the peering that authorizes this
    /// visa was selected by the caller from that same view, so the generation recorded on
    /// the visa has to come from it too, or a policy install landing mid-call stamps the
    /// visa with a generation that never authorized it.
    ///
    /// TODO: Added as a HACK to get initial MULTINODE working. Should be re-evaluated later.
    /// See: https://github.com/org-zpr/zpr-visaservice/issues/301
    pub async fn vsapi_bootstrap_visa_for_future_peer(
        &self,
        asm: &Assembly,
        policy: &Arc<Policy>,
        future_peer: &IpAddr,
        via_node: &IpAddr,
        direction: Direction,
    ) -> Result<Visa, ServiceError> {
        let vs_addr = asm.config.get_vs_addr();
        let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);
        // The wildcard port sits on the peer's side in both cases: it is the client, so its
        // port is unknown until it picks one. This is also what `create_visa_with_path`
        // derives for a BiDirectional packet in each direction, so the dedup lookup below
        // compares equal to what was stored.
        let ft = match direction {
            Direction::Forward => make_fivetuple_tcp(*future_peer, vs_addr, 0, vsapi_port)?,
            Direction::Reverse => make_fivetuple_tcp(vs_addr, *future_peer, vsapi_port, 0)?,
        };
        // One neighbour can mint for the same peer from several places concurrently -- its
        // topology sends (the policy-update fan-out, or every worker's initial sync after a VS
        // restart) and a visa request pulling the visa. Without this the lookup below and the
        // create further down interleave across their DB awaits and both mint, producing two
        // visas with different IDs for one (peer, via_node).
        //
        // NOTE: Using one global lock, not per-peer -- bootstrap minting only happens while a
        // peer is unconnected. (Switch to per-peer if this ever lands on a hot path.)
        let _guard = self.bootstrap_lock.lock().await;

        // A bootstrap visa is delivered inside a neighbour's topology message, so it stays
        // PendingInstall until `future_peer` itself connects and its own worker pushes it.
        // Match on that state too, otherwise every set_topology mints a duplicate.
        //
        // Dedup is per (peer, via_node), not per five-tuple: the path is baked into the visa,
        // so a peer with two connected neighbours needs one visa per neighbour. Sharing one
        // would leave the second neighbour off the visa's path -- its own copy could not be
        // actualized, and the peer's copy would forward over the wrong link.
        if let Some(visa) = self
            .find_node_visa_by_five_tuple(
                future_peer,
                &ft,
                &[
                    db::NodeVisaState::Installed,
                    db::NodeVisaState::PendingInstall,
                ],
                Some(via_node),
            )
            .await?
        {
            Ok(visa)
        } else {
            let pkt_data = PacketDesc {
                five_tuple: ft,
                comm_flags: CommFlag::BiDirectional,
            };

            // The path cannot be routed -- the peer's link is not up -- so hand it in
            // explicitly. It has to be there: without it the peer's copy gets no fwd_pep
            // and the relaying nodes get no copy at all, leaving the visa unusable.
            //
            // The path and the recorded generation come from different places on purpose.
            // Everything policy-derived -- the peering that authorizes this visa, its
            // link_id and cost, the generation stamped below -- comes from the caller's
            // `policy`, so one mint cannot straddle two policy installs. The path is read
            // live from the router instead, and has to be: actualization pushes a copy to
            // every node on it, so it must name nodes whose links are actually up. A
            // `PolicySnapshot` carries no topology at all (see `policy_mgr::PolicyState`),
            // so there is no snapshot to take the path from.
            let hit = Hit::new_no_signal(0, direction);
            // [path_for_future_peer] is peer-first, which is the forward flow's orientation. The
            // reply ingresses at the other end, so flip it: actualization decides each node's
            // role from the path plus the ingress node, and `path[0]` is that node either way.
            let mut path = path_for_future_peer(asm, future_peer, via_node)?;
            if direction == Direction::Reverse {
                path.reverse();
            }
            let ingress_node = path[0]; // path_for_future_peer is never empty

            let visawmd = self
                .create_visa_with_path(
                    asm,
                    &ingress_node,
                    &pkt_data,
                    &hit,
                    Some(path),
                    BOOTSTRAP_VISA_ZPL,
                    policy.get_version().unwrap_or(0),
                    policy.vinst(),
                    SystemTime::now() + config::MAX_VISA_LIFETIME,
                )
                .await?;
            Ok(visawmd.visa)
        }
    }

    /// Find a visa *installed* on the node matching the given five-tuple.
    pub async fn get_node_visa_by_five_tuple(
        &self,
        node_addr: &IpAddr,
        ft: &VsapiFiveTuple,
    ) -> Result<Option<Visa>, ServiceError> {
        self.find_node_visa_by_five_tuple(node_addr, ft, &[db::NodeVisaState::Installed], None)
            .await
    }

    /// Use a linear search of the node's visas in any of `states` to find a five-tuple match.
    ///
    /// `relay`, when given, additionally requires the visa's path to put that node next to
    /// `node_addr`. A five-tuple match alone is ambiguous once the path matters: a node with
    /// several links needs one visa per link for the same flow, because each visa carries a
    /// single path.
    ///
    /// TODO: Need in-memory indexes for this.
    async fn find_node_visa_by_five_tuple(
        &self,
        node_addr: &IpAddr,
        ft: &VsapiFiveTuple,
        states: &[db::NodeVisaState],
        relay: Option<&IpAddr>,
    ) -> Result<Option<Visa>, ServiceError> {
        for state in states {
            for visa in self.repo.get_visas_for_node_by_state(node_addr, *state)? {
                if !dock_pep_matches_five_tuple(&visa, ft) {
                    continue;
                }
                if let Some(relay) = relay {
                    let md = self.repo.get_visa_metadata_by_id(visa.issuer_id)?;
                    let neighbour = md
                        .path
                        .as_ref()
                        .and_then(|p| path_neighbour_of_endpoint(p, node_addr));
                    if neighbour.as_ref() != Some(relay) {
                        continue;
                    }
                }
                return Ok(Some(visa));
            }
        }
        Ok(None)
    }

    /// Ask policy for a visa permitting this visa service to talk to the given node VSS addr.
    /// Creating the visa has the side effect of storing it and marking it PENDING on every
    /// node along the path.
    ///
    /// `node_addr` - node ZPR address hosting the VSS.
    ///
    /// `node_addr` is passed as the requesting node even though the flow runs the other way:
    /// it is the node whose reply carries the visa (see
    /// [VisaMgr::post_register_vss_visas_for_node]), and that is all `requesting_node` still
    /// selects -- who is excluded from the background push. Path geometry comes from the
    /// flow's source instead, see [path_for_flow].
    async fn create_vs_to_node_vss_visa(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_port: u16,
    ) -> Result<Visa, ServiceError> {
        // TODO: We may have this visa on hand already, if so return it and do not re-generate.

        let pkt_data =
            PacketDesc::new_tcp_with_addr(asm.config.get_vs_addr(), *node_addr, 0, vss_port)?;

        // TODO: This call to return a FULL visa plus Route info.
        // then we need to do some work.
        self.create_visa_for_packet(asm, pkt_data, node_addr).await
    }

    /// `requesting_node_addr` - The visa is created as if this node has requested it.
    ///
    /// The returned visa is a full visa (TODO: return route info).
    /// The visa needs to be crunched through PATH to determine what is sent to `requesting_node_addr` node.
    async fn create_visa_for_packet(
        &self,
        asm: Arc<Assembly>,
        pkt_data: PacketDesc,
        requesting_node_addr: &IpAddr,
    ) -> Result<Visa, ServiceError> {
        // This will end up calling into `create_visa` which means we get a route
        // and state will have been updated if any visas need to be sent to nodes.
        //
        // When it comes time to actually deliver a visa to a node
        // we can use the PATH to create correct visa contents. The visa stored in state
        // by ID is the FULL visa.
        //
        match request_visa_wait_response(
            &asm,
            requesting_node_addr,
            pkt_data,
            config::DEFAULT_VISA_REQ_TIMEOUT,
        )
        .await
        {
            Ok(VisaDecision::Allow(visa, _route)) => Ok(visa), // TODO: do something with the route
            Ok(VisaDecision::Deny(dcode)) => Err(ServiceError::VisaDenied(dcode.to_string())),
            Err(e) => Err(e),
        }
    }

    /// Placeholder implementation, called concurrently.
    /// Called after making use of libeval to check policy.
    /// No checking to see if visa already exists.
    /// Fake keys.
    ///
    /// Note that visa state with respect to the requesting node is set to PENDING_INSTALL.
    ///
    /// A path is created from the route using the direction inforation in the hit.
    ///
    /// This returns a FULL visa.
    pub async fn create_visa(
        &self,
        asm: &Assembly,
        requesting_node: &IpAddr,
        pdesc: &PacketDesc,
        hit: &Hit,
        route: &Route,
        source_zpl: impl Into<String>,
        policy_version: u64,
        vinst: u64,
        expiration_time: SystemTime,
    ) -> Result<VisaWithMetadata, ServiceError> {
        let path = path_for_flow(asm, &pdesc.five_tuple.source_addr, route).await?;
        let vwmd = self
            .create_visa_with_path(
                asm,
                requesting_node,
                pdesc,
                hit,
                path,
                source_zpl,
                policy_version,
                vinst,
                expiration_time,
            )
            .await?;

        // A link on the route may have gone down after the route was chosen and before
        // the visa was stored (zl-zipline#224). The link-down revocation pass lists the
        // visas that were stored when it ran, so it can miss this one. Check now that
        // the visa is committed: if the link went down before this check, the check
        // catches it; if it goes down after, the revocation pass finds the visa stored.
        if !asm.topo_mgr.route_links_up(&route.links) {
            let visa_id = vwmd.visa.issuer_id;
            warn!(target: VISA, "visa {visa_id}: a link on its route went down while it was issued; revoking it");
            if let Err(e) = self.mark_visa_revoked(visa_id).await {
                warn!(target: VISA, "visa {visa_id}: failed to revoke after its route went down: {e}");
            }
        }
        Ok(vwmd)
    }

    /// As [VisaMgr::create_visa], but with the node path supplied rather than derived from
    /// a route. For visas whose path cannot be routed -- see
    /// [VisaMgr::vsapi_bootstrap_visa_for_future_peer].
    async fn create_visa_with_path(
        &self,
        asm: &Assembly,
        requesting_node: &IpAddr,
        pdesc: &PacketDesc,
        hit: &Hit,
        path: Option<Vec<IpAddr>>,
        source_zpl: impl Into<String>,
        policy_version: u64,
        vinst: u64,
        expiration_time: SystemTime,
    ) -> Result<VisaWithMetadata, ServiceError> {
        let (source_port, dest_port) = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP | ip_proto::UDP => {
                if pdesc.comm_flags == CommFlag::BiDirectional {
                    match hit.direction {
                        Direction::Forward => {
                            // client->server, allow any source port.
                            (0, pdesc.five_tuple.dest_port)
                        }
                        Direction::Reverse => {
                            // server->client, allow any dest port.
                            (pdesc.five_tuple.source_port, 0)
                        }
                    }
                } else {
                    // unidirectional, exact ports.
                    // TODO: What is ReRequest flag?
                    (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
                }
            }
            ip_proto::IPV6_ICMP => {
                // icmp type/code in ports
                (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
            }
            _ => {
                return Err(ServiceError::Internal(format!(
                    "unsupported protocol for visa: {}",
                    pdesc.five_tuple.l4_protocol
                )));
            }
        };

        let pep = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP => DockPepType::TCP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::UDP => DockPepType::UDP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::IPV6_ICMP => {
                DockPepType::ICMP(IcmpPep::new(source_port as u8, dest_port as u8))
            }

            _ => unreachable!(), // already handled above
        };

        let visa_id = self.repo.get_next_visa_id().await?;

        let mut metadata = db::VisaMetadata::new(
            requesting_node.clone(),
            policy_version,
            vinst,
            source_zpl.into(),
            hit.direction,
            path,
            pdesc,
        );
        if let Some(sig) = hit.signal.as_ref() {
            metadata.signal_msgs.push(sig.message.clone());
        }

        let mut ingress_key = a2a_dh_pubkey_bytes(asm, &pdesc.five_tuple.source_addr).await?;
        let mut egress_key = a2a_dh_pubkey_bytes(asm, &pdesc.five_tuple.dest_addr).await?;

        if ingress_key.is_empty() || egress_key.is_empty() {
            ingress_key.clear();
            egress_key.clear();
        }

        let pep = DockPep {
            pep,
            source_addr: pdesc.five_tuple.source_addr.clone(),
            dest_addr: pdesc.five_tuple.dest_addr.clone(),
            session_key: KeySet::new(&ingress_key, &egress_key),
        };

        let visa = Visa {
            issuer_id: visa_id,
            config: 0,
            expires: expiration_time,
            visa_type: VisaType::Full,
            dock_pep: Some(pep),
            fwd_pep: None,
            cons: None,
        };

        // The store also updates the visa state along the path.
        self.repo
            .store_visa(&visa, metadata.clone(), db::NodeVisaState::PendingInstall)
            .await?;

        info!("created visa {visa_id}");
        Ok(VisaWithMetadata::new(visa, metadata))
    }

    pub async fn get_pending_visas_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let visas = self
            .repo
            .get_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)?;
        Ok(visas)
    }

    pub async fn get_pending_visa_ids_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self
            .repo
            .get_visa_ids_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)?;
        Ok(visa_ids)
    }

    pub async fn get_installed_visa_ids_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self
            .repo
            .get_visa_ids_for_node_by_state(node_addr, db::NodeVisaState::Installed)?;
        Ok(visa_ids)
    }

    pub async fn get_num_pending_install_visas(
        &self,
        node_addr: &IpAddr,
    ) -> Result<u32, ServiceError> {
        let pending_revokes = self
            .repo
            .get_count_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)?;
        Ok(pending_revokes)
    }

    pub async fn get_num_pending_revoked_visas(
        &self,
        node_addr: &IpAddr,
    ) -> Result<u32, ServiceError> {
        let pending_revokes = self
            .repo
            .get_count_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingRevoke)?;
        Ok(pending_revokes)
    }

    /// Register that visa `visa_id` has been installed on node at ZPR address
    /// `node_addr`.
    ///
    /// This is a CAS (Compare And Swap) `PendingInstall -> Installed`: if the
    /// check-all-visas-due-to-new-policy sweep marked the node `PendingRevoke`
    /// while the push RPC was in flight the transition misses and we leave the
    /// state... so PendingRevoke wins, and housekeeping sends the revoke.
    pub async fn visa_installed(
        &self,
        visa_id: u64,
        node_addr: &IpAddr,
    ) -> Result<(), ServiceError> {
        let applied = self
            .repo
            .transition_node_visa_state(
                *node_addr,
                visa_id,
                db::NodeVisaState::PendingInstall,
                db::NodeVisaState::Installed,
            )
            .await?;
        if !applied {
            // The CAS misses for two very different reasons; say which. An already-Installed
            // or PendingRevoke state is expected (a re-ack, or the sweep won the race), but a
            // node with no entry at all means the visa was never staged for it -- e.g. the
            // node is not on the visa's path, or the stored visa predates it being there.
            match self.repo.get_node_visa_state(visa_id, node_addr) {
                Some(state) => {
                    debug!(target: VISA, "visa {visa_id} install ack for node {node_addr} did not apply: state is {state:?}, not PendingInstall; leaving it")
                }
                None => {
                    warn!(target: VISA, "visa {visa_id} install ack for node {node_addr} did not apply: the visa is not staged for that node at all")
                }
            }
        }
        Ok(())
    }

    /// Snapshot of `(visa_id, metadata)` for all live visas — for the sweep.
    pub async fn list_visa_metadata(&self) -> Vec<(u64, VisaMetadata)> {
        self.repo.list_visa_metadata().await
    }

    /// Apply an allow verdict to a visa at policy generation `vinst`. See [db::VisaRepo::record_allow_verdict].
    pub async fn record_allow_verdict(
        &self,
        visa_id: u64,
        vinst: u64,
    ) -> Result<bool, ServiceError> {
        Ok(self.repo.record_allow_verdict(visa_id, vinst).await?)
    }

    /// Apply a deny verdict to a visa at policy generation `vinst`. See [db::VisaRepo::record_deny_verdict].
    pub async fn record_deny_verdict(
        &self,
        visa_id: u64,
        vinst: u64,
    ) -> Result<bool, ServiceError> {
        Ok(self.repo.record_deny_verdict(visa_id, vinst).await?)
    }

    /// Mark every node of a visa `PendingRevoke` with no policy-generation gate. Used by
    /// the attribute-change sweep, where the policy `vinst` has not moved and so the
    /// verdict recorders would no-op. See [db::VisaRepo::mark_visa_revoked].
    pub async fn mark_visa_revoked(&self, visa_id: u64) -> Result<bool, ServiceError> {
        Ok(self.repo.mark_visa_revoked(visa_id).await?)
    }

    /// Remove a visa entirely (Redis + memory). See [db::VisaRepo::remove_visa].
    pub async fn remove_visa(&self, visa_id: u64) -> Result<(), ServiceError> {
        self.repo.remove_visa(visa_id).await?;
        Ok(())
    }

    /// Check whether a live visa still references any node.
    pub async fn visa_has_node_refs(&self, visa_id: u64) -> bool {
        self.repo.visa_has_node_refs(visa_id).await
    }

    /// The visa IDs for a node currently marked `PendingRevoke`.
    pub async fn get_pending_revoke_visa_ids_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let ids = self
            .repo
            .get_visa_ids_for_node_by_state(node_addr, db::NodeVisaState::PendingRevoke)?;
        Ok(ids)
    }

    /// Post-ack VSS revoke teardown, keeping the two-step ordering in one place: drop
    /// the node from the record if it is still `PendingRevoke`, then remove the
    /// whole visa once no node references remain.
    pub async fn revoke_acked(&self, node_addr: IpAddr, visa_id: u64) {
        if let Err(e) = self
            .repo
            .remove_node_if_pending_revoke(node_addr, visa_id)
            .await
        {
            warn!(target: VISA, "error tearing down revoked node {node_addr} on visa {visa_id}: {e}");
            return;
        }
        if !self.visa_has_node_refs(visa_id).await {
            if let Err(e) = self.remove_visa(visa_id).await {
                warn!(target: VISA, "error removing orphaned visa {visa_id}: {e}");
            }
        }
    }

    /// Re-evaluate an existing visa against the given policy snapshot. Rebuilds
    /// the packet from the stored five-tuple, resolves both actors, and
    /// delegates the eval to the shared `evaluate_against_policy` function.
    ///
    /// Note that AAA-related visas are not re-evaluated by this function.
    /// TODO: Possibly needs more thought for how to deal with cases where an auth service
    /// is removed by policy.
    ///
    /// ### returns
    /// - `SkipUnresolvedActor` = an actor could not be resolved (skip, don't bump)
    /// - `AllowSameRoute` = still allowed on the same route
    /// - `Revoke` = denied, or allowed but the selected route changed. Denial
    ///   already folds in an undocked endpoint or missing route.
    ///
    /// A still-allowed visa whose newly-selected route differs from the stored
    /// `metadata.path` is treated as a revoke: rather than migrate a single visa
    /// id between paths in place, we revoke it and let the next actor comm
    /// install a fresh visa on the current route.
    pub async fn recheck_visa_allowed(
        &self,
        asm: &Assembly,
        metadata: &VisaMetadata,
        psnap: &PolicySnapshot,
    ) -> Result<VisaRecheck, ServiceError> {
        // TODO: comm_flags is not persisted; for now default to BiDirectional.
        let pkt = PacketDesc {
            five_tuple: metadata.five_tuple.clone(),
            comm_flags: CommFlag::BiDirectional,
        };
        let src_zpr = metadata.five_tuple.source_addr;
        let dst_zpr = metadata.five_tuple.dest_addr;

        let (Ok(Some(src)), Ok(Some(dst))) = (
            asm.actor_mgr.get_actor_by_zpr_addr(&src_zpr).await,
            asm.actor_mgr.get_actor_by_zpr_addr(&dst_zpr).await,
        ) else {
            return Ok(VisaRecheck::SkipUnresolvedActor);
        };

        let policy = psnap.policy_arc();
        let (hits, default_route) =
            match evaluate_against_policy(asm, &src, &dst, &src_zpr, &dst_zpr, &pkt, &policy)
                .await?
            {
                PolicyOutcome::Allow {
                    hits,
                    default_route,
                    // The sweep rechecks an existing visa; requester binding was
                    // enforced when it was issued (zipline#183), so the docking
                    // nodes the eval resolved are not re-checked here.
                    ..
                } => (hits, default_route),
                PolicyOutcome::Deny(_) => return Ok(VisaRecheck::Revoke),
            };

        // Still allowed: revoke iff the newly-selected route differs from the
        // stored path. Derive the new path exactly as create_visa did so the
        // comparison is apples-to-apples.
        let route = route_for_allow(&hits, default_route)?;
        match path_for_flow(asm, &src_zpr, &route).await {
            Ok(new_path) if new_path == metadata.path => Ok(VisaRecheck::AllowSameRoute),
            Ok(_) => Ok(VisaRecheck::Revoke),
            // The source's docking node is no longer on the new route (topology
            // moved under us) -- the route definitely changed, so revoke.
            Err(_) => Ok(VisaRecheck::Revoke),
        }
    }

    /// Designed to be used to setup database in clean state as we prepare for a
    /// fresh node joining.
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.repo.clear_node_state(node_addr).await?;
        Ok(())
    }

    /// Remove all visas tied to the given node -- assumes that `node_addr` has departed.
    ///
    /// The node is gone, so for every visa it participates in we mark all as
    /// `PendingRevoke` (VSS housekeeping revokes the visa from the OTHER, live
    /// nodes -- including where the departed node was only a multihop
    /// intermediary), then force-drop the departed node's own refs (it can never
    /// ack a revoke), then remove any visa left with no node refs.
    ///
    /// TODO: This probably needs a lock on the node address -- we do not want the
    /// same node reconnecting while this clean-up runs.
    ///
    /// TODO (reconnect-with-state): this wipes the node's visa state outright. We
    /// have NOT yet worked out how that interacts with a node reconnecting and
    /// expecting us to re-push its previously-installed visas rather than making
    /// it re-request everything. When that story is settled this teardown likely
    /// needs to preserve or snapshot state instead of dropping it. TBD.
    pub async fn remove_visas_for_node(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        // Capture the referencing visas before clear_node_state unindexes the node.
        let ids = self.repo.get_all_visa_ids_for_node(node_addr)?;

        // 1. Revoke each from the other nodes still holding it. Log-and-continue
        //    so one failure can't strand the rest.
        for &id in &ids {
            if let Err(e) = self.repo.mark_visa_revoked(id).await {
                warn!(target: VISA, "failed to mark visa {id} revoked for departed node {node_addr}: {e}");
            }
        }

        // 2. Force-drop the departed node's own refs in one atomic pass (no RPC).
        self.repo.clear_node_state(node_addr).await?;

        // 3. Remove any visa now orphaned (no node refs) rather than wait for TTL.
        for id in ids {
            if !self.visa_has_node_refs(id).await {
                if let Err(e) = self.remove_visa(id).await {
                    warn!(target: VISA, "failed to remove orphaned visa {id}: {e}");
                }
            }
        }
        Ok(())
    }

    /// Remove all visas tied to the listed actors, assumes the actors have departed.
    ///
    /// For each visa with a departed endpoint we mark every node `PendingRevoke`
    /// so VSS housekeeping revokes it from the nodes still holding it, then
    /// removes the visa on ack. A visa left with no node refs (its only node was
    /// already cleared by `remove_visas_for_node`) is dropped here instead of
    /// waiting for TTL.
    ///
    pub async fn remove_visas_for_actors(
        &self,
        actor_addrs: &[IpAddr],
    ) -> Result<(), ServiceError> {
        if actor_addrs.is_empty() {
            return Ok(());
        }
        for id in self.get_visa_ids_for_actors(actor_addrs).await? {
            // Log-and-continue: one failure must not strand the remaining visas.
            match self.repo.mark_visa_revoked(id).await {
                Ok(true) => {}
                Ok(false) => continue, // vanished/expired between query and mark
                Err(e) => {
                    warn!(target: VISA, "failed to mark visa {id} revoked for departed actor: {e}");
                    continue;
                }
            }
            // No node left to revoke to (purely-local visa already cleared) -> drop now.
            if !self.visa_has_node_refs(id).await {
                if let Err(e) = self.remove_visa(id).await {
                    warn!(target: VISA, "failed to remove orphaned visa {id}: {e}");
                }
            }
        }
        Ok(())
    }

    /// Drop expired visas from the in-memory store. Called by housekeeping.
    pub fn purge_expired_visas(&self) -> Result<(), ServiceError> {
        self.repo.purge_expired()?;
        Ok(())
    }

    /// Get all the visa IDs (non-expired).
    pub async fn list_all_visa_ids(&self) -> Result<Vec<u64>, ServiceError> {
        let visa_ids = self.repo.list_visa_ids()?;
        Ok(visa_ids)
    }

    /// Live visa IDs referencing any of the given actor endpoint addresses.
    pub async fn get_visa_ids_for_actors(
        &self,
        actor_addrs: &[IpAddr],
    ) -> Result<Vec<u64>, ServiceError> {
        Ok(self.repo.get_visa_ids_for_actors(actor_addrs)?)
    }

    /// Shorthand and slightly more race-condition safe way of calling `get_visa_by_id` and `get_visa_metadata_by_id`.
    /// Returns None if either the visa or the metadata is not found.
    pub async fn get_visa_with_metadata_by_id(
        &self,
        visa_id: u64,
    ) -> Result<Option<VisaWithMetadata>, ServiceError> {
        match self.repo.get_visa_by_id(visa_id) {
            Ok(visa) => match self.repo.get_visa_metadata_by_id(visa_id) {
                Ok(md) => Ok(Some(VisaWithMetadata { visa, metadata: md })),
                Err(StoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(ServiceError::from(e)),
            },
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Get just the visa (no metadata) using the visa ID.
    /// Returns None if not found.
    #[allow(dead_code)]
    pub async fn get_visa_by_id(&self, visa_id: u64) -> Result<Option<Visa>, ServiceError> {
        match self.repo.get_visa_by_id(visa_id) {
            Ok(visa) => Ok(Some(visa)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Get just the visa metadata using the visa ID.
    /// Returns None if not found.
    #[allow(dead_code)]
    pub async fn get_visa_metadata_by_id(
        &self,
        visa_id: u64,
    ) -> Result<Option<VisaMetadata>, ServiceError> {
        match self.repo.get_visa_metadata_by_id(visa_id) {
            Ok(md) => Ok(Some(md)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }
}

/// Gets public key as bytes.
/// Returns empty bytes when the actor's key is not found.
async fn a2a_dh_pubkey_bytes(asm: &Assembly, addr: &IpAddr) -> Result<Vec<u8>, ServiceError> {
    match asm.actor_mgr.get_a2a_dh_pubkey_by_zpr_addr(addr).await? {
        Some(key) => Ok(key.public_key),
        None => {
            debug!(target: VISA, "actor {addr} sent no A2A DH public key; visa session key will be empty");
            Ok(Vec::new())
        }
    }
}

fn ep_from_dir(dir: &Direction) -> EndpointT {
    match dir {
        // Matched forward direction: client to server.
        Direction::Forward => EndpointT::Client,

        // Matched reverse direction: server to client.
        Direction::Reverse => EndpointT::Server,
    }
}

fn to_forwarding_visa(mut visa: Visa, fwd_pep: FwdPep) -> Visa {
    visa.visa_type = VisaType::ForwardOnly;
    visa.dock_pep = None;
    visa.fwd_pep = Some(fwd_pep);
    visa
}

/// The node `target_node` hands off to on `path`: the next one along, since the path runs in
/// flow order. `None` if `target_node` is the egress node or is not on the path at all.
fn next_hop_in_path<'a>(path: &'a [IpAddr], target_node: &IpAddr) -> Option<&'a IpAddr> {
    let pos = path.iter().position(|n| n == target_node)?;
    path.get(pos + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{FakeDb, VisaRepo};
    use crate::packet::make_fivetuple_tcp;
    use crate::test_helpers::{
        make_adapter_actor_defexp, make_node_actor_defexp, make_pdesc, make_visa,
    };
    use std::sync::Arc;
    use std::time::Duration;

    async fn make_mgr() -> VisaMgr {
        let db = Arc::new(FakeDb::new());
        VisaMgr::new(VisaRepo::new(db, 1).await.unwrap())
    }

    // The default visa from make_visa has source fd5a:5052::10, dest fd5a:5052::20,
    // TCP source_port=1234, dest_port=443.
    const NODE_ADDR: &str = "fd5a:5052::1";
    const SRC_ADDR: &str = "fd5a:5052::10";
    const DST_ADDR: &str = "fd5a:5052::20";

    #[test]
    fn test_next_hop_empty() {
        let path = vec![];
        let target = "fd5a:5052::2".parse().unwrap();
        assert_eq!(next_hop_in_path(&path, &target), None);
    }

    #[test]
    fn test_next_hop_one_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let path = vec![n0];
        assert_eq!(next_hop_in_path(&path, &n0), None);
        assert_eq!(next_hop_in_path(&path, &n1), None);
    }

    #[test]
    fn test_next_hop_two_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let path = vec![n0, n1];
        assert_eq!(next_hop_in_path(&path, &n0), Some(&n1));
        // n1 is the egress end: nothing beyond it.
        assert_eq!(next_hop_in_path(&path, &n1), None);
    }

    #[test]
    fn test_next_hop_three_elem() {
        let n0 = "fd5a:5052::1".parse().unwrap();
        let n1 = "fd5a:5052::2".parse().unwrap();
        let n2 = "fd5a:5052::3".parse().unwrap();
        let unknown = "fd5a:5052::4".parse().unwrap();
        let path = vec![n0, n1, n2];
        assert_eq!(next_hop_in_path(&path, &n0), Some(&n1));
        assert_eq!(next_hop_in_path(&path, &n1), Some(&n2));
        assert_eq!(next_hop_in_path(&path, &n2), None);

        assert_eq!(next_hop_in_path(&path, &unknown), None);
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_found() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(1, std::time::Duration::from_secs(60));

        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::Installed)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().issuer_id, 1);
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_not_found_empty() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_wrong_ports() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(2, std::time::Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::Installed)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            8080, // wrong dest_port
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_node_visa_by_five_tuple_pending_not_matched() {
        // Visas in PendingInstall state should not be returned.
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(3, std::time::Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .get_node_visa_by_five_tuple(&node_addr, &ft)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    /// Callers that pass PendingInstall explicitly (the bootstrap-visa dedup) must match a
    /// created-but-not-yet-delivered visa, otherwise they mint a duplicate on every pass.
    #[tokio::test]
    async fn test_find_node_visa_by_five_tuple_matches_pending_when_requested() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        let visa = make_visa(4, std::time::Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            node_addr.clone(),
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );

        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let ft = make_fivetuple_tcp(
            SRC_ADDR.parse().unwrap(),
            DST_ADDR.parse().unwrap(),
            1234,
            443,
        )
        .unwrap();

        let result = mgr
            .find_node_visa_by_five_tuple(
                &node_addr,
                &ft,
                &[
                    db::NodeVisaState::Installed,
                    db::NodeVisaState::PendingInstall,
                ],
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.expect("pending visa should match").issuer_id, 4);
    }

    /// Stand up the minimum a bootstrap mint needs: one connected node, which the visa
    /// service docks on. Returns that node's address, usable as `via_node`.
    async fn add_vs_docking_node(asm: &Assembly) -> IpAddr {
        let node_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        asm.topo_mgr.add_node(node_addr).unwrap();
        asm.actor_mgr
            .hack_set_vs_docking_node(&node_addr)
            .await
            .unwrap();
        node_addr
    }

    /// A bootstrap visa must be mintable for a peer that has no actor and no route of its
    /// own -- that is the entire point, the link is not up yet. Going through the normal
    /// visa request pipeline would deny NoRoute here. Also asserts the dedup: a second
    /// call reuses the first visa rather than minting a duplicate.
    #[tokio::test]
    async fn test_vsapi_bootstrap_visa_for_future_peer_no_route_no_actor() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let via_node = add_vs_docking_node(&asm).await;
        // Never added to actor_mgr or topo_mgr: an unconnected peer.
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();

        let visa = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_node,
                Direction::Forward,
            )
            .await
            .expect("bootstrap visa must not need a route from the peer itself");

        let dock_pep = visa.dock_pep.as_ref().expect("full visa has a dock_pep");
        assert_eq!(dock_pep.source_addr, future_peer);
        assert_eq!(dock_pep.dest_addr, asm.config.get_vs_addr());
        match &dock_pep.pep {
            DockPepType::TCP(tpep) => {
                assert_eq!(tpep.source_port, 0, "any source port");
                assert_eq!(
                    tpep.dest_port,
                    asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT)
                );
            }
            other => panic!("expected a TCP dock pep, got {other:?}"),
        }

        // Stored pending-install against the peer, so its own worker installs it on connect.
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&future_peer)
            .await
            .unwrap();
        assert_eq!(pending, vec![visa.issuer_id]);

        let again = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_node,
                Direction::Forward,
            )
            .await
            .unwrap();
        assert_eq!(
            again.issuer_id, visa.issuer_id,
            "second call must reuse the pending visa, not mint a duplicate"
        );
    }

    /// A peer with two connected neighbours gets one bootstrap visa per neighbour: the path is
    /// baked into the visa, so sharing one would leave the second neighbour off it. Deduping
    /// still holds per neighbour -- asking twice for the same relay reuses.
    #[tokio::test]
    async fn test_bootstrap_visa_is_per_relay_not_per_five_tuple() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let via_a = add_vs_docking_node(&asm).await; // docks the VS
        let via_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();

        // via_b reaches the VS docking node through a link to via_a.
        asm.topo_mgr.add_node(via_b).unwrap();
        asm.topo_mgr
            .add_link(via_a, via_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        let visa_a = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_a,
                Direction::Forward,
            )
            .await
            .unwrap();
        let visa_b = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_b,
                Direction::Forward,
            )
            .await
            .unwrap();

        assert_ne!(
            visa_a.issuer_id, visa_b.issuer_id,
            "each relay needs its own visa: one visa carries one path"
        );

        // Each visa hands off from the peer to its own relay, and stages that relay.
        for (visa, via) in [(&visa_a, via_a), (&visa_b, via_b)] {
            let md = asm
                .visa_mgr
                .repo
                .get_visa_metadata_by_id(visa.issuer_id)
                .unwrap();
            let path = md.path.expect("bootstrap visa has an explicit path");
            assert_eq!(path[0], future_peer, "the peer is the ingress node");
            assert_eq!(path[1], via, "the peer hands off to its own relay");
            assert_eq!(
                asm.visa_mgr.repo.get_node_visa_state(visa.issuer_id, &via),
                Some(db::NodeVisaState::PendingInstall),
                "the relay on the path is staged"
            );
        }

        // Dedup still applies per relay.
        let again = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_b,
                Direction::Forward,
            )
            .await
            .unwrap();
        assert_eq!(
            again.issuer_id, visa_b.issuer_id,
            "same relay must reuse its visa, not mint another"
        );
    }

    /// The relaying node is on the bootstrap visa's path, so it is staged PendingInstall too
    /// and its install ack applies. Without that staging the ack would find no entry and the
    /// VS would never learn the relay installed the visa.
    #[tokio::test]
    async fn test_bootstrap_visa_stages_the_relaying_node() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let via_node = add_vs_docking_node(&asm).await;
        let future_peer: IpAddr = "fd5a:5052:3000::7".parse().unwrap();

        let visa = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_node,
                Direction::Forward,
            )
            .await
            .unwrap();

        assert_eq!(
            asm.visa_mgr
                .repo
                .get_node_visa_state(visa.issuer_id, &via_node),
            Some(db::NodeVisaState::PendingInstall),
            "the relaying node must be staged for the visa it forwards"
        );

        asm.visa_mgr
            .visa_installed(visa.issuer_id, &via_node)
            .await
            .unwrap();
        assert_eq!(
            asm.visa_mgr
                .repo
                .get_node_visa_state(visa.issuer_id, &via_node),
            Some(db::NodeVisaState::Installed),
            "the relay's install ack must apply"
        );
    }

    /// The peer installs this visa as its own ingress node, so its copy must carry a
    /// fwd_pep pointing at the neighbour that relays for it -- otherwise it has nowhere to
    /// send its VSAPI traffic. The relaying neighbour must also be queued a copy.
    #[tokio::test]
    async fn test_vsapi_bootstrap_visa_actualizes_with_fwd_pep_to_via_node() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let via_node = add_vs_docking_node(&asm).await;
        let future_peer: IpAddr = "fd5a:5052:3000::9".parse().unwrap();

        let visa = asm
            .visa_mgr
            .vsapi_bootstrap_visa_for_future_peer(
                &asm,
                &asm.policy_mgr.get_current(),
                &future_peer,
                &via_node,
                Direction::Forward,
            )
            .await
            .unwrap();
        let md = asm
            .visa_mgr
            .get_visa_metadata_by_id(visa.issuer_id)
            .await
            .unwrap()
            .expect("metadata for a just-created visa");
        assert_eq!(
            md.path,
            Some(vec![future_peer, via_node]),
            "path runs from the peer through its first hop to the VS docking node"
        );

        let actualized = asm
            .visa_mgr
            .actualize_visa_for_target_node(visa.clone(), &future_peer)
            .await
            .unwrap();
        let fwd_pep = actualized
            .fwd_pep
            .as_ref()
            .expect("the peer's copy must forward");
        assert_eq!(fwd_pep.next_hop, via_node);

        // The relaying neighbour needs its own copy to let the traffic through.
        let pending = asm
            .visa_mgr
            .get_pending_visa_ids_for_node(&via_node)
            .await
            .unwrap();
        assert!(pending.contains(&visa.issuer_id));
    }

    /// The mint must hold `bootstrap_lock` across its whole check-then-create. Two neighbours
    /// minting for the same future peer would otherwise interleave at the DB awaits, both see
    /// no visa, and mint duplicates. Holding the lock here has to stall a concurrent mint;
    /// with the clock paused the timeout can only fire because the mint is blocked on it.
    #[tokio::test(start_paused = true)]
    async fn test_vsapi_bootstrap_visa_mint_is_serialized() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let via_node = add_vs_docking_node(&asm).await;
        let future_peer: IpAddr = "fd5a:5052:3000::8".parse().unwrap();

        let guard = asm.visa_mgr.bootstrap_lock.lock().await;
        // Named local: the future outlives the statement, so this cannot be a temporary.
        let policy = asm.policy_mgr.get_current();
        let mut mint = Box::pin(asm.visa_mgr.vsapi_bootstrap_visa_for_future_peer(
            &asm,
            &policy,
            &future_peer,
            &via_node,
            Direction::Forward,
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut mint)
                .await
                .is_err(),
            "mint must block while the bootstrap lock is held"
        );

        drop(guard);
        mint.await.expect("mint completes once the lock is free");
    }

    // --- actualize_visa_for_target_node tests ---

    // Path nodes used by actualize tests; distinct from the constants above.
    const PATH_NODE_A: &str = "fd5a:5052::a"; // ingress position
    const PATH_NODE_B: &str = "fd5a:5052::b"; // intermediary position
    const PATH_NODE_C: &str = "fd5a:5052::c"; // egress position

    /// Three-node path [A, B, C] used by the actualize tests.
    fn three_node_path() -> Vec<IpAddr> {
        vec![
            PATH_NODE_A.parse().unwrap(),
            PATH_NODE_B.parse().unwrap(),
            PATH_NODE_C.parse().unwrap(),
        ]
    }

    /// Store a visa in the repo with the given path; requesting_node is the first path node (or A if no path).
    async fn store_test_visa(mgr: &VisaMgr, id: u64, path: Option<Vec<IpAddr>>) -> Visa {
        let visa = make_visa(id, Duration::from_secs(60));
        let requesting_node: IpAddr = path
            .as_ref()
            .and_then(|p| p.first())
            .cloned()
            .unwrap_or_else(|| PATH_NODE_A.parse().unwrap());
        let metadata = db::VisaMetadata::new(
            requesting_node,
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            path,
            &make_pdesc(),
        );
        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();
        visa
    }

    async fn store_test_visa_with_reqesting_node(
        mgr: &VisaMgr,
        id: u64,
        path: Option<Vec<IpAddr>>,
        requesting_node: IpAddr,
    ) -> Visa {
        let visa = make_visa(id, Duration::from_secs(60));
        let metadata = db::VisaMetadata::new(
            requesting_node,
            0,
            0,
            "zpl".to_string(),
            Direction::Forward,
            path,
            &make_pdesc(),
        );
        mgr.repo
            .store_visa(&visa, metadata, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();
        visa
    }

    /// No path in metadata → visa returned unchanged with no fwd_pep.
    #[tokio::test]
    async fn test_actualize_no_path_returns_unchanged() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = PATH_NODE_A.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, None).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_addr)
            .await
            .unwrap();
        assert_eq!(result.issuer_id, 1);
        assert!(result.fwd_pep.is_none());
    }

    /// Path with only one node → visa returned unchanged.
    #[tokio::test]
    async fn test_actualize_path_too_short_returns_unchanged() {
        let mgr = make_mgr().await;
        let node_addr: IpAddr = PATH_NODE_A.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(vec![node_addr.clone()])).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_addr)
            .await
            .unwrap();
        assert_eq!(result.issuer_id, 1);
        assert!(result.fwd_pep.is_none());
    }

    /// Ingress context (first node + Forward) → full visa with fwd_pep pointing to the second path node.
    #[tokio::test]
    async fn test_actualize_ingress_forward_sets_fwd_pep() {
        let mgr = make_mgr().await;
        let node_a: IpAddr = PATH_NODE_A.parse().unwrap();
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_a)
            .await
            .unwrap();
        let fwd_pep = result.fwd_pep.expect("expected fwd_pep on ingress visa");
        assert_eq!(fwd_pep.next_hop, node_b);
        assert!(result.dock_pep.is_some(), "ingress visa retains dock_pep");
    }

    /// Egress context (last node + Forward) → full visa returned unchanged (no fwd_pep added).
    #[tokio::test]
    async fn test_actualize_egress_forward_returns_full_visa() {
        let mgr = make_mgr().await;
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_c)
            .await
            .unwrap();
        assert!(result.fwd_pep.is_none());
        assert!(result.dock_pep.is_some(), "egress returns full visa");
    }

    /// A reverse-flow visa stores its own flow order [C, B, A], so C is the ingress end:
    /// full visa with fwd_pep towards B.
    #[tokio::test]
    async fn test_actualize_ingress_reverse_sets_fwd_pep() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let mut path = three_node_path();
        path.reverse();
        let visa = store_test_visa(&mgr, 1, Some(path)).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_c)
            .await
            .unwrap();
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on ingress-reverse visa");
        assert_eq!(fwd_pep.next_hop, node_b);
        assert!(
            result.dock_pep.is_some(),
            "ingress-reverse visa retains dock_pep"
        );
    }

    /// The other end of that reverse-flow path [C, B, A]: A is egress, full visa unchanged.
    #[tokio::test]
    async fn test_actualize_egress_reverse_returns_full_visa() {
        let mgr = make_mgr().await;
        let node_a: IpAddr = PATH_NODE_A.parse().unwrap();
        let mut path = three_node_path();
        path.reverse();
        let visa = store_test_visa(&mgr, 1, Some(path)).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_a)
            .await
            .unwrap();
        assert!(result.fwd_pep.is_none());
        assert!(
            result.dock_pep.is_some(),
            "egress-reverse returns full visa"
        );
    }

    /// The bug this geometry replaced: a visa the VS mints pre-emptively names the flow's
    /// *destination* as the requesting node, and the destination must still come out egress.
    /// Keying the role off `requesting_node` instead handed it a fwd_pep pointing back at the
    /// node the packets arrived from, which ping-ponged binds between the two nodes.
    #[tokio::test]
    async fn test_actualize_role_ignores_requesting_node() {
        let mgr = make_mgr().await;
        let node_a: IpAddr = PATH_NODE_A.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        // Flow runs A → C, but C is the node that asked for the visa.
        let visa =
            store_test_visa_with_reqesting_node(&mgr, 1, Some(three_node_path()), node_c).await;

        let at_c = mgr
            .actualize_visa_for_target_node(visa.clone(), &node_c)
            .await
            .unwrap();
        assert!(
            at_c.fwd_pep.is_none(),
            "destination node must not be told to forward the flow onwards"
        );
        assert!(at_c.dock_pep.is_some(), "destination docks the flow");

        let at_a = mgr
            .actualize_visa_for_target_node(visa, &node_a)
            .await
            .unwrap();
        assert_eq!(
            at_a.fwd_pep
                .expect("source node forwards into the fabric")
                .next_hop,
            PATH_NODE_B.parse::<IpAddr>().unwrap()
        );
    }

    /// Demonstrates the next_hop bug: for intermediary node B on path [A, B, C] with Forward
    /// direction, the correct next hop is C (the node AFTER B in the path), not A (the first
    /// node != B, as returned by the buggy iter().find()).
    #[tokio::test]
    async fn test_actualize_next_hop_bug_intermediary_forward() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_b)
            .await
            .unwrap();
        assert_eq!(result.visa_type, VisaType::ForwardOnly);
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on intermediary visa");
        assert_eq!(
            fwd_pep.next_hop, node_c,
            "next hop for B (Forward) must be C, not A"
        );
    }

    /// Intermediary context → ForwardOnly visa: dock_pep stripped, fwd_pep set to node after target.
    #[tokio::test]
    async fn test_actualize_intermediary_returns_forwarding_only_visa() {
        let mgr = make_mgr().await;
        let node_b: IpAddr = PATH_NODE_B.parse().unwrap();
        let node_c: IpAddr = PATH_NODE_C.parse().unwrap();
        let visa = store_test_visa(&mgr, 1, Some(three_node_path())).await;

        let result = mgr
            .actualize_visa_for_target_node(visa, &node_b)
            .await
            .unwrap();
        assert_eq!(result.visa_type, VisaType::ForwardOnly);
        assert!(
            result.dock_pep.is_none(),
            "ForwardOnly visa has no dock_pep"
        );
        let fwd_pep = result
            .fwd_pep
            .expect("expected fwd_pep on intermediary visa");
        assert_eq!(fwd_pep.next_hop, node_c);
    }

    // --- create_visa multihop integration tests ---
    // These verify that create_visa uses the explicit route parameter to populate
    // metadata.path, mark all path nodes pending, and enable actualize to set fwd_pep.

    use crate::assembly::tests::new_assembly_for_tests;
    use libeval::route::LinkId;

    // Three nodes forming a linear chain: SRC → MID → DST (no direct SRC–DST link),
    // with one adapter docked at each end.
    const MH_SRC: &str = "fd5a:5052::a1";
    const MH_MID: &str = "fd5a:5052::b1";
    const MH_DST: &str = "fd5a:5052::c1";
    const MH_SRC_ADAPTER: &str = "fd5a:5052:1234::a100";
    const MH_DST_ADAPTER: &str = "fd5a:5052:1234::a200";

    /// Build an assembly with topology SRC→MID→DST and no direct SRC–DST link. The end
    /// adapters are docked so that [path_for_flow] can orient a flow between them.
    async fn make_multihop_assembly() -> Assembly {
        let asm = new_assembly_for_tests(None).await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        asm.topo_mgr.add_node(src).unwrap();
        asm.topo_mgr.add_node(mid).unwrap();
        asm.topo_mgr.add_node(dst).unwrap();
        asm.topo_mgr
            .add_link(src, mid, LinkId("link-src-mid".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(mid, dst, LinkId("link-mid-dst".into()), vec![], 1)
            .unwrap();
        for (adapter, node, cn) in [
            (MH_SRC_ADAPTER, src, "mh-src-adapter"),
            (MH_DST_ADAPTER, dst, "mh-dst-adapter"),
        ] {
            asm.actor_mgr
                .add_adapter_via_node(
                    &make_adapter_actor_defexp(adapter, cn),
                    &node,
                    &Default::default(),
                )
                .await
                .unwrap();
        }
        asm
    }

    /// create_visa with a multihop route records the full [src, mid, dst] path in metadata.
    #[tokio::test]
    async fn test_create_visa_multihop_path_stored_in_metadata() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();

        let src_adapter: IpAddr = MH_SRC_ADAPTER.parse().unwrap();
        let dst_adapter: IpAddr = MH_DST_ADAPTER.parse().unwrap();

        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap(); // route between the nodes

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &src,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        let metadata = asm
            .visa_mgr
            .repo
            .get_visa_metadata_by_id(visawmd.visa.issuer_id)
            .unwrap();
        assert_eq!(metadata.path, Some(vec![src, mid, dst]));
    }

    /// create_visa with a multihop route marks every path node (including the intermediary) pending.
    #[tokio::test]
    async fn test_create_visa_multihop_marks_all_path_nodes_pending() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = MH_SRC_ADAPTER.parse().unwrap();
        let dst_adapter: IpAddr = MH_DST_ADAPTER.parse().unwrap();
        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &src,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        let visa_id = visawmd.visa.issuer_id;
        let pending_src = asm.visa_mgr.get_pending_visas_for_node(&src).await.unwrap();
        let pending_mid = asm.visa_mgr.get_pending_visas_for_node(&mid).await.unwrap();
        let pending_dst = asm.visa_mgr.get_pending_visas_for_node(&dst).await.unwrap();

        assert_eq!(
            pending_src.len(),
            1,
            "requesting node (src) must be pending"
        );
        assert_eq!(pending_mid.len(), 1, "intermediary (mid) must be pending");
        assert_eq!(pending_dst.len(), 1, "egress node (dst) must be pending");
        // All three pending entries refer to the same visa.
        assert!(pending_src.iter().any(|v| v.issuer_id == visa_id));
        assert!(pending_mid.iter().any(|v| v.issuer_id == visa_id));
        assert!(pending_dst.iter().any(|v| v.issuer_id == visa_id));
    }

    /// A reverse-direction visa covers packets sent by the forward flow's destination, so its
    /// path starts at that end: dst is the ingress node and must get a fwd_pep towards mid.
    #[tokio::test]
    async fn test_create_visa_reverse_multihop_requesting_node_gets_fwd_pep() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = MH_SRC_ADAPTER.parse().unwrap();
        let dst_adapter: IpAddr = MH_DST_ADAPTER.parse().unwrap();

        // Reverse packet: dst is the sender, src is the destination.
        let pdesc = PacketDesc::new_tcp_with_addr(dst_adapter, src_adapter, 54321, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Reverse);
        let route = asm.topo_mgr.get_best_route(&dst, &src).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &dst,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        // dst is the ingress for reverse traffic; it must get fwd_pep pointing to mid.
        let actualized = asm
            .visa_mgr
            .actualize_visa_for_target_node(visawmd.visa.clone(), &dst)
            .await
            .unwrap();

        let fwd_pep = actualized
            .fwd_pep
            .expect("reverse ingress node (dst) must have fwd_pep on a multihop visa");
        assert_eq!(
            fwd_pep.next_hop, mid,
            "reverse ingress fwd_pep must point to the intermediary"
        );
        assert!(
            actualized.dock_pep.is_some(),
            "reverse ingress node retains dock_pep"
        );
    }

    /// Actualizing a multihop visa for the ingress node sets fwd_pep to the next hop.
    #[tokio::test]
    async fn test_create_visa_multihop_actualize_ingress_sets_fwd_pep() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let mid: IpAddr = MH_MID.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();
        let src_adapter: IpAddr = MH_SRC_ADAPTER.parse().unwrap();
        let dst_adapter: IpAddr = MH_DST_ADAPTER.parse().unwrap();
        let pdesc = PacketDesc::new_tcp_with_addr(src_adapter, dst_adapter, 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &src,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        let actualized = asm
            .visa_mgr
            .actualize_visa_for_target_node(visawmd.visa.clone(), &src)
            .await
            .unwrap();

        let fwd_pep = actualized
            .fwd_pep
            .expect("ingress node must have a forwarding PEP on a multihop visa");
        assert_eq!(
            fwd_pep.next_hop, mid,
            "ingress fwd_pep must point to the intermediary"
        );
        assert!(
            actualized.dock_pep.is_some(),
            "ingress node retains the dock PEP"
        );
        // The egress node dst is not the target here, so this just confirms the visa
        // was created for the right endpoints.
        let _ = dst;
    }

    // --- A2A DH session key tests ---
    // create_visa reads both adapters' stored zpr.a2a_dh_pubkey attributes and carries
    // them in the DockPep session key.

    use libeval::attribute::{Attribute, key};
    use libeval::pubkey::encode_public_key;
    use zpr::vsapi_types::PublicKey;

    const SRC_ADAPTER: &str = "fd5a:5052:1234::a100";
    const DST_ADAPTER: &str = "fd5a:5052:1234::a200";

    async fn add_keyed_adapter(asm: &Assembly, zpr_addr: &str, cn: &str, key_bytes: &[u8]) {
        let mut actor = make_adapter_actor_defexp(zpr_addr, cn);
        actor
            .add_attribute(
                Attribute::builder(key::A2A_DH_PUBKEY)
                    .value(encode_public_key(&PublicKey::new(key_bytes))),
            )
            .unwrap();
        asm.actor_mgr
            .hack_add_adapter_no_node(&actor, &Default::default())
            .await
            .unwrap();
    }

    /// Both adapters' keys land in the session key, source as ingress and dest as egress.
    #[tokio::test]
    async fn test_create_visa_session_key_carries_adapter_pubkeys() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();

        let src_key: Vec<u8> = (0..32u8).collect();
        let dst_key: Vec<u8> = (32..64u8).collect();
        add_keyed_adapter(&asm, SRC_ADAPTER, "src-adapter", &src_key).await;
        add_keyed_adapter(&asm, DST_ADAPTER, "dst-adapter", &dst_key).await;

        let pdesc = PacketDesc::new_tcp_with_addr(
            SRC_ADAPTER.parse().unwrap(),
            DST_ADAPTER.parse().unwrap(),
            12345,
            80,
        )
        .unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &src,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        let session_key = &visawmd.visa.dock_pep.as_ref().unwrap().session_key;
        assert_eq!(session_key.ingress_key, src_key);
        assert_eq!(session_key.egress_key, dst_key);
    }

    /// Endpoints with no stored key produce an empty session key rather than failing the visas.
    #[tokio::test]
    async fn test_create_visa_session_key_empty_without_pubkeys() {
        let asm = make_multihop_assembly().await;
        let src: IpAddr = MH_SRC.parse().unwrap();
        let dst: IpAddr = MH_DST.parse().unwrap();

        let pdesc = PacketDesc::new_tcp_with_addr(
            SRC_ADAPTER.parse().unwrap(),
            DST_ADAPTER.parse().unwrap(),
            12345,
            80,
        )
        .unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = asm.topo_mgr.get_best_route(&src, &dst).unwrap();

        let visawmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &src,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + config::MAX_VISA_LIFETIME,
            )
            .await
            .unwrap();

        let session_key = &visawmd.visa.dock_pep.as_ref().unwrap().session_key;
        assert!(session_key.ingress_key.is_empty());
        assert!(session_key.egress_key.is_empty());
    }

    // --- Phase 2 manager tests ---

    /// Store a single-node visa in the given state via the repo.
    async fn store_node_visa(mgr: &VisaMgr, id: u64, node: IpAddr, state: db::NodeVisaState) {
        let visa = make_visa(id, Duration::from_secs(60));
        let md = db::VisaMetadata::new(
            node,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        mgr.repo.store_visa(&visa, md, state).await.unwrap();
    }

    /// visa_installed is a CAS: once the node is PendingRevoke (sweep denied it
    /// mid-push), the install ack does not apply — PendingRevoke wins.
    #[tokio::test]
    async fn test_visa_installed_loses_to_pending_revoke() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        store_node_visa(&mgr, 800, node, db::NodeVisaState::PendingInstall).await;
        assert!(mgr.repo.record_deny_verdict(800, 1).await.unwrap());

        mgr.visa_installed(800, &node).await.unwrap();

        let revoke_ids = mgr
            .repo
            .get_visa_ids_for_node_by_state(&node, db::NodeVisaState::PendingRevoke)
            .unwrap();
        assert_eq!(revoke_ids, vec![800]);
    }

    /// revoke_acked drops the node ref and then removes the now-orphaned visa.
    #[tokio::test]
    async fn test_revoke_acked_removes_node_then_orphan_visa() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        store_node_visa(&mgr, 810, node, db::NodeVisaState::Installed).await;
        assert!(mgr.repo.record_deny_verdict(810, 1).await.unwrap());

        mgr.revoke_acked(node, 810).await;

        assert!(!mgr.visa_has_node_refs(810).await);
        assert!(mgr.repo.get_visa_by_id(810).is_err());
    }

    /// revoke_acked misses when the node is not PendingRevoke (an allow verdict
    /// canceled the revoke mid-RPC): the record survives.
    #[tokio::test]
    async fn test_revoke_acked_leaves_record_when_not_pending_revoke() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        store_node_visa(&mgr, 811, node, db::NodeVisaState::Installed).await;

        mgr.revoke_acked(node, 811).await;

        assert!(mgr.repo.get_visa_by_id(811).is_ok());
        assert!(mgr.visa_has_node_refs(811).await);
    }

    /// recheck_visa_allowed skips when an actor cannot be resolved.
    #[tokio::test]
    async fn test_recheck_visa_allowed_unresolved_actor_skips() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let md = db::VisaMetadata::new(
            "fd5a:5052::10".parse().unwrap(),
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &make_pdesc(),
        );
        let psnap = asm.policy_mgr.get_current_snapshot();
        let res = asm
            .visa_mgr
            .recheck_visa_allowed(&asm, &md, &psnap)
            .await
            .unwrap();
        assert_eq!(res, VisaRecheck::SkipUnresolvedActor);
    }

    /// recheck_visa_allowed returns Revoke when both actors resolve and dock
    /// but there is no route between their nodes (the sweep would revoke).
    #[tokio::test]
    async fn test_recheck_visa_allowed_no_route_denies() {
        let asm = new_assembly_for_tests(None).await;
        let node_a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052:3000::1", "na", "10.0.0.1:1"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052:3000::2", "nb", "10.0.0.2:2"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.topo_mgr.add_node(node_a).unwrap();
        asm.topo_mgr.add_node(node_b).unwrap();
        // No link between the nodes → no route.

        let src_adapter = make_adapter_actor_defexp("fd5a:5052:4000::a", "src");
        let dst_adapter = make_adapter_actor_defexp("fd5a:5052:4000::b", "dst");
        asm.actor_mgr
            .add_adapter_via_node(&src_adapter, &node_a, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&dst_adapter, &node_b, &Default::default())
            .await
            .unwrap();

        let asm = Arc::new(asm);
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 443).unwrap();
        let md = db::VisaMetadata::new(
            node_a,
            0,
            0,
            String::new(),
            Direction::Forward,
            None,
            &pdesc,
        );
        let psnap = asm.policy_mgr.get_current_snapshot();
        let res = asm
            .visa_mgr
            .recheck_visa_allowed(&asm, &md, &psnap)
            .await
            .unwrap();
        assert_eq!(res, VisaRecheck::Revoke);
    }

    /// path_for_flow returns None for a direct (same-node) route -- a direct visa
    /// stores `path = None`, so recheck compares None == None and stays AllowSameRoute.
    #[tokio::test]
    async fn test_path_for_flow_direct_is_none() {
        let asm = new_assembly_for_tests(None).await;
        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        asm.topo_mgr.add_node(a).unwrap();
        let route = asm.topo_mgr.get_best_route(&a, &a).unwrap();
        assert_eq!(path_for_flow(&asm, &a, &route).await.unwrap(), None);
    }

    /// Build a—b—c with node actors for a and c, plus an adapter docked on c.
    async fn make_abc_assembly() -> (Assembly, IpAddr, IpAddr, IpAddr) {
        let asm = new_assembly_for_tests(None).await;
        let a: IpAddr = "fd5a:5052::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052::2".parse().unwrap();
        let c: IpAddr = "fd5a:5052::3".parse().unwrap();
        for n in [a, b, c] {
            asm.topo_mgr.add_node(n).unwrap();
        }
        asm.topo_mgr
            .add_link(a, b, LinkId("ab".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(b, c, LinkId("bc".into()), vec![], 1)
            .unwrap();
        for (addr, cn) in [(a, "node-a"), (c, "node-c")] {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(&addr.to_string(), cn, "10.0.0.1:10001"),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
        }
        (asm, a, b, c)
    }

    /// The path runs in flow order from wherever the *source* docks: from a it is
    /// [a, b, c], from c it is [c, b, a], and an adapter docked on c is oriented
    /// like c. This is what makes a node's actualization role positional.
    #[tokio::test]
    async fn test_path_for_flow_orients_on_source_dock() {
        let (asm, a, b, c) = make_abc_assembly().await;
        let adapter_on_c: IpAddr = "fd5a:5052:1234::c1".parse().unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp(&adapter_on_c.to_string(), "adapter-c"),
                &c,
                &Default::default(),
            )
            .await
            .unwrap();

        // A route's links are ordered from the source's end, exactly as the policy eval
        // builds it (get_best_route(source dock, dest dock)), so each direction gets its own.
        let a_to_c = asm.topo_mgr.get_best_route(&a, &c).unwrap();
        let c_to_a = asm.topo_mgr.get_best_route(&c, &a).unwrap();
        assert_eq!(
            path_for_flow(&asm, &a, &a_to_c).await.unwrap(),
            Some(vec![a, b, c])
        );
        assert_eq!(
            path_for_flow(&asm, &c, &c_to_a).await.unwrap(),
            Some(vec![c, b, a])
        );
        assert_eq!(
            path_for_flow(&asm, &adapter_on_c, &c_to_a).await.unwrap(),
            Some(vec![c, b, a]),
            "an adapter's flow enters the fabric at its docking node"
        );
    }

    /// Two ways the path cannot be oriented, both of which recheck maps to Revoke:
    /// an undocked source, and a source docked off the route (topology moved under us).
    #[tokio::test]
    async fn test_path_for_flow_unorientable_source_errors() {
        let (asm, a, b, _c) = make_abc_assembly().await;
        let route = asm.topo_mgr.get_best_route(&a, &b).unwrap();

        let undocked: IpAddr = "fd5a:5052:1234::99".parse().unwrap();
        assert!(path_for_flow(&asm, &undocked, &route).await.is_err());

        // Node d is docked (on itself) but the a—b route does not touch it.
        let d: IpAddr = "fd5a:5052::4".parse().unwrap();
        asm.topo_mgr.add_node(d).unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp(&d.to_string(), "node-d", "10.0.0.4:10001"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        assert!(path_for_flow(&asm, &d, &route).await.is_err());
    }

    /// An adapter leaving while its node stays up: the visa on the live node is
    /// marked PendingRevoke and left in place (awaiting the revoke ack).
    #[tokio::test]
    async fn test_remove_visas_for_actors_marks_live_node_pending_revoke() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        let src: IpAddr = SRC_ADDR.parse().unwrap();
        store_node_visa(&mgr, 900, node, db::NodeVisaState::Installed).await;

        mgr.remove_visas_for_actors(&[src]).await.unwrap();

        let revoke_ids = mgr
            .repo
            .get_visa_ids_for_node_by_state(&node, db::NodeVisaState::PendingRevoke)
            .unwrap();
        assert_eq!(revoke_ids, vec![900]);
        // Visa still present -- housekeeping removes it on ack.
        assert!(mgr.repo.get_visa_by_id(900).is_ok());
    }

    /// A visa whose only node was already cleared (no refs left) is dropped
    /// outright rather than waiting for TTL.
    #[tokio::test]
    async fn test_remove_visas_for_actors_drops_orphan() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        let src: IpAddr = SRC_ADDR.parse().unwrap();
        store_node_visa(&mgr, 910, node, db::NodeVisaState::Installed).await;
        // Simulate remove_visas_for_node having cleared the node's only ref.
        mgr.clear_node_state(&node).await.unwrap();
        assert!(!mgr.visa_has_node_refs(910).await);

        mgr.remove_visas_for_actors(&[src]).await.unwrap();

        assert!(mgr.repo.get_visa_by_id(910).is_err());
    }

    /// Empty actor list, and an actor with no visas, are both no-ops.
    #[tokio::test]
    async fn test_remove_visas_for_actors_noops() {
        let mgr = make_mgr().await;
        mgr.remove_visas_for_actors(&[]).await.unwrap();
        let unknown: IpAddr = "fd5a:5052::dead".parse().unwrap();
        mgr.remove_visas_for_actors(&[unknown]).await.unwrap();
    }

    /// Store a visa across the path [a, b, c] (a is the requesting node, Installed;
    /// b and c PendingInstall).
    async fn store_multihop_visa(mgr: &VisaMgr, id: u64, a: IpAddr, b: IpAddr, c: IpAddr) {
        let visa = make_visa(id, Duration::from_secs(60));
        let md = db::VisaMetadata::new(
            a,
            0,
            0,
            String::new(),
            Direction::Forward,
            Some(vec![a, b, c]),
            &make_pdesc(),
        );
        mgr.repo
            .store_visa(&visa, md, db::NodeVisaState::Installed)
            .await
            .unwrap();
    }

    /// Multihop [A, B, C] visa; intermediary B departs. The visa's other nodes go
    /// PendingRevoke, B is no longer referenced, and the visa survives (awaiting
    /// the revoke acks from A and C).
    #[tokio::test]
    async fn test_remove_visas_for_node_multihop_revokes_others() {
        let mgr = make_mgr().await;
        let a: IpAddr = "fd5a:5052::a".parse().unwrap();
        let b: IpAddr = "fd5a:5052::b".parse().unwrap();
        let c: IpAddr = "fd5a:5052::c".parse().unwrap();
        store_multihop_visa(&mgr, 1000, a, b, c).await;

        mgr.remove_visas_for_node(&b).await.unwrap();

        // B no longer referenced.
        assert!(mgr.repo.get_all_visa_ids_for_node(&b).unwrap().is_empty());
        // A and C queued for revoke.
        for n in [a, c] {
            assert_eq!(
                mgr.repo
                    .get_visa_ids_for_node_by_state(&n, db::NodeVisaState::PendingRevoke)
                    .unwrap(),
                vec![1000]
            );
        }
        // Visa still present -- housekeeping removes it on ack.
        assert!(mgr.repo.get_visa_by_id(1000).is_ok());
    }

    /// A visa referencing only the departed node is captured (snapshot before
    /// clear) and removed outright once its sole ref is dropped.
    #[tokio::test]
    async fn test_remove_visas_for_node_drops_sole_ref_orphan() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        store_node_visa(&mgr, 1010, node, db::NodeVisaState::Installed).await;

        mgr.remove_visas_for_node(&node).await.unwrap();

        assert!(
            mgr.repo
                .get_all_visa_ids_for_node(&node)
                .unwrap()
                .is_empty()
        );
        assert!(mgr.repo.get_visa_by_id(1010).is_err());
    }

    /// A node with no visas is a no-op.
    #[tokio::test]
    async fn test_remove_visas_for_node_noop() {
        let mgr = make_mgr().await;
        let node: IpAddr = "fd5a:5052::beef".parse().unwrap();
        mgr.remove_visas_for_node(&node).await.unwrap();
    }
}
