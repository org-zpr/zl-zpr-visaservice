//! Manage the creating, storage and retrieval of visas for the visa service.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
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
use crate::visa_bootstrap::{BOOTSTRAP_VISA_LIFETIME, BOOTSTRAP_VISA_ZPL};
use crate::visa_policy::{
    PolicyOutcome, docking_node_for_addr, evaluate_against_policy, route_for_allow,
};

use libeval::eval_result::{Direction, Hit};
use libeval::policy::Policy;
use libeval::route::{LinkId, NodeId, Route};
use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, DockPepType, EndpointT, FwdPep, FwdPepStyle, IcmpPep, KeySet, PacketDesc,
    TcpUdpPep, Visa, VisaType, VsapiFiveTuple,
};

use tracing::info;

#[derive(Clone)]
pub struct VisaMgr {
    repo: db::VisaRepo,
    /// Visas whose revocation write failed, at commit ([VisaMgr::revoke_if_route_down])
    /// or when a link went down (`revoke_visas_over_link`). They are never handed out,
    /// and their revocation is retried on every [VisaMgr::get_pending_visas_for_node].
    quarantine: Arc<Mutex<HashSet<u64>>>,
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

/// True if the visa's dock PEP is for exactly this five-tuple: both addresses and both TCP
/// ports. A visa with no dock PEP cannot match -- only full visas are stored, so that is a bug
/// worth logging.
pub(crate) fn dock_pep_matches_five_tuple(visa: &Visa, ft: &VsapiFiveTuple) -> bool {
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

impl VisaWithMetadata {
    pub fn new(visa: Visa, metadata: db::VisaMetadata) -> Self {
        VisaWithMetadata { visa, metadata }
    }
}

impl VisaMgr {
    pub fn new(db: db::VisaRepo) -> Self {
        VisaMgr {
            repo: db,
            quarantine: Arc::new(Mutex::new(HashSet::new())),
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
    /// In every context the copy's `prev_hop` names the node before `target_node` on the
    /// path, and is unset on the ingress node and for a visa with no path of two or more
    /// nodes (zl-zipline#245).
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

        // Every node's copy names the node before it on the path: the only node it may accept
        // a StreamIdRequest for this visa from (zl-zipline#245). The ingress node is first on
        // the path, so its copy has none -- the flow starts there.
        visa.prev_hop = prev_hop_in_path(path, target_node).copied();

        match vctx {
            // The flow terminates here, so there is nothing to forward: the full visa, with
            // only its previous hop set above.
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

    /// The visas for the `register_vss` reply of `node_addr`, which has just registered
    /// its VSS at `vss_addr`: only the node's copy of a NEW VS->VSS visa (J5b, see
    /// [crate::core_visas::issue_vss_visa]).
    ///
    /// That copy has to ride in the reply: it is what lets the visa service open the VSS
    /// connection, so it cannot be pushed over it. Everything else pending for the node --
    /// its J5a VSAPI pair included -- is pushed over VSS once that connection is up, in
    /// ingress-last order (gate g89 q4, see [VisaMgr::deliverable_visas_for_node]).
    pub async fn post_register_vss_visas_for_node(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        session: Option<&str>,
    ) -> Result<Vec<Visa>, ServiceError> {
        let visa_id =
            crate::core_visas::issue_vss_visa(&asm, node_addr, vss_addr.port(), session).await?;
        let visa = self.repo.get_visa_by_id(visa_id)?;
        Ok(vec![
            self.actualize_visa_for_target_node(visa, node_addr).await?,
        ])
    }

    /// Mint one direction of a joining peer's bootstrap flow: the visa that lets `peer`
    /// reach the visa service's VSAPI port through `relay` before it has a VS-API session
    /// (ZODE_LINKS.md J3). Only [crate::visa_bootstrap::request_bootstrap_visas] calls this,
    /// after checking the narrow rule; the rest of the bootstrap machinery lives there, and
    /// only the minting is here, because it needs this module's private store helpers.
    ///
    /// `direction` picks which half of the flow this visa is for. A visa carries exactly one
    /// dock PEP and one path orientation, so the two halves cannot share one:
    /// - [Direction::Forward] is the peer's own requests, `peer:any -> vs:VSAPI`, ingressing
    ///   at the peer and forwarded to the relay, where the visa service docks.
    /// - [Direction::Reverse] is the visa service's replies, `vs:VSAPI -> peer:any`,
    ///   ingressing at the relay and forwarded to the peer.
    ///
    /// This deliberately bypasses policy evaluation: the peer has no actor until it has
    /// authenticated, and a peering declared in policy *is* the authorization (J3). `policy`
    /// is the caller's view, the one the peering was selected from, so the generation
    /// recorded on the visa is the one that authorized it.
    ///
    /// The path is stitched from the peering, `[peer, relay]` (reversed for the reverse
    /// half), never routed: the peer's link may not be in the router yet, and for a peer
    /// that is still connected a routed path could run back through the peer itself. In v1
    /// the relay is the node the visa service docks on (J3), so the path ends there.
    ///
    /// Every call mints a NEW visa, valid for [BOOTSTRAP_VISA_LIFETIME] (J6). It is recorded
    /// installed on both nodes at once, never pending: the relay hands both copies over
    /// itself (installing its own, passing the peer's on in ZDP message 146), so nothing may
    /// push them. The relay's state is written with the visa, so its VSS worker never sees
    /// it pending. The peer's is set right after. The only VSS worker the peer can have then
    /// is its previous session's, on a rejoin: that session's links are gone (R9), so a push
    /// in between cannot reach the peer, and the worker is stopped once the rejoin is done
    /// (see `visa_bootstrap::end_previous_join`).
    pub async fn mint_bootstrap_visa(
        &self,
        asm: &Assembly,
        policy: &Policy,
        peer: &IpAddr,
        relay: &IpAddr,
        direction: Direction,
    ) -> Result<Visa, ServiceError> {
        let vs_addr = asm.config.get_vs_addr();
        let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);
        // The wildcard port sits on the peer's side in both directions: it is the client,
        // so its port is unknown until it picks one. `create_visa_with_path` derives the same
        // for a BiDirectional packet in each direction.
        let (ft, path) = match direction {
            Direction::Forward => (
                make_fivetuple_tcp(*peer, vs_addr, 0, vsapi_port)?,
                vec![*peer, *relay],
            ),
            Direction::Reverse => (
                make_fivetuple_tcp(vs_addr, *peer, vsapi_port, 0)?,
                vec![*relay, *peer],
            ),
        };
        let pkt_data = PacketDesc {
            five_tuple: ft,
            comm_flags: CommFlag::BiDirectional,
        };
        let vwm = self
            .create_visa_with_path(
                asm,
                relay,
                db::NodeVisaState::Installed,
                &pkt_data,
                &Hit::new_no_signal(0, direction),
                Some(path),
                BOOTSTRAP_VISA_ZPL,
                policy.get_version().unwrap_or(0),
                policy.vinst(),
                SystemTime::now() + BOOTSTRAP_VISA_LIFETIME,
            )
            .await?;
        self.visa_installed(vwm.visa.issuer_id, peer).await?;
        Ok(vwm.visa)
    }

    /// Mark every visa installed on `node_addr` pending install again, and return their IDs.
    ///
    /// For a node that lost every visa it held (a rejoin wipes its links, R9) but keeps its
    /// state in the visa service so it can `reconnect`: its VSS worker then pushes them all
    /// again (ZODE_LINKS.md "Settled after the builder check"). Only the per-node install
    /// state changes; the visas themselves are never touched. A visa whose state moved
    /// meanwhile (to `PendingRevoke`, say) is left as it is.
    pub async fn forget_installs_on_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<u64>, ServiceError> {
        let mut forgotten = Vec::new();
        for id in self.get_installed_visa_ids_for_node(node_addr).await? {
            if self
                .repo
                .transition_node_visa_state(
                    *node_addr,
                    id,
                    db::NodeVisaState::Installed,
                    db::NodeVisaState::PendingInstall,
                )
                .await?
            {
                forgotten.push(id);
            }
        }
        Ok(forgotten)
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
                db::NodeVisaState::PendingInstall,
                pdesc,
                hit,
                path,
                source_zpl,
                policy_version,
                vinst,
                expiration_time,
            )
            .await?;

        // The path was derived from the live router after the route was chosen, so it
        // must also still end where the destination is docked now.
        let egress = match &vwmd.metadata.path {
            Some(_) => {
                crate::visa_policy::docking_node_for_addr(asm, &pdesc.five_tuple.dest_addr).await
            }
            None => None,
        };
        self.revoke_if_route_down(
            asm,
            vwmd.visa.issuer_id,
            &route.links,
            vwmd.metadata.path.as_deref(),
            egress,
        )
        .await?;
        Ok(vwmd)
    }

    /// Commit-time check for a just-stored visa (zl-zipline#224). A link on its route
    /// may have gone down, or its id moved to another edge, after the route was chosen
    /// and before the visa was stored; `path` is the visa's recorded node path, against
    /// which each route link's endpoints are checked, and `egress` the destination's
    /// docking node, at which that path must end;
    /// the link-down revocation pass lists the visas stored when it ran, so it can miss
    /// this one. Called once the visa is committed: if the link went down before this
    /// check, the check catches it; if it goes down after, the pass finds the visa.
    ///
    /// A stale visa is marked `PendingRevoke` and an error is returned either way, so
    /// `create_visa` never hands it out. If the revocation write fails, the visa is also
    /// quarantined -- never handed out by [VisaMgr::get_pending_visas_for_node], which
    /// also retries the revocation -- and an error is returned so `create_visa` does not
    /// return it either. This works whether a route link went down or was removed.
    pub(crate) async fn revoke_if_route_down(
        &self,
        asm: &Assembly,
        visa_id: u64,
        links: &[LinkId],
        path: Option<&[IpAddr]>,
        egress: Option<IpAddr>,
    ) -> Result<(), ServiceError> {
        // With a recorded path, it must end at the destination's docking node
        // (`egress`, looked up afresh): the path itself was derived from the mutable
        // router after the route was chosen, so a link id moved in between would
        // otherwise validate against a path to the wrong node.
        let ends_ok = match (path, egress) {
            (Some(p), Some(e)) => p.last() == Some(&e),
            (Some(_), None) => false,
            (None, _) => true,
        };
        if ends_ok && asm.topo_mgr.route_still_valid(links, path) {
            // The route looks valid now, but a link may have gone down and come back
            // up since the visa was stored: its revocation pass then revoked the visa
            // already, and link recovery must not make it issuable again.
            if !self.repo.is_issuable(visa_id) {
                return Err(ServiceError::Internal(format!(
                    "visa {visa_id}: revoked while it was issued"
                )));
            }
            return Ok(());
        }
        warn!(target: VISA, "visa {visa_id}: a link on its route went down while it was issued; revoking it");
        if let Err(e) = self.mark_visa_revoked(visa_id).await {
            self.quarantine(visa_id);
            return Err(ServiceError::Internal(format!(
                "visa {visa_id}: its route went down while it was issued and revoking it failed: {e}"
            )));
        }
        // Revoked, but never hand it out: the requester would otherwise get an Allow
        // and a visa on a route that is already down.
        Err(ServiceError::Internal(format!(
            "visa {visa_id}: its route went down while it was issued; revoked"
        )))
    }

    /// As [VisaMgr::create_visa], but with the node path supplied rather than derived from
    /// a route, and the requesting node's install state given (every other node on the path
    /// starts pending install). For visas whose path is not routed -- see
    /// [VisaMgr::mint_bootstrap_visa].
    async fn create_visa_with_path(
        &self,
        asm: &Assembly,
        requesting_node: &IpAddr,
        requester_state: db::NodeVisaState,
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
            // Per node: set when the visa is actualized for each node on its path
            // (see [VisaMgr::actualize_visa_for_target_node]).
            prev_hop: None,
        };

        // The store also updates the visa state along the path: `requester_state` for the
        // requesting node, pending install for every other node on the path.
        self.repo
            .store_visa(&visa, metadata.clone(), requester_state)
            .await?;

        info!("created visa {visa_id}");
        Ok(VisaWithMetadata::new(visa, metadata))
    }

    /// Visas waiting to be installed on `node_addr`. Quarantined visas (see
    /// [VisaMgr::revoke_if_route_down]) are never returned; this call also retries
    /// their revocation, so housekeeping drives the retry.
    pub async fn get_pending_visas_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        self.retry_quarantined_revocations().await;
        let quarantined = self.quarantine.lock().unwrap().clone();
        let visas = self
            .repo
            .get_visas_for_node_by_state(node_addr, db::NodeVisaState::PendingInstall)?
            .into_iter()
            .filter(|v| !quarantined.contains(&v.issuer_id))
            .collect();
        Ok(visas)
    }

    /// The visas pending on `node_addr` that may be pushed to it now: those from
    /// [VisaMgr::get_pending_visas_for_node], minus any copy for the *ingress* of a visa's
    /// path (its first node) while another node on the path has not yet acknowledged its
    /// own copy.
    ///
    /// This is the "ingress last" rule (gate g89 q4, ZODE_LINKS.md J11). The ingress is
    /// where a flow enters the fabric, and installing a visa there is what makes the node
    /// use it -- for a visa superseding one with the same five-tuple, it starts the rebind.
    /// Holding the ingress copy back until every other hop holds its copy means the rebind
    /// never reaches a hop that cannot bind it. The VSS worker's push goes through here, so
    /// the rule holds whichever order the acknowledgements arrive in. A visa with no path
    /// has one node and no ordering.
    pub async fn deliverable_visas_for_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<Visa>, ServiceError> {
        let pending = self.get_pending_visas_for_node(node_addr).await?;
        Ok(pending
            .into_iter()
            .filter(|v| self.other_hops_installed_if_ingress(v.issuer_id, node_addr))
            .collect())
    }

    /// True unless `node_addr` is the first node of the visa's path and some other node on
    /// the path has not acknowledged its copy (is not `Installed`). See
    /// [VisaMgr::deliverable_visas_for_node].
    fn other_hops_installed_if_ingress(&self, visa_id: u64, node_addr: &IpAddr) -> bool {
        let Ok(md) = self.repo.get_visa_metadata_by_id(visa_id) else {
            return false; // gone meanwhile: nothing to deliver
        };
        match md.path.as_deref() {
            Some([ingress, rest @ ..]) if ingress == node_addr => rest.iter().all(|hop| {
                self.repo.get_node_visa_state(visa_id, hop) == Some(db::NodeVisaState::Installed)
            }),
            _ => true,
        }
    }

    /// Whether `visa_id` may still be granted to `node_addr`: staged there as
    /// `PendingInstall` or `Installed`, and not quarantined. For visas prepared before
    /// a caller took the topology lock (`register_vss`): one revoked, acknowledged or
    /// quarantined meanwhile must not be granted again.
    pub fn still_grantable(&self, visa_id: u64, node_addr: &IpAddr) -> bool {
        let staged = matches!(
            self.repo.get_node_visa_state(visa_id, node_addr),
            Some(db::NodeVisaState::PendingInstall | db::NodeVisaState::Installed)
        );
        staged && !self.quarantine.lock().unwrap().contains(&visa_id)
    }

    /// Quarantine a visa whose revocation write failed: it is never handed out by
    /// [VisaMgr::get_pending_visas_for_node], which also retries the revocation until
    /// it succeeds. Covers visas installed or pending on any route, whatever later
    /// happens to the link that made them stale.
    pub(crate) fn quarantine(&self, visa_id: u64) {
        self.quarantine.lock().unwrap().insert(visa_id);
    }

    /// Try again to revoke every quarantined visa; drop each one whose revocation
    /// now succeeds (or that no longer exists).
    async fn retry_quarantined_revocations(&self) {
        let ids: Vec<u64> = self.quarantine.lock().unwrap().iter().copied().collect();
        for visa_id in ids {
            match self.mark_visa_revoked(visa_id).await {
                Ok(_) => {
                    self.quarantine.lock().unwrap().remove(&visa_id);
                    info!(target: VISA, "visa {visa_id}: quarantined stale visa revoked on retry");
                }
                Err(e) => {
                    warn!(target: VISA, "visa {visa_id}: quarantined stale visa still not revoked: {e}")
                }
            }
        }
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

        // A genuinely absent actor is unresolved (skipped); a store read error
        // is propagated, so a sweep counts it as a failure and keeps the work
        // for a retry instead of treating the visa as settled (#63 review).
        let (Some(src), Some(dst)) = (
            asm.actor_mgr.get_actor_by_zpr_addr(&src_zpr).await?,
            asm.actor_mgr.get_actor_by_zpr_addr(&dst_zpr).await?,
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
        let ids = self.get_visa_ids_for_actors(actor_addrs).await?;
        self.revoke_visa_ids(&ids).await;
        Ok(())
    }

    /// Revoke each of `ids` everywhere: mark every node holding it `PendingRevoke`, so VSS
    /// housekeeping revokes it from those nodes and removes it on their acks. A visa with
    /// no node left to revoke from is removed at once instead of waiting for its TTL.
    /// Failures are logged and the rest carry on. The visas themselves are never changed.
    pub async fn revoke_visa_ids(&self, ids: &[u64]) {
        for &id in ids {
            // Log-and-continue: one failure must not strand the remaining visas.
            match self.repo.mark_visa_revoked(id).await {
                Ok(true) => {}
                Ok(false) => continue, // vanished/expired between query and mark
                Err(e) => {
                    warn!(target: VISA, "failed to mark visa {id} revoked: {e}");
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

/// The node that hands off to `target_node` on `path`: the one before it, since the path runs
/// in flow order. `None` if `target_node` is the ingress node or is not on the path at all.
fn prev_hop_in_path<'a>(path: &'a [IpAddr], target_node: &IpAddr) -> Option<&'a IpAddr> {
    let pos = path.iter().position(|n| n == target_node)?;
    path.get(pos.checked_sub(1)?)
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
        assert!(result.prev_hop.is_none(), "no path, no previous hop");
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
        // A single-node visa never arrives by StreamIdRequest, so it names no
        // previous hop (zl-zipline#245, g65 q2).
        assert!(
            result.prev_hop.is_none(),
            "single-node visa, no previous hop"
        );
    }

    /// Each node's copy names the node before it on the flow-order path as its previous
    /// hop, which is the only node it may accept a StreamIdRequest for the visa from
    /// (zl-zipline#245). The ingress node has none: the flow starts there. The reverse
    /// visa stores its own flow order [C, B, A], so the roles and previous hops flip with it.
    #[tokio::test]
    async fn test_actualize_sets_prev_hop_from_flow_order_path() {
        let mgr = make_mgr().await;
        let a: IpAddr = PATH_NODE_A.parse().unwrap();
        let b: IpAddr = PATH_NODE_B.parse().unwrap();
        let c: IpAddr = PATH_NODE_C.parse().unwrap();
        let mut reverse_path = three_node_path();
        reverse_path.reverse();
        let forward = store_test_visa(&mgr, 1, Some(three_node_path())).await;
        let reverse = store_test_visa(&mgr, 2, Some(reverse_path)).await;

        // (visa, target node, expected prev_hop): ingress, intermediary, egress per direction.
        let cases = [
            (&forward, a, None),
            (&forward, b, Some(a)),
            (&forward, c, Some(b)),
            (&reverse, c, None),
            (&reverse, b, Some(c)),
            (&reverse, a, Some(b)),
        ];
        for (visa, node, expected) in cases {
            let result = mgr
                .actualize_visa_for_target_node(visa.clone(), &node)
                .await
                .unwrap();
            assert_eq!(
                result.prev_hop, expected,
                "visa {} actualized for {node}",
                visa.issuer_id
            );
        }
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

    /// Ingress last (gate g89 q4, ZODE_LINKS.md J11): on a three-node path [A, B, C] the
    /// ingress A's pending copy is held back until B and C have both acknowledged theirs.
    /// B and C are deliverable from the start.
    #[tokio::test]
    async fn test_ingress_copy_deliverable_only_after_every_other_node_installed() {
        let mgr = make_mgr().await;
        let a: IpAddr = "fd5a:5052::a".parse().unwrap();
        let b: IpAddr = "fd5a:5052::b".parse().unwrap();
        let c: IpAddr = "fd5a:5052::c".parse().unwrap();
        let visa = make_visa(820, Duration::from_secs(60));
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
            .store_visa(&visa, md, db::NodeVisaState::PendingInstall)
            .await
            .unwrap();
        let has = |v: Vec<Visa>| v.iter().any(|v| v.issuer_id == 820);

        assert!(has(mgr.deliverable_visas_for_node(&b).await.unwrap()));
        assert!(has(mgr.deliverable_visas_for_node(&c).await.unwrap()));
        assert!(!has(mgr.deliverable_visas_for_node(&a).await.unwrap()));

        mgr.visa_installed(820, &b).await.unwrap();
        assert!(
            !has(mgr.deliverable_visas_for_node(&a).await.unwrap()),
            "C has not acknowledged yet"
        );

        mgr.visa_installed(820, &c).await.unwrap();
        assert!(has(mgr.deliverable_visas_for_node(&a).await.unwrap()));
    }

    /// A visa with no path has no ingress ordering: its one node gets it at once.
    #[tokio::test]
    async fn test_pathless_visa_is_deliverable_at_once() {
        let mgr = make_mgr().await;
        let node: IpAddr = NODE_ADDR.parse().unwrap();
        store_node_visa(&mgr, 821, node, db::NodeVisaState::PendingInstall).await;
        let ready = mgr.deliverable_visas_for_node(&node).await.unwrap();
        assert!(ready.iter().any(|v| v.issuer_id == 821));
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
