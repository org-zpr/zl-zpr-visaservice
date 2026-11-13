//! A node's core visas: the three visas it needs to talk to the visa service at all
//! (ZODE_LINKS.md "Keeping the core visas alive"):
//! - its VSAPI pair, `node:0 -> vs:VSAPI` and `vs:VSAPI -> node:0` (J5a), issued when a
//!   VS-API session starts (`authenticate`, or `open` for a reconnect), and
//! - its VSS visa, `vs:0 -> node:VSS` (J5b), issued on every `registerVss`.
//!
//! **Visas are immutable** (core tenet). Everything here issues *new* visas. A granted visa
//! is never edited: a node's previous core visas are revoked through the normal revoke path,
//! and its bootstrap pair is left to expire (J5c). A live stream moves onto a new visa for
//! the same five-tuple by supersede-and-rebind (J11), which the nodes do.
//!
//! **Minting.** Every core visa goes through the ordinary visa-request pipeline, so policy
//! evaluates it (the compiler's built-in "allow node access to visa service" and "allow visa
//! service to access node visa support" rules). Nothing here hand-builds a visa.
//!
//! **Delivery order** (gate g89 q4, "ordered push"). The copies for every node on a core
//! visa's path except its *ingress* node -- the first node on the path, where the flow
//! enters the fabric -- are pushed over VSS and acknowledged first, and the ingress copy goes
//! last. The ingress is the node that starts the J11 rebind once its copy is installed, so
//! every other hop already holds its copy when it does. Two pieces give this order:
//! - [mint_core_visa] makes the request as if the ingress node had asked. The pipeline then
//!   pushes every *other* node's copy (`distribute_visa_on_path`) and leaves the ingress
//!   copy pending-install on the ingress node; the caller drops the copy it gets back.
//! - The VSS worker hands a node its pending visas through
//!   [crate::visa_mgr::VisaMgr::deliverable_visas_for_node], which holds back an ingress copy
//!   until every other node on the path has acknowledged its own.
//!
//! The one exception is the node's own copy of its VSS visa, which rides in the
//! `registerVss` reply: it cannot be pushed over the VSS connection it is what opens.
//! The node is the egress of that flow, so its copy goes first either way.

use std::net::IpAddr;

use tracing::{debug, info};
use zpr::vsapi_types::{CommFlag, PacketDesc, VsapiFiveTuple};

use crate::assembly::Assembly;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::VISA;
use crate::packet::make_fivetuple_tcp;
use crate::visa_bootstrap::BOOTSTRAP_VISA_ZPL;
use crate::visa_mgr::dock_pep_matches_five_tuple;
use crate::visa_policy::docking_node_for_addr;
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

/// The two five-tuples of `node`'s VSAPI session, in the shape a stored visa's dock PEP has
/// them: the node's requests `node:0 -> vs:VSAPI` (forward), then the visa service's replies
/// `vs:VSAPI -> node:0` (reverse). The wildcard port is the node's: it is the client. These
/// are also the five-tuples of the node's bootstrap pair, which these visas supersede.
fn vsapi_five_tuples(asm: &Assembly, node: &IpAddr) -> Result<[VsapiFiveTuple; 2], ServiceError> {
    let vs_addr = asm.config.get_vs_addr();
    let vsapi_port = asm.config.core.vsapi_port.unwrap_or(config::VSAPI_PORT);
    Ok([
        make_fivetuple_tcp(*node, vs_addr, 0, vsapi_port)?,
        make_fivetuple_tcp(vs_addr, *node, vsapi_port, 0)?,
    ])
}

/// The five-tuple of the visa service's VSS connection to `node`: `vs:0 -> node:vss_port`.
fn vss_five_tuple(
    asm: &Assembly,
    node: &IpAddr,
    vss_port: u16,
) -> Result<VsapiFiveTuple, ServiceError> {
    make_fivetuple_tcp(asm.config.get_vs_addr(), *node, 0, vss_port)
}

/// J5a: issue `node` its own VSAPI pair for a VS-API session that has just started, and
/// revoke the pair from its previous session, if any. Returns the new IDs, forward first.
///
/// The node's bootstrap pair (same five-tuples) is left alone: it carries the session until
/// the node rebinds onto the new pair (J11), then expires (J5c).
///
/// Revoking the previous session's pair is safe because every session starts with a join
/// (J6, J10): the node's links were wiped (R9), so nothing still runs over those visas.
pub(crate) async fn issue_vsapi_visas(
    asm: &Assembly,
    node: &IpAddr,
) -> Result<[u64; 2], ServiceError> {
    let fts = vsapi_five_tuples(asm, node)?;
    // The forward packet's ports as a client sends them (wildcard source port); the reverse
    // is the same packet seen from the server, which policy evaluates as the reply. Both
    // directions store the wildcard on the node's side, matching `fts`.
    let [fwd_ft, rev_ft] = &fts;
    let fwd = mint_core_visa(asm, packet_for(fwd_ft)).await?;
    let rev = mint_core_visa(asm, packet_for(rev_ft)).await?;
    info!(target: VISA, "node {node}: new VSAPI visas {fwd} (forward) and {rev} (reverse) for its session (J5a)");
    revoke_superseded(asm, node, &fts, &[fwd, rev]).await?;
    Ok([fwd, rev])
}

/// J5b: issue `node` a new VSS visa for the VSS it has just registered on `vss_port`, and
/// revoke its previous VSS visa, if any. Returns the new ID.
///
/// A new visa every time, never a reused one: after a rejoin the node has lost every visa
/// (R9), and an installed record here says nothing about what the node holds now. The
/// previous VSS visa carries nothing either: `registerVss` replaces the VSS connection.
pub(crate) async fn issue_vss_visa(
    asm: &Assembly,
    node: &IpAddr,
    vss_port: u16,
) -> Result<u64, ServiceError> {
    let ft = vss_five_tuple(asm, node, vss_port)?;
    let id = mint_core_visa(asm, packet_for(&ft)).await?;
    info!(target: VISA, "node {node}: new VSS visa {id} (J5b)");
    revoke_superseded(asm, node, &[ft], &[id]).await?;
    Ok(id)
}

/// The packet a core visa is requested for. TCP, both directions allowed: the dock PEP the
/// pipeline derives from it keeps the wildcard port where `ft` has it.
fn packet_for(ft: &VsapiFiveTuple) -> PacketDesc {
    PacketDesc {
        five_tuple: *ft,
        comm_flags: CommFlag::BiDirectional,
    }
}

/// Mint one core visa for `pkt` through the visa-request pipeline, so policy evaluates it,
/// and return its ID.
///
/// The request is made as if by the flow's ingress node: the docking node of its source,
/// which is how the pipeline orients the visa's path (`path_for_flow`), so it is the
/// path's first node. That makes the pipeline push every other node's copy at once and
/// leave the ingress copy pending, for the VSS worker to push once the others have
/// acknowledged (module docs, "Delivery order"). The copy the pipeline hands back is the
/// ingress copy, and it is dropped here on purpose: delivering it now would skip the order.
async fn mint_core_visa(asm: &Assembly, pkt: PacketDesc) -> Result<u64, ServiceError> {
    let source = pkt.five_tuple.source_addr;
    let Some(ingress) = docking_node_for_addr(asm, &source).await else {
        return Err(ServiceError::Internal(format!(
            "cannot mint core visa: source {source} is not docked to any node"
        )));
    };
    match request_visa_wait_response(asm, &ingress, pkt, config::DEFAULT_VISA_REQ_TIMEOUT).await? {
        VisaDecision::Allow(visa, _route) => Ok(visa.issuer_id),
        VisaDecision::Deny(code) => Err(ServiceError::VisaDenied(code.to_string())),
    }
}

/// Revoke every visa with `node` as an endpoint whose dock PEP is one of `fts`, except the
/// ones in `keep` and the node's bootstrap visas (left to expire, J5c). These are the core
/// visas a newer issue has just superseded. They are revoked, never edited.
async fn revoke_superseded(
    asm: &Assembly,
    node: &IpAddr,
    fts: &[VsapiFiveTuple],
    keep: &[u64],
) -> Result<(), ServiceError> {
    let mut superseded = Vec::new();
    for id in asm.visa_mgr.get_visa_ids_for_actors(&[*node]).await? {
        if keep.contains(&id) {
            continue;
        }
        let Some(vwm) = asm.visa_mgr.get_visa_with_metadata_by_id(id).await? else {
            continue; // expired meanwhile
        };
        if vwm.metadata.zpl == BOOTSTRAP_VISA_ZPL {
            continue;
        }
        if fts
            .iter()
            .any(|ft| dock_pep_matches_five_tuple(&vwm.visa, ft))
        {
            superseded.push(id);
        }
    }
    if !superseded.is_empty() {
        debug!(target: VISA, "node {node}: revoking superseded core visas {superseded:?}");
        asm.visa_mgr.revoke_visa_ids(&superseded).await;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use libeval::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE, key};
    use libeval::eval_result::Direction;
    use libeval::route::LinkId;
    use tokio::sync::mpsc;
    use zpr::vsapi_types::{DockPepType, Visa};

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::{
        make_actor_with_services_defexp, make_allow_policy_for_tcp_services,
    };
    use crate::vss::VssCmd;

    /// The node the visa service docks on.
    const RELAY: &str = "fd5a:5052:3000::1";
    /// A Zode joined to the relay over its initial link.
    pub(crate) const ZODE: &str = "fd5a:5052:3000::7";
    /// The port the nodes' VSS listens on.
    const VSS_PORT: u16 = 8183;

    /// A relay that docks the visa service and a Zode linked to it, both connected, under a
    /// policy standing in for the compiler's two built-in rules: nodes may reach the visa
    /// service's VSAPI port (service `vsapi`, provided by the visa service), and the visa
    /// service may reach a node's VSS port (service `vss`, provided by each node). A
    /// visa-request arena runs, so core visas mint through the real pipeline.
    pub(crate) async fn build_net() -> (Arc<Assembly>, IpAddr, IpAddr) {
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::FakeResolver;
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let (vreq_tx, vreq_rx) = mpsc::channel(8);
        let mut asm = new_assembly_for_tests(Some(vreq_tx)).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            make_allow_policy_for_tcp_services(&[("vsapi", config::VSAPI_PORT), ("vss", VSS_PORT)]),
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
        let asm = Arc::new(asm);
        tokio::spawn(crate::visareq_worker::launch_arena(asm.clone(), vreq_rx, 4));

        let relay: IpAddr = RELAY.parse().unwrap();
        let zode: IpAddr = ZODE.parse().unwrap();
        for (addr, cn) in [(RELAY, "relay"), (ZODE, "zode")] {
            let mut node = make_actor_with_services_defexp(ROLE_NODE, addr, &["vss"], cn);
            node.add_attribute(Attribute::builder(key::SUBSTRATE_ADDR).value("10.0.0.1:5000"))
                .unwrap();
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            asm.topo_mgr.add_node(addr.parse().unwrap()).unwrap();
        }
        asm.topo_mgr
            .add_link(relay, zode, LinkId("link-rz".into()), vec![], 1)
            .unwrap();

        let vs_addr = asm.config.get_vs_addr();
        asm.actor_mgr
            .hack_add_adapter_no_node(
                &make_actor_with_services_defexp(
                    ROLE_ADAPTER,
                    &vs_addr.to_string(),
                    &["vsapi"],
                    config::VS_CN,
                ),
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .hack_set_vs_docking_node(&relay)
            .await
            .unwrap();
        (asm, relay, zode)
    }

    /// Mint the Zode's bootstrap pair the way the relay join does today, forward first.
    async fn mint_bootstrap_pair(asm: &Arc<Assembly>, relay: &IpAddr, zode: &IpAddr) -> [Visa; 2] {
        let policy = asm.policy_mgr.get_current();
        let mut out = Vec::new();
        for direction in [Direction::Forward, Direction::Reverse] {
            out.push(
                asm.visa_mgr
                    .vsapi_bootstrap_visa_for_future_peer(asm, &policy, zode, relay, direction)
                    .await
                    .unwrap(),
            );
        }
        out.try_into().unwrap()
    }

    /// The stored (full) visa for `id`.
    async fn stored(asm: &Assembly, id: u64) -> Visa {
        asm.visa_mgr
            .get_visa_by_id(id)
            .await
            .unwrap()
            .expect("visa must be stored")
    }

    /// `(source, source port, dest, dest port)` of a visa's TCP dock PEP.
    fn pep_tuple(visa: &Visa) -> (IpAddr, u16, IpAddr, u16) {
        let pep = visa.dock_pep.as_ref().expect("full visa");
        let DockPepType::TCP(tpep) = &pep.pep else {
            panic!("expected a TCP dock PEP, got {:?}", pep.pep)
        };
        (
            pep.source_addr,
            tpep.source_port,
            pep.dest_addr,
            tpep.dest_port,
        )
    }

    /// True if no node in `nodes` holds `id` as `PendingRevoke`: it has not been revoked.
    async fn not_revoked(asm: &Assembly, id: u64, nodes: &[IpAddr]) -> bool {
        for n in nodes {
            let revoking = asm
                .visa_mgr
                .get_pending_revoke_visa_ids_for_node(n)
                .await
                .unwrap();
            if revoking.contains(&id) {
                return false;
            }
        }
        true
    }

    /// The node path recorded for visa `id`.
    async fn path_of(asm: &Assembly, id: u64) -> Option<Vec<IpAddr>> {
        asm.visa_mgr
            .get_visa_metadata_by_id(id)
            .await
            .unwrap()
            .expect("visa must be stored")
            .path
    }

    /// J5a: after authentication the Zode gets two NEW visas for exactly the five-tuples of
    /// its bootstrap pair, and the bootstrap pair itself is untouched (immutable, J5c).
    #[tokio::test]
    async fn vsapi_visas_are_new_visas_for_the_bootstrap_five_tuples() {
        let (asm, relay, zode) = build_net().await;
        let bootstrap = mint_bootstrap_pair(&asm, &relay, &zode).await;

        let ids = issue_vsapi_visas(&asm, &zode).await.unwrap();

        for (new_id, old) in ids.iter().zip(bootstrap.iter()) {
            assert_ne!(
                *new_id, old.issuer_id,
                "a new visa, never the bootstrap one"
            );
            let new = stored(&asm, *new_id).await;
            assert_eq!(pep_tuple(&new), pep_tuple(old), "same five-tuple");
            // The bootstrap visa is exactly as it was: same expiry, same dock PEP.
            let old_now = stored(&asm, old.issuer_id).await;
            assert_eq!(old_now.expires, old.expires);
            assert_eq!(old_now.dock_pep, old.dock_pep);
            assert!(
                not_revoked(&asm, old.issuer_id, &[relay, zode]).await,
                "J5c: left to expire"
            );
        }
        // Normal lifetime, not the bootstrap one: bounded by MAX_VISA_LIFETIME and well past
        // the minimum.
        let fwd = stored(&asm, ids[0]).await;
        let left = fwd
            .expires
            .duration_since(std::time::SystemTime::now())
            .unwrap();
        assert!(left > config::MIN_VISA_LIFETIME && left <= config::MAX_VISA_LIFETIME);
        // The forward visa ingresses at the Zode, the reverse one at the relay.
        assert_eq!(path_of(&asm, ids[0]).await, Some(vec![zode, relay]));
        assert_eq!(path_of(&asm, ids[1]).await, Some(vec![relay, zode]));
    }

    /// A new session revokes the previous session's VSAPI pair, but never the bootstrap pair
    /// or the new one.
    #[tokio::test]
    async fn new_session_revokes_previous_vsapi_pair_only() {
        let (asm, relay, zode) = build_net().await;
        let bootstrap = mint_bootstrap_pair(&asm, &relay, &zode).await;

        let first = issue_vsapi_visas(&asm, &zode).await.unwrap();
        let second = issue_vsapi_visas(&asm, &zode).await.unwrap();

        for id in first {
            assert!(!second.contains(&id), "every session gets new visas");
            assert!(
                !not_revoked(&asm, id, &[relay, zode]).await,
                "previous pair revoked"
            );
        }
        for id in second {
            assert!(not_revoked(&asm, id, &[relay, zode]).await, "new pair kept");
        }
        for b in bootstrap {
            assert!(
                not_revoked(&asm, b.issuer_id, &[relay, zode]).await,
                "bootstrap kept"
            );
        }
    }

    /// J5b: every `registerVss` mints a new VSS visa -- even when the previous one is
    /// recorded installed -- and revokes the previous one.
    #[tokio::test]
    async fn register_vss_mints_a_new_vss_visa_every_time() {
        let (asm, relay, zode) = build_net().await;
        let vss = std::net::SocketAddr::new(zode, VSS_PORT);

        let first = asm
            .visa_mgr
            .post_register_vss_visas_for_node(asm.clone(), &zode, &vss)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        // register_vss records the reply's visas as installed on the node.
        asm.visa_mgr
            .visa_installed(first[0].issuer_id, &zode)
            .await
            .unwrap();
        let second = asm
            .visa_mgr
            .post_register_vss_visas_for_node(asm.clone(), &zode, &vss)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);

        assert_ne!(first[0].issuer_id, second[0].issuer_id);
        assert_eq!(pep_tuple(&first[0]), pep_tuple(&second[0]));
        assert_eq!(
            pep_tuple(&second[0]),
            (asm.config.get_vs_addr(), 0, zode, VSS_PORT)
        );
        assert!(!not_revoked(&asm, first[0].issuer_id, &[relay, zode]).await);
        assert!(not_revoked(&asm, second[0].issuer_id, &[relay, zode]).await);
    }

    /// The `registerVss` reply carries only the node's copy of its VSS visa. Everything else
    /// -- the J5a pair included -- goes by VSS push (gate g89 q4), in order.
    #[tokio::test]
    async fn register_vss_reply_is_only_the_vss_visa() {
        let (asm, _relay, zode) = build_net().await;
        let vsapi = issue_vsapi_visas(&asm, &zode).await.unwrap();

        let reply = asm
            .visa_mgr
            .post_register_vss_visas_for_node(
                asm.clone(),
                &zode,
                &std::net::SocketAddr::new(zode, VSS_PORT),
            )
            .await
            .unwrap();
        assert_eq!(reply.len(), 1);
        assert!(!vsapi.contains(&reply[0].issuer_id));
        assert_eq!(pep_tuple(&reply[0]).3, VSS_PORT);
        // It is the node's (egress) copy: no forwarding.
        assert!(reply[0].fwd_pep.is_none());
    }

    /// Ordered push, end to end: the forward VSAPI visa ingresses at the Zode, so the relay's
    /// copy is pushed first, and the Zode's copy becomes deliverable only once the relay has
    /// acknowledged.
    #[tokio::test]
    async fn ingress_copy_is_delivered_only_after_the_relay_acks() {
        let (asm, relay, zode) = build_net().await;
        let (tx, mut relay_vss) = mpsc::channel(8);
        asm.vss_mgr.insert_test_handle(relay, tx);

        let [fwd, _rev] = issue_vsapi_visas(&asm, &zode).await.unwrap();

        // The relay is asked to install its copy of the forward visa...
        let resp = loop {
            match tokio::time::timeout(Duration::from_secs(2), relay_vss.recv()).await {
                Ok(Some(VssCmd::PushVisas(visas, resp))) => {
                    if visas.iter().any(|v| v.issuer_id == fwd) {
                        break resp;
                    }
                    let _ = resp.send(Ok(visas.len()));
                }
                Ok(Some(_)) => continue,
                other => panic!("relay never got the forward visa: {:?}", other.is_ok()),
            }
        };
        // ...and until it acks, the Zode's ingress copy is held back.
        let held = asm
            .visa_mgr
            .deliverable_visas_for_node(&zode)
            .await
            .unwrap();
        assert!(
            held.iter().all(|v| v.issuer_id != fwd),
            "ingress copy must wait"
        );

        resp.send(Ok(1)).unwrap();
        // The ack is recorded by the push task; give it a moment.
        let mut delivered = false;
        for _ in 0..50 {
            let ready = asm
                .visa_mgr
                .deliverable_visas_for_node(&zode)
                .await
                .unwrap();
            if ready.iter().any(|v| v.issuer_id == fwd) {
                delivered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(delivered, "after the relay's ack the Zode's copy goes out");
    }
}
