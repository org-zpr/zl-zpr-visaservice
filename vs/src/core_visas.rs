//! A node's core visas: the three visas it needs to talk to the visa service at all
//! (ZODE_LINKS.md "Keeping the core visas alive"):
//! - its VSAPI pair, `node:0 -> vs:VSAPI` and `vs:VSAPI -> node:0` (J5a), issued when a
//!   VS-API session starts (`authenticate`, or `open` for a reconnect), and
//! - its VSS visa, `vs:0 -> node:VSS` (J5b), issued on every `registerVss`.
//!
//! **Visas are immutable** (core tenet). Everything here issues *new* visas. A granted visa
//! is never edited. A live stream moves onto a new visa for the same five-tuple by
//! supersede-and-rebind (J11), which the nodes do.
//!
//! **A newer issue never revokes an older one.** The visas it supersedes -- a previous
//! session's pair, a previous VSS visa, a renewed visa, the bootstrap pair -- are left to
//! expire. Revoking them at issue time could pull a visa a node still uses before its
//! replacement has reached every hop (ingress last, below). Core visas are revoked only when
//! the join they belong to is over: by a rejoin ([revoke_previous_join]) or a disconnect.
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
use std::time::SystemTime;

use libeval::attribute::key;
use tracing::{debug, info};
use zpr::vsapi_types::{CommFlag, PacketDesc, VsapiFiveTuple};

use crate::assembly::Assembly;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::VISA;
use crate::packet::make_fivetuple_tcp;
use crate::visa_bootstrap::BOOTSTRAP_VISA_ZPL;
use crate::visa_mgr::{VisaWithMetadata, dock_pep_matches_five_tuple};
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

/// Serializes core-visa issuance, so the session check and the mint run as one step: a call
/// for a session that has been replaced in the meantime fails its session check and mints
/// nothing. The rejoin teardown takes it too ([lock_issuance]), so it never interleaves with
/// an issuance for the session it ends.
///
/// ponytail: one global lock, held across a visa request (milliseconds, bounded by
/// `config::DEFAULT_VISA_REQ_TIMEOUT`). Issuance happens once per session start,
/// `registerVss` and renewal; switch to per-node locks if that ever becomes a hot path.
static ISSUE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Proof that the caller holds [ISSUE_LOCK]; see [lock_issuance].
pub(crate) type IssueGuard = tokio::sync::MutexGuard<'static, ()>;

/// Take [ISSUE_LOCK] for a step outside this module that must not interleave with core-visa
/// issuance: the rejoin teardown (`visa_bootstrap::request_bootstrap_visas`).
///
/// Lock order: this lock first, then the topology lock, then the node commit lock. Issuance
/// mints through the visa-request pipeline while holding it, and the pipeline can take the
/// topology lock (an attribute refresh commits under it), so never wait for this lock while
/// holding the topology lock.
pub(crate) async fn lock_issuance() -> IssueGuard {
    ISSUE_LOCK.lock().await
}

/// Err unless `session` is `node`'s current VS-API session: the `zpr.session` of its stored
/// node actor (two `None`s match, as in the VS-API handle's liveness check). A node with no
/// stored node actor has no session at all.
pub(crate) async fn require_current_session(
    asm: &Assembly,
    node: &IpAddr,
    session: Option<&str>,
) -> Result<(), ServiceError> {
    let stored = match asm.actor_mgr.get_actor_by_zpr_addr(node).await? {
        Some(actor) if actor.is_node() => actor,
        _ => {
            return Err(ServiceError::Internal(format!(
                "node {node} has no VS-API session: no core visas"
            )));
        }
    };
    let current = stored
        .get_attribute(key::SESSION)
        .and_then(|a| a.get_single_value().ok());
    if current != session {
        return Err(ServiceError::Internal(format!(
            "node {node}: session {session:?} is no longer current: no core visas"
        )));
    }
    Ok(())
}

/// J5a: issue `node` its own VSAPI pair for a VS-API session that has just started. Returns
/// the new IDs, forward first.
///
/// The visas with the same five-tuples -- the bootstrap pair, a previous session's pair --
/// are left alone: they carry the session until the node rebinds onto the new pair (J11),
/// then expire (J5c, module docs).
///
/// `session` is the VS-API session (`zpr.session`) this is issued for. If it is no longer
/// the node's current session, nothing is minted and an error is returned: see
/// [ISSUE_LOCK].
pub(crate) async fn issue_vsapi_visas(
    asm: &Assembly,
    node: &IpAddr,
    session: Option<&str>,
) -> Result<[u64; 2], ServiceError> {
    let _issuing = ISSUE_LOCK.lock().await;
    require_current_session(asm, node, session).await?;
    let fts = vsapi_five_tuples(asm, node)?;
    // The forward packet's ports as a client sends them (wildcard source port); the reverse
    // is the same packet seen from the server, which policy evaluates as the reply. Both
    // directions store the wildcard on the node's side, matching `fts`.
    let [fwd_ft, rev_ft] = &fts;
    let fwd = mint_core_visa(asm, packet_for(fwd_ft)).await?;
    let rev = mint_core_visa(asm, packet_for(rev_ft)).await?;
    info!(target: VISA, "node {node}: new VSAPI visas {fwd} (forward) and {rev} (reverse) for its session (J5a)");
    Ok([fwd, rev])
}

/// J5b: issue `node` a new VSS visa for the VSS it has just registered on `vss_port`.
/// Returns the new ID. The previous VSS visa, if any, is left to expire (module docs).
///
/// A new visa every time, never a reused one: after a rejoin the node has lost every visa
/// (R9), and an installed record here says nothing about what the node holds now.
///
/// `session` is the caller's VS-API session, checked as in [issue_vsapi_visas].
pub(crate) async fn issue_vss_visa(
    asm: &Assembly,
    node: &IpAddr,
    vss_port: u16,
    session: Option<&str>,
) -> Result<u64, ServiceError> {
    let _issuing = ISSUE_LOCK.lock().await;
    require_current_session(asm, node, session).await?;
    let ft = vss_five_tuple(asm, node, vss_port)?;
    let id = mint_core_visa(asm, packet_for(&ft)).await?;
    info!(target: VISA, "node {node}: new VSS visa {id} (J5b)");
    Ok(id)
}

/// J9 threshold (gate g89 q3): a core visa is renewed once this fraction of its lifetime,
/// `(numerator, denominator)`, has passed. 2/3 leaves the last third for the push, the
/// rebind (J11) and retries on later heartbeats, while the current visas still work.
const RENEW_AT: (u32, u32) = (2, 3);

/// Whether a visa created at `created` and expiring at `expires` has reached [RENEW_AT] of
/// its lifetime at `now`. A visa that expires before it was created is nonsense, so due.
fn renewal_due(created: SystemTime, expires: SystemTime, now: SystemTime) -> bool {
    let Ok(lifetime) = expires.duration_since(created) else {
        return true;
    };
    now >= created + lifetime * RENEW_AT.0 / RENEW_AT.1
}

/// J9: renew `node`'s core visas before they expire. For each of the three -- the VSAPI pair
/// and the VSS visa on `vss_port` -- the newest one still grantable to the node is looked
/// at, and once it has reached [RENEW_AT] of its lifetime at `now`, a NEW visa is minted for
/// the same five-tuple and delivered in ingress-last order, like every core visa. Returns
/// the new IDs.
///
/// The visa being renewed is never touched: it keeps working until the node has rebound
/// onto the new one (J11), then expires on its own. Only the newest visa per five-tuple
/// counts, so a renewed generation is not renewed again: right after a renewal the newest
/// is the fresh visa.
///
/// Runs on the node's VSS worker heartbeat (`vss_worker::do_housekeeping`): the worker
/// exists only while the node has a registered VSS, which is the connection the renewal is
/// pushed over, and the heartbeat is also what retries a push that failed. That makes a
/// per-node timer unnecessary. A failed mint is retried by the next heartbeat too, since the
/// old visa is still due then. A node with no VS-API session (no stored node actor) gets
/// nothing: it comes back through a rejoin (J10). A five-tuple with no core visa at all is
/// skipped; issuing them is J5a/J5b's job.
pub(crate) async fn renew_core_visas(
    asm: &Assembly,
    node: &IpAddr,
    vss_port: u16,
    now: SystemTime,
) -> Result<Vec<u64>, ServiceError> {
    // Under the issuance lock: a renewal must not interleave with a session's
    // issuance or rejoin step (see [ISSUE_LOCK]).
    let _issuing = ISSUE_LOCK.lock().await;
    match asm.actor_mgr.get_actor_by_zpr_addr(node).await? {
        Some(actor) if actor.is_node() => {}
        _ => {
            debug!(target: VISA, "node {node} has no VS-API session: no core-visa renewal");
            return Ok(Vec::new());
        }
    }
    let [fwd, rev] = vsapi_five_tuples(asm, node)?;
    let mut renewed = Vec::new();
    for ft in [fwd, rev, vss_five_tuple(asm, node, vss_port)?] {
        let newest = core_visas_for(asm, node, &ft)
            .await?
            .into_iter()
            .filter(|vwm| asm.visa_mgr.still_grantable(vwm.visa.issuer_id, node))
            .max_by_key(|vwm| vwm.visa.issuer_id); // IDs only go up
        let Some(current) = newest else {
            continue;
        };
        if !renewal_due(current.metadata.ctime, current.visa.expires, now) {
            continue;
        }
        let id = mint_core_visa(asm, packet_for(&ft)).await?;
        info!(target: VISA, "node {node}: core visa {} renewed as {id} (J9)", current.visa.issuer_id);
        renewed.push(id);
    }
    Ok(renewed)
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

/// Every live visa with `node` as an endpoint for which `wanted` holds.
async fn node_visas_where(
    asm: &Assembly,
    node: &IpAddr,
    wanted: impl Fn(&VisaWithMetadata) -> bool,
) -> Result<Vec<VisaWithMetadata>, ServiceError> {
    let mut out = Vec::new();
    for id in asm.visa_mgr.get_visa_ids_for_actors(&[*node]).await? {
        let Some(vwm) = asm.visa_mgr.get_visa_with_metadata_by_id(id).await? else {
            continue; // expired meanwhile
        };
        if wanted(&vwm) {
            out.push(vwm);
        }
    }
    Ok(out)
}

/// `node`'s core visas for `ft`: its visas whose dock PEP is `ft`, except its bootstrap
/// visas, which are not core visas (J5c).
async fn core_visas_for(
    asm: &Assembly,
    node: &IpAddr,
    ft: &VsapiFiveTuple,
) -> Result<Vec<VisaWithMetadata>, ServiceError> {
    node_visas_where(asm, node, |vwm| {
        vwm.metadata.zpl != BOOTSTRAP_VISA_ZPL && dock_pep_matches_five_tuple(&vwm.visa, ft)
    })
    .await
}

/// Rejoin (J6, ZODE_LINKS.md "Settled after the builder check"): revoke every visa that
/// carried `node`'s previous join -- every visa between `node` and the visa service: its
/// bootstrap pairs, its VSAPI pairs and its VSS visas, whatever VSS port each was issued
/// for (issuance leaves superseded ones to expire, so there can be several). The new join
/// starts from fresh bootstrap visas. The visas are revoked through the normal revoke path,
/// never edited.
///
/// The caller holds the issuance lock (`_issuing`), so no issuance for the session being
/// ended runs alongside this (see [ISSUE_LOCK]).
///
/// ponytail: a core-visa request that timed out is not cancelled by the pipeline, so it can
/// still commit after this has run. That visa is policy-evaluated and covers only the
/// node's own VS-API or VSS flow, so it grants nothing new; it expires on its own. Fence
/// pipeline commits by session if that ever matters.
pub(crate) async fn revoke_previous_join(
    asm: &Assembly,
    _issuing: &IssueGuard,
    node: &IpAddr,
) -> Result<(), ServiceError> {
    let vs = asm.config.get_vs_addr();
    let ids: Vec<u64> = node_visas_where(asm, node, |vwm| {
        let ft = &vwm.metadata.five_tuple;
        (ft.source_addr == *node && ft.dest_addr == vs)
            || (ft.source_addr == vs && ft.dest_addr == *node)
    })
    .await?
    .iter()
    .map(|vwm| vwm.visa.issuer_id)
    .collect();
    if !ids.is_empty() {
        info!(target: VISA, "node {node}: rejoin revokes the visas of its previous join {ids:?}");
        asm.visa_mgr.revoke_visa_ids(&ids).await;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use libeval::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE};
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
    pub(crate) const RELAY: &str = "fd5a:5052:3000::1";
    /// A Zode joined to the relay over its initial link.
    pub(crate) const ZODE: &str = "fd5a:5052:3000::7";
    /// The port the nodes' VSS listens on.
    pub(crate) const VSS_PORT: u16 = 8183;

    /// A relay that docks the visa service and a Zode linked to it, both connected, under a
    /// policy standing in for the compiler's two built-in rules: nodes may reach the visa
    /// service's VSAPI port (service `vsapi`, provided by the visa service), and the visa
    /// service may reach a node's VSS port (service `vss`, provided by each node). A
    /// visa-request arena runs, so core visas mint through the real pipeline.
    pub(crate) async fn build_net() -> (Arc<Assembly>, IpAddr, IpAddr) {
        build_net_with_policy(make_allow_policy_for_tcp_services(&[
            ("vsapi", config::VSAPI_PORT),
            ("vss", VSS_PORT),
        ]))
        .await
    }

    /// As [build_net], under `policy` (container bytes) instead of the two built-in rules.
    pub(crate) async fn build_net_with_policy(policy: Vec<u8>) -> (Arc<Assembly>, IpAddr, IpAddr) {
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::FakeResolver;
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let (vreq_tx, vreq_rx) = mpsc::channel(8);
        let mut asm = new_assembly_for_tests(Some(vreq_tx)).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            policy,
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

    /// Mint the Zode's bootstrap pair the way the relay join does, forward first.
    async fn mint_bootstrap_pair(asm: &Arc<Assembly>, relay: &IpAddr, zode: &IpAddr) -> [Visa; 2] {
        let policy = asm.policy_mgr.get_current();
        let mut out = Vec::new();
        for direction in [Direction::Forward, Direction::Reverse] {
            out.push(
                asm.visa_mgr
                    .mint_bootstrap_visa(asm, &policy, zode, relay, direction)
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

        let ids = issue_vsapi_visas(&asm, &zode, None).await.unwrap();

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

    /// A new session gets a new VSAPI pair and revokes nothing: neither the previous
    /// session's pair nor the bootstrap pair. Superseded core visas expire on their own, as
    /// renewed ones do (J9, J11): revoking them at issue could pull a pair a node still uses
    /// before its replacement has reached every hop. Only the end of a join revokes them
    /// (`revoke_previous_join`).
    #[tokio::test]
    async fn new_session_revokes_nothing() {
        let (asm, relay, zode) = build_net().await;
        let bootstrap = mint_bootstrap_pair(&asm, &relay, &zode).await;

        let first = issue_vsapi_visas(&asm, &zode, None).await.unwrap();
        let second = issue_vsapi_visas(&asm, &zode, None).await.unwrap();

        for id in first {
            assert!(!second.contains(&id), "every session gets new visas");
        }
        for id in first
            .iter()
            .chain(&second)
            .chain(&bootstrap.map(|b| b.issuer_id))
        {
            assert!(
                not_revoked(&asm, *id, &[relay, zode]).await,
                "visa {id} kept"
            );
        }
    }

    /// J5b: every `registerVss` mints a new VSS visa -- even when the previous one is
    /// recorded installed -- and leaves the previous one to expire.
    #[tokio::test]
    async fn register_vss_mints_a_new_vss_visa_every_time() {
        let (asm, relay, zode) = build_net().await;
        let vss = std::net::SocketAddr::new(zode, VSS_PORT);

        let first = asm
            .visa_mgr
            .post_register_vss_visas_for_node(asm.clone(), &zode, &vss, None)
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
            .post_register_vss_visas_for_node(asm.clone(), &zode, &vss, None)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);

        assert_ne!(first[0].issuer_id, second[0].issuer_id);
        assert_eq!(pep_tuple(&first[0]), pep_tuple(&second[0]));
        assert_eq!(
            pep_tuple(&second[0]),
            (asm.config.get_vs_addr(), 0, zode, VSS_PORT)
        );
        assert!(not_revoked(&asm, first[0].issuer_id, &[relay, zode]).await);
        assert!(not_revoked(&asm, second[0].issuer_id, &[relay, zode]).await);
    }

    /// The end of a join revokes every VSS visa of that join, also one for a VSS port the
    /// node registered earlier and then replaced: issuance leaves the older one to expire,
    /// so the teardown cannot go by the latest registered port alone.
    #[tokio::test]
    async fn revoke_previous_join_takes_vss_visas_of_every_port() {
        let (asm, relay, zode) = build_net_with_policy(make_allow_policy_for_tcp_services(&[
            ("vsapi", config::VSAPI_PORT),
            ("vss", VSS_PORT),
            ("vss", VSS_PORT + 1),
        ]))
        .await;
        let first = issue_vss_visa(&asm, &zode, VSS_PORT, None).await.unwrap();
        let second = issue_vss_visa(&asm, &zode, VSS_PORT + 1, None)
            .await
            .unwrap();
        let [fwd, rev] = issue_vsapi_visas(&asm, &zode, None).await.unwrap();

        revoke_previous_join(&asm, &lock_issuance().await, &zode)
            .await
            .unwrap();

        for id in [first, second, fwd, rev] {
            assert!(
                !not_revoked(&asm, id, &[relay, zode]).await,
                "visa {id} revoked"
            );
        }
    }

    /// The `registerVss` reply carries only the node's copy of its VSS visa. Everything else
    /// -- the J5a pair included -- goes by VSS push (gate g89 q4), in order.
    #[tokio::test]
    async fn register_vss_reply_is_only_the_vss_visa() {
        let (asm, _relay, zode) = build_net().await;
        let vsapi = issue_vsapi_visas(&asm, &zode, None).await.unwrap();

        let reply = asm
            .visa_mgr
            .post_register_vss_visas_for_node(
                asm.clone(),
                &zode,
                &std::net::SocketAddr::new(zode, VSS_PORT),
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply.len(), 1);
        assert!(!vsapi.contains(&reply[0].issuer_id));
        assert_eq!(pep_tuple(&reply[0]).3, VSS_PORT);
        // It is the node's (egress) copy: no forwarding.
        assert!(reply[0].fwd_pep.is_none());
    }

    /// Issuance belongs to one VS-API session. A call made for a session that is no longer
    /// the node's current one mints nothing and revokes nothing.
    #[tokio::test]
    async fn a_stale_session_issues_and_revokes_nothing() {
        let (asm, relay, zode) = build_net().await;
        let mut actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&zode)
            .await
            .unwrap()
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::SESSION).value("2-current"))
            .unwrap();
        asm.actor_mgr
            .update_actor(&actor, &Default::default())
            .await
            .unwrap();

        let current = issue_vsapi_visas(&asm, &zode, Some("2-current"))
            .await
            .unwrap();
        let vss = issue_vss_visa(&asm, &zode, VSS_PORT, Some("2-current"))
            .await
            .unwrap();
        let before = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();

        assert!(issue_vsapi_visas(&asm, &zode, Some("1-old")).await.is_err());
        assert!(
            issue_vss_visa(&asm, &zode, VSS_PORT, Some("1-old"))
                .await
                .is_err()
        );

        let mut after = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();
        let mut before = before;
        before.sort();
        after.sort();
        assert_eq!(after, before, "nothing minted for the stale session");
        for id in current.iter().chain([&vss]) {
            assert!(
                not_revoked(&asm, *id, &[relay, zode]).await,
                "nothing revoked"
            );
        }
    }

    /// Ordered push, end to end: the forward VSAPI visa ingresses at the Zode, so the relay's
    /// copy is pushed first, and the Zode's copy becomes deliverable only once the relay has
    /// acknowledged.
    #[tokio::test]
    async fn ingress_copy_is_delivered_only_after_the_relay_acks() {
        let (asm, relay, zode) = build_net().await;
        let (tx, mut relay_vss) = mpsc::channel(8);
        asm.vss_mgr.insert_test_handle(relay, tx);

        let [fwd, _rev] = issue_vsapi_visas(&asm, &zode, None).await.unwrap();

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

    // ---- J9 renewal ----

    /// Give the actor at `addr` a `zpr.services` attribute (the provider attribute that bounds
    /// these visas' lifetime in this policy) expiring in `expiry`.
    async fn set_services_expiry(asm: &Assembly, addr: &IpAddr, expiry: Duration) {
        let mut actor = asm
            .actor_mgr
            .get_actor_by_zpr_addr(addr)
            .await
            .unwrap()
            .unwrap();
        let services: Vec<String> = actor
            .get_attribute(key::SERVICES)
            .unwrap()
            .get_value()
            .to_vec();
        actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(expiry)
                    .values(services.iter().map(String::as_str)),
            )
            .unwrap();
        asm.actor_mgr
            .update_actor(&actor, &Default::default())
            .await
            .unwrap();
    }

    /// Issue the Zode its three core visas (J5a, J5b); returns them forward VSAPI, reverse
    /// VSAPI, VSS.
    async fn issue_all(asm: &Arc<Assembly>, zode: &IpAddr) -> [u64; 3] {
        let [fwd, rev] = issue_vsapi_visas(asm, zode, None).await.unwrap();
        let vss = issue_vss_visa(asm, zode, VSS_PORT, None).await.unwrap();
        [fwd, rev, vss]
    }

    /// The earliest instant at which every one of `ids` has reached [RENEW_AT].
    async fn renew_point(asm: &Assembly, ids: &[u64]) -> std::time::SystemTime {
        let mut latest = std::time::UNIX_EPOCH;
        for id in ids {
            let vwm = asm
                .visa_mgr
                .get_visa_with_metadata_by_id(*id)
                .await
                .unwrap()
                .unwrap();
            let life = vwm.visa.expires.duration_since(vwm.metadata.ctime).unwrap();
            latest = latest.max(vwm.metadata.ctime + life * RENEW_AT.0 / RENEW_AT.1);
        }
        latest
    }

    #[test]
    fn renewal_is_due_from_two_thirds_of_the_lifetime() {
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let exp = t + Duration::from_secs(3 * 3600);
        assert!(!renewal_due(t, exp, t));
        assert!(!renewal_due(t, exp, t + Duration::from_secs(2 * 3600 - 1)));
        assert!(renewal_due(t, exp, t + Duration::from_secs(2 * 3600)));
        assert!(renewal_due(t, exp, exp + Duration::from_secs(1)));
    }

    /// Nothing is renewed before RENEW_AT.
    #[tokio::test]
    async fn nothing_is_renewed_before_renew_at() {
        let (asm, _relay, zode) = build_net().await;
        let ids = issue_all(&asm, &zode).await;
        let before = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();

        let at = renew_point(&asm, &ids).await - Duration::from_secs(5);
        let renewed = renew_core_visas(&asm, &zode, VSS_PORT, at).await.unwrap();

        assert!(renewed.is_empty());
        let after = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();
        assert_eq!(after.len(), before.len());
    }

    /// At RENEW_AT three NEW visas appear for the identical five-tuples, and the old ones are
    /// unchanged: same expiry, not revoked (they expire on their own, J9).
    #[tokio::test]
    async fn at_renew_at_three_new_visas_replace_nothing() {
        let (asm, relay, zode) = build_net().await;
        let old = issue_all(&asm, &zode).await;
        let mut old_visas = Vec::new();
        for id in old {
            old_visas.push(stored(&asm, id).await);
        }

        let at = renew_point(&asm, &old).await;
        let renewed = renew_core_visas(&asm, &zode, VSS_PORT, at).await.unwrap();

        assert_eq!(renewed.len(), 3, "the VSAPI pair and the VSS visa");
        for (new_id, old) in renewed.iter().zip(old_visas.iter()) {
            assert!(!old_visas.iter().any(|o| o.issuer_id == *new_id), "new IDs");
            assert_eq!(pep_tuple(&stored(&asm, *new_id).await), pep_tuple(old));
            let old_now = stored(&asm, old.issuer_id).await;
            assert_eq!(old_now.expires, old.expires, "old visa untouched");
            assert!(not_revoked(&asm, old.issuer_id, &[relay, zode]).await);
        }
    }

    /// A node with no VS-API session gets nothing: its rejoin (J10) brings it back.
    #[tokio::test]
    async fn a_disconnected_node_gets_no_renewal() {
        let (asm, _relay, zode) = build_net().await;
        let ids = issue_all(&asm, &zode).await;
        let at = renew_point(&asm, &ids).await;
        // The node disconnects: its node state and its actor record go.
        asm.actor_mgr.remove_node(&zode).await.unwrap();
        asm.actor_mgr.remove_actor_by_zpr_addr(&zode).await.unwrap();
        let before = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();

        let renewed = renew_core_visas(&asm, &zode, VSS_PORT, at).await.unwrap();

        assert!(renewed.is_empty());
        let after = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();
        assert_eq!(after.len(), before.len());
    }

    /// A generation is renewed once. Here the first generation is short-lived and the second
    /// long-lived, so at one instant the first is past RENEW_AT and the second is not: a
    /// second check at that instant must mint nothing.
    #[tokio::test]
    async fn a_generation_is_renewed_only_once() {
        let (asm, relay, zode) = build_net().await;
        let vs_addr = asm.config.get_vs_addr();
        for addr in [vs_addr, zode] {
            set_services_expiry(&asm, &addr, Duration::from_secs(90)).await;
        }
        let first = issue_all(&asm, &zode).await;
        for addr in [vs_addr, zode] {
            set_services_expiry(&asm, &addr, Duration::from_secs(3600)).await;
        }
        let at = renew_point(&asm, &first).await;

        let second = renew_core_visas(&asm, &zode, VSS_PORT, at).await.unwrap();
        assert_eq!(second.len(), 3);
        let again = renew_core_visas(&asm, &zode, VSS_PORT, at).await.unwrap();
        assert!(again.is_empty(), "the first generation was already renewed");
        let _ = relay;
    }
}
