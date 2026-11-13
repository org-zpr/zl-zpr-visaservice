use chrono::prelude::{DateTime, Utc};
use openssl::rand::rand_bytes;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};

use ::zpr::vsapi::v1 as vsapi;
use libeval::actor::Actor;
use libeval::attribute::{Attribute, key};
use zpr::vsapi_types::{
    ConnectRequest, ConnectType, Connection, LinkStateReport, PacketDesc, Param, ParamValue,
    PublicKey, ReauthRequest, SockAddr, VSConnectRequest, VisaOp, pname,
};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::connection_control::{
    CommitRecheck, actor_prepared_vinst, policy_moved_error, recheck_before_commit,
};
use crate::counters::CounterType;
use crate::error::ServiceError;
use crate::event_mgr::VsEvent;
use crate::link_state::validate_snapshot;
use crate::logging::targets::API;
use crate::login_nonce::MintError;
use crate::net_mgr;
use crate::packet::describe_five_tuple;
use crate::topology_mgr::{AddLinkedNodeError, TopoOps, TopologyMgr};
use crate::visa_reconciler::revoke_visas_over_link;
use crate::visareq_worker::{VisaDecision, request_visa_wait_response};

// During node authentication we keep track in here of what state we have
// changed so that we can do an undo in case of an error in the sequence.
#[derive(Default)]
struct AuthenticateUndo {
    taken_zpr_addr: Option<IpAddr>,
    actor_mgr_add_node: Option<IpAddr>,
    added_node_to_router: Option<IpAddr>,
}

impl AuthenticateUndo {
    /// We checked out one of our ZPR addresses.
    fn took_zpr_addr(&mut self, addr: &IpAddr) {
        self.taken_zpr_addr = Some(addr.clone());
    }

    /// We added a node to state.
    fn added_node_to_actor_mgr(&mut self, addr: &IpAddr) {
        self.actor_mgr_add_node = Some(addr.clone());
    }

    /// Add a node to the router. If it was not already there then note the fact that we
    /// added it in our undo state.
    ///
    /// Returns `true` if the node was added. False if it already existed.
    fn add_node_to_router_and_track_if_added(
        &mut self,
        topo_mgr: &TopologyMgr,
        ops: &TopoOps<'_>,
        addr: IpAddr,
    ) -> bool {
        let added_node_to_router = topo_mgr.add_node_if_not_exists(ops, addr);
        if added_node_to_router {
            self.added_node_to_router = Some(addr);
        }
        added_node_to_router
    }

    /// Undo what authentication changed. `ops` is the caller's topology guard if it
    /// holds one (the lock is not re-entrant); otherwise one is taken here if the router
    /// must be touched.
    async fn undo(self, asm: &Assembly, ops: Option<&TopoOps<'_>>) {
        if let Some(addr) = self.added_node_to_router {
            match ops {
                Some(ops) => asm.topo_mgr.remove_node(ops, &addr).await,
                None => {
                    let ops = asm.topo_mgr.ops().await;
                    asm.topo_mgr.remove_node(&ops, &addr).await;
                }
            }
        }
        if let Some(addr) = self.actor_mgr_add_node {
            let _ = asm.actor_mgr.remove_node(&addr).await;
            let _ = asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await;
        }
        if let Some(addr) = self.taken_zpr_addr {
            let _ = asm.net_mgr.release_zpr_addr(addr);
        }
    }
}

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listen: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(target: API, "VSAPI service listening on {} (capnp)", listen);
    let acceptor = tls_acceptor(listen)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;

    loop {
        let (sock, addr) = listener.accept().await?;
        info!(target: API, "TCP connection from {}", addr);
        sock.set_nodelay(true)?;

        let tls = acceptor.accept(sock).await?;
        info!(target: API, "TLS connection");
        let (reader, writer) = tokio::io::split(tls);

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let vs_service: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
            asm: asm.clone(),
            remote: addr,
        });

        let rpc_system =
            capnp_rpc::RpcSystem::new(Box::new(network), Some(vs_service.clone().client));

        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
}

pub async fn launch(asm: Arc<Assembly>, listen: SocketAddr) {
    match launch_capnp(asm.clone(), listen).await {
        Ok(()) => (),
        Err(e) => error!(target: API, "VSAPI capnp error: {}", e),
    };
}

// This function creates a certificate, and the clients will not require verification of the
// cert. In the future, we may actually want to share a cert between the VSAPI and VSS in VS/VSConn in Libnode2
fn tls_acceptor(listen: SocketAddr) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let self_signed_cert = rcgen::generate_simple_self_signed(vec![listen.to_string()])?;
    // Create self signed certificate that does not require client authentication
    let cert_der = self_signed_cert.cert.der();
    let key_der = self_signed_cert.signing_key.serialize_der();

    // Convert the cert into a format the
    let chain = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[allow(dead_code)]
struct VisaServiceImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
}

#[allow(dead_code)]
struct VSGateImpl {
    a2a_dh_pubkey: Option<PublicKey>,
    asm: Arc<Assembly>,
    remote: SocketAddr,
    remote_cn: String,
    req_zpr_addr: IpAddr,
    req_substrate_addr: SocketAddr,

    // This is set in `challenge` call and read in the `authenticate` call.
    // Safe to use here since the capn proto rpc is confined to a single thread.
    challenge_data: Cell<[u8; 32]>,

    // If node passes the "reconnect" flag.
    reconnect: bool,
}

#[allow(dead_code)]
struct VSHandleImpl {
    asm: Arc<Assembly>,
    node: Actor,
    /// The session generation this handle is bound to, captured from the
    /// node actor's [key::SESSION] attribute at construction (zipline#123,
    /// PR #41 review): [Self::node_is_live] compares it against the STORED
    /// actor's session on every gated call, so a handle minted before a
    /// disconnect/reconnect (or before the address was reused) goes dead
    /// even though some node still occupies the address.
    session: Option<String>,
}

impl VSGateImpl {
    #[allow(dead_code)]
    fn new(
        asm: Arc<Assembly>,
        remote: SocketAddr,
        remote_cn: String,
        req_zpr_addr: IpAddr,
        req_substrate_addr: SocketAddr,
        a2a_dh_pubkey: Option<PublicKey>,
        reconnect: bool,
    ) -> Self {
        VSGateImpl {
            asm,
            remote,
            remote_cn,
            challenge_data: Cell::new([0u8; 32]),
            req_zpr_addr,
            req_substrate_addr,
            a2a_dh_pubkey,
            reconnect,
        }
    }
}

/// Mint a fresh session id and stamp it on `actor` (zipline#123, PR #41
/// review). The authenticate and reconnect paths call this BEFORE
/// persisting the actor and before building its handle: the persisted
/// session is the current generation, the handle captures it, and every
/// handle bound to an earlier generation fails [VSHandleImpl::node_is_live].
/// A rejoin (`visa_bootstrap::end_previous_join`) stamps one to end a session
/// nobody holds a handle for yet.
///
/// The id is `"<generation>-<uuid>"`. The generation comes from a process-wide
/// counter that only goes up, so link-state reports can tell a newer session from
/// an older one (zl-zipline#224, `link_state::session_generation`); the uuid keeps
/// ids unpredictable. Session checks elsewhere compare the whole string.
pub(crate) fn stamp_new_session(actor: &mut Actor) {
    static SESSION_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let generation = SESSION_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    actor
        .add_attribute(
            Attribute::builder(key::SESSION)
                .value(format!("{generation}-{}", uuid::Uuid::new_v4())),
        )
        .expect("session attribute is unvalidated and cannot fail");
}

impl VSHandleImpl {
    fn new(asm: Arc<Assembly>, node: Actor) -> Self {
        let session = node
            .get_attribute(key::SESSION)
            .and_then(|a| a.get_single_value().ok().map(str::to_string));
        VSHandleImpl { asm, node, session }
    }

    /// Admission checks `authorize_connect` makes under the caller's [TopoOps],
    /// after authenticating the connecting `actor` outside it: the calling handle
    /// must still be live (an `open` may have replaced its session meanwhile), and
    /// `actor` must have been approved under the current policy. Returns the error
    /// code and message to refuse with.
    async fn admit_under_guard(
        &self,
        _ops: &TopoOps<'_>,
        actor: &Actor,
    ) -> Result<(), (vsapi::ErrorCode, &'static str)> {
        if !self.node_is_live().await {
            return Err((
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            ));
        }
        if !approved_under_current_policy(&self.asm, actor) {
            return Err((
                vsapi::ErrorCode::TemporarilyUnavailable,
                "policy changed during authorization; retry",
            ));
        }
        Ok(())
    }

    /// Capability-liveness gate (zipline#123, K2): a `VSHandleImpl` holds a
    /// snapshot of the node actor, and capnp keeps the capability alive for as
    /// long as the client holds it — so a node dropped by `cc.disconnect`
    /// could keep using its old handle indefinitely. Every handler consults
    /// this first: the stored actor must still exist at the handle's address,
    /// still be a node, and — because an address can be reused or reconnected
    /// at (PR #41 review, Codex P1) — carry the SAME session generation this
    /// handle was minted under. A dropped node gets `authRequired` and must
    /// re-authenticate through `connect`.
    async fn node_is_live(&self) -> bool {
        let Some(addr) = self.node.get_zpr_addr() else {
            return false;
        };
        let stored = match self.asm.actor_mgr.get_actor_by_zpr_addr(addr).await {
            Ok(Some(actor)) if actor.is_node() => actor,
            _ => return false,
        };
        // Session binding: the stored actor's generation must match the one
        // captured at handle construction. A mismatch means the address was
        // re-authenticated (reuse or reconnect) after this handle was minted.
        // Two `None`s compare equal deliberately: an actor persisted before
        // this attribute existed keeps its live handle working.
        let stored_session = stored
            .get_attribute(key::SESSION)
            .and_then(|a| a.get_single_value().ok().map(str::to_string));
        stored_session == self.session
    }

    /// Squash (but log) any errors.
    async fn update_last_seen_time(&self, node_addr: &IpAddr) {
        match self.asm.actor_mgr.update_node_last_seen(node_addr).await {
            Ok(_) => (),
            Err(e) => {
                warn!(target: API, "failed to update last-seen time for node at addr {}: {}", node_addr, e);
            }
        }
    }

    // Helper to process a visa request and either return an API error or a visa decision.
    async fn do_visa_request(
        &self,
        args: vsapi::v_s_handle::VisaRequestParams,
        timeout: Duration,
    ) -> Result<VisaDecision, (vsapi::ErrorCode, String)> {
        let Some(requestor_ip) = self.node.get_zpr_addr() else {
            warn!(target: API, "visa_request called by node {:?} with no ZPR address assigned", self.node.get_cn());
            return Err((
                vsapi::ErrorCode::InvalidOperation,
                "node has no ZPR address assigned".to_string(),
            ));
        };

        let vreq = match args.get() {
            Ok(a) => match a.get_req() {
                Ok(r) => r,
                Err(e) => {
                    error!(target: API, "error getting visa request: {}", e);
                    return Err((
                        vsapi::ErrorCode::Internal,
                        "internal error getting visa request".to_string(),
                    ));
                }
            },
            Err(e) => {
                error!(target: API, "error getting visa request args: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting visa request args".to_string(),
                ));
            }
        };

        let cp_pdesc = match vreq.get_packet() {
            Ok(p) => p,
            Err(e) => {
                error!(target: API, "error getting packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting packet description".to_string(),
                ));
            }
        };

        let previous_id = {
            let pid = vreq.get_previous_id();
            if pid > 0 { Some(pid) } else { None }
        };
        if previous_id.is_some() {
            warn!(target: API, "visa_request: supplied previous_id is ignored (TODO)");
        }

        let pdesc: PacketDesc = match cp_pdesc.try_into() {
            Ok(pd) => pd,
            Err(e) => {
                error!(target: API, "error parsing packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("invalid packet description: {}", e),
                ));
            }
        };

        debug!(target: API, "preparing visa request from node {} for packet {}", requestor_ip, describe_five_tuple(&pdesc));

        // Note that we assume that everything above this has taken no time.
        match request_visa_wait_response(&self.asm, requestor_ip, pdesc, timeout).await {
            Ok(vd) => Ok(vd),
            Err(e) => {
                error!(target: API, "error processing visa request: {}", e);
                Err((
                    vsapi::ErrorCode::Internal,
                    "visa request processing failed".to_string(),
                ))
            }
        }
    }
}

/// The state half of `open` (a node resuming its VS-API session over an existing
/// link): load the node's own actor, keep its substrate address current, stamp
/// a NEW session generation and persist it -- all under the self-renewal lock
/// (`PolicyMgr::node_commit_lock`, #63 review audit), the lock every
/// writer of a node's own actor takes, so a concurrent login, logout or
/// re-authentication cannot land between this load and these writes and be
/// overwritten with the stale copy. Errors carry the `open` reply code and
/// message.
async fn resume_node_actor_for_open(
    asm: &Assembly,
    node_zpr_addr: IpAddr,
    reported_substrate: SocketAddr,
    cn: &str,
) -> Result<Actor, (vsapi::ErrorCode, String)> {
    let internal = || {
        (
            vsapi::ErrorCode::Internal,
            "internal error during open".to_string(),
        )
    };
    let _guard = asm.policy_mgr.node_commit_lock.lock().await;
    let mut existing_actor = match asm.actor_mgr.get_actor_by_zpr_addr(&node_zpr_addr).await {
        Ok(Some(actor)) => actor,
        Ok(None) => return Err((vsapi::ErrorCode::OutOfSync, "no state".to_string())),
        Err(e) => {
            error!(target: API, "error checking existing state for node calling open {}: {}", node_zpr_addr, e);
            return Err(internal());
        }
    };
    if !existing_actor.is_node() {
        warn!(target: API, "reconnect attempt denied for {}: found {:?}", node_zpr_addr, existing_actor.get_cn());
        return Err((
            vsapi::ErrorCode::InvalidOperation,
            "address in use".to_string(),
        ));
    }

    // If policy topology declares a substrate for this node it must agree with the
    // reported one; with no topology entry the reported value stands.
    if let Some(sa) = crate::connection_control::substrate_addr_from_topology(asm, &node_zpr_addr)
        && sa != reported_substrate
    {
        return Err((
            vsapi::ErrorCode::ParamError,
            format!(
                "substrate address mismatch: policy declares {sa}, node reported {reported_substrate}"
            ),
        ));
    }

    // A soft reconnect may carry a changed dock address; keep the stored claim current.
    let stored = existing_actor
        .get_attribute(key::SUBSTRATE_ADDR)
        .and_then(|a| a.get_value().first().cloned());
    if stored.as_deref() != Some(reported_substrate.to_string().as_str()) {
        info!(target: API, "node {} substrate address {} -> {} on open", cn, stored.unwrap_or_default(), reported_substrate);
        if let Err(e) = existing_actor.add_attribute(
            Attribute::builder(key::SUBSTRATE_ADDR).value(reported_substrate.to_string()),
        ) {
            error!(target: API, "failed to update substrate addr claim for {}: {}", cn, e);
            return Err(internal());
        }
    }

    // A reconnect mints a NEW session generation (zipline#123, PR #41
    // review): stamp and persist it before building the handle, so every
    // handle from before this open fails the liveness gate — an old
    // revoked capability cannot ride the reconnect back to life. One write
    // carries both the substrate update and the new session.
    stamp_new_session(&mut existing_actor);
    if let Err(e) = asm
        .actor_mgr
        .update_actor(&existing_actor, &asm.policy_service_names())
        .await
    {
        error!(target: API, "failed to persist session for {}: {}", cn, e);
        return Err(internal());
    }
    Ok(existing_actor)
}

/// Mint a login nonce for the node at `node_addr` whose handle was minted under
/// VS-API session `session`. Under the self-renewal lock -- which a node's
/// authenticate holds while it persists a new session -- the stored session is
/// re-checked first, so a stale handle that passed the liveness gate just before
/// a reconnect cannot mint, and cannot sweep away the new session's nonces
/// (#63 review). A mismatch is [MintError::StaleSession].
async fn mint_login_nonce_for_handle(
    asm: &Assembly,
    node_addr: IpAddr,
    session: &str,
) -> Result<(String, SystemTime), MintError> {
    let _guard = asm.policy_mgr.node_commit_lock.lock().await;
    if recheck_before_commit(asm, &node_addr, Some(session), None)
        .await
        .is_err()
    {
        return Err(MintError::StaleSession);
    }
    asm.cc
        .login_nonces
        .mint(node_addr, session, SystemTime::now())
}

/// Persist an authenticated node (its fresh `zpr.session` included) while
/// holding the self-renewal lock (`PolicyMgr::node_commit_lock`). A
/// node's reauthorization of its own actor holds the same lock from loading the
/// actor to persisting it, so this write can never land between that renewal's
/// session check and its write and be overwritten with the old session (#63
/// review). The lock is held only for the write, not for authentication.
///
/// Before the write, the shared commit-time recheck (#63 review audit): the
/// actor was authorized under the policy generation stamped in its
/// `zpr.vinst`; if an install landed since, the authentication is refused
/// (`temporarilyUnavailable`) and the node authenticates again under the new
/// policy, rather than persisting an admission that install's reconciliation
/// never saw. A fresh (`Reset`, `!reconnect`) connect tears the node's old
/// state down ([reset_node_state]) only after that recheck and under the same
/// lock, so a refused authentication never leaves the old node with its
/// adapters, visas and topology destroyed (#63 review).
///
/// The caller holds the topology guard (`ops`, #224's [TopoOps]); this takes
/// the node commit lock inside it. Lock order: topology lock, then node commit
/// lock (see `PolicyMgr::node_commit_lock`).
async fn add_node_serialized(
    asm: &Assembly,
    ops: &TopoOps<'_>,
    node_actor: &Actor,
    reconnect: bool,
) -> Result<(), ServiceError> {
    let _guard = asm.policy_mgr.node_commit_lock.lock().await;
    if let Some(addr) = node_actor.get_zpr_addr()
        && recheck_before_commit(asm, addr, None, actor_prepared_vinst(node_actor)).await?
            == CommitRecheck::PolicyMoved
    {
        return Err(policy_moved_error());
    }
    if !reconnect && let Some(addr) = node_actor.get_zpr_addr() {
        reset_node_state(asm, ops, addr).await?;
    }
    asm.actor_mgr
        .add_node(node_actor, reconnect, &asm.policy_service_names())
        .await
}

/// R13a (ZODE_LINKS.md): `node` has just (re)connected its VS-API session, which counts as
/// "something about the pair changed" for every failed pair it is part of. Clear those
/// marks ([TopologyMgr::clear_failed_pairs_for]) and send `setTopology` to the other end
/// of each, so its topology names the link again and the owner tries once more (R13).
/// `node` itself gets its topology through its normal connect sync.
///
/// Called under the topology guard, so the clear is ordered with reports and policy
/// passes. The sends wait on node RPCs, so they run in a spawned task and never under the
/// guard ([TopoOps] rules); they read the marks after the clear, whenever they run.
fn repropose_failed_pairs(asm: &Arc<Assembly>, ops: &TopoOps<'_>, node: &IpAddr) {
    let others = asm.topo_mgr.clear_failed_pairs_for(ops, node);
    if others.is_empty() {
        return;
    }
    info!(target: API, "node {node} reconnected: proposing its failed links to {others:?} again");
    let asm = asm.clone();
    tokio::task::spawn_local(async move {
        let psnap = asm.policy_mgr.get_current_snapshot();
        crate::event_mgr::send_topology_to(&asm, &psnap, &others).await;
    });
}

/// J5a: a VS-API session for `node` has just started (`authenticate`, or `open` for a
/// reconnect), so issue the node its own VSAPI pair ([crate::core_visas::issue_vsapi_visas]).
///
/// A failure is logged, not returned: the session itself is good, and the node keeps
/// working over its bootstrap pair. If that pair expires first, the session breaks and
/// the node rejoins (J10), which starts a new session and tries again.
async fn start_session_core_visas(asm: &Assembly, node_actor: &Actor) {
    let Some(node) = node_actor.get_zpr_addr() else {
        return; // every authenticated node has one; nothing to issue for without it
    };
    let session = node_actor
        .get_attribute(key::SESSION)
        .and_then(|a| a.get_single_value().ok());
    if let Err(e) = crate::core_visas::issue_vsapi_visas(asm, node, session).await {
        error!(target: API, "node {node}: failed to issue its VSAPI visas (J5a): {e}");
    }
}

/// Helper to write an error into a capnp error builder with a retry of zero.
fn write_error(bldr: &mut vsapi::error::Builder, code: vsapi::ErrorCode, message: &str) {
    bldr.set_code(code);
    bldr.set_message(message);
    bldr.set_retry_in(0);
}

/// Tear down the state a node held before a fresh (`ctype=Reset`) connect.
///
/// A resetting node has discarded everything it knew, so what we recorded for
/// it is stale:
/// - the adapters docked through it are removed and their visas revoked from
///   every other node (zipline#138: previously their actor records were
///   orphaned, blocking a re-dock at the same address). The visa service's own
///   adapter is spared by [crate::connection_control::ConnectionControl::remove_departed_adapters]
///   itself (zipline#167): the VS keeps running across its
///   docking node's reset, and its record is otherwise re-created only at VS
///   startup or when its adapter re-docks;
/// - its own visa refs are cleared;
/// - it is removed from the router, persisted edges included.
///
/// Must run before [crate::actor_mgr::ActorMgr::add_node] replaces the node
/// record, which drops the node's connected-adapters set.
/// Whether `actor` was approved (its `zpr.vinst`, stamped by `approve_connection`)
/// under the policy that is current now. Call under a [TopoOps]: policy installs
/// commit under it, so the answer holds until the guard is dropped.
fn approved_under_current_policy(asm: &Assembly, actor: &Actor) -> bool {
    crate::auth_sweep::actor_vinst(actor) == asm.policy_mgr.get_current_snapshot().vinst()
}

async fn reset_node_state(
    asm: &Assembly,
    ops: &TopoOps<'_>,
    node_addr: &IpAddr,
) -> Result<(), ServiceError> {
    let departed: Vec<IpAddr> = asm
        .actor_mgr
        .get_adapters_connected_to_node(node_addr)
        .await?;
    let removed_adapters = asm.cc.remove_departed_adapters(asm, &departed).await;
    if let Err(e) = asm
        .visa_mgr
        .remove_visas_for_actors(&removed_adapters)
        .await
    {
        // Same as disconnect: log, the teardown proceeds regardless.
        error!(target: API, "failed to remove visas for adapters of reset node {node_addr}: {e}");
    }
    asm.visa_mgr.clear_node_state(node_addr).await?;
    asm.topo_mgr.remove_node(ops, node_addr).await;
    Ok(())
}

/// Install router edges for every policy-declared peering between `node_addr` and a node
/// that is already connected, persisting each edge.
///
/// A node that joins by calling `connect` over a link never passes through its peer's
/// `authorize_connect`, so nothing else installs its links: it would land in the router
/// with no edges at all and every visa request involving it would deny `NoRoute`.
///
/// Failures are logged, not fatal -- the node is authenticated either way. Nothing
/// reconciles the missing edge afterwards: every `add_linked_node` failure path leaves it
/// in neither the router nor persisted state, and `revalidate_against_policy` only works
/// the union of those two stores, so it never installs a policy-declared edge absent from
/// both. The link stays missing until one of its endpoints reconnects and re-runs this or
/// `authorize_connect`. Meanwhile the node is still *told* the link exists -- topology
/// sends come from policy, not the router -- so its visa requests over that link deny
/// `NoRoute` with nothing on the node side to explain why.
///
/// TODO: retry instead of just logging. `add_linked_node` is idempotent (tolerates
/// `LinkExists`, re-persists on the already-connected path), so a "links dirty" flag on
/// `VssState` next to `needs_set_topology` would let `do_housekeeping` re-run this on the
/// next tick -- no new machinery required.
/// See: https://github.com/org-zpr/zpr-visaservice/issues/302
///
/// TODO: a declared peering between two connected nodes is taken as evidence that the
/// link is up. VS cannot see which peer forwarded the VSAPI connection, so a node with
/// more than one connected peer gets edges for all of them. Upgrade path: have the node
/// report the link it came in over as a connect param.
///
/// TODO: Rethink this: do we really node connect and open in VSAPI?
/// See: https://github.com/org-zpr/zpr-visaservice/issues/302
async fn install_policy_links_for_node(
    asm: &Assembly,
    ops: &TopoOps<'_>,
    node_actor: &Actor,
    node_addr: &IpAddr,
) {
    let psnap = asm.policy_mgr.get_current_snapshot();
    let Some(peers) = psnap.policy().get_peers_for_node(node_addr) else {
        return; // No peerings declared for this node.
    };
    let connected = match asm.actor_mgr.list_node_addrs().await {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!(target: API, "cannot install links for node {node_addr}: node list unavailable: {e}");
            return;
        }
    };
    for peer in peers {
        if !connected.contains(&peer.remote_zpr_addr) {
            debug!(target: API, "peer {} of node {node_addr} is not connected: link {} deferred", peer.remote_zpr_addr, peer.link_id);
            continue;
        }
        match asm
            .topo_mgr
            .add_linked_node(
                ops,
                &psnap,
                &asm.actor_mgr,
                node_actor,
                &peer.remote_zpr_addr,
                node_addr,
            )
            .await
        {
            Ok(()) => {
                info!(target: API, "installed link {} between node {node_addr} and peer {}", peer.link_id, peer.remote_zpr_addr)
            }
            Err(e) => {
                error!(target: API, "failed to install link {} between node {node_addr} and peer {}: {e} -- node has no route over that link until an endpoint reconnects", peer.link_id, peer.remote_zpr_addr);
                asm.counters.incr(CounterType::LinkInstallFailed);
            }
        }
    }
}

/// Convert a vsapi schema IpAddr into a rust ip address.
fn ipaddr_from_capnp(addr: vsapi::ip_addr::Reader) -> Result<std::net::IpAddr, capnp::Error> {
    match addr.which()? {
        vsapi::ip_addr::V4(ipv4) => {
            let octets = ipv4?;
            if octets.len() != 4 {
                return Err(capnp::Error::failed(
                    "invalid ipv4 address length".to_string(),
                ));
            }
            Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        vsapi::ip_addr::V6(ipv6) => {
            let octets = ipv6?;
            if octets.len() != 16 {
                return Err(capnp::Error::failed(
                    "invalid ipv6 address length".to_string(),
                ));
            }
            let mut octets_copy = [0u8; 16];
            octets_copy.copy_from_slice(&octets);
            Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets_copy)))
        }
    }
}

/// Parse and validate a substrate address param value. Unparseable, unspecified-IP
/// (e.g. 0.0.0.0) and port-0 values are rejected -- the VS cannot verify reachability
/// of an advertised address, but it can reject values that are structurally unusable.
fn parse_substrate_addr_str(s: &str) -> Result<SocketAddr, ServiceError> {
    let sa: SocketAddr = s.parse().map_err(|_| {
        ServiceError::Param(format!(
            "param {} is not a valid socket address: '{s}'",
            pname::SUBSTRATE_ADDR
        ))
    })?;
    if sa.ip().is_unspecified() || sa.port() == 0 {
        return Err(ServiceError::Param(format!(
            "param {} must be a specific address with a non-zero port, got '{sa}'",
            pname::SUBSTRATE_ADDR
        )));
    }
    Ok(sa)
}

/// Find and parse the required `substrate_addr` param. Used by `open`, which (unlike
/// `connect`) requires no other params. See
/// https://github.com/org-zpr/zpr-visaservice/issues/299
fn parse_substrate_addr_param(params: &[Param]) -> Result<SocketAddr, ServiceError> {
    for pp in params {
        if pp.name.as_str() == pname::SUBSTRATE_ADDR {
            return match &pp.value {
                ParamValue::StrParam(s) => parse_substrate_addr_str(s),
                _ => Err(ServiceError::Param(format!(
                    "param {} has invalid type",
                    pname::SUBSTRATE_ADDR
                ))),
            };
        }
    }
    Err(ServiceError::Param("SUBSTRATE_ADDR param missing".into()))
}

impl VisaServiceImpl {
    /// Helper for the connect routine -- returns the two connect params we require, zpr_addr
    /// and substrate_addr, plus the node's A2A DH public key if it sent one. Older code used
    /// to pass in the AAA_PREFIX here but now we send that over the VSS.
    ///
    /// During this transition period we will error out if node passes use AAA_PREFIX.
    ///
    /// `substrate_addr` is the node's advertised substrate address (the address peers dial),
    /// sent as a string param and parsed as a `SocketAddr`. Unparseable, unspecified-IP
    /// (e.g. 0.0.0.0) and port-0 values are rejected -- the VS cannot verify reachability,
    /// but it can reject values that are structurally unusable.
    /// See https://github.com/org-zpr/zpr-visaservice/issues/299
    fn parse_my_connect_params(
        &self,
        params: &[Param],
    ) -> Result<(IpAddr, SocketAddr, Option<PublicKey>), ServiceError> {
        let mut node_zpr_addr = None;
        let mut node_substrate_addr = None;
        let mut a2a_dh_pubkey = None;

        for pp in params {
            match pp.name.as_str() {
                pname::ZPR_ADDR => match &pp.value {
                    ParamValue::IpParam(ipa) => node_zpr_addr = Some(ipa.clone()),
                    _ => {
                        return Err(ServiceError::Param(format!(
                            "param {} has invalid type",
                            pname::ZPR_ADDR
                        )));
                    }
                },

                pname::SUBSTRATE_ADDR => match &pp.value {
                    ParamValue::StrParam(s) => {
                        node_substrate_addr = Some(parse_substrate_addr_str(s)?);
                    }
                    _ => {
                        return Err(ServiceError::Param(format!(
                            "param {} has invalid type",
                            pname::SUBSTRATE_ADDR
                        )));
                    }
                },

                pname::AAA_PREFIX => {
                    return Err(ServiceError::Param(format!(
                        "param {} must not be sent to VS",
                        pname::AAA_PREFIX
                    )));
                }

                pname::A2A_DH_PUBKEY => match &pp.value {
                    ParamValue::X25519PubKey(pubkey) => {
                        a2a_dh_pubkey = Some(PublicKey::new(pubkey.as_bytes()));
                    }
                    _ => {
                        return Err(ServiceError::Param(format!(
                            "param {} has invalid type",
                            pname::A2A_DH_PUBKEY
                        )));
                    }
                },

                name => info!(target: API, "ignored connect param {}", name),
            }
        }

        let Some(node_zpr_addr) = node_zpr_addr else {
            return Err(ServiceError::Param("ZPR_ADDR param missing".into()));
        };
        let Some(node_substrate_addr) = node_substrate_addr else {
            return Err(ServiceError::Param("SUBSTRATE_ADDR param missing".into()));
        };
        Ok((node_zpr_addr, node_substrate_addr, a2a_dh_pubkey))
    }

    /// Helper to handle errors during connect call.
    /// Returns a Capn Proto OK, but an API level error.
    fn ok_with_connect_error(
        &self,
        mut results: vsapi::visa_service::ConnectResults,
        code: vsapi::ErrorCode,
        message: &str,
    ) -> Result<(), capnp::Error> {
        self.asm.counters.incr(CounterType::NodeConnectionsFailed);
        let res_builder = results.get().init_resp();
        let mut err_builder = res_builder.init_error();
        write_error(&mut err_builder, code, message);
        Ok(())
    }

    /// Helper to handle errors during connect call.
    /// Returns a Capn Proto OK, but an API level error.
    fn ok_with_open_error(
        &self,
        mut results: vsapi::visa_service::OpenResults,
        code: vsapi::ErrorCode,
        message: &str,
    ) -> Result<(), capnp::Error> {
        self.asm.counters.incr(CounterType::NodeConnectionsFailed);
        let res_builder = results.get().init_resp();
        let mut err_builder = res_builder.init_error();
        write_error(&mut err_builder, code, message);
        Ok(())
    }
}

impl vsapi::visa_service::Server for VisaServiceImpl {
    // Node connection request to the Visa Service.
    // The node must pass its ZPR_ADDR and SUBSTRATE_ADDR as connect params.
    async fn connect(
        self: Rc<Self>,
        params: vsapi::visa_service::ConnectParams,
        mut results: vsapi::visa_service::ConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "connect call from {}", self.remote);

        let vs_connect_request_rdr = params.get()?.get_req()?;

        let vs_connect_request = match VSConnectRequest::try_from(vs_connect_request_rdr) {
            Ok(req) => req,
            Err(e) => {
                return self.ok_with_connect_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    &format!("failed to parse connect request: {e}"),
                );
            }
        };

        // There must be at least one param (zpr addr)
        let parsed_params = match vs_connect_request.params {
            Some(p) => p,
            None => {
                return self.ok_with_connect_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    "connect params missing",
                );
            }
        };

        let (node_zpr_addr, node_substrate_addr, a2a_dh_pubkey) =
            match self.parse_my_connect_params(&parsed_params) {
                Ok(parsed) => parsed,
                Err(e) => {
                    return self.ok_with_connect_error(
                        results,
                        vsapi::ErrorCode::ParamError,
                        format!("{e}").as_str(),
                    );
                }
            };

        info!(target: API, "node {} requests zpr addr {} (CONNECT_TYPE={:?})", vs_connect_request.cn, node_zpr_addr, vs_connect_request.ctype);

        // The requested address is an unauthenticated claim. A node reaches VSAPI from its ZPR
        // address using a bootstrap visa pinned to that address, so the address it claims must
        // be the one we are talking to; past this point `node_zpr_addr` is source-verified.
        //
        // The check is skipped when VSAPI is not bound to a ZPR address (`vs_addr` set to
        // loopback or a substrate address for local development) -- there is no fabric
        // enforcing the source there, so there is nothing to compare against. Not a supported
        // production configuration.
        let remote_ip = self.remote.ip();
        if net_mgr::is_zpr_addr(&remote_ip) && remote_ip != node_zpr_addr {
            warn!(target: API, "node {} connecting from ZPR addr {} claims addr {}: rejected", vs_connect_request.cn, remote_ip, node_zpr_addr);
            return self.ok_with_connect_error(
                results,
                vsapi::ErrorCode::ParamError,
                "zpr addr does not match connection source",
            );
        }

        match vs_connect_request.ctype {
            ConnectType::Reset => {}
            ConnectType::Reconnect => {
                // Node thinks it has state which means it may have connected adapters and a bunch of
                // visas already. If we don't know anything about this node we can deny this.

                let existing_actor = match self
                    .asm
                    .actor_mgr
                    .get_actor_by_zpr_addr(&node_zpr_addr)
                    .await
                {
                    Ok(Some(actor)) => actor,
                    Ok(None) => {
                        return self.ok_with_connect_error(
                            results,
                            vsapi::ErrorCode::OutOfSync,
                            "no state",
                        );
                    }
                    Err(e) => {
                        error!(target: API, "error checking existing state for reconnecting node {}: {}", node_zpr_addr, e);
                        return self.ok_with_connect_error(
                            results,
                            vsapi::ErrorCode::Internal,
                            "internal error during reconnect",
                        );
                    }
                };
                if !existing_actor.is_node() {
                    warn!(target: API, "reconnect attempt denied for {}: found {:?}", node_zpr_addr, existing_actor.get_cn());
                    return self.ok_with_connect_error(
                        results,
                        vsapi::ErrorCode::InvalidOperation,
                        "address in use",
                    );
                }
            }
        }

        let mut res_builder = results.get().init_resp();

        let vs_gate: vsapi::v_s_gate::Client = capnp_rpc::new_client(VSGateImpl::new(
            self.asm.clone(),
            self.remote,
            vs_connect_request.cn,
            node_zpr_addr,
            node_substrate_addr,
            a2a_dh_pubkey,
            vs_connect_request.ctype == ConnectType::Reconnect,
        ));

        res_builder.set_ok(vs_gate)?;

        Ok(())
    }

    async fn open(
        self: Rc<Self>,
        params: vsapi::visa_service::OpenParams,
        mut results: vsapi::visa_service::OpenResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "open call from {}", self.remote);

        let vs_connect_request_rdr = params.get()?.get_req()?;
        let vs_connect_request = match VSConnectRequest::try_from(vs_connect_request_rdr) {
            Ok(req) => req,
            Err(e) => {
                return self.ok_with_open_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    &format!("failed to parse connect request: {e}"),
                );
            }
        };

        // The one param `open` requires is the node's advertised substrate address; the
        // same policy-mismatch check as `connect` applies. `zpr_addr` remains
        // optional/ignored here -- the node should be using its real ZPR address already
        // authenticated/granted during authorize_connect.
        // See https://github.com/org-zpr/zpr-visaservice/issues/299

        let reported_substrate = match vs_connect_request
            .params
            .as_deref()
            .ok_or_else(|| ServiceError::Param("connect params missing".into()))
            .and_then(parse_substrate_addr_param)
        {
            Ok(sa) => sa,
            Err(e) => {
                return self.ok_with_open_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    format!("{e}").as_str(),
                );
            }
        };

        let node_zpr_addr = self.remote.ip();
        info!(target: API, "node {} requests open from addr {} (CONNECT_TYPE={:?})", vs_connect_request.cn, node_zpr_addr, vs_connect_request.ctype);

        // Topology operation lock (see TopoOps): held from the actor lookup through
        // the session persist, so an overlapping authenticate, open, disconnect or
        // link-state report sees this node's session either before or after it, and
        // session generations are persisted in the order they are minted. Inside
        // it, the load -> write of the node's own actor also runs under the node
        // commit lock (#63 review audit): a concurrent login/logout of this node
        // cannot land between them. Order: topology lock, then node commit lock.
        let ops = self.asm.topo_mgr.ops().await;
        let existing_actor = match resume_node_actor_for_open(
            &self.asm,
            node_zpr_addr,
            reported_substrate,
            &vs_connect_request.cn,
        )
        .await
        {
            Ok(actor) => actor,
            Err((code, message)) => return self.ok_with_open_error(results, code, &message),
        };
        if matches!(vs_connect_request.ctype, ConnectType::Reset) {
            warn!(target: API, "{} requests RESET: not yet implemented", vs_connect_request.cn);
        }
        // A session reconnect: the node's failed pairs are proposed again (R13a).
        repropose_failed_pairs(&self.asm, &ops, &node_zpr_addr);

        drop(ops);

        start_session_core_visas(&self.asm, &existing_actor).await;

        // Skip ahead to the handle:
        let vs_handle: vsapi::v_s_handle::Client =
            capnp_rpc::new_client(VSHandleImpl::new(self.asm.clone(), existing_actor));
        let mut res_builder = results.get().init_resp();
        res_builder.set_ok(vs_handle)?;
        Ok(())
    }
}

impl VSGateImpl {
    /// Helper to handle errors during authenticate call.
    /// Returns a Capn Proto OK, but an API level error.
    fn ok_with_authenticate_error(
        &self,
        mut results: vsapi::v_s_gate::AuthenticateResults,
        code: vsapi::ErrorCode,
        message: &str,
    ) -> Result<(), capnp::Error> {
        self.asm.counters.incr(CounterType::NodeConnectionsFailed);
        let res_builder = results.get().init_res();
        let mut err_builder = res_builder.init_error();
        write_error(&mut err_builder, code, message);
        Ok(())
    }
}

impl vsapi::v_s_gate::Server for VSGateImpl {
    async fn challenge(
        self: Rc<Self>,
        _params: vsapi::v_s_gate::ChallengeParams,
        mut results: vsapi::v_s_gate::ChallengeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "challenge call from {} as {}", self.remote, self.remote_cn);
        let mut res_builder = results.get().init_challenge();
        res_builder.set_alg(vsapi::ChallengeAlg::RsaSha256Pkcs1v15);
        let mut challenge_data = [0u8; 32];
        rand_bytes(&mut challenge_data).unwrap();
        res_builder.set_bytes(&challenge_data);
        self.challenge_data.set(challenge_data);
        Ok(())
    }

    /// Authenticate VSAPI call is also the "authorize_connect" call for a node.
    async fn authenticate(
        self: Rc<Self>,
        params: vsapi::v_s_gate::AuthenticateParams,
        mut results: vsapi::v_s_gate::AuthenticateResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "authenticate from {} as {}", self.remote, self.remote_cn);
        let cresp = params.get()?.get_cresp()?; // has challenge (bytes), timestamp (uint64), bytes (bytes)

        let challenge_presented = cresp.get_challenge()?;

        // We must have sent challenge data ... meaning it cannot all be zeros.
        if challenge_presented.iter().all(|&b| b == 0) {
            warn!(target: API, "all zeros challenge presented from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "invalid challenge",
            );
        }

        // Must match the challenge we sent.
        if challenge_presented != &self.challenge_data.get() {
            warn!(target: API, "invalid challenge from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "challenge mismatch",
            );
        }

        // Challenge is one time use - so we set our memory of it to zeros.
        self.challenge_data.set([0u8; 32]);

        // Time must be within acceptable range.
        let unix_ts = cresp.get_timestamp();
        let now = SystemTime::now();
        let my_unix_ts = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        if my_unix_ts.abs_diff(unix_ts) > config::MAX_CLOCK_SKEW_SECS {
            warn!(target: API, "excess clock skew from {}, authenticate fails", self.remote_cn);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "excess clock skew",
            );
        }

        let challenge_response = cresp.get_bytes()?;

        // Perform the authentication
        //
        let mut node_actor = match self
            .asm
            .cc
            .authenticate_node(
                self.asm.clone(),
                challenge_presented,
                unix_ts,
                &self.remote_cn,
                challenge_response,
                self.req_zpr_addr,
                self.req_substrate_addr,
                self.a2a_dh_pubkey.as_ref(),
            )
            .await
        {
            Ok(node_id) => node_id,
            Err(ServiceError::AuthenticationFailed(reason)) => {
                warn!(target: API, "authentication failed for {}: {}", self.remote_cn, reason);
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::AuthError,
                    format!("authentication failed: {reason}").as_str(),
                );
            }
            Err(ServiceError::Param(reason)) => {
                warn!(target: API, "param error during authentication for {}: {}", self.remote_cn, reason);
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::ParamError,
                    format!("param error: {reason}").as_str(),
                );
            }
            Err(e) => {
                error!(target: API, "internal error during authentication for {}: {}", self.remote_cn, e);
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "internal error during authentication",
                );
            }
        };

        // At this point we may have taken an IP addr and assigned it to the actor.
        let mut undo = AuthenticateUndo::default();

        // Sanity check - every node has a CN and a ZPR address.
        // If this fails it means our authentication code is broken.
        let node_zpr_addr = match node_actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                error!(target: API, "auth subsystem failed to set a ZPR address on an authenticated node");
                undo.undo(&self.asm, None).await;
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (ADDR)",
                );
            }
        };
        // Release-on-failure for a pool-allocated address. After zipline#98 a
        // STATIC (policy-pinned) node address can never be in-pool -- the
        // authorize path rejects it -- so reaching here with a managed address
        // means authorize_connection just allocated it from the node pool
        // (the request was scrubbed or absent). If a later step fails, the
        // undo returns that fresh allocation to the pool. The zipline#98 plan
        // slated this branch for removal as dead; it is dead for static
        // addresses but still live for pool-allocated ones, so it stays (see
        // the note on the issue).
        if self.asm.net_mgr.is_managed_address(&node_zpr_addr) {
            undo.took_zpr_addr(&node_zpr_addr);
        }

        // Policy can hand back a different address than the node asked for: the requested
        // address is an unauthenticated claim, scrubbed unless a join policy matched it, in
        // which case an address is allocated instead. A node that joined over a link is only
        // reachable at the address it claimed -- its bootstrap visa and its peering are keyed
        // to it -- so a substitution leaves it unroutable. Fail rather than authenticate it
        // at an address it cannot use.
        if node_zpr_addr != self.req_zpr_addr && net_mgr::is_zpr_addr(&self.remote.ip()) {
            warn!(target: API, "node {} requested addr {} but policy granted {}: rejecting, it joined over a link at the requested addr", self.remote_cn, self.req_zpr_addr, node_zpr_addr);
            undo.undo(&self.asm, None).await;
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::AuthError,
                "requested zpr address not granted by policy",
            );
        }

        let node_cn = match node_actor.get_cn() {
            Some(cn) => cn.to_owned(),
            None => {
                error!(target: API, "auth subsystem failed to set a CN on an authenticated node");
                undo.undo(&self.asm, None).await;
                return self.ok_with_authenticate_error(
                    results,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (CN)",
                );
            }
        };

        let node_aaa_net = net_mgr::aaa_network_for_node(&node_zpr_addr);

        info!(
            target: API,
            "successfully authenticated node {node_cn} from {:?} and assigned ip {node_zpr_addr} and AAA net {node_aaa_net}",
            self.remote,
        );

        // Ok, we have verified the credentials and checked with policy. Time to
        // update our state and return success.

        node_actor
            .add_attribute(Attribute::builder(key::AAA_NET).value(node_aaa_net.to_string()))
            .unwrap();

        // Note that the node may have services on it in addition to its node-ness.

        // Topology operation lock (see TopoOps): held from the policy recheck and the
        // session stamp through the policy link install, so a policy install or
        // revalidation, a link-state report, an `open` or a disconnect cannot
        // interleave with this node's state being rebuilt. Undo calls inside this
        // span pass the guard; the lock is not re-entrant.
        let ops = self.asm.topo_mgr.ops().await;

        // The node was approved (above, outside the lock: authentication can query
        // trusted services) under the policy current then. If a newer policy has
        // been installed since, its pass may already have run without this node, so
        // refuse; the node retries and is judged under the current policy. Installs
        // commit under the guard, so the answer holds until it is dropped.
        if !approved_under_current_policy(&self.asm, &node_actor) {
            warn!(target: API, "policy changed while authenticating {:?}; refusing, node to retry", &node_cn);
            undo.undo(&self.asm, Some(&ops)).await;
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::TemporarilyUnavailable,
                "policy changed during authentication; retry",
            );
        }

        // Bind the handle we are about to mint to THIS authentication
        // (zipline#123, PR #41 review): a fresh session generation is stamped
        // before the actor is persisted, so any handle from a previous
        // session at this address fails the liveness gate from here on. Stamped
        // under the guard, so generations are persisted in the order minted.
        stamp_new_session(&mut node_actor);

        // A Reset's teardown of the node's old state runs inside
        // add_node_serialized, under the topology guard held here and the node
        // commit lock it takes, after the generation recheck (#63 review).
        // The add_node call will clean up after ifself if it fails.
        if let Err(e) = add_node_serialized(&self.asm, &ops, &node_actor, self.reconnect).await {
            undo.undo(&self.asm, Some(&ops)).await;
            if let ServiceError::ApiResponse(api) = e {
                info!(target: API, "authentication of node {:?} refused at commit: {}", &node_cn, api.message);
                return self.ok_with_authenticate_error(results, api.code.into(), &api.message);
            }
            error!(target: API, "failed to add authenticated node {:?} to actor db: {}", &node_cn, e);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
        }
        undo.added_node_to_actor_mgr(&node_zpr_addr);

        // TODO: This is a hack: the visa service "actor" needs to know what node it's adapter is docked to.
        //       Ideally we would query our adapter directly.
        {
            let vs_zpr_addr = self.asm.config.get_vs_addr();
            if let Ok(maybe_visa_service_actor) =
                self.asm.actor_mgr.get_actor_by_zpr_addr(&vs_zpr_addr).await
            {
                if let Some(visa_service_actor) = maybe_visa_service_actor {
                    if self
                        .asm
                        .actor_mgr
                        .get_docking_node_for_actor(&visa_service_actor)
                        .is_none()
                    {
                        // VS does not yet have a docking address.  ASSUME this node is our dock.
                        // This does not update the 'connect_via' attribute on the vs actor. (TODO - rethink that)

                        if let Err(e) = self
                            .asm
                            .actor_mgr
                            .hack_set_vs_docking_node(&node_zpr_addr)
                            .await
                        {
                            error!(target: API, "failed to set VS docking node to {:?}: {}", &node_cn, e);
                            undo.undo(&self.asm, Some(&ops)).await;
                            return self.ok_with_authenticate_error(
                                results,
                                vsapi::ErrorCode::Internal,
                                "vs docking node update failed",
                            );
                        }
                        // No need to update the `undo` here since undoing the node-add will also remove the vs docking mapping.
                    }
                }
            }
        }

        // Add the node to the router, preserving restored links if it already exists.
        if !undo.add_node_to_router_and_track_if_added(&self.asm.topo_mgr, &ops, node_zpr_addr) {
            // Node exists already.
            info!(target: API, "node {:?} already present in router on (re)connect; keeping existing node and links", &node_cn);
        }

        // Install the node's policy-declared links to already-connected peers. Must happen
        // before ActorJoins: that event drives the topology fan-out, which reads the router.
        install_policy_links_for_node(&self.asm, &ops, &node_actor, &node_zpr_addr).await;
        // A new connect, reconnect or reset: the node's failed pairs are proposed again
        // (R13a).
        repropose_failed_pairs(&self.asm, &ops, &node_zpr_addr);
        drop(ops);

        let evt = VsEvent::ActorJoins(node_zpr_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            error!(target: API, "failed to record actor joins event for node {:?}: {}", &node_cn, e);
            undo.undo(&self.asm, None).await;
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::Internal,
                "event enqueue failed",
            );
        }
        self.asm.counters.incr(CounterType::NodeConnectionsSuccess);

        // PR #42 review (P1): the node is persisted — re-check the denylist to
        // close the check-then-persist race with an admin revocation. The gate
        // disconnects the node (its state teardown is the full disconnect
        // path, which the undo tracker does not model), so no undo here.
        if let Err(e) = self
            .asm
            .cc
            .enforce_denylist_after_persist(&self.asm, &node_actor)
            .await
        {
            warn!(target: API, "node authentication revoked post-persist for {}: {}", node_cn, e);
            return self.ok_with_authenticate_error(
                results,
                vsapi::ErrorCode::AuthError,
                "authentication failed: not authorized",
            );
        }

        start_session_core_visas(&self.asm, &node_actor).await;

        let vs_handle: vsapi::v_s_handle::Client =
            capnp_rpc::new_client(VSHandleImpl::new(self.asm.clone(), node_actor));
        let mut res_builder = results.get().init_res();
        res_builder.set_ok(vs_handle)?;

        Ok(())
    }
}

impl vsapi::v_s_handle::Server for VSHandleImpl {
    /// Node should call this after it has authenticated itself and it has installed its
    /// ZPR address into its tables.
    ///
    /// The VS mints a NEW visa for VS->VSS communications every time (J5b) and hands the
    /// node its copy with this call. Everything else pending for the node is pushed over
    /// VSS once the connection is up (gate g89 q4).
    ///
    async fn register_vss(
        self: Rc<Self>,
        params: vsapi::v_s_handle::RegisterVssParams,
        mut res: vsapi::v_s_handle::RegisterVssResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "register_vss from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "register_vss from disconnected node {:?}: refused", self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        let saddr_rdr = params.get()?.get_addr()?;

        let node_zpr_addr = self.node.get_zpr_addr().unwrap();
        self.update_last_seen_time(node_zpr_addr).await;

        let vss_sockaddr: SockAddr = match SockAddr::try_from(saddr_rdr) {
            Ok(addr) => addr,
            Err(e) => {
                error!(target: API, "failed to convert addr arg to SockAddr: {}", e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::ParamError,
                    "invalid sockaddr",
                );
                return Ok(());
            }
        };

        // The socket addr address must match node address I think.
        if vss_sockaddr.addr != *node_zpr_addr {
            error!(target: API, "VSS socket address '{}' does not match node address '{}' for {:?}", vss_sockaddr.addr, node_zpr_addr, self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::ParamError,
                "VSS socket address does not match node address",
            );
            return Ok(());
        }

        let saddr: SocketAddr = vss_sockaddr.into();
        let amgr_asm = self.asm.clone();

        let prepared = self
            .asm
            .visa_mgr
            .post_register_vss_visas_for_node(
                amgr_asm,
                node_zpr_addr,
                &saddr,
                self.session.as_deref(),
            )
            .await;

        // Topology operation lock (see TopoOps), taken after the visa preparation
        // above (which can wait on the visa request queue and remote attribute
        // services, so it stays outside): the caller's liveness is rechecked under it
        // and it is held through the local registration and worker start, so a
        // handle whose node reconnected or disconnected meanwhile cannot register a
        // VSS for the new session or for a node that is gone.
        let ops = self.asm.topo_mgr.ops().await;
        if !self.node_is_live().await {
            warn!(target: API, "register_vss from superseded handle {:?}: refused", self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        // A superseded handle is told to re-authenticate (above) before it hears
        // about a preparation failure.
        // The visas were prepared before the guard: drop any revoked, acknowledged or
        // quarantined meanwhile (a link-down report can revoke one while preparation
        // waits), so a revoked visa is never granted again.
        let initial_visas = match prepared {
            Ok(visas) => visas
                .into_iter()
                .filter(|v| {
                    self.asm
                        .visa_mgr
                        .still_grantable(v.issuer_id, node_zpr_addr)
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(target: API, "failed to initialize node VSS for {:?}: {}", self.node.get_cn(), e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "failed to initialize node VSS",
                );
                return Ok(());
            }
        };

        let res_builder = res.get().init_res();
        let mut ok_builder = res_builder.initn_ok(initial_visas.len() as u32);

        for (i, visa) in initial_visas.iter().enumerate() {
            let mut vop_builder = ok_builder.reborrow().get(i as u32);

            let vop = VisaOp::Grant(visa.clone());
            vop.write_to(&mut vop_builder);
        }

        // Now assume that our reply will make it to the node and mark its VSS visa as
        // installed. That also releases the ingress (relay-side) copy of the visa to the
        // relay's VSS push (ingress last, gate g89 q4). A node whose call fails calls
        // register_vss again and gets a new VSS visa (J5b).
        //
        // TODO: Improve vsapi by adding a way for node to request its installed visas.
        // https://github.com/org-zpr/zpr-visaservice/issues/108

        for visa in &initial_visas {
            if let Err(e) = self
                .asm
                .visa_mgr
                .visa_installed(visa.issuer_id, node_zpr_addr)
                .await
            {
                warn!(target: API, "failed to mark visa {} as installed on {:?}: {}", visa.issuer_id, self.node.get_cn(), e);
            }
        }

        // Finally, update DB with node vss
        self.asm
            .actor_mgr
            .set_node_vss(&self.node.get_zpr_addr().unwrap(), &saddr)
            .await
            .unwrap_or_else(|e| {
                error!(target: API, "failed to set VSS for node {:?}: {}", self.node.get_cn(), e);
            });

        // As we return we kick off the vss worker for this node which will send config and list of services.
        // but will not work until visas are installed... So start it with small delay.
        //
        // A worker may already be running for this node — a reconnecting node
        // re-registers its VSS while the previous session's worker is still
        // around (zipline#123, K2). The node just restarted its listener, so
        // the old worker's connection is dead: replace it rather than warn and
        // leave the node without a live VSS channel.
        let node_zpr_addr = self.node.get_zpr_addr().unwrap();
        let start_result = if self.asm.vss_mgr.get_handle(node_zpr_addr).is_some() {
            info!(target: API, "VSS worker already running for node {:?}; restarting it for the re-registered VSS", self.node.get_cn());
            self.asm.vss_mgr.restart_vss_worker(
                self.asm.clone(),
                node_zpr_addr,
                &saddr,
                config::VSS_START_DELAY,
            )
        } else {
            self.asm.vss_mgr.start_vss_worker(
                self.asm.clone(),
                node_zpr_addr,
                &saddr,
                config::VSS_START_DELAY,
            )
        };
        if let Err(e) = start_result {
            warn!(target: API, "failed to start VSS worker for node {:?}: {}", self.node.get_cn(), e);
        }
        drop(ops);

        Ok(())
    }

    // When an adapter (or node, which for connection stuff _acts_ like an adapter) connects to a node,
    // a node ends up making a call here to authorize the connection.  If successful the VS returns
    // a ZPR address for the adapter, and an expiration time.
    //
    // TODO: How do we handle re-connect or re-auth?
    async fn authorize_connect(
        self: Rc<Self>,
        params: vsapi::v_s_handle::AuthorizeConnectParams,
        mut results: vsapi::v_s_handle::AuthorizeConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "authorize_connect from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "authorize_connect from disconnected node {:?}: refused", self.node.get_cn());
            let mut err_builder = results.get().init_resp().init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }

        let cr_rdr = params.get()?.get_req()?;
        let creq = ConnectRequest::try_from(cr_rdr).map_err(|e| {
            capnp::Error::failed(format!("failed to parse ConnectionRequest: {}", e))
        })?;

        let connect_via = self.node.get_zpr_addr().unwrap();
        self.update_last_seen_time(connect_via).await;
        let actor = match self
            .asm
            .cc
            .authenticate_adapter_or_node(self.asm.clone(), creq, connect_via)
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                warn!(target: API, "connection authorization failed for node {:?}: {}", connect_via, e);
                let mut err_builder = results.get().init_resp().init_error();
                // An error the auth path already classified for the wire carries its
                // exact code and retry hint (zipline#11; `ErrorCode` in vs.capnp); everything else
                // stays a blanket authError. Neither branch echoes internal detail.
                match e {
                    ServiceError::ApiResponse(api) => {
                        err_builder.set_code(api.code.into());
                        err_builder.set_message(&api.message);
                        err_builder.set_retry_in(api.retry_in);
                    }
                    _ => write_error(
                        &mut err_builder,
                        vsapi::ErrorCode::AuthError,
                        format!("adapter authorization failed: {}", e).as_str(),
                    ),
                }
                self.asm.counters.incr(CounterType::AuthorizeConnectFailed);
                return Ok(());
            }
        };

        let actor_addr = actor.get_zpr_addr().unwrap().clone(); // MUST have an addr by now.

        // Topology operation lock (see TopoOps): from the admission recheck through
        // the node's link install or the adapter's actor write. Authentication above
        // ran outside it (it can query trusted services), so recheck here that the
        // calling session is still live and the policy is still the one `actor` was
        // approved under; a superseded handle must not mutate the new session's state.
        let ops = self.asm.topo_mgr.ops().await;
        if let Err((code, msg)) = self.admit_under_guard(&ops, &actor).await {
            warn!(target: API, "authorize_connect for {:?} via {:?} refused under lock: {msg}", actor.get_cn(), connect_via);
            // Release the address only if it is not live elsewhere (a node already in
            // the router keeps it).
            if !self.asm.topo_mgr.has_node(&actor_addr)
                && self.asm.net_mgr.is_managed_address(&actor_addr)
            {
                if let Err(e) = self.asm.net_mgr.release_zpr_addr(actor_addr) {
                    warn!(target: API, "failed to release address, actor={}: {}", actor_addr, e);
                }
            }
            let mut err_builder = results.get().init_resp().init_error();
            write_error(&mut err_builder, code, msg);
            self.asm.counters.incr(CounterType::AuthorizeConnectFailed);
            return Ok(());
        }

        if actor.is_node() {
            let psnap = self.asm.policy_mgr.get_current_snapshot();
            if let Err(add_err) = self
                .asm
                .topo_mgr
                .add_linked_node(
                    &ops,
                    &psnap,
                    &self.asm.actor_mgr,
                    &actor,
                    &connect_via,
                    &actor_addr,
                )
                .await
            {
                warn!(target: API, "failed to add connecting node {:?} to during authorize_connect: {}", actor.get_cn(), add_err);

                // Only release the address if THIS call created the node. For a
                // pre-existing node the address is still live in actor/router state, so
                // releasing it would corrupt the allocator.
                if matches!(add_err, AddLinkedNodeError::NewNodeFailed(_))
                    && self.asm.net_mgr.is_managed_address(&actor_addr)
                {
                    if let Err(e) = self.asm.net_mgr.release_zpr_addr(actor_addr) {
                        warn!(target: API, "failed to release node address in error handler, actor={}: {}", actor_addr, e);
                    }
                }

                let mut err_builder = results.get().init_resp().init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "state update failed",
                );
                self.asm.counters.incr(CounterType::AuthorizeConnectFailed);
                return Ok(());
            }
        } else {
            // Have an actor. Will have a ZPR address at this point.
            if let Err(e) = self
                .asm
                .actor_mgr
                .add_adapter_via_node(&actor, &connect_via, &self.asm.policy_service_names())
                .await
            {
                error!(target: API, "failed to add authenticated adapter {:?} to actor db: {}", actor.get_cn(), e);

                if self.asm.net_mgr.is_managed_address(&actor_addr) {
                    if let Err(e) = self.asm.net_mgr.release_zpr_addr(actor_addr) {
                        warn!(target: API, "failed to release adapter address {}: {}", actor_addr, e);
                    }
                }

                let mut err_builder = results.get().init_resp().init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "state update failed",
                );
                self.asm.counters.incr(CounterType::AuthorizeConnectFailed);
                return Ok(());
            }
        }

        // Released before the denylist re-check, which may disconnect (and so take
        // the lock itself), and before the event-queue send below.
        drop(ops);

        // PR #42 review (P1): the actor is persisted — re-check the denylist
        // to close the check-then-persist race with an admin revocation. On a
        // hit the gate has already disconnected the actor; report the same
        // uniform credential rejection a pre-check hit gets.
        if let Err(e) = self
            .asm
            .cc
            .enforce_denylist_after_persist(&self.asm, &actor)
            .await
        {
            warn!(target: API, "connection authorization revoked post-persist for node {:?}: {}", connect_via, e);
            let mut err_builder = results.get().init_resp().init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthError,
                "adapter authorization failed: not authorized",
            );
            self.asm.counters.incr(CounterType::AuthorizeConnectFailed);
            return Ok(());
        }

        {
            let expires_val = if let Some(exp) = actor.get_authentication_expiration() {
                let dt: DateTime<Utc> = exp.into();
                dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            } else {
                "never".to_string()
            };
            info!(
                target: API,
                "successfully authorized {} {:?} with address {actor_addr} (expires {})",
                if actor.is_node() { "node" } else { "adapter" },
                actor.get_cn(),
                expires_val
            );
        }
        let zpr_con = Connection::new(actor_addr, connect_auth_expires(&actor));
        let mut resp_builder = results.get().init_resp().init_ok();
        zpr_con.write_to(&mut resp_builder);

        let evt = VsEvent::ActorJoins(actor_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: API, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
        }

        // If a node just connected, the next thing it will try to do is open a connection
        // to VSAPI. We do not generate a visa since we currently have no mechanism to
        // hand the visa down to the new node. Instead, we plan to let the new node issue
        // a request (like an adapter) to its new peer which will need to somehow get the
        // visa installed on the node node (not link an adapter).

        // TODO: Is this counter name misleading?  We use node-connection-success for VSAPI node-authorization calls.
        // This success is for the VSAPI authorize_connect call which could be authorizing an
        // actor with role node or adapter.
        self.asm.counters.incr(CounterType::AuthorizeConnectSuccess);

        Ok(())
    }

    async fn reauthorize(
        self: Rc<Self>,
        params: vsapi::v_s_handle::ReauthorizeParams,
        mut results: vsapi::v_s_handle::ReauthorizeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "reauthorize from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "reauthorize from disconnected node {:?}: refused", self.node.get_cn());
            let mut err_builder = results.get().init_resp().init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }

        let req = ReauthRequest::try_from(params.get()?.get_req()?)
            .map_err(|e| capnp::Error::failed(format!("failed to parse ReauthRequest: {}", e)))?;
        let zpr_addr = req.zpr_addr;
        let blobs = req.blobs;

        let connect_via = self.node.get_zpr_addr().unwrap();
        self.update_last_seen_time(connect_via).await;

        let actor = match self
            .asm
            .cc
            .reauthorize_actor(
                self.asm.clone(),
                zpr_addr,
                blobs,
                connect_via,
                self.session.as_deref(),
            )
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                info!(target: API, "reauthorize failed for actor {zpr_addr} via node {:?}: {}", self.node.get_cn(), e);
                let mut err_builder = results.get().init_resp().init_error();
                // Same wire discipline as authorize_connect: an error the
                // reauth path already classified carries its exact code and
                // retry hint; everything else stays a blanket authError.
                // Neither branch echoes internal detail.
                match e {
                    ServiceError::ApiResponse(api) => {
                        err_builder.set_code(api.code.into());
                        err_builder.set_message(&api.message);
                        err_builder.set_retry_in(api.retry_in);
                    }
                    _ => write_error(
                        &mut err_builder,
                        vsapi::ErrorCode::AuthError,
                        "reauthorization failed",
                    ),
                }
                return Ok(());
            }
        };

        let auth_expires = connect_auth_expires(&actor);
        {
            let dt: DateTime<Utc> = auth_expires.into();
            info!(
                target: API,
                "reauthorized {} {:?} at address {zpr_addr} (expires {})",
                if actor.is_node() { "node" } else { "adapter" },
                actor.get_cn(),
                dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            );
        }
        let zpr_con = Connection::new(zpr_addr, auth_expires);
        let mut resp_builder = results.get().init_resp().init_ok();
        zpr_con.write_to(&mut resp_builder);
        Ok(())
    }

    async fn notify_disconnect(
        self: Rc<Self>,
        req: vsapi::v_s_handle::NotifyDisconnectParams,
        mut resp: vsapi::v_s_handle::NotifyDisconnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "notify_disconnect from {:?}", self.node.get_cn());
        // Liveness gate BEFORE parsing or acting on the notice (PR #41 review,
        // Codex P1): a node dropped by `cc.disconnect` retains its capnp
        // capability, and without this gate that dead handle could still
        // drive `cc.disconnect` for any address and remove live actor state.
        if !self.node_is_live().await {
            warn!(target: API, "notify_disconnect from disconnected node {:?}: refused", self.node.get_cn());
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        let dnotice = req.get()?.get_req()?;

        // If no ZPR address is specified that means that the node itself is disconnecting.
        let maybe_zpr_addr = if dnotice.has_zpr_addr() {
            let zpr_ipaddr = dnotice.get_zpr_addr()?;
            Some(ipaddr_from_capnp(zpr_ipaddr)?)
        } else {
            // populate with the actor ZPR addr.
            self.node.get_zpr_addr().cloned()
        };

        // I believe we need a ZPR address here otherwise this is just a NOP.
        if maybe_zpr_addr.is_none() {
            warn!(target: API, "notify_disconnect but no zpr address passed or derivable from actor {:?}", self.node.get_cn());
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation,
                "disconnect requires zpr address",
            );
            return Ok(());
        }
        let zpr_addr = maybe_zpr_addr.unwrap();

        // Scope the disconnect to the calling node (zipline#182): a live node
        // may disconnect only itself, an adapter docked to it, or an AAA actor
        // whose registered docking node is the caller. Without this check any
        // live node could name any actor or node and `cc.disconnect` would
        // tear it down — one subverted node could deny the whole ZPRnet,
        // breaking the SECURITY_MODEL.md Case 2 containment. An unknown target
        // has no docking entry and so falls out here as a refusal, which is
        // the safe default. Mirrors the session bindings `reauthorize` has.
        //
        // Topology operation lock (see TopoOps): the caller's liveness is rechecked
        // and the scope decided under it, and the teardown runs under it, so a handle
        // whose node reconnected meanwhile cannot tear down the new session's state.
        let ops = self.asm.topo_mgr.ops().await;
        if !self.node_is_live().await {
            warn!(target: API, "notify_disconnect from superseded handle {:?}: refused", self.node.get_cn());
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        let caller_addr = self.node.get_zpr_addr();
        let in_scope = match caller_addr {
            Some(caller) => {
                zpr_addr == *caller
                    || self.asm.actor_mgr.get_docking_node_for_adapter(&zpr_addr) == Some(*caller)
                    || self.asm.actor_mgr.get_docking_node_for_aaa(&zpr_addr) == Some(*caller)
            }
            // A caller with no ZPR address cannot own anything; refuse.
            None => false,
        };
        if !in_scope {
            warn!(
                target: API,
                "notify_disconnect from node {:?} for out-of-scope target {}: refused",
                self.node.get_cn(), zpr_addr
            );
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation,
                "disconnect target is not the calling node or docked to it",
            );
            return Ok(());
        }

        let reason = dnotice.get_reason_code()?;
        debug!(
            target: API,
            "disconnect call from node {:?} for {} with reason {:?}",
            self.node.get_cn(), zpr_addr, reason
        );

        // The disconnect call updates our state database. The VSS worker of a
        // disconnected node is stopped after the guard is released.
        let (vss, result) = self
            .asm
            .cc
            .disconnect_locked(&ops, &self.asm, zpr_addr, reason)
            .await;
        drop(ops);
        crate::connection_control::ConnectionControl::stop_vss_worker(vss, &zpr_addr).await;
        match result {
            Ok(()) => (),
            Err(e) => {
                warn!(target: API, "error processing disconnect of {}: {}", zpr_addr, e);
                let res_builder = resp.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "internal error during disconnect",
                );
                return Ok(());
            }
        }
        let evt = VsEvent::ActorLeaves(zpr_addr, reason);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: API, "failed to record actor leaves event for {}: {}", zpr_addr, e);
        }
        let mut res_builder = resp.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }

    /// A node reports which of its links are up (zl-zipline#224). The call carries a
    /// snapshot: every link the node has, by peer CN, replacing its previous report.
    /// The visa service routes over a link only while both ends report it up; a link
    /// that goes down has the visas crossing it revoked, so their flows re-request and
    /// get a route around it. A link coming up affects new visas only. A `failed` entry
    /// marks the pair, which is then left out of both ends' topology until either end
    /// reconnects (R13a); the report itself never sends topology.
    ///
    /// Errors: `authRequired` on a dead handle; `paramError` for more entries than the
    /// node's policy-declared links, an empty peerCn, or a peerCn listed twice.
    async fn report_link_states(
        self: Rc<Self>,
        params: vsapi::v_s_handle::ReportLinkStatesParams,
        mut results: vsapi::v_s_handle::ReportLinkStatesResults,
    ) -> Result<(), capnp::Error> {
        /// Answer with an error and log why.
        fn refuse(
            results: &mut vsapi::v_s_handle::ReportLinkStatesResults,
            code: vsapi::ErrorCode,
            msg: &str,
        ) {
            let mut err_builder = results.get().init_res().init_error();
            write_error(&mut err_builder, code, msg);
        }

        // Topology operation lock (see TopoOps), taken before this call's first await
        // and held through the last revocation. Taking it first keeps reports a node
        // pipelines on one handle in the order they arrived: the lock is FIFO and the
        // RPC system starts handlers in arrival order, so a later snapshot can never
        // apply before an earlier one. Under it, the liveness check, validation and
        // application cannot interleave with a disconnect, reconnect or policy pass.
        let ops = self.asm.topo_mgr.ops().await;
        if !self.node_is_live().await {
            warn!(target: API, "report_link_states from disconnected node {:?}: refused", self.node.get_cn());
            refuse(
                &mut results,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        let Some(reporter) = self.node.get_zpr_addr().cloned() else {
            refuse(
                &mut results,
                vsapi::ErrorCode::InvalidOperation,
                "node has no ZPR address assigned",
            );
            return Ok(());
        };

        // Decode, then validate at the trust boundary before storing anything.
        let mut entries = Vec::new();
        for reader in params.get()?.get_links()?.iter() {
            match LinkStateReport::try_from(reader) {
                Ok(e) => entries.push(e),
                Err(e) => {
                    warn!(target: API, "report_link_states from {reporter}: undecodable entry: {e}");
                    refuse(
                        &mut results,
                        vsapi::ErrorCode::ParamError,
                        "undecodable link-state entry",
                    );
                    return Ok(());
                }
            }
        }
        let psnap = self.asm.policy_mgr.get_current_snapshot();
        let declared_peers = psnap.policy().get_peers_for_node(&reporter).unwrap_or(&[]);
        let entries = match validate_snapshot(entries, declared_peers.len()) {
            Ok(entries) => entries,
            Err(why) => {
                warn!(target: API, "report_link_states from {reporter}: {why}");
                refuse(&mut results, vsapi::ErrorCode::ParamError, &why);
                return Ok(());
            }
        };

        // Entries that match no declared peer's CN are kept (they are harmless and may
        // race a policy change) but can never make a link usable; note them.
        let cn_of = TopologyMgr::policy_cn_lookup(&psnap);
        for e in &entries {
            let known = declared_peers
                .iter()
                .any(|p| cn_of(&p.remote_zpr_addr).as_deref() == Some(e.peer_cn.as_str()));
            if !known {
                debug!(target: API, "report_link_states from {reporter}: peerCn '{}' matches no declared peer", e.peer_cn);
            }
        }

        // Apply the report with the CNs of the policy current at application time, not
        // the snapshot captured above: a policy update whose revalidation finishes in
        // between would otherwise be overwritten with old-policy CNs. record_link_states
        // loads that snapshot once, inside its table lock (which revalidation also
        // holds), and evaluates every CN against it. `get_current_snapshot` is a
        // lock-free load, so there is no lock-order concern.
        let current_policy = || self.asm.policy_mgr.get_current_snapshot();
        let went_down = self.asm.topo_mgr.record_link_states(
            &ops,
            &reporter,
            self.session.as_deref(),
            entries,
            &current_policy,
        );
        // Revoke the visas crossing every link that just went down. A visa whose
        // revocation write fails is quarantined and retried per visa (VisaMgr), so the
        // report itself succeeds either way.
        for (a, b) in went_down {
            let _ = revoke_visas_over_link(&self.asm, &a, &b).await;
        }
        drop(ops);

        results.get().init_res().set_ok(());
        Ok(())
    }

    async fn visa_request(
        self: Rc<Self>,
        args: vsapi::v_s_handle::VisaRequestParams,
        mut response: vsapi::v_s_handle::VisaRequestResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "visa_request from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "visa_request from disconnected node {:?}: refused", self.node.get_cn());
            let res_builder = response.get().init_resp();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }

        self.asm.counters.incr(CounterType::VsApiVisaRequests);

        // A node must have an address.
        let requestor_addr = self
            .node
            .get_zpr_addr()
            .expect("programming error - node must have an address");
        self.update_last_seen_time(requestor_addr).await;

        match self
            .do_visa_request(args, config::DEFAULT_VISA_REQ_TIMEOUT)
            .await
        {
            Ok(decision) => match decision {
                VisaDecision::Allow(visa, _route) => {
                    // TODO: Do something with the route
                    let res_builder = response.get().init_resp();
                    let mut visa_bldr = res_builder.init_allow();
                    visa.write_to(&mut visa_bldr);

                    // Set visa as installed in our state
                    if let Err(e) = self
                        .asm
                        .visa_mgr
                        .visa_installed(visa.issuer_id, requestor_addr)
                        .await
                    {
                        error!(target: API, "failed to update visa {} as installed on {}: {}", visa.issuer_id, requestor_addr, e);
                    }
                }
                VisaDecision::Deny(denial_reason) => {
                    let mut res_builder = response.get().init_resp();
                    res_builder.set_deny(denial_reason.into());
                }
            },

            Err((code, msg)) => {
                error!(target: API, "internal error ({code:?})processing visa_request: {msg}");
                let res_builder = response.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(&mut err_builder, code, &msg);
            }
        }
        return Ok(());
    }

    async fn ping(
        self: Rc<Self>,
        _req: vsapi::v_s_handle::PingParams,
        mut results: vsapi::v_s_handle::PingResults,
    ) -> Result<(), capnp::Error> {
        let node_cn = self.node.get_cn().unwrap_or("<unknown>");
        trace!(target: API, "ping from {node_cn}");
        if !self.node_is_live().await {
            warn!(target: API, "ping from disconnected node {node_cn}: refused");
            let res_builder = results.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }
        if let Some(addr) = self.node.get_zpr_addr() {
            self.update_last_seen_time(addr).await;
        }
        self.asm.counters.incr(CounterType::VsApiPings);

        if let Some(node_addr) = self.node.get_zpr_addr() {
            if let Some(vssaddr) = self
                .asm
                .actor_mgr
                .get_node_vss(&node_addr)
                .await
                .unwrap_or(None)
            {
                match self.asm.vss_mgr.start_vss_worker_if_none(
                    self.asm.clone(),
                    &node_addr,
                    &vssaddr,
                    Duration::from_secs(0),
                ) {
                    Ok(true) => {
                        info!(
                            "found no VSS worker running for node {node_cn} @ {node_addr} - started one"
                        );
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(target: API, "failed to start VSS worker for node {node_cn}: {}", e);
                    }
                }
            }
        }

        let mut res_builder = results.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }

    /// `getLoginNonce` (zl-zipline#232): mint a visa-service OIDC login nonce
    /// for the calling node's OWN login. The nonce is bound, in the
    /// [crate::login_nonce::LoginNonceStore], to this node's actor address and
    /// to the VS-API session generation this handle was minted under, so only
    /// this node, in this session, can spend it on a `reauthorize` that gains
    /// its user namespace. Errors (vs.capnp): `authRequired` on a dead handle,
    /// `quotaExceeded` when the node already holds the maximum number of
    /// outstanding nonces.
    async fn get_login_nonce(
        self: Rc<Self>,
        _params: vsapi::v_s_handle::GetLoginNonceParams,
        mut results: vsapi::v_s_handle::GetLoginNonceResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "get_login_nonce from {:?}", self.node.get_cn());
        let addr_and_session = self.node.get_zpr_addr().copied().zip(self.session.clone());
        let (true, Some((node_addr, session))) = (self.node_is_live().await, addr_and_session)
        else {
            warn!(target: API, "get_login_nonce from disconnected node {:?}: refused", self.node.get_cn());
            write_error(
                &mut results.get().init_res().init_error(),
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        };
        self.update_last_seen_time(&node_addr).await;

        match mint_login_nonce_for_handle(&self.asm, node_addr, &session).await {
            Ok((nonce, expires)) => {
                let expires_at = expires
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut ok = results.get().init_res().init_ok();
                ok.set_nonce(&nonce);
                ok.set_expires_at(expires_at);
            }
            Err(MintError::QuotaExceeded) => {
                info!(target: API, "get_login_nonce from {:?}: outstanding nonce limit reached", self.node.get_cn());
                write_error(
                    &mut results.get().init_res().init_error(),
                    vsapi::ErrorCode::QuotaExceeded,
                    "too many outstanding login nonces",
                );
            }
            Err(MintError::StaleSession) => {
                warn!(target: API, "get_login_nonce from {:?}: the node re-authenticated; stale handle refused", self.node.get_cn());
                write_error(
                    &mut results.get().init_res().init_error(),
                    vsapi::ErrorCode::AuthRequired,
                    "node is no longer connected; re-authenticate",
                );
            }
            Err(MintError::Random(e)) => {
                error!(target: API, "get_login_nonce: random source failed: {e}");
                write_error(
                    &mut results.get().init_res().init_error(),
                    vsapi::ErrorCode::Internal,
                    "internal error",
                );
            }
        }
        Ok(())
    }

    /// The relay asks for a joining Zode's bootstrap visas when that Zode's initial link
    /// comes up (ZODE_LINKS.md J2, J3, J6); see
    /// [crate::visa_bootstrap::request_bootstrap_visas] for the rule and what a request does
    /// to the joiner's previous join. A trust boundary: only the node the visa service
    /// docks on may ask, and only for a CN in its own topology.
    ///
    /// Errors (vs.capnp): `authRequired` on a dead handle; `invalidOperation` when the
    /// caller is not the relay; `notFound` when `peerCn` names no peer in the caller's
    /// topology (or is not valid UTF-8); `internal` when the visas could not be minted.
    async fn request_bootstrap_visas(
        self: Rc<Self>,
        params: vsapi::v_s_handle::RequestBootstrapVisasParams,
        mut results: vsapi::v_s_handle::RequestBootstrapVisasResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "request_bootstrap_visas from {:?}", self.node.get_cn());
        let refuse = |results: &mut vsapi::v_s_handle::RequestBootstrapVisasResults,
                      code: vsapi::ErrorCode,
                      message: &str| {
            write_error(&mut results.get().init_res().init_error(), code, message);
        };
        let (true, Some(relay)) = (self.node_is_live().await, self.node.get_zpr_addr().copied())
        else {
            warn!(target: API, "request_bootstrap_visas from disconnected node {:?}: refused", self.node.get_cn());
            refuse(
                &mut results,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        };
        self.update_last_seen_time(&relay).await;
        // An unreadable CN names no peer.
        let Ok(peer_cn) = params.get()?.get_peer_cn()?.to_str() else {
            warn!(target: API, "request_bootstrap_visas from {relay}: peerCn is not valid UTF-8: refused");
            refuse(
                &mut results,
                vsapi::ErrorCode::NotFound,
                "peerCn names no peer",
            );
            return Ok(());
        };

        let refusal = match crate::visa_bootstrap::request_bootstrap_visas(
            &self.asm,
            &relay,
            self.session.as_deref(),
            peer_cn,
        )
        .await
        {
            Ok(visas) => {
                visas.write_to(&mut results.get().init_res().init_ok());
                return Ok(());
            }
            Err(refusal) => refusal,
        };
        use crate::visa_bootstrap::Refusal;
        let (code, message) = match refusal {
            Refusal::StaleSession => (
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            ),
            Refusal::NotRelay => (
                vsapi::ErrorCode::InvalidOperation,
                "only the relay may request bootstrap visas",
            ),
            Refusal::UnknownPeer => (
                vsapi::ErrorCode::NotFound,
                "peerCn is not a peer in the caller's topology",
            ),
            Refusal::Failed(e) => {
                error!(target: API, "request_bootstrap_visas from {relay} for {peer_cn:?}: {e}");
                (vsapi::ErrorCode::Internal, "failed to mint bootstrap visas")
            }
        };
        warn!(target: API, "request_bootstrap_visas from {relay} for {peer_cn:?}: refused ({code:?})");
        refuse(&mut results, code, message);
        Ok(())
    }

    async fn visa_ids_request(
        self: Rc<Self>,
        _req: vsapi::v_s_handle::VisaIdsRequestParams,
        mut res: vsapi::v_s_handle::VisaIdsRequestResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "visa_ids_request from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "visa_ids_request from disconnected node {:?}: refused", self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }

        let requestor_addr = self
            .node
            .get_zpr_addr()
            .expect("programming error - node must have an address");
        self.update_last_seen_time(requestor_addr).await;

        let installed_visas_res = self
            .asm
            .visa_mgr
            .get_installed_visa_ids_for_node(requestor_addr)
            .await;

        let res_builder = res.get().init_res();

        match installed_visas_res {
            Ok(installed_visas) => {
                let mut ok_builder = res_builder.initn_ok(installed_visas.len() as u32);

                for (i, id) in installed_visas.iter().enumerate() {
                    ok_builder.set(i as u32, *id);
                }
            }
            Err(_) => {
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "failed to retrieve visa ids",
                );
            }
        }

        Ok(())
    }

    async fn visa_request_by_id(
        self: Rc<Self>,
        req: vsapi::v_s_handle::VisaRequestByIdParams,
        mut res: vsapi::v_s_handle::VisaRequestByIdResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: API, "visa_request_by_id from {:?}", self.node.get_cn());
        if !self.node_is_live().await {
            warn!(target: API, "visa_request_by_id from disconnected node {:?}: refused", self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::AuthRequired,
                "node is no longer connected; re-authenticate",
            );
            return Ok(());
        }

        let requestor_addr = self
            .node
            .get_zpr_addr()
            .expect("programming error - node must have an address");
        self.update_last_seen_time(requestor_addr).await;

        let ids_list_rdr = req.get()?.get_req()?;
        let ids: Vec<u64> = ids_list_rdr.iter().collect();

        let res_builder = res.get().init_res();

        if ids.len() > config::MAX_NUM_VISA_REQUEST {
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                format!(
                    "Node can only request {} visas at a time",
                    config::MAX_NUM_VISA_REQUEST
                )
                .as_str(),
            );

            return Ok(());
        }

        // Have to know what visas the node is actually allowed to know about
        // TODO would it be better to make a function that gets a visa by id but only if it is installed on a given node?
        // I don't think so because I think this would result in more db access than the current strategy
        let installed_visas_res = self
            .asm
            .visa_mgr
            .get_installed_visa_ids_for_node(requestor_addr)
            .await;

        match installed_visas_res {
            Ok(installed_visas) => {
                // Remove all ids that are not installed on the node
                let installed_set: std::collections::HashSet<u64> =
                    installed_visas.into_iter().collect();
                let filtered_ids: Vec<u64> = ids
                    .into_iter()
                    .filter(|id| installed_set.contains(id))
                    .collect();

                // Create vec of actualized visas
                let mut visas = Vec::new();
                for id in filtered_ids.iter() {
                    match self.asm.visa_mgr.get_visa_with_metadata_by_id(*id).await {
                        Ok(Some(visa_with_metadata)) => {
                            match self
                                .asm
                                .visa_mgr
                                .actualize_visa_for_target_node(
                                    visa_with_metadata.visa,
                                    requestor_addr,
                                )
                                .await
                            {
                                Ok(v) => visas.push(v),
                                Err(_) => {
                                    debug!(target: API, "Node {requestor_addr} requested visa {id} but actualization failed")
                                }
                            };
                        }
                        _ => {
                            debug!(target: API, "Node {requestor_addr} requested visa {id} but not found")
                        }
                    }
                }

                let mut ok_builder = res_builder.initn_ok(visas.len() as u32);

                for (i, v) in visas.iter().enumerate() {
                    let mut visa_bldr = ok_builder.reborrow().get(i as u32);
                    v.write_to(&mut visa_bldr);
                }
            }
            Err(_) => {
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "failed to retrieve visa ids",
                );
            }
        }

        Ok(())
    }
}

/// The `authExpires` for a `Connection` response (zipline#86): the actor's
/// authentication expiry — the minimum over its authority and identity
/// attributes — falling back to the ZPR-address attribute's expiry only when
/// the actor carries no authentication expiry at all. Returning the address
/// lease here (previous behaviour of `authorize_connect`) told the node its
/// authentication lasted ~100 years, so it never scheduled silent OIDC
/// renewal.
fn connect_auth_expires(actor: &Actor) -> SystemTime {
    actor.get_authentication_expiration().unwrap_or_else(|| {
        actor
            .get_attribute(key::ZPR_ADDR)
            .expect("connected actor must carry a zpr.addr attribute")
            .get_expires()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use capnp::message::Builder;

    /// The authExpires an endpoint gets back must be its authentication
    /// expiry, not the ZPR-address lease. With a user authority expiring in
    /// 120 s and a default-expiry (far-future) zpr.addr, the helper returns
    /// the user-authority expiry (zipline#86).
    #[test]
    fn test_connect_auth_expires_uses_user_authority_not_addr_lease() {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de:1::9"))
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder(key::USER_AUTHORITY)
                    .expires_in(Duration::from_secs(120))
                    .value("some-oidc-issuer"),
            )
            .unwrap();

        let user_expiry = actor
            .get_attribute(key::USER_AUTHORITY)
            .unwrap()
            .get_expires();
        let addr_expiry = actor.get_attribute(key::ZPR_ADDR).unwrap().get_expires();

        let got = connect_auth_expires(&actor);
        assert_eq!(
            got, user_expiry,
            "authExpires must be the authentication expiry, not the address lease"
        );
        assert_ne!(
            got, addr_expiry,
            "sanity: the address lease (default far-future) must not be the result"
        );
        // ≈ now + 120 s, well under the far-future address lease.
        let secs_out = got
            .duration_since(SystemTime::now())
            .expect("expiry must be in the future")
            .as_secs();
        assert!(
            (100..=120).contains(&secs_out),
            "expected ~120 s out, got {secs_out} s"
        );
    }

    /// Authentication's policy recheck under the topology lock (round 13): an
    /// actor approved under the current policy passes; one approved under an older
    /// policy, or carrying no `zpr.vinst`, does not.
    #[tokio::test]
    async fn test_approved_under_current_policy() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let current = asm.policy_mgr.get_current_snapshot().vinst();
        let with_vinst = |v: u64| {
            let mut a = Actor::new();
            a.add_attribute(Attribute::builder(key::VINST).value(v.to_string()))
                .unwrap();
            a
        };
        assert!(approved_under_current_policy(&asm, &with_vinst(current)));
        assert!(!approved_under_current_policy(
            &asm,
            &with_vinst(current + 1)
        ));
        if current > 0 {
            assert!(!approved_under_current_policy(
                &asm,
                &with_vinst(current - 1)
            ));
        }
        assert!(!approved_under_current_policy(&asm, &Actor::new()) || current == 0);
    }

    /// A device-only actor (no user authority) gets its device-authority
    /// expiry as authExpires. Since zipline#119 the bootstrap stamp is
    /// far-future, so a bootstrap-only endpoint's authExpires is far-future
    /// too — it never needs to schedule renewal.
    #[test]
    fn test_connect_auth_expires_device_only_uses_device_authority() {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de:1::9"))
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(crate::config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();

        let device_expiry = actor
            .get_attribute(key::DEVICE_AUTHORITY)
            .unwrap()
            .get_expires();
        assert_eq!(connect_auth_expires(&actor), device_expiry);
        // Sanity: the bootstrap window really is far-future (zipline#119).
        assert!(device_expiry > SystemTime::now() + Duration::from_secs(50 * 365 * 24 * 60 * 60));
    }

    /// With no authentication expiry at all, the helper falls back to the
    /// zpr.addr attribute's expiry — the pre-#86 behaviour, now only the
    /// fallback.
    #[test]
    fn test_connect_auth_expires_falls_back_to_addr_expiry() {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder(key::ZPR_ADDR)
                    .expires_in(Duration::from_secs(500))
                    .value("fd5a:5052:90de:1::9"),
            )
            .unwrap();

        let addr_expiry = actor.get_attribute(key::ZPR_ADDR).unwrap().get_expires();
        assert_eq!(connect_auth_expires(&actor), addr_expiry);
    }

    /// Helper function to create a v_s_connect_request message with the given params
    fn build_connect_request(
        build_fn: impl FnOnce(vsapi::v_s_connect_request::Builder),
    ) -> capnp::message::Reader<capnp::serialize::OwnedSegments> {
        let mut message = Builder::new_default();
        {
            let req = message.init_root::<vsapi::v_s_connect_request::Builder>();
            build_fn(req);
        }
        // Serialize and deserialize to get a Reader
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &message).unwrap();
        let reader =
            capnp::serialize::read_message(&mut &buf[..], capnp::message::ReaderOptions::new())
                .unwrap();
        reader
    }

    /// A param whose declared type disagrees with the value union must fail conversion,
    /// which connect()/open() report as ParamError rather than an RPC-level failure.
    #[test]
    fn test_connect_request_mistyped_param_fails_conversion() {
        let message = build_connect_request(|mut req| {
            req.set_cn("node1");
            let mut params = req.init_params(1);
            let mut param = params.reborrow().get(0);
            param.set_name("test_name");
            param.set_ptype(vsapi::ParamT::String);
            param.set_value_u64(42);
        });

        let reader: vsapi::v_s_connect_request::Reader = message.get_root().unwrap();
        assert!(VSConnectRequest::try_from(reader).is_err());
    }

    /// A node joining via `connect` gets router edges for its policy-declared peers that
    /// are already connected, and none for peers that are not.
    #[tokio::test]
    async fn test_install_policy_links_only_for_connected_peers() {
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::{
            FakeResolver, make_node_actor_defexp, make_peering, policy_with_peerings,
        };
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap(); // connected peer
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap(); // the joining node
        let c: IpAddr = "fd5a:5052:90de:1::3".parse().unwrap(); // declared but absent peer

        let mut asm = new_assembly_for_tests(None).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[
                make_peering(a, b, "link-ab", vec![]),
                make_peering(b, c, "link-bc", vec![]),
            ]),
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

        // Both A and B are authenticated nodes in the router; C is not connected at all.
        for (addr, cn) in [(a, "node-a"), (b, "node-b")] {
            let actor = make_node_actor_defexp(&addr.to_string(), cn, "[fd5a:5052::100]:1234");
            asm.actor_mgr
                .add_node(&actor, false, &Default::default())
                .await
                .unwrap();
            asm.topo_mgr.add_node(addr).unwrap();
        }
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");

        install_policy_links_for_node(&asm, &asm.topo_mgr.ops_now(), &actor_b, &b).await;

        assert_eq!(
            asm.topo_mgr.get_peers(&b),
            vec![a],
            "expected exactly the link to the connected peer A"
        );
    }

    /// J5a on `open` (a session reconnect): the node gets two new VSAPI visas, forward
    /// and reverse, for its own session. `authenticate` calls the same
    /// [start_session_core_visas].
    #[tokio::test]
    async fn open_issues_the_node_new_vsapi_visas() {
        use crate::core_visas::tests::{ZODE, build_net};

        let (asm, _relay, zode) = build_net().await;
        let before = asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap();
        assert!(before.is_empty());

        let vs: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
            asm: asm.clone(),
            remote: SocketAddr::new(zode, 1234),
        });
        let mut req = vs.open_request();
        {
            let mut r = req.get().init_req();
            r.set_cn("zode");
            r.set_ctype(vsapi::VSConnT::Reconnect);
            let mut p = r.init_params(1).get(0);
            p.set_ptype(vsapi::ParamT::String);
            p.set_name(pname::SUBSTRATE_ADDR);
            p.set_value_text(format!("[{ZODE}]:5000"));
        }
        let resp = req.send().promise.await.unwrap();
        assert!(matches!(
            resp.get().unwrap().get_resp().unwrap().which().unwrap(),
            vsapi::result::Which::Ok(_)
        ));

        let vs_addr = asm.config.get_vs_addr();
        let mut tuples = Vec::new();
        for id in asm.visa_mgr.get_visa_ids_for_actors(&[zode]).await.unwrap() {
            let visa = asm.visa_mgr.get_visa_by_id(id).await.unwrap().unwrap();
            let pep = visa.dock_pep.unwrap();
            tuples.push((pep.source_addr, pep.dest_addr));
        }
        tuples.sort();
        let mut want = vec![(zode, vs_addr), (vs_addr, zode)];
        want.sort();
        assert_eq!(
            tuples, want,
            "one new visa per direction of the VSAPI session"
        );
    }

    mod authenticate_undo {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::test_helpers::make_node_actor_defexp;
        use libeval::actor::Role;
        use std::sync::Arc;

        #[tokio::test]
        async fn test_noop() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let undo = AuthenticateUndo::default();
            undo.undo(&asm, None).await; // must not panic
        }

        #[tokio::test]
        async fn test_releases_zpr_addr() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr = asm.net_mgr.get_next_zpr_addr(&Role::Node).unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.took_zpr_addr(&addr);
            undo.undo(&asm, None).await;

            // Address was released back to the pool, so take_zpr_addr should succeed.
            assert!(
                asm.net_mgr.take_zpr_addr(&addr).is_ok(),
                "address should have been released by undo"
            );
        }

        #[tokio::test]
        async fn test_removes_node_from_router() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();

            let mut undo = AuthenticateUndo::default();
            assert!(
                undo.add_node_to_router_and_track_if_added(
                    &asm.topo_mgr,
                    &asm.topo_mgr.ops_now(),
                    addr
                ),
                "new router node should be reported as added"
            );
            undo.undo(&asm, None).await;

            // Node was removed, so add_node must succeed again.
            assert!(
                asm.topo_mgr.add_node(addr).is_ok(),
                "node should have been removed from router by undo"
            );
        }

        #[tokio::test]
        async fn test_add_node_to_router_does_not_undo_preexisting_node() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr: IpAddr = "fd5a:5052:90de:1::3".parse().unwrap();

            asm.topo_mgr.add_node(addr).unwrap();

            let mut undo = AuthenticateUndo::default();
            let added = undo.add_node_to_router_and_track_if_added(
                &asm.topo_mgr,
                &asm.topo_mgr.ops_now(),
                addr,
            );

            assert!(
                !added,
                "pre-existing router node should not be reported as newly added"
            );
            undo.undo(&asm, None).await;
            assert!(
                asm.topo_mgr.add_node(addr).is_err(),
                "undo must not remove a node it did not add"
            );
        }

        #[tokio::test]
        async fn test_removes_node_from_actor_mgr() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
            let actor =
                make_node_actor_defexp("fd5a:5052:90de:1::2", "test-node", "[fd5a:5052::100]:1234");

            asm.actor_mgr
                .add_node(&actor, false, &Default::default())
                .await
                .unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.added_node_to_actor_mgr(&addr);
            undo.undo(&asm, None).await;

            let result = asm.actor_mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
            assert!(
                result.is_none(),
                "node should have been removed from actor_mgr by undo"
            );
        }

        #[tokio::test]
        async fn test_all_three_undone() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let addr = asm.net_mgr.get_next_zpr_addr(&Role::Node).unwrap();
            let actor =
                make_node_actor_defexp(&addr.to_string(), "test-node-2", "[fd5a:5052::101]:1234");

            asm.actor_mgr
                .add_node(&actor, false, &Default::default())
                .await
                .unwrap();

            let mut undo = AuthenticateUndo::default();
            undo.took_zpr_addr(&addr);
            undo.added_node_to_actor_mgr(&addr);
            assert!(
                undo.add_node_to_router_and_track_if_added(
                    &asm.topo_mgr,
                    &asm.topo_mgr.ops_now(),
                    addr
                ),
                "new router node should be reported as added"
            );
            undo.undo(&asm, None).await;

            assert!(
                asm.topo_mgr.add_node(addr).is_ok(),
                "node should have been removed from router"
            );
            asm.topo_mgr
                .remove_node(&asm.topo_mgr.ops_now(), &addr)
                .await;

            let actor_result = asm.actor_mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
            assert!(
                actor_result.is_none(),
                "node should have been removed from actor_mgr"
            );

            assert!(
                asm.net_mgr.take_zpr_addr(&addr).is_ok(),
                "zpr address should have been released"
            );
        }
    }

    // ---- K2 VS side (zipline#123) ----

    /// zipline#138: a fresh (`ctype=Reset`) connect must tear down the
    /// adapters docked through the node, not orphan their actor records.
    mod reset_teardown {
        use super::*;
        use crate::test_helpers::{build_sweep_asm, create_sweep_visa, make_adapter_actor_defexp};
        use libeval::actor::Role;
        use zpr::vsapi::v1::DisconnectReason;

        /// Node B resets. Before the fix its adapter actor records survived
        /// `add_node`'s replacement of the node record, so re-docking them was
        /// refused (occupied address), their visas stayed live on node A and
        /// their pool addresses were never released.
        #[tokio::test]
        async fn test_reset_tears_down_docked_adapters() {
            let (asm, node_a) = build_sweep_asm(true).await;
            let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
            let dst: IpAddr = "fd5a:5052:4000::b".parse().unwrap();

            // A second adapter on node B, on a managed pool address.
            let pooled = asm.net_mgr.get_next_zpr_addr(&Role::Adapter).unwrap();
            let pooled_actor = make_adapter_actor_defexp(&pooled.to_string(), "pooled");
            asm.actor_mgr
                .add_adapter_via_node(&pooled_actor, &node_b, &Default::default())
                .await
                .unwrap();

            // A visa held by node A from its adapter to node B's adapter.
            let visa_id = create_sweep_visa(&asm, &node_a, 0).await;

            // What the authenticate handler does for a Reset connect.
            reset_node_state(&asm, &asm.topo_mgr.ops_now(), &node_b)
                .await
                .unwrap();
            let node_b_actor = asm
                .actor_mgr
                .get_actor_by_zpr_addr(&node_b)
                .await
                .unwrap()
                .unwrap();
            asm.actor_mgr
                .add_node(&node_b_actor, false, &Default::default())
                .await
                .unwrap();

            for addr in [dst, pooled] {
                assert!(
                    asm.actor_mgr
                        .get_actor_by_zpr_addr(&addr)
                        .await
                        .unwrap()
                        .is_none(),
                    "adapter {addr} must not survive its node's reset"
                );
            }
            assert!(
                asm.actor_mgr
                    .get_adapters_connected_to_node(&node_b)
                    .await
                    .unwrap()
                    .is_empty(),
                "the reset node must have no docked adapters"
            );
            assert!(
                asm.net_mgr.take_zpr_addr(&pooled).is_ok(),
                "the pooled adapter's address must be released"
            );
            asm.net_mgr.release_zpr_addr(pooled).unwrap();
            assert_eq!(
                asm.visa_mgr
                    .get_pending_revoke_visa_ids_for_node(&node_a)
                    .await
                    .unwrap(),
                vec![visa_id],
                "the visa to the departed adapter must be revoked from node A"
            );

            // The same adapters re-dock cleanly.
            asm.actor_mgr
                .add_adapter_via_node(
                    &make_adapter_actor_defexp("fd5a:5052:4000::b", "dst"),
                    &node_b,
                    &Default::default(),
                )
                .await
                .expect("re-dock of dst after reset");
            asm.actor_mgr
                .add_adapter_via_node(&pooled_actor, &node_b, &Default::default())
                .await
                .expect("re-dock of pooled adapter after reset");
        }

        /// PR #45 review (Codex P1): an adapter that departed node A on its own
        /// and re-docked at node B (same address -- a static claim, or a
        /// recycled pool address) must survive a later Reset of node A.
        #[tokio::test]
        async fn test_reset_spares_adapter_redocked_elsewhere() {
            let (asm, node_a) = build_sweep_asm(false).await;
            let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
            let src: IpAddr = "fd5a:5052:4000::a".parse().unwrap();

            // The adapter leaves node A alone, then docks at node B.
            asm.cc
                .disconnect(asm.clone(), src, DisconnectReason::Admin)
                .await
                .unwrap();
            asm.actor_mgr
                .add_adapter_via_node(
                    &make_adapter_actor_defexp("fd5a:5052:4000::a", "src"),
                    &node_b,
                    &Default::default(),
                )
                .await
                .unwrap();

            reset_node_state(&asm, &asm.topo_mgr.ops_now(), &node_a)
                .await
                .unwrap();

            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&src)
                    .await
                    .unwrap()
                    .is_some(),
                "an adapter now docked at another node must survive this node's reset"
            );
            assert_eq!(
                asm.actor_mgr.get_docking_node_for_adapter(&src),
                Some(node_b)
            );
        }

        /// The visa service's own adapter is recorded as docked at its node
        /// (`hack_set_vs_docking_node`). A Reset of that node must not remove
        /// the VS's own actor record: the VS keeps running across the reset.
        #[tokio::test]
        async fn test_reset_spares_vs_own_adapter() {
            let (asm, node_a) = build_sweep_asm(false).await;
            let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
            asm.actor_mgr
                .hack_add_adapter_no_node(
                    &make_adapter_actor_defexp(&vs_addr.to_string(), config::VS_CN),
                    &Default::default(),
                )
                .await
                .unwrap();
            asm.actor_mgr
                .hack_set_vs_docking_node(&node_a)
                .await
                .unwrap();

            reset_node_state(&asm, &asm.topo_mgr.ops_now(), &node_a)
                .await
                .unwrap();

            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&vs_addr)
                    .await
                    .unwrap()
                    .is_some(),
                "the VS's own actor record must survive a reset of its docking node"
            );
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&"fd5a:5052:4000::a".parse().unwrap())
                    .await
                    .unwrap()
                    .is_none(),
                "other adapters on the node are still torn down"
            );
        }
    }

    mod k2_reconnect {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};
        use std::sync::Arc;
        use zpr::vsapi::v1::DisconnectReason;

        const NODE: &str = "fd5a:5052:3000::1";
        const ADAPTER: &str = "fd5a:5052:4000::a";

        /// A node's `Reconnect` re-approval must not disturb its docked
        /// adapters (K2): `add_node(reconnect = true)` — the store update the
        /// authenticate handler performs for `ctype=Reconnect` — updates the
        /// stored node actor (here its `zpr.vinst`) while the adapter stays
        /// connected to it.
        #[tokio::test]
        async fn test_reconnect_add_node_updates_vinst_and_keeps_adapters() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let node_addr: std::net::IpAddr = NODE.parse().unwrap();

            let mut node = make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
            node.add_attribute(Attribute::builder(key::VINST).value("1"))
                .unwrap();
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            asm.actor_mgr
                .add_adapter_via_node(
                    &make_adapter_actor_defexp(ADAPTER, "adapter-k2"),
                    &node_addr,
                    &Default::default(),
                )
                .await
                .unwrap();

            // The reconnect re-approval under the new snapshot: same node,
            // fresh vinst stamp, updated in place.
            let mut renewed = make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
            renewed
                .add_attribute(Attribute::builder(key::VINST).value("2"))
                .unwrap();
            asm.actor_mgr
                .add_node(&renewed, true, &Default::default())
                .await
                .unwrap();

            let stored = asm
                .actor_mgr
                .get_actor_by_zpr_addr(&node_addr)
                .await
                .unwrap()
                .expect("node must still exist after reconnect");
            assert_eq!(
                stored
                    .get_attribute(key::VINST)
                    .and_then(|a| a.get_single_value().ok().map(str::to_string)),
                Some("2".to_string()),
                "reconnect must stamp the new zpr.vinst"
            );
            let adapters = asm
                .actor_mgr
                .get_adapters_connected_to_node(&node_addr)
                .await
                .unwrap();
            assert_eq!(
                adapters,
                vec![ADAPTER.parse::<std::net::IpAddr>().unwrap()],
                "docked adapters must be untouched by the reconnect"
            );
        }

        /// A node dropped by `cc.disconnect` is refused on its next VS-API
        /// call (K2): the handle's liveness gate goes false, so every
        /// `VSHandleImpl` method answers `authRequired` instead of serving
        /// the stale capability.
        #[tokio::test]
        async fn test_disconnected_node_handle_is_refused() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let node_addr: std::net::IpAddr = NODE.parse().unwrap();

            let node = make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();

            // The handle the node held from its authenticate call.
            let handle = VSHandleImpl::new(asm.clone(), node);
            assert!(
                handle.node_is_live().await,
                "a connected node's handle must be live"
            );

            asm.cc
                .disconnect(asm.clone(), node_addr, DisconnectReason::Admin)
                .await
                .unwrap();

            assert!(
                !handle.node_is_live().await,
                "a disconnected node's handle must be refused"
            );
        }

        /// PR #41 review (Codex P1, zipline#123): `notify_disconnect` must apply
        /// the same liveness gate as every other `VSHandleImpl` handler. A node
        /// dropped by `cc.disconnect` retains its capnp capability; without the
        /// gate that dead handle can still submit a disconnect notice for any
        /// address and remove live actor state.
        #[tokio::test]
        async fn test_disconnected_node_handle_notify_disconnect_refused() {
            const VICTIM: &str = "fd5a:5052:3000::2";
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let asm = Arc::new(new_assembly_for_tests(None).await);
                    let node_addr: std::net::IpAddr = NODE.parse().unwrap();
                    let victim_addr: std::net::IpAddr = VICTIM.parse().unwrap();

                    let node =
                        make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
                    asm.actor_mgr
                        .add_node(&node, false, &Default::default())
                        .await
                        .unwrap();
                    // An independent second node: disconnecting the first must not
                    // touch it, so any removal below is the dead handle's doing.
                    asm.actor_mgr
                        .add_node(
                            &make_node_actor_defexp(
                                VICTIM,
                                "node-k2b",
                                "[fd5a:5052:3000::102]:1234",
                            ),
                            false,
                            &Default::default(),
                        )
                        .await
                        .unwrap();

                    // The capability the first node held from its authenticate call.
                    let handle: vsapi::v_s_handle::Client =
                        capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node));

                    // Drop the first node; its retained capability must go dead.
                    asm.cc
                        .disconnect(asm.clone(), node_addr, DisconnectReason::Admin)
                        .await
                        .unwrap();

                    let mut req = handle.notify_disconnect_request();
                    {
                        let mut dnotice = req.get().init_req();
                        let mut addr_bldr = dnotice.reborrow().init_zpr_addr();
                        victim_addr.write_to(&mut addr_bldr);
                        dnotice.set_reason_code(DisconnectReason::RemoteDisconnect);
                    }
                    let resp = req.send().promise.await.unwrap();
                    let res = resp.get().unwrap().get_res().unwrap();
                    match res.which().unwrap() {
                        vsapi::ok_or_error::Which::Error(err) => {
                            assert_eq!(
                                err.unwrap().get_code().unwrap(),
                                vsapi::ErrorCode::AuthRequired,
                                "a revoked handle must be told to re-authenticate"
                            );
                        }
                        vsapi::ok_or_error::Which::Ok(_) => {
                            panic!("a revoked handle must not drive notify_disconnect")
                        }
                    }
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&victim_addr)
                            .await
                            .unwrap()
                            .is_some(),
                        "live actor state must survive a revoked handle's disconnect notice"
                    );
                })
                .await;
        }

        /// PR #41 review (Codex P1, zipline#123): liveness must be bound to
        /// the authenticated session, not address+role. If a revoked node's
        /// address is reused by a DIFFERENT node, the old retained capability
        /// must stay dead — some node occupying the address is not enough.
        #[tokio::test]
        async fn test_address_reuse_does_not_revive_old_handle() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let node_addr: std::net::IpAddr = NODE.parse().unwrap();

            let mut node_a = make_node_actor_defexp(NODE, "node-a", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node_a);
            asm.actor_mgr
                .add_node(&node_a, false, &Default::default())
                .await
                .unwrap();
            let handle_a = VSHandleImpl::new(asm.clone(), node_a);
            assert!(handle_a.node_is_live().await, "precondition: A is live");

            // A is revoked; its address goes back to the pool.
            asm.cc
                .disconnect(asm.clone(), node_addr, DisconnectReason::Admin)
                .await
                .unwrap();
            assert!(!handle_a.node_is_live().await);

            // A different node authenticates at the reused address (fresh
            // session stamped, as the authenticate path does).
            let mut node_b = make_node_actor_defexp(NODE, "node-b", "[fd5a:5052:3000::102]:1234");
            stamp_new_session(&mut node_b);
            asm.actor_mgr
                .add_node(&node_b, false, &Default::default())
                .await
                .unwrap();

            assert!(
                !handle_a.node_is_live().await,
                "address reuse must not revive a revoked handle"
            );
            let handle_b = VSHandleImpl::new(asm.clone(), node_b);
            assert!(
                handle_b.node_is_live().await,
                "the current occupant's own handle must be live"
            );
        }

        /// PR #41 review (Codex P1, zipline#123): a reconnect at the same
        /// pinned address mints a new session generation, so every handle
        /// from before the reconnect goes dead — only the handle returned by
        /// the reconnect is live.
        #[tokio::test]
        async fn test_reconnect_kills_pre_reconnect_handle() {
            let asm = Arc::new(new_assembly_for_tests(None).await);

            let mut node = make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            let old_handle = VSHandleImpl::new(asm.clone(), node);
            assert!(old_handle.node_is_live().await, "precondition: live");

            // The node reconnects at its pinned address: same CN, fresh
            // session stamped and persisted (what authenticate/open do).
            let mut renewed = make_node_actor_defexp(NODE, "node-k2", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut renewed);
            asm.actor_mgr
                .add_node(&renewed, true, &Default::default())
                .await
                .unwrap();

            assert!(
                !old_handle.node_is_live().await,
                "a reconnect must invalidate every pre-reconnect handle"
            );
            let new_handle = VSHandleImpl::new(asm.clone(), renewed);
            assert!(
                new_handle.node_is_live().await,
                "the reconnect's own handle must be live"
            );
        }

        /// Round 14 (Codex P1): `authorize_connect` rechecks the calling handle's
        /// session under the topology lock. A handle superseded by a reconnect while
        /// it authenticated the newcomer is refused with `authRequired`, so it cannot
        /// install the newcomer through the reconnected node's router entry; the live
        /// handle is admitted.
        #[tokio::test]
        async fn test_admission_under_guard_rejects_a_superseded_handle() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let mut node = make_node_actor_defexp(NODE, "node-k3", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            let old_handle = VSHandleImpl::new(asm.clone(), node);

            // An adapter the old handle has just authenticated (policy-current).
            let vinst = asm.policy_mgr.get_current_snapshot().vinst();
            let mut newcomer = Actor::new();
            newcomer
                .add_attribute(Attribute::builder(key::VINST).value(vinst.to_string()))
                .unwrap();

            let mut renewed = make_node_actor_defexp(NODE, "node-k3", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut renewed);
            asm.actor_mgr
                .add_node(&renewed, true, &Default::default())
                .await
                .unwrap();
            let new_handle = VSHandleImpl::new(asm.clone(), renewed);

            let ops = asm.topo_mgr.ops().await;
            assert!(matches!(
                old_handle.admit_under_guard(&ops, &newcomer).await,
                Err((vsapi::ErrorCode::AuthRequired, _))
            ));
            assert!(new_handle.admit_under_guard(&ops, &newcomer).await.is_ok());
        }
    }

    /// zipline#182: `notifyDisconnect` must be scoped to the calling node.
    /// A live node may disconnect only itself, an adapter docked to it, or
    /// an AAA actor whose registered docking node is the caller — anything
    /// else is refused with `invalidOperation`, state untouched, no
    /// `ActorLeaves` event.
    mod disconnect_scope {
        use super::*;
        use crate::assembly::tests::new_assembly_with_event_rx;
        use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};
        use std::sync::Arc;
        use zpr::vsapi::v1::DisconnectReason;

        const NODE_A: &str = "fd5a:5052:3000::1";
        const NODE_B: &str = "fd5a:5052:3000::2";
        const ADAPTER: &str = "fd5a:5052:4000::a";
        const AAA: &str = "fd5a:5052:5000::1";

        /// Assembly with event receiver, nodes A and B in the actor db, and
        /// the capnp handle node A holds from its authenticate call.
        async fn build_two_node_asm() -> (
            Arc<Assembly>,
            tokio::sync::mpsc::Receiver<VsEvent>,
            vsapi::v_s_handle::Client,
        ) {
            let (asm, event_rx) = new_assembly_with_event_rx(None).await;
            let asm = Arc::new(asm);
            let node_a = make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052:3000::101]:1234");
            asm.actor_mgr
                .add_node(&node_a, false, &Default::default())
                .await
                .unwrap();
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(NODE_B, "node-b", "[fd5a:5052:3000::102]:1234"),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
            let handle: vsapi::v_s_handle::Client =
                capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node_a));
            (asm, event_rx, handle)
        }

        /// Send a `notifyDisconnect` for `target` (None = no address, the
        /// node-disconnecting-itself fallback) and return Ok(()) or the
        /// error code the VS answered with.
        async fn send_notify_disconnect(
            handle: &vsapi::v_s_handle::Client,
            target: Option<std::net::IpAddr>,
        ) -> Result<(), vsapi::ErrorCode> {
            let mut req = handle.notify_disconnect_request();
            {
                let mut dnotice = req.get().init_req();
                if let Some(addr) = target {
                    let mut addr_bldr = dnotice.reborrow().init_zpr_addr();
                    addr.write_to(&mut addr_bldr);
                }
                dnotice.set_reason_code(DisconnectReason::RemoteDisconnect);
            }
            let resp = req.send().promise.await.unwrap();
            let res = resp.get().unwrap().get_res().unwrap();
            match res.which().unwrap() {
                vsapi::ok_or_error::Which::Ok(_) => Ok(()),
                vsapi::ok_or_error::Which::Error(err) => Err(err.unwrap().get_code().unwrap()),
            }
        }

        /// Round 14: `registerVss` rechecks the caller's session under the topology
        /// lock: a handle whose node reconnected while the call waited is refused
        /// with `authRequired`.
        #[tokio::test]
        async fn register_vss_from_a_superseded_handle_is_refused() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, _rx) = new_assembly_with_event_rx(None).await;
                    let asm = Arc::new(asm);
                    let node_addr: std::net::IpAddr = NODE_A.parse().unwrap();
                    let mut node_a =
                        make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052:3000::101]:1234");
                    stamp_new_session(&mut node_a);
                    asm.actor_mgr
                        .add_node(&node_a, false, &Default::default())
                        .await
                        .unwrap();
                    let handle: vsapi::v_s_handle::Client =
                        capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node_a));
                    let mut req = handle.register_vss_request();
                    {
                        let mut sa = req.get().init_addr();
                        node_addr.write_to(&mut sa.reborrow().init_addr());
                        sa.set_port(8183);
                    }

                    let held = asm.topo_mgr.ops().await;
                    let call = tokio::task::spawn_local(async move {
                        let resp = req.send().promise.await.unwrap();
                        let res = resp.get().unwrap().get_res().unwrap();
                        match res.which().unwrap() {
                            vsapi::result::Which::Ok(_) => Ok(()),
                            vsapi::result::Which::Error(err) => {
                                Err(err.unwrap().get_code().unwrap())
                            }
                        }
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let mut renewed =
                        make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052:3000::101]:1234");
                    stamp_new_session(&mut renewed);
                    asm.actor_mgr
                        .add_node(&renewed, true, &Default::default())
                        .await
                        .unwrap();
                    drop(held);

                    assert_eq!(call.await.unwrap(), Err(vsapi::ErrorCode::AuthRequired));
                })
                .await;
        }

        /// Round 14: `notifyDisconnect` checks the caller's session under the
        /// topology lock, right before the teardown. A handle whose node reconnected
        /// while the call waited is refused with `authRequired` and cannot tear down
        /// the new session's state.
        #[tokio::test]
        async fn notify_disconnect_from_a_superseded_handle_is_refused() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, _rx) = new_assembly_with_event_rx(None).await;
                    let asm = Arc::new(asm);
                    let node_addr: std::net::IpAddr = NODE_A.parse().unwrap();
                    let mut node_a =
                        make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052:3000::101]:1234");
                    stamp_new_session(&mut node_a);
                    asm.actor_mgr
                        .add_node(&node_a, false, &Default::default())
                        .await
                        .unwrap();
                    let handle: vsapi::v_s_handle::Client =
                        capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node_a));

                    let held = asm.topo_mgr.ops().await;
                    let call = tokio::task::spawn_local({
                        let handle = handle.clone();
                        async move { send_notify_disconnect(&handle, None).await }
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    // The node reconnects meanwhile: a new session is persisted.
                    let mut renewed =
                        make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052:3000::101]:1234");
                    stamp_new_session(&mut renewed);
                    asm.actor_mgr
                        .add_node(&renewed, true, &Default::default())
                        .await
                        .unwrap();
                    drop(held);

                    assert_eq!(call.await.unwrap(), Err(vsapi::ErrorCode::AuthRequired));
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&node_addr)
                            .await
                            .unwrap()
                            .is_some(),
                        "the new session's node must survive"
                    );
                })
                .await;
        }

        /// Node A names an adapter docked at node B: refused, the adapter's
        /// actor record and docking entry unchanged, no event recorded.
        #[tokio::test]
        async fn notify_disconnect_refuses_adapter_docked_elsewhere() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_b_addr: std::net::IpAddr = NODE_B.parse().unwrap();
                    let adapter_addr: std::net::IpAddr = ADAPTER.parse().unwrap();
                    asm.actor_mgr
                        .add_adapter_via_node(
                            &make_adapter_actor_defexp(ADAPTER, "adapter-b"),
                            &node_b_addr,
                            &Default::default(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(adapter_addr)).await,
                        Err(vsapi::ErrorCode::InvalidOperation),
                        "a node must not disconnect an adapter docked at another node"
                    );
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&adapter_addr)
                            .await
                            .unwrap()
                            .is_some(),
                        "the refused target's actor record must be unchanged"
                    );
                    assert_eq!(
                        asm.actor_mgr.get_docking_node_for_adapter(&adapter_addr),
                        Some(node_b_addr),
                        "the refused target's docking entry must be unchanged"
                    );
                    assert!(
                        event_rx.try_recv().is_err(),
                        "no ActorLeaves event may be recorded for a refused disconnect"
                    );
                })
                .await;
        }

        /// Node A names node B's own address: refused, node B stays in the
        /// topology and its docked adapters are untouched.
        #[tokio::test]
        async fn notify_disconnect_refuses_other_node_target() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_b_addr: std::net::IpAddr = NODE_B.parse().unwrap();
                    let adapter_addr: std::net::IpAddr = ADAPTER.parse().unwrap();
                    asm.actor_mgr
                        .add_adapter_via_node(
                            &make_adapter_actor_defexp(ADAPTER, "adapter-b"),
                            &node_b_addr,
                            &Default::default(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(node_b_addr)).await,
                        Err(vsapi::ErrorCode::InvalidOperation),
                        "a node must not disconnect another node"
                    );
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&node_b_addr)
                            .await
                            .unwrap()
                            .is_some(),
                        "the refused node must stay in the actor db"
                    );
                    assert_eq!(
                        asm.actor_mgr
                            .get_adapters_connected_to_node(&node_b_addr)
                            .await
                            .unwrap(),
                        vec![adapter_addr],
                        "the refused node's docked adapters must be untouched"
                    );
                    assert!(
                        event_rx.try_recv().is_err(),
                        "no ActorLeaves event may be recorded for a refused disconnect"
                    );
                })
                .await;
        }

        /// The no-address fallback — the node disconnecting itself — still
        /// works: self-disconnect is in scope by definition.
        #[tokio::test]
        async fn notify_disconnect_allows_self_fallback_no_address() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_a_addr: std::net::IpAddr = NODE_A.parse().unwrap();

                    assert_eq!(
                        send_notify_disconnect(&handle, None).await,
                        Ok(()),
                        "a node must be able to disconnect itself (fallback path)"
                    );
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&node_a_addr)
                            .await
                            .unwrap()
                            .is_none(),
                        "the self-disconnected node must be removed"
                    );
                    match event_rx.try_recv() {
                        Ok(VsEvent::ActorLeaves(addr, _)) => assert_eq!(addr, node_a_addr),
                        other => panic!("expected ActorLeaves for the node, got {other:?}"),
                    }
                })
                .await;
        }

        /// A node naming its own address explicitly is the same
        /// self-disconnect and still works.
        #[tokio::test]
        async fn notify_disconnect_allows_explicit_self_address() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_a_addr: std::net::IpAddr = NODE_A.parse().unwrap();

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(node_a_addr)).await,
                        Ok(()),
                        "a node must be able to disconnect itself (explicit address)"
                    );
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&node_a_addr)
                            .await
                            .unwrap()
                            .is_none(),
                        "the self-disconnected node must be removed"
                    );
                    match event_rx.try_recv() {
                        Ok(VsEvent::ActorLeaves(addr, _)) => assert_eq!(addr, node_a_addr),
                        other => panic!("expected ActorLeaves for the node, got {other:?}"),
                    }
                })
                .await;
        }

        /// A node can still disconnect an adapter docked to itself.
        #[tokio::test]
        async fn notify_disconnect_allows_adapter_docked_to_caller() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_a_addr: std::net::IpAddr = NODE_A.parse().unwrap();
                    let adapter_addr: std::net::IpAddr = ADAPTER.parse().unwrap();
                    asm.actor_mgr
                        .add_adapter_via_node(
                            &make_adapter_actor_defexp(ADAPTER, "adapter-a"),
                            &node_a_addr,
                            &Default::default(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(adapter_addr)).await,
                        Ok(()),
                        "a node must be able to disconnect an adapter docked to it"
                    );
                    assert!(
                        asm.actor_mgr
                            .get_actor_by_zpr_addr(&adapter_addr)
                            .await
                            .unwrap()
                            .is_none(),
                        "the adapter must be removed"
                    );
                    assert_eq!(
                        asm.actor_mgr.get_docking_node_for_adapter(&adapter_addr),
                        None,
                        "the adapter's docking entry must be gone"
                    );
                    match event_rx.try_recv() {
                        Ok(VsEvent::ActorLeaves(addr, _)) => assert_eq!(addr, adapter_addr),
                        other => panic!("expected ActorLeaves for the adapter, got {other:?}"),
                    }
                })
                .await;
        }

        /// zipline#182 Q2: an AAA actor whose registered docking node is the
        /// caller IS disconnectable by that caller.
        #[tokio::test]
        async fn notify_disconnect_allows_aaa_registered_to_caller() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, _event_rx, handle) = build_two_node_asm().await;
                    let node_a_addr: std::net::IpAddr = NODE_A.parse().unwrap();
                    let aaa_addr: std::net::IpAddr = AAA.parse().unwrap();
                    asm.actor_mgr.register_aaa(
                        aaa_addr,
                        node_a_addr,
                        SystemTime::now() + Duration::from_secs(600),
                    );

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(aaa_addr)).await,
                        Ok(()),
                        "an AAA actor registered to the caller must be disconnectable"
                    );
                })
                .await;
        }

        /// zipline#182 Q2, the other half: an AAA actor registered to a
        /// DIFFERENT node is refused like any other out-of-scope target.
        #[tokio::test]
        async fn notify_disconnect_refuses_aaa_registered_elsewhere() {
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let (asm, mut event_rx, handle) = build_two_node_asm().await;
                    let node_b_addr: std::net::IpAddr = NODE_B.parse().unwrap();
                    let aaa_addr: std::net::IpAddr = AAA.parse().unwrap();
                    asm.actor_mgr.register_aaa(
                        aaa_addr,
                        node_b_addr,
                        SystemTime::now() + Duration::from_secs(600),
                    );

                    assert_eq!(
                        send_notify_disconnect(&handle, Some(aaa_addr)).await,
                        Err(vsapi::ErrorCode::InvalidOperation),
                        "an AAA actor registered to another node must be refused"
                    );
                    assert_eq!(
                        asm.actor_mgr.get_docking_node_for_aaa(&aaa_addr),
                        Some(node_b_addr),
                        "the refused AAA registration must be unchanged"
                    );
                    assert!(
                        event_rx.try_recv().is_err(),
                        "no ActorLeaves event may be recorded for a refused disconnect"
                    );
                })
                .await;
        }
    }

    /// zl-zipline#224: `reportLinkStates` validates the snapshot, refuses a dead
    /// handle, and drives the router's link flag.
    mod link_state_reports {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::{
            FakeResolver, make_node_actor_defexp, make_peering, policy_with_peerings_and_node_cns,
        };
        use crate::trusted_services::TrustedServicesMgr;
        use libeval::route::LinkId;
        use std::path::PathBuf;
        use std::sync::Arc;
        use zpr::vsapi::v1::DisconnectReason;
        use zpr::vsapi_types::LinkState;
        use zpr::write_to::WriteTo;

        const NODE_A: &str = "fd5a:5052:3000::1";
        const NODE_B: &str = "fd5a:5052:3000::2";
        const NODE_C: &str = "fd5a:5052:3000::3";

        /// Policy declares A-B and A-C (C never connects). A and B are connected nodes
        /// with their A-B link in the router. Returns node A's capnp handle.
        async fn build() -> (Arc<Assembly>, vsapi::v_s_handle::Client) {
            build_with_cns(false).await
        }

        /// As [build]; with `cns`, the policy also maps A and B to the CNs
        /// "node-a" and "node-b", so reports naming them resolve.
        async fn build_with_cns(cns: bool) -> (Arc<Assembly>, vsapi::v_s_handle::Client) {
            build_with(cns, 0).await
        }

        /// As [build_with_cns]; a non-zero `substrate_port` gives every node the substrate
        /// address `[<its ZPR address>]:<substrate_port>` in policy, so the node can
        /// `open` (which refuses port 0 and checks the address against policy).
        async fn build_with(
            cns: bool,
            substrate_port: u16,
        ) -> (Arc<Assembly>, vsapi::v_s_handle::Client) {
            let (a, b, c): (IpAddr, IpAddr, IpAddr) = (
                NODE_A.parse().unwrap(),
                NODE_B.parse().unwrap(),
                NODE_C.parse().unwrap(),
            );
            let node_cns: &[(IpAddr, &str)] = if cns {
                &[(a, "node-a"), (b, "node-b")]
            } else {
                &[]
            };
            let mut asm = new_assembly_for_tests(None).await;
            asm.policy_mgr = PolicyMgr::new_with_initial_policy(
                policy_with_peerings_and_node_cns(
                    &[
                        make_peering(a, b, "link-ab", vec![]),
                        make_peering(a, c, "link-ac", vec![]),
                    ]
                    .map(|mut p| {
                        if substrate_port != 0 {
                            p.substrate_a = Some(zpr::policy_types::NetAddr::new_for_ip_or_host(
                                &p.node_a.to_string(),
                                substrate_port,
                            ));
                            p.substrate_b = Some(zpr::policy_types::NetAddr::new_for_ip_or_host(
                                &p.node_b.to_string(),
                                substrate_port,
                            ));
                        }
                        p
                    }),
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
            let node_a = make_node_actor_defexp(NODE_A, "node-a", "[fd5a:5052::101]:1234");
            for actor in [
                node_a.clone(),
                make_node_actor_defexp(NODE_B, "node-b", "[fd5a:5052::102]:1234"),
            ] {
                asm.actor_mgr
                    .add_node(&actor, false, &Default::default())
                    .await
                    .unwrap();
            }
            asm.topo_mgr.add_node(a).unwrap();
            asm.topo_mgr.add_node(b).unwrap();
            asm.topo_mgr
                .add_link(a, b, LinkId("link-ab".into()), vec![], 1)
                .unwrap();
            let asm = Arc::new(asm);
            let handle = capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node_a));
            (asm, handle)
        }

        /// Send a snapshot and return Ok(()) or the error code the VS answered with.
        async fn send_report(
            handle: &vsapi::v_s_handle::Client,
            entries: &[LinkStateReport],
        ) -> Result<(), vsapi::ErrorCode> {
            let mut req = handle.report_link_states_request();
            {
                let mut list = req.get().init_links(entries.len() as u32);
                for (i, e) in entries.iter().enumerate() {
                    e.write_to(&mut list.reborrow().get(i as u32));
                }
            }
            let resp = req.send().promise.await.unwrap();
            let res = resp.get().unwrap().get_res().unwrap();
            match res.which().unwrap() {
                vsapi::ok_or_error::Which::Ok(_) => Ok(()),
                vsapi::ok_or_error::Which::Error(err) => Err(err.unwrap().get_code().unwrap()),
            }
        }

        fn entry(cn: &str, state: LinkState) -> LinkStateReport {
            LinkStateReport {
                peer_cn: cn.to_string(),
                state,
            }
        }

        fn ab_route_exists(asm: &Assembly) -> bool {
            asm.topo_mgr
                .get_best_route(&NODE_A.parse().unwrap(), &NODE_B.parse().unwrap())
                .is_some()
        }

        /// The report handler runs under the topology operation lock (TopoOps): while
        /// another operation holds it, the report applies nothing; once released, it
        /// applies. Guards the round-12 class -- a report interleaving a policy pass,
        /// disconnect or reconnect between that operation's read and its write.
        #[tokio::test]
        async fn report_waits_for_the_topology_operation_lock() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build().await;
                    let held = asm.topo_mgr.ops().await;
                    let report = tokio::task::spawn_local({
                        let handle = handle.clone();
                        async move { send_report(&handle, &[]).await }
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    assert!(!report.is_finished(), "report must wait for the lock");
                    assert!(
                        ab_route_exists(&asm),
                        "nothing applied while the lock is held"
                    );
                    drop(held);
                    assert_eq!(report.await.unwrap(), Ok(()));
                    assert!(!ab_route_exists(&asm));
                })
                .await;
        }

        /// `open` reads the node's actor and persists its new session under the
        /// topology operation lock (round 13, Copilot): while another operation holds
        /// it, `open` does not complete, so overlapping opens, authentications and
        /// report applications cannot persist sessions out of order.
        #[tokio::test]
        async fn open_waits_for_the_topology_operation_lock() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, _handle) = build().await;
                    let vs: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
                        asm: asm.clone(),
                        remote: SocketAddr::new(NODE_A.parse().unwrap(), 1234),
                    });
                    let mut req = vs.open_request();
                    {
                        let mut r = req.get().init_req();
                        r.set_cn("node-a");
                        r.set_ctype(vsapi::VSConnT::Reconnect);
                        let mut p = r.init_params(1).get(0);
                        p.set_ptype(vsapi::ParamT::String);
                        p.set_name(pname::SUBSTRATE_ADDR);
                        p.set_value_text("[fd5a:5052::101]:1234");
                    }
                    let held = asm.topo_mgr.ops().await;
                    let open =
                        tokio::task::spawn_local(
                            async move { req.send().promise.await.map(|_| ()) },
                        );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    assert!(!open.is_finished(), "open must wait for the lock");
                    drop(held);
                    open.await.unwrap().unwrap();
                })
                .await;
        }

        /// Round 15 (Codex P1): reports pipelined on one handle apply in the order
        /// they were sent. The handler takes the topology lock before its first await
        /// (the lock is FIFO), so a later "down" snapshot cannot overtake an earlier
        /// "up" one and leave the stale "up" applied last.
        #[tokio::test]
        async fn pipelined_reports_apply_in_order() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build_with_cns(true).await;
                    let send = |entries: Vec<LinkStateReport>| {
                        let mut req = handle.report_link_states_request();
                        {
                            let mut list = req.get().init_links(entries.len() as u32);
                            for (i, e) in entries.iter().enumerate() {
                                e.write_to(&mut list.reborrow().get(i as u32));
                            }
                        }
                        req.send().promise
                    };
                    // B reports its end up, so A's snapshots alone decide the link
                    // (R14: both ends must report up).
                    asm.topo_mgr.record_link_states(
                        &asm.topo_mgr.ops().await,
                        &NODE_B.parse().unwrap(),
                        None,
                        vec![entry("node-a", LinkState::Up)],
                        &|| asm.policy_mgr.get_current_snapshot(),
                    );
                    // Down, then up: the up snapshot is the node's latest word.
                    let held = asm.topo_mgr.ops().await;
                    let down = send(vec![]);
                    let up = send(vec![entry("node-b", LinkState::Up)]);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    drop(held);
                    down.await.unwrap();
                    up.await.unwrap();
                    assert!(ab_route_exists(&asm), "the later (up) snapshot wins");

                    // Up, then down: the down snapshot wins.
                    let held = asm.topo_mgr.ops().await;
                    let up = send(vec![entry("node-b", LinkState::Up)]);
                    let down = send(vec![]);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    drop(held);
                    up.await.unwrap();
                    down.await.unwrap();
                    assert!(!ab_route_exists(&asm), "the later (down) snapshot wins");
                })
                .await;
        }

        /// An empty snapshot says "no link is up": A's link to B goes down.
        #[tokio::test]
        async fn empty_snapshot_takes_the_link_down() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build().await;
                    assert!(ab_route_exists(&asm));
                    assert_eq!(send_report(&handle, &[]).await, Ok(()));
                    assert!(!ab_route_exists(&asm));
                })
                .await;
        }

        /// More entries than the node's declared links: paramError, nothing stored.
        #[tokio::test]
        async fn too_many_entries_is_param_error() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build().await;
                    let three = [
                        entry("b.zpr", LinkState::Up),
                        entry("c.zpr", LinkState::Up),
                        entry("d.zpr", LinkState::Up),
                    ];
                    assert_eq!(
                        send_report(&handle, &three).await,
                        Err(vsapi::ErrorCode::ParamError)
                    );
                    assert!(ab_route_exists(&asm), "a rejected report changes nothing");
                })
                .await;
        }

        /// A duplicate or empty peerCn: paramError, nothing stored.
        #[tokio::test]
        async fn duplicate_or_empty_cn_is_param_error() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build().await;
                    let dup = [
                        entry("b.zpr", LinkState::Up),
                        entry("b.zpr", LinkState::Down),
                    ];
                    assert_eq!(
                        send_report(&handle, &dup).await,
                        Err(vsapi::ErrorCode::ParamError)
                    );
                    assert_eq!(
                        send_report(&handle, &[entry("", LinkState::Up)]).await,
                        Err(vsapi::ErrorCode::ParamError)
                    );
                    assert!(ab_route_exists(&asm));
                })
                .await;
        }

        /// A disconnected node's handle is refused with authRequired.
        #[tokio::test]
        async fn dead_handle_is_auth_required() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build().await;
                    asm.cc
                        .disconnect(
                            asm.clone(),
                            NODE_A.parse().unwrap(),
                            DisconnectReason::Admin,
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        send_report(&handle, &[]).await,
                        Err(vsapi::ErrorCode::AuthRequired)
                    );
                })
                .await;
        }

        // --- R13a (ZODE_LINKS.md): failed pairs ---

        /// Substrate port the R13a tests give every node in policy (see [build_with]).
        const R13A_PORT: u16 = 7000;

        /// A capnp `VSSHandle` stand-in for `node`: the returned receiver gets every
        /// command the visa service sends to the node's VSS.
        fn capture_vss(
            asm: &Assembly,
            node: &str,
        ) -> tokio::sync::mpsc::Receiver<crate::vss::VssCmd> {
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            asm.vss_mgr.insert_test_handle(node.parse().unwrap(), tx);
            rx
        }

        /// True if `rx` receives a `SetTopology` within a second.
        async fn gets_topology(rx: &mut tokio::sync::mpsc::Receiver<crate::vss::VssCmd>) -> bool {
            matches!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv()).await,
                Ok(Some(crate::vss::VssCmd::SetTopology(..)))
            )
        }

        /// True if nothing reaches `rx` within 100 ms.
        async fn gets_nothing(rx: &mut tokio::sync::mpsc::Receiver<crate::vss::VssCmd>) -> bool {
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err()
        }

        /// `open` (a soft VS-API session reconnect) as `node`, whose CN is `cn`.
        async fn reopen(asm: &Arc<Assembly>, node: &str, cn: &str) {
            let vs: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
                asm: asm.clone(),
                remote: SocketAddr::new(node.parse().unwrap(), 1234),
            });
            let mut req = vs.open_request();
            {
                let mut r = req.get().init_req();
                r.set_cn(cn);
                r.set_ctype(vsapi::VSConnT::Reconnect);
                let mut p = r.init_params(1).get(0);
                p.set_ptype(vsapi::ParamT::String);
                p.set_name(pname::SUBSTRATE_ADDR);
                p.set_value_text(format!("[{node}]:{R13A_PORT}"));
            }
            let resp = req.send().promise.await.unwrap();
            assert!(
                matches!(
                    resp.get().unwrap().get_resp().unwrap().which().unwrap(),
                    vsapi::result::Which::Ok(_)
                ),
                "open as {node} must succeed"
            );
        }

        /// A, the owner, reports its link to B `failed` through its handle.
        async fn a_reports_b_failed(asm: &Assembly, handle: &vsapi::v_s_handle::Client) {
            assert_eq!(
                send_report(handle, &[entry("node-b", LinkState::Failed)]).await,
                Ok(())
            );
            assert!(
                asm.topo_mgr
                    .is_failed_pair(&NODE_A.parse().unwrap(), &NODE_B.parse().unwrap())
            );
        }

        /// A `failed` report marks the pair and never itself sends topology (R13a: the
        /// owner has already stopped; sending would only loop).
        #[tokio::test]
        async fn failed_report_marks_the_pair_and_sends_no_topology() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build_with(true, R13A_PORT).await;
                    let mut a_vss = capture_vss(&asm, NODE_A);
                    let mut b_vss = capture_vss(&asm, NODE_B);
                    a_reports_b_failed(&asm, &handle).await;
                    assert!(
                        gets_nothing(&mut a_vss).await,
                        "no topology to the reporter"
                    );
                    assert!(gets_nothing(&mut b_vss).await, "no topology to the peer");
                })
                .await;
        }

        /// A `down` report sets no mark.
        #[tokio::test]
        async fn down_report_sets_no_mark() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build_with(true, R13A_PORT).await;
                    assert_eq!(
                        send_report(&handle, &[entry("node-b", LinkState::Down)]).await,
                        Ok(())
                    );
                    assert!(
                        !asm.topo_mgr
                            .is_failed_pair(&NODE_A.parse().unwrap(), &NODE_B.parse().unwrap())
                    );
                })
                .await;
        }

        /// A session reconnect of either end clears the mark and sends `setTopology`
        /// to the other end, which now names the link again; R13 then makes the owner
        /// try once more. The reconnecting end gets topology from its own connect
        /// sync, not from here.
        #[tokio::test]
        async fn reconnect_of_either_end_clears_the_pair_and_tells_the_other_end() {
            for (reconnecting, cn, other) in
                [(NODE_A, "node-a", NODE_B), (NODE_B, "node-b", NODE_A)]
            {
                tokio::task::LocalSet::new()
                    .run_until(async {
                        let (asm, handle) = build_with(true, R13A_PORT).await;
                        a_reports_b_failed(&asm, &handle).await;
                        let mut reconnecting_vss = capture_vss(&asm, reconnecting);
                        let mut other_vss = capture_vss(&asm, other);
                        reopen(&asm, reconnecting, cn).await;
                        assert!(
                            !asm.topo_mgr
                                .is_failed_pair(&NODE_A.parse().unwrap(), &NODE_B.parse().unwrap()),
                            "{reconnecting} reconnected: the pair is cleared"
                        );
                        assert!(
                            gets_topology(&mut other_vss).await,
                            "{other} is sent topology with the link again"
                        );
                        assert!(gets_nothing(&mut reconnecting_vss).await);
                    })
                    .await;
            }
        }

        /// A reconnect of a node outside the pair leaves the mark alone and sends no
        /// topology to the pair's ends.
        #[tokio::test]
        async fn reconnect_of_an_unrelated_node_keeps_the_mark() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, handle) = build_with(true, R13A_PORT).await;
                    asm.actor_mgr
                        .add_node(
                            &make_node_actor_defexp(NODE_C, "node-c", "[fd5a:5052::103]:1234"),
                            false,
                            &Default::default(),
                        )
                        .await
                        .unwrap();
                    a_reports_b_failed(&asm, &handle).await;
                    let mut a_vss = capture_vss(&asm, NODE_A);
                    let mut b_vss = capture_vss(&asm, NODE_B);
                    reopen(&asm, NODE_C, "node-c").await;
                    assert!(
                        asm.topo_mgr
                            .is_failed_pair(&NODE_A.parse().unwrap(), &NODE_B.parse().unwrap())
                    );
                    assert!(gets_nothing(&mut a_vss).await);
                    assert!(gets_nothing(&mut b_vss).await);
                })
                .await;
        }
    }

    /// `getLoginNonce` (zl-zipline#232), driven through a real capnp client.
    mod login_nonce {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::test_helpers::make_node_actor_defexp;
        use std::sync::Arc;
        use zpr::vsapi::v1::DisconnectReason;

        const NODE: &str = "fd5a:5052:3000::1";

        /// Persist a live node with a fresh session and return its handle.
        async fn live_node(asm: &Arc<Assembly>) -> vsapi::v_s_handle::Client {
            let mut node = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), node))
        }

        /// One `getLoginNonce` call: `Ok((nonce, expiresAt))` or the error code.
        async fn get_nonce(
            handle: &vsapi::v_s_handle::Client,
        ) -> Result<(String, u64), vsapi::ErrorCode> {
            let resp = handle
                .get_login_nonce_request()
                .send()
                .promise
                .await
                .unwrap();
            let res = resp.get().unwrap().get_res().unwrap();
            match res.which().unwrap() {
                vsapi::result::Which::Ok(ok) => {
                    let ok = ok.unwrap();
                    Ok((
                        ok.get_nonce().unwrap().to_string().unwrap(),
                        ok.get_expires_at(),
                    ))
                }
                vsapi::result::Which::Error(err) => Err(err.unwrap().get_code().unwrap()),
            }
        }

        /// Test 19: a live node gets a nonce that the store accepts for that
        /// node and session, with `expiresAt` one TTL ahead.
        #[tokio::test]
        async fn test_get_login_nonce_live_node_gets_bound_nonce() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let asm = Arc::new(new_assembly_for_tests(None).await);
                    let handle = live_node(&asm).await;
                    let before = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let (nonce, expires_at) =
                        get_nonce(&handle).await.expect("live node gets a nonce");
                    assert!(
                        expires_at >= before + config::LOGIN_NONCE_TTL_SECS
                            && expires_at <= before + config::LOGIN_NONCE_TTL_SECS + 2,
                        "expiresAt must be one TTL ahead"
                    );
                    let stored = asm
                        .actor_mgr
                        .get_actor_by_zpr_addr(&NODE.parse().unwrap())
                        .await
                        .unwrap()
                        .unwrap();
                    let session = stored
                        .get_attribute(key::SESSION)
                        .unwrap()
                        .get_single_value()
                        .unwrap()
                        .to_string();
                    assert!(
                        asm.cc.login_nonces.consume(
                            &nonce,
                            NODE.parse().unwrap(),
                            &session,
                            SystemTime::now()
                        ),
                        "the nonce must be bound to this node and its session"
                    );
                })
                .await;
        }

        /// Test 19: past the per-node limit the call answers `quotaExceeded`.
        #[tokio::test]
        async fn test_get_login_nonce_quota_exceeded() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let asm = Arc::new(new_assembly_for_tests(None).await);
                    let handle = live_node(&asm).await;
                    for _ in 0..config::LOGIN_NONCE_MAX_PER_ACTOR {
                        get_nonce(&handle).await.expect("within the limit");
                    }
                    assert_eq!(
                        get_nonce(&handle).await,
                        Err(vsapi::ErrorCode::QuotaExceeded)
                    );
                })
                .await;
        }

        /// #63 review (Codex P1): a node's authenticate persists its new
        /// session under the self-renewal lock, so a reconnect's session write
        /// cannot land between a self-renewal's session check and its write.
        #[tokio::test]
        async fn test_node_persist_waits_for_self_renewal_lock() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let mut node = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            let guard = asm.policy_mgr.node_commit_lock.lock().await;
            let task = tokio::spawn({
                let asm = asm.clone();
                async move {
                    let ops = asm.topo_mgr.ops().await;
                    add_node_serialized(&asm, &ops, &node, false).await
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                !task.is_finished(),
                "the node persist must wait for the lock"
            );
            drop(guard);
            task.await
                .unwrap()
                .expect("the persist completes once the lock is free");
        }

        /// #63 round 4 (Codex P2): a handle whose session is no longer the
        /// stored one (the node reconnected after its liveness check) mints
        /// nothing and leaves the new session's nonces alone.
        #[tokio::test]
        async fn test_stale_handle_mint_refused_and_keeps_new_nonces() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let mut node = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            let addr: std::net::IpAddr = NODE.parse().unwrap();
            let current = node
                .get_attribute(key::SESSION)
                .unwrap()
                .get_single_value()
                .unwrap()
                .to_string();
            let (fresh, _) = mint_login_nonce_for_handle(&asm, addr, &current)
                .await
                .expect("the current session mints");
            assert!(
                mint_login_nonce_for_handle(&asm, addr, "an-older-session")
                    .await
                    .is_err(),
                "a stale session must not mint"
            );
            assert!(
                asm.cc
                    .login_nonces
                    .consume(&fresh, addr, &current, SystemTime::now()),
                "the current session's nonce must survive the stale mint"
            );
        }

        /// #63 audit: a node authenticated under a policy generation that an
        /// install has since replaced is not persisted (the node authenticates
        /// again under the new policy).
        #[tokio::test]
        async fn test_node_persist_refused_when_policy_moved() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let mut node = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut node);
            let stale = asm.policy_mgr.get_current_snapshot().vinst() + 1;
            node.add_attribute(Attribute::builder(key::VINST).value(stale.to_string()))
                .unwrap();
            let err = add_node_serialized(&asm, &asm.topo_mgr.ops().await, &node, false)
                .await
                .expect_err("a stale admission must not persist");
            assert!(
                matches!(&err, ServiceError::ApiResponse(api) if matches!(api.code, zpr::vsapi_types::ErrorCode::TemporarilyUnavailable)),
                "got {err:?}"
            );
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&NODE.parse().unwrap())
                    .await
                    .unwrap()
                    .is_none()
            );

            // The current generation persists.
            let current = asm.policy_mgr.get_current_snapshot().vinst();
            node.add_attribute(Attribute::builder(key::VINST).value(current.to_string()))
                .unwrap();
            add_node_serialized(&asm, &asm.topo_mgr.ops().await, &node, false)
                .await
                .expect("a current admission persists");
        }

        /// #63 audit: `open`'s load -> write of the node's own actor runs under
        /// the self-renewal lock.
        #[tokio::test]
        async fn test_open_state_update_waits_for_self_renewal_lock() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let node = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            let guard = asm.policy_mgr.node_commit_lock.lock().await;
            let task = tokio::spawn({
                let asm = asm.clone();
                async move {
                    resume_node_actor_for_open(
                        &asm,
                        NODE.parse().unwrap(),
                        "[fd5a:5052:3000::101]:1234".parse().unwrap(),
                        "zode",
                    )
                    .await
                    .map(|_| ())
                    .map_err(|(code, msg)| format!("{code:?}: {msg}"))
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                !task.is_finished(),
                "open's state update must wait for the lock"
            );
            drop(guard);
            task.await
                .unwrap()
                .expect("open's state update completes once the lock is free");
        }

        /// #63 review (Codex P1): a Reset authentication tears the node's old
        /// state down only inside the locked commit, after the generation
        /// recheck: refused under a moved generation, the old state (here, a
        /// docked adapter) is untouched; accepted, it is torn down.
        #[tokio::test]
        async fn test_reset_teardown_only_after_generation_recheck() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let node_addr: std::net::IpAddr = NODE.parse().unwrap();
            let old = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            asm.actor_mgr
                .add_node(&old, false, &Default::default())
                .await
                .unwrap();
            asm.actor_mgr
                .add_adapter_via_node(
                    &crate::test_helpers::make_adapter_actor_defexp("fd5a:5052:4000::a", "dock"),
                    &node_addr,
                    &Default::default(),
                )
                .await
                .unwrap();
            // The docked adapter's actor record: only the Reset teardown removes it.
            let adapter: std::net::IpAddr = "fd5a:5052:4000::a".parse().unwrap();
            let adapter_present = || async {
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&adapter)
                    .await
                    .unwrap()
                    .is_some()
            };

            let mut fresh = make_node_actor_defexp(NODE, "zode", "[fd5a:5052:3000::101]:1234");
            stamp_new_session(&mut fresh);
            let stale = asm.policy_mgr.get_current_snapshot().vinst() + 1;
            fresh
                .add_attribute(Attribute::builder(key::VINST).value(stale.to_string()))
                .unwrap();
            assert!(
                add_node_serialized(&asm, &asm.topo_mgr.ops().await, &fresh, false)
                    .await
                    .is_err()
            );
            assert!(
                adapter_present().await,
                "a refused Reset must not tear anything down"
            );

            let current = asm.policy_mgr.get_current_snapshot().vinst();
            fresh
                .add_attribute(Attribute::builder(key::VINST).value(current.to_string()))
                .unwrap();
            add_node_serialized(&asm, &asm.topo_mgr.ops().await, &fresh, false)
                .await
                .expect("a current Reset commits");
            assert!(
                !adapter_present().await,
                "an accepted Reset tears the old state down"
            );
        }

        /// Test 19: a dead handle (node disconnected) gets `authRequired`.
        #[tokio::test]
        async fn test_get_login_nonce_dead_handle_auth_required() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let asm = Arc::new(new_assembly_for_tests(None).await);
                    let handle = live_node(&asm).await;
                    asm.cc
                        .disconnect(asm.clone(), NODE.parse().unwrap(), DisconnectReason::Admin)
                        .await
                        .unwrap();
                    assert_eq!(
                        get_nonce(&handle).await,
                        Err(vsapi::ErrorCode::AuthRequired)
                    );
                })
                .await;
        }
    }

    /// `requestBootstrapVisas` (ZODE_LINKS.md J2, J3, J6), driven through a real capnp
    /// client. The relay docks the visa service; the joiner is its policy peer.
    mod bootstrap_visas {
        use super::*;
        use crate::core_visas::tests::{RELAY, VSS_PORT, ZODE, build_net_with_policy};
        use crate::test_helpers::{
            make_adapter_actor_defexp, make_peering, policy_with_peerings_cns_and_tcp_services,
        };
        use crate::visa_bootstrap::BOOTSTRAP_VISA_LIFETIME;
        use crate::vss::VssCmd;
        use std::sync::Arc;
        use zpr::vsapi_types::{BootstrapVisas, DockPepType, LinkState, Visa};

        /// A node policy names but that is no peer of the relay.
        const OTHER: &str = "fd5a:5052:3000::9";

        /// The relay and the joiner (`ZODE`), linked in policy as `link-rz`, with CNs
        /// `relay.zpr` and `zode.zpr`, plus `other.zpr` for [OTHER], which policy names but
        /// does not peer with the relay. Both nodes are connected, and the built-in VSAPI and
        /// VSS rules hold (see `core_visas::tests::build_net`). Returns (asm, relay, joiner).
        async fn join_net() -> (Arc<Assembly>, IpAddr, IpAddr) {
            let relay: IpAddr = RELAY.parse().unwrap();
            let zode: IpAddr = ZODE.parse().unwrap();
            let other: IpAddr = OTHER.parse().unwrap();
            build_net_with_policy(policy_with_peerings_cns_and_tcp_services(
                &[make_peering(relay, zode, "link-rz", vec![])],
                &[
                    (relay, "relay.zpr"),
                    (zode, "zode.zpr"),
                    (other, "other.zpr"),
                ],
                &[("vsapi", config::VSAPI_PORT), ("vss", VSS_PORT)],
            ))
            .await
        }

        /// As [join_net], with the joiner not connected: it has no actor, as before its
        /// first join.
        async fn join_net_unconnected_joiner() -> (Arc<Assembly>, IpAddr, IpAddr) {
            let (asm, relay, zode) = join_net().await;
            asm.actor_mgr.remove_node(&zode).await.unwrap();
            asm.actor_mgr.remove_actor_by_zpr_addr(&zode).await.unwrap();
            (asm, relay, zode)
        }

        /// A capnp handle for the node stored at `addr`, bound to its current session.
        async fn handle_for(asm: &Arc<Assembly>, addr: &IpAddr) -> vsapi::v_s_handle::Client {
            let actor = asm.actor_mgr.get_actor_by_zpr_addr(addr).await.unwrap();
            capnp_rpc::new_client(VSHandleImpl::new(asm.clone(), actor.unwrap()))
        }

        /// One `requestBootstrapVisas(peer_cn)` call: the decoded answer or the error code.
        async fn request(
            handle: &vsapi::v_s_handle::Client,
            peer_cn: &str,
        ) -> Result<BootstrapVisas, vsapi::ErrorCode> {
            let mut req = handle.request_bootstrap_visas_request();
            req.get().set_peer_cn(peer_cn);
            let resp = req.send().promise.await.unwrap();
            let res = resp.get().unwrap().get_res().unwrap();
            match res.which().unwrap() {
                vsapi::result::Which::Ok(ok) => Ok(BootstrapVisas::try_from(ok.unwrap()).unwrap()),
                vsapi::result::Which::Error(err) => Err(err.unwrap().get_code().unwrap()),
            }
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

        /// IDs of a list of visas, in order.
        fn ids(visas: &[Visa]) -> Vec<u64> {
            visas.iter().map(|v| v.issuer_id).collect()
        }

        /// True if `id` is marked `PendingRevoke` on `node`: it has been revoked.
        async fn revoked_on(asm: &Assembly, id: u64, node: &IpAddr) -> bool {
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(node)
                .await
                .unwrap()
                .contains(&id)
        }

        /// The relay gets 2+2 visas: the joiner's copies and its own, of the same two
        /// visas, forward (`joiner:0 -> vs:VSAPI`) then reverse. Each path is stitched from
        /// the peering, `[joiner, relay]`, never routed, even though the joiner is connected
        /// here and the router knows its link (a routed path could revisit the joiner). Both
        /// copies are recorded installed, never pending: the relay delivers them.
        #[tokio::test]
        async fn relay_gets_both_directions_for_its_peer() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, zode) = join_net().await;
                    let vs = asm.config.get_vs_addr();
                    let vsapi_port = config::VSAPI_PORT;

                    let bv = request(&handle_for(&asm, &relay).await, "zode.zpr")
                        .await
                        .expect("the relay may ask for its peer");

                    assert_eq!(
                        ids(&bv.peer),
                        ids(&bv.relay),
                        "two copies of the same visas"
                    );
                    let [fwd, rev] = [bv.peer[0].issuer_id, bv.peer[1].issuer_id];
                    assert_ne!(fwd, rev);
                    for copies in [&bv.peer, &bv.relay] {
                        assert_eq!(pep_tuple(&copies[0]), (zode, 0, vs, vsapi_port));
                        assert_eq!(pep_tuple(&copies[1]), (vs, vsapi_port, zode, 0));
                    }
                    // The joiner is the forward visa's ingress and forwards to the relay; the
                    // relay is the reverse visa's ingress and forwards to the joiner.
                    assert_eq!(bv.peer[0].fwd_pep.as_ref().unwrap().next_hop, relay);
                    assert!(bv.relay[0].fwd_pep.is_none());
                    assert_eq!(bv.relay[0].prev_hop, Some(zode));
                    assert_eq!(bv.relay[1].fwd_pep.as_ref().unwrap().next_hop, zode);
                    assert!(bv.peer[1].fwd_pep.is_none());
                    assert_eq!(bv.peer[1].prev_hop, Some(relay));

                    for (id, path) in [(fwd, vec![zode, relay]), (rev, vec![relay, zode])] {
                        let md = asm
                            .visa_mgr
                            .get_visa_metadata_by_id(id)
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(md.path, Some(path), "visa {id}: stitched path");
                        assert_eq!(md.zpl, crate::visa_bootstrap::BOOTSTRAP_VISA_ZPL);
                        for node in [relay, zode] {
                            let installed = asm
                                .visa_mgr
                                .get_installed_visa_ids_for_node(&node)
                                .await
                                .unwrap();
                            assert!(installed.contains(&id), "visa {id} installed on {node}");
                        }
                    }
                })
                .await;
        }

        /// The bootstrap visas are short-lived (gate g89 q3): they expire
        /// [BOOTSTRAP_VISA_LIFETIME] after they were minted.
        #[tokio::test]
        async fn bootstrap_visas_expire_at_the_short_lifetime() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, _zode) = join_net_unconnected_joiner().await;
                    let before = std::time::SystemTime::now();
                    let bv = request(&handle_for(&asm, &relay).await, "zode.zpr")
                        .await
                        .unwrap();
                    let after = std::time::SystemTime::now();
                    for visa in bv.peer.iter().chain(&bv.relay) {
                        // The wire carries whole milliseconds, so allow one below `before`.
                        let earliest = before + BOOTSTRAP_VISA_LIFETIME - Duration::from_millis(1);
                        assert!(
                            visa.expires >= earliest
                                && visa.expires <= after + BOOTSTRAP_VISA_LIFETIME,
                            "visa {} expires outside the bootstrap lifetime",
                            visa.issuer_id
                        );
                    }
                })
                .await;
        }

        /// J3: only the node the visa service docks on may ask. A connected node that is
        /// not the relay, asking for its own policy peer (the relay), is refused, and
        /// nothing is minted.
        #[tokio::test]
        async fn a_caller_that_is_not_the_relay_is_invalid_operation() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, zode) = join_net().await;
                    assert_eq!(
                        request(&handle_for(&asm, &zode).await, "relay.zpr")
                            .await
                            .unwrap_err(),
                        vsapi::ErrorCode::InvalidOperation
                    );
                    assert!(
                        asm.visa_mgr
                            .get_visa_ids_for_actors(&[relay, zode])
                            .await
                            .unwrap()
                            .is_empty()
                    );
                })
                .await;
        }

        /// J3: the CN must name a peer in the relay's topology. An unknown CN, a node policy
        /// names that is no peer of the relay, the relay's own CN, and a peer whose link was
        /// reported failed (left out of topology, R13a) are all refused, and nothing is
        /// minted.
        #[tokio::test]
        async fn a_cn_not_in_the_callers_topology_is_not_found() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, zode) = join_net_unconnected_joiner().await;
                    let handle = handle_for(&asm, &relay).await;
                    for cn in ["nobody.zpr", "other.zpr", "relay.zpr", ""] {
                        assert_eq!(
                            request(&handle, cn).await.unwrap_err(),
                            vsapi::ErrorCode::NotFound,
                            "CN {cn:?}"
                        );
                    }
                    asm.topo_mgr.record_link_states(
                        &asm.topo_mgr.ops().await,
                        &relay,
                        None,
                        vec![LinkStateReport {
                            peer_cn: "zode.zpr".to_string(),
                            state: LinkState::Failed,
                        }],
                        &|| asm.policy_mgr.get_current_snapshot(),
                    );
                    assert_eq!(
                        request(&handle, "zode.zpr").await.unwrap_err(),
                        vsapi::ErrorCode::NotFound,
                        "a failed pair is not in the relay's topology"
                    );
                    assert!(
                        asm.visa_mgr
                            .get_visa_ids_for_actors(&[relay, zode])
                            .await
                            .unwrap()
                            .is_empty()
                    );
                })
                .await;
        }

        /// A handle whose session is no longer current gets `authRequired`.
        #[tokio::test]
        async fn a_dead_session_is_auth_required() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, zode) = join_net_unconnected_joiner().await;
                    let handle = handle_for(&asm, &relay).await;
                    // The relay re-authenticates: a new session, so the old handle is dead.
                    let mut actor = asm
                        .actor_mgr
                        .get_actor_by_zpr_addr(&relay)
                        .await
                        .unwrap()
                        .unwrap();
                    stamp_new_session(&mut actor);
                    asm.actor_mgr
                        .update_actor(&actor, &Default::default())
                        .await
                        .unwrap();

                    assert_eq!(
                        request(&handle, "zode.zpr").await.unwrap_err(),
                        vsapi::ErrorCode::AuthRequired
                    );
                    assert!(
                        asm.visa_mgr
                            .get_visa_ids_for_actors(&[zode])
                            .await
                            .unwrap()
                            .is_empty()
                    );
                })
                .await;
        }

        /// J6: every request is a new join. Two requests mint distinct visas, and the
        /// second revokes the first pair: the relay's new request is the proof that the
        /// link those were for is gone (R5).
        #[tokio::test]
        async fn every_request_mints_new_visas_and_revokes_the_previous_pair() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, _zode) = join_net_unconnected_joiner().await;
                    let handle = handle_for(&asm, &relay).await;
                    let first = request(&handle, "zode.zpr").await.unwrap();
                    let second = request(&handle, "zode.zpr").await.unwrap();

                    for id in ids(&first.peer) {
                        assert!(!ids(&second.peer).contains(&id), "new visas every time");
                        assert!(
                            revoked_on(&asm, id, &relay).await,
                            "previous visa {id} revoked"
                        );
                    }
                    for id in ids(&second.peer) {
                        assert!(!revoked_on(&asm, id, &relay).await);
                    }
                })
                .await;
        }

        /// The rejoin rule. A request while the joiner still has a live VS-API session ends
        /// that session (its handle goes dead and its VSS worker is stopped), revokes its
        /// core visas, and marks every other visa installed on it pending, so it is pushed
        /// again after a reconnect. The node actor and its adapters stay, so the joiner may
        /// still `reconnect`. No visa is edited.
        #[tokio::test]
        async fn a_request_for_a_live_peer_ends_its_session_and_keeps_its_actor() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    let (asm, relay, zode) = join_net().await;
                    // The joiner's live session: a session id, an adapter, a registered VSS,
                    // its three core visas, and one other visa (to the relay's VSS port),
                    // all installed on it.
                    let mut actor = asm
                        .actor_mgr
                        .get_actor_by_zpr_addr(&zode)
                        .await
                        .unwrap()
                        .unwrap();
                    stamp_new_session(&mut actor);
                    asm.actor_mgr
                        .update_actor(&actor, &Default::default())
                        .await
                        .unwrap();
                    let session = actor
                        .get_attribute(key::SESSION)
                        .and_then(|a| a.get_single_value().ok())
                        .map(str::to_string);
                    let old_handle = VSHandleImpl::new(asm.clone(), actor.clone());
                    let adapter: IpAddr = "fd5a:5052:3000::70".parse().unwrap();
                    asm.actor_mgr
                        .add_adapter_via_node(
                            &make_adapter_actor_defexp(&adapter.to_string(), "laptop"),
                            &zode,
                            &Default::default(),
                        )
                        .await
                        .unwrap();
                    asm.actor_mgr
                        .set_node_vss(&zode, &SocketAddr::new(zode, VSS_PORT))
                        .await
                        .unwrap();
                    let [fwd, rev] =
                        crate::core_visas::issue_vsapi_visas(&asm, &zode, session.as_deref())
                            .await
                            .unwrap();
                    let vss = crate::core_visas::issue_vss_visa(
                        &asm,
                        &zode,
                        VSS_PORT,
                        session.as_deref(),
                    )
                    .await
                    .unwrap();
                    let other = match request_visa_wait_response(
                        &asm,
                        &zode,
                        PacketDesc::new_tcp(&zode.to_string(), &relay.to_string(), 40000, VSS_PORT)
                            .unwrap(),
                        config::DEFAULT_VISA_REQ_TIMEOUT,
                    )
                    .await
                    .unwrap()
                    {
                        VisaDecision::Allow(visa, _) => visa.issuer_id,
                        VisaDecision::Deny(code) => panic!("other visa denied: {code:?}"),
                    };
                    for id in [fwd, rev, vss, other] {
                        asm.visa_mgr.visa_installed(id, &zode).await.unwrap();
                    }
                    let (vss_tx, mut vss_rx) = tokio::sync::mpsc::channel(8);
                    asm.vss_mgr.insert_test_handle(zode, vss_tx);

                    let bv = request(&handle_for(&asm, &relay).await, "zode.zpr")
                        .await
                        .expect("a live peer's rejoin is granted");

                    assert!(
                        !old_handle.node_is_live().await,
                        "the old session's handle is dead"
                    );
                    let stored = asm.actor_mgr.get_actor_by_zpr_addr(&zode).await.unwrap();
                    assert!(stored.is_some_and(|a| a.is_node()), "the node actor stays");
                    assert_eq!(
                        asm.actor_mgr
                            .get_adapters_connected_to_node(&zode)
                            .await
                            .unwrap(),
                        vec![adapter],
                        "its adapters stay"
                    );
                    for id in [fwd, rev, vss] {
                        assert!(revoked_on(&asm, id, &zode).await, "core visa {id} revoked");
                    }
                    assert!(!revoked_on(&asm, other, &zode).await);
                    assert!(
                        asm.visa_mgr
                            .get_pending_visa_ids_for_node(&zode)
                            .await
                            .unwrap()
                            .contains(&other),
                        "the other visa is pending re-push"
                    );
                    let installed = asm
                        .visa_mgr
                        .get_installed_visa_ids_for_node(&zode)
                        .await
                        .unwrap();
                    assert_eq!(
                        {
                            let mut v = installed;
                            v.sort();
                            v
                        },
                        ids(&bv.peer),
                        "only the new bootstrap visas are installed on the joiner"
                    );
                    let stopped = loop {
                        match tokio::time::timeout(Duration::from_secs(2), vss_rx.recv()).await {
                            Ok(Some(VssCmd::Stop())) => break true,
                            Ok(Some(_)) => continue,
                            _ => break false,
                        }
                    };
                    assert!(stopped, "the old session's VSS worker is stopped");
                })
                .await;
        }
    }
}
