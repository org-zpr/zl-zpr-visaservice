//! Each node's VSS service is managed by a worker here on the VS side.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_rustls::TlsConnector;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};

use libeval::policy::Policy;
use zpr::vsapi::v1;
use zpr::vsapi_types::{
    ApiResponseError, Link, LinkRole, Param, ServiceDescriptor, SockAddr, Visa, VisaOp, pname,
};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::error::{ServiceError, VssSyncError};
use crate::logging::targets::VSS;
use crate::net_mgr;
use crate::policy_mgr::{PolicySnapshot, ResolvedPeer};
use crate::vss::VssCmd;

/// Default timeout for a single Cap'n Proto RPC call.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum (and initial) timeout for a ping RPC call.
const PING_MIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct VssState {
    last_configure: Option<Instant>,
    services_state: AgedState,
    topology_state: AgedState,
}

impl VssState {
    fn needs_configure(&self) -> bool {
        self.last_configure.is_none()
    }

    /// Indicates that the initial configuration call was performed.
    fn mark_configured(&mut self) {
        self.last_configure = Some(Instant::now());
    }

    fn needs_set_services(&self) -> bool {
        self.services_state.needs_sync()
    }

    fn mark_services_updated(&mut self) {
        self.services_state.last_update = Instant::now();
    }

    /// Indicates we have sent the services list across.
    fn mark_services_synced(&mut self) {
        self.services_state.mark_synced();
    }

    fn needs_set_topology(&self) -> bool {
        self.topology_state.needs_sync()
    }

    /// If topology effecting this node has been updated, indicate that here.
    /// Marking it updated makes housekeeping re-send topology if the inline
    /// set-topology RPC fails, so the node never sticks with stale topology.
    fn mark_topology_updated(&mut self) {
        self.topology_state.last_update = Instant::now();
    }

    /// Indicates we have sent the topology information across.
    fn mark_topology_synced(&mut self) {
        self.topology_state.mark_synced();
    }
}

#[derive(Debug)]
struct AgedState {
    last_update: Instant,
    last_sync: Option<Instant>,
}

impl AgedState {
    fn needs_sync(&self) -> bool {
        self.last_sync.is_none() || self.last_sync.as_ref().unwrap() < &self.last_update
    }

    fn mark_synced(&mut self) {
        self.last_sync = Some(Instant::now());
    }
}

impl Default for AgedState {
    fn default() -> Self {
        Self {
            last_update: Instant::now(),
            last_sync: None,
        }
    }
}

/// Run-loop for a thread that manages a VSS connection to a node.
///
/// `node_addr` is the nodes ZPR address and the socket that its VSS is listening on.
pub async fn vss_worker_loop(
    asm: Arc<Assembly>,
    node_addr: SocketAddr,
    mut cmd_rx: mpsc::Receiver<VssCmd>,
) {
    // Open connect to VSS.
    info!(target: VSS, "connecting to VSS at {}", node_addr);

    let vss_handle = match vss_connect(asm.config.get_vs_addr(), node_addr).await {
        Ok(h) => h,
        Err(e) => {
            error!(target: VSS, "failed to connect to VSS at {}: {}", node_addr, e);
            asm.counters.incr(CounterType::VssErrors);
            return;
        }
    };

    info!(target: VSS, "now connected to VSS at {}", node_addr);
    let mut state = VssState::default();
    do_housekeeping(&mut state, &asm, &node_addr, &vss_handle).await;

    let ping_timeout = tokio::time::sleep(config::VSS_PING_INTERVAL);
    tokio::pin!(ping_timeout);
    let mut ping_failures = 0;

    let mut heartbeat = tokio::time::interval(config::VSS_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(cmd) => match cmd {
                        VssCmd::Stop() => {
                            info!(target: VSS, "stop called on VSS worker for {}", node_addr);
                            break;
                        }
                        VssCmd::PushVisas(visas, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_push_visas(&vss_handle, &visas).await) {
                                error!(target: VSS, "failed to send response for push-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeVisasById(visa_ids, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_revoke_visas(&vss_handle, &visa_ids).await) {
                                error!(target: VSS, "failed to send response for revoke-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeAuthsByZprAddr(zpr_addrs, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_revoke_auths(&vss_handle, &zpr_addrs).await) {
                                error!(target: VSS, "failed to send response for revoke-auths command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RequestAuthsByZprAddr(zpr_addrs, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_request_auths(&vss_handle, &zpr_addrs).await) {
                                error!(target: VSS, "failed to send response for request-auths command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::SetServices(services, resp_tx) => {
                            state.mark_services_updated();
                            if let Err(e) = resp_tx.send(vss_do_set_services(&vss_handle, services).await) {
                                error!(target: VSS, "failed to send response for set-services command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::Configure(params, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_configure(&vss_handle, params).await) {
                                error!(target: VSS, "failed to send response for configure command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::SetTopology(psnap, resp_tx) => {
                            state.mark_topology_updated();
                            if let Err(e) = resp_tx.send(vss_do_set_topology(&vss_handle, asm.clone(), &node_addr.ip(), psnap).await) {
                                error!(target: VSS, "failed to send response for set-topology command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                    }
                    None => {
                        // Uh oh - channel closed.
                        warn!(target: VSS, "command channel closed for VSS worker for {}", node_addr);
                        break;
                    }
                }
            }

            _ = heartbeat.tick() => {
                do_housekeeping(&mut state, &asm, &node_addr, &vss_handle).await;
            }

            () = &mut ping_timeout => {
                let ping_dur = PING_MIN_TIMEOUT + Duration::from_secs(ping_failures);
                match rpc_with_timeout("ping", ping_dur, vss_handle.ping_request().send().promise).await {
                    Ok(ping_response_rdr) => {
                        match ping_response_rdr.get().unwrap().get_res().unwrap().which().unwrap() {
                            v1::ok_or_error::Which::Ok(_) => {
                                trace!(target: VSS, "ping to VSS at {} succeeded", node_addr);
                                asm.actor_mgr.update_node_last_seen(&node_addr.ip()).await.ok(); // Ignore errors.
                                ping_failures = 0;
                            }
                            v1::ok_or_error::Which::Error(err_rdr) => {
                                let err_obj = err_rdr.unwrap();
                                error!(target: VSS, "VSS ping returns error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                                asm.counters.incr(CounterType::VssErrors);
                                // TODO: What does this even mean? We got a reply but it is a coded error message? Should we just disconnect from node?
                                ping_failures += 1;
                            }
                        }
                    }
                    Err(VssSyncError::Timeout(_)) => {
                        warn!(target: VSS, "ping to VSS at {} timed out", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                    Err(_) => {
                        warn!(target: VSS, "ping to VSS at {} failed", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                }
                if ping_failures == 0 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + config::VSS_PING_INTERVAL);
                } else if ping_failures < config::VSS_MAX_PING_FAILURES as u64 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
                } else {
                    error!(target: VSS, "too many VSS ping failures to {}, exiting VSS worker", node_addr);
                    return;
                }
            }
        }
    }
}

/// Open a TCP connection to `remote` from the local address `local`.
///
/// The visa service must originate VSS traffic from its own ZPR address
/// (`vs_addr`). On a relay Zode the TUN also carries the relay's own address,
/// and the kernel's source-address choice could pick that one instead; the
/// relay grants the visa service's visas only for `vs_addr`, so such a
/// connection would be dropped. Binding first removes the choice. A `local`
/// that is not a local address, or of a different family than `remote`, is
/// an error — never a silent fallback to a kernel-chosen source.
async fn connect_from(local: IpAddr, remote: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let sock = if local.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    sock.bind(SocketAddr::new(local, 0))?;
    sock.connect(remote).await
}

/// Perform TCP connect (from `local`, see [connect_from]), TLS handshake,
/// Cap'n Proto RPC bootstrap, and the initial connect RPC, returning a
/// ready-to-use VSS handle client.
async fn vss_connect(
    local: IpAddr,
    node_addr: SocketAddr,
) -> Result<v1::v_s_s_handle::Client, VssSyncError> {
    let sock = connect_from(local, node_addr)
        .await
        .map_err(|e| VssSyncError::Internal(format!("TCP connect from {local}: {e}")))?;

    let tls = tls_connect()
        .connect(node_addr.ip().into(), sock)
        .await
        .map_err(|e| VssSyncError::Internal(format!("TLS handshake: {e}")))?;

    let (reader, writer) = tokio::io::split(tls);
    let network = capnp_rpc::twoparty::VatNetwork::new(
        tokio::io::BufReader::new(reader).compat(),
        tokio::io::BufWriter::new(writer).compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    );
    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);
    let vss_service: v1::visa_support_service::Client =
        rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
    tokio::task::spawn_local(rpc_system);

    let req = vss_service.connect_request();
    let handle_result_rdr =
        rpc_with_timeout("connect", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let handle_result_ok_or_error = handle_result_rdr.get()?.get_resp()?;
    match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => Ok(vss_handle_obj.unwrap()),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            Err(VssSyncError::Internal(format!(
                "VSS rejected connect: code={:?} msg={:?}",
                err_obj.get_code(),
                err_obj.get_message(),
            )))
        }
    }
}

/// One heartbeat of the worker for the node whose VSS listens on `vss_addr`: the initial
/// configuration sends, J9 core-visa renewal, then the pending visa and revoke queues.
async fn do_housekeeping(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    vss_addr: &SocketAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    let node_addr = &vss_addr.ip();
    // Currently these three items are all onoly part of intiial VSS connection.
    // Once they are sent, they are not sent again.
    if state.needs_configure() {
        send_configure(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_services() {
        send_auth_services(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_topology() {
        send_topology(state, asm, node_addr, vss_handle).await;
    }

    // Drop any expired visas from the in-memory store before working the queues.
    if let Err(e) = asm.visa_mgr.purge_expired_visas() {
        warn!(target: VSS, "failed to purge expired visas: {e}");
    }

    // J9: renew the node's core visas before they expire. Their copies are queued
    // pending-install, so the push just below starts delivering them (ingress last).
    if let Err(e) = crate::core_visas::renew_core_visas(
        asm,
        node_addr,
        vss_addr.port(),
        std::time::SystemTime::now(),
    )
    .await
    {
        warn!(target: VSS, "core visa renewal for node {node_addr} failed, retrying next heartbeat: {e}");
    }

    send_pending_visas(asm, node_addr, vss_handle).await;
    send_pending_revokes(asm, node_addr, vss_handle).await;

    // TODO: Check for pending authentication revocations.
}

/// If there are pending visas for this node, use VSS api to send them over.
/// Update DB state if we are successful.
async fn send_pending_visas(
    asm: &Assembly,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    // Ingress copies wait for the other hops' acks (gate g89 q4): see
    // `VisaMgr::deliverable_visas_for_node`.
    match asm.visa_mgr.deliverable_visas_for_node(node_addr).await {
        Ok(pending_visas) => {
            let mut actualized = Vec::new();
            for visa in pending_visas {
                let issuer_id = visa.issuer_id;
                match asm
                    .visa_mgr
                    .actualize_visa_for_target_node(visa, node_addr)
                    .await
                {
                    Ok(a_visa) => actualized.push(a_visa),
                    Err(e) => {
                        error!(target: VSS, "failed to actualize pending visa {issuer_id} for node {}: {}", node_addr, e);
                    }
                }
            }
            if !actualized.is_empty() {
                match vss_do_push_visas(vss_handle, &actualized).await {
                    Ok(processed) => {
                        // Update our state for the processed visas.
                        // TODO: Need to consider that housekeeping will run frequently, possibly bombarding
                        // nodes that for some reason are not accepting visas. Not sure correct solution yet.
                        for pushed in actualized.iter().take(processed) {
                            if let Err(e) = asm
                                .visa_mgr
                                .visa_installed(pushed.issuer_id, &node_addr)
                                .await
                            {
                                // TODO: Means it will be attempt to be installed next housekeeping run.
                                warn!(target: VSS,
                                    "error marking visa {} as installed for node {node_addr}: {e}", pushed.issuer_id
                                );
                            }
                        }

                        debug!(target: VSS, "successfully pushed {} pending visas to node {}", actualized.len(), node_addr);
                    }
                    Err(e) => {
                        error!(target: VSS, "failed to push {} pending visas to node {}: {}", actualized.len(), node_addr, e);
                        return;
                    }
                }
            }
        }
        Err(e) => {
            warn!(target: VSS, "failed to get pending visas for node {}: {}", node_addr, e);
        }
    }
}

/// If there are visas pending revocation for this node, send the revokes over
/// VSS and tear down the acked ones. Mirrors `send_pending_visas`.
///
/// No per-id staleness re-check is needed: allow verdicts cancel queued revokes
/// under the same store lock that marks them, so a `PendingRevoke` with a newer
/// allow cannot exist in memory.
async fn send_pending_revokes(
    asm: &Assembly,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    let ids = match asm
        .visa_mgr
        .get_pending_revoke_visa_ids_for_node(node_addr)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            warn!(target: VSS, "failed to get pending-revoke visas for node {}: {}", node_addr, e);
            return;
        }
    };
    if ids.is_empty() {
        return; // Nothing to revoke; skip the RPC.
    }

    match vss_do_revoke_visas(vss_handle, &ids).await {
        Ok(processed) => {
            // Tear down state for the acked ids (same prefix convention as install).
            for &id in ids.iter().take(processed) {
                asm.visa_mgr.revoke_acked(*node_addr, id).await;
            }
            debug!(target: VSS, "revoked {} of {} pending visas on node {}", processed, ids.len(), node_addr);
        }
        Err(e) => {
            error!(target: VSS, "failed to revoke {} pending visas on node {}: {}", ids.len(), node_addr, e);
        }
    }
}

async fn send_configure(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    // The AAA net is stored in the actor properties, but it is statically tied to
    // the node ZPR address so we just recompute it here.
    let aaa_net = net_mgr::aaa_network_for_node(node_addr);
    let params = vec![Param::new_str(
        pname::AAA_PREFIX.into(),
        aaa_net.to_string(),
    )];
    debug!(target: VSS, "sending configure to VSS at {node_addr}");
    match vss_do_configure(vss_handle, params).await {
        Ok(_) => {
            debug!(target: VSS, "{node_addr} configured successfully");
            state.mark_configured();
        }
        Err(e) => {
            warn!(target: VSS, "failed to configure VSS at {node_addr}: {e}");
            asm.counters.incr(CounterType::VssErrors);
        }
    }
}

async fn send_auth_services(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => {
            debug!(target: VSS, "sending initial auth services list to VSS at {}", node_addr);
            if let Err(e) = vss_do_set_services(&vss_handle, services).await {
                error!(target: VSS, "failed to send initial auth services list to VSS at {}: {}", node_addr, e);
                asm.counters.incr(CounterType::VssErrors);
            } else {
                debug!(target: VSS, "initial auth services list sent to VSS at {}", node_addr);
                state.mark_services_synced();
            }
        }
        Err(e) => {
            warn!(target: VSS, "failed to get auth services list for VSS at {}: {}", node_addr, e);
        }
    }
}

async fn send_topology(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    let psnap = asm.policy_mgr.get_current_snapshot();
    debug!(target: VSS, "sending initial topology to VSS at {}", node_addr);
    if let Err(e) = vss_do_set_topology(vss_handle, asm.clone(), node_addr, psnap).await {
        error!(target: VSS, "failed to send initial topology to VSS at {}: {}", node_addr, e);
        asm.counters.incr(CounterType::VssErrors);
    } else {
        debug!(target: VSS, "initial topology sent to VSS at {}", node_addr);
        state.mark_topology_synced();
    }
}

#[derive(Debug)]
struct NoVerification;

// Implement the dangerous trait ServerCertVerifier NoVerification which will
// just always approve the connection
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

// Create a dangerous connector - the verifier will always approve
// TODO decide if we want to use an actual certificate
fn tls_connect() -> TlsConnector {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(cfg))
}

/// Wrap a Cap'n Proto RPC future with a timeout, mapping errors.
async fn rpc_with_timeout<F, T>(
    name: &'static str,
    duration: Duration,
    fut: F,
) -> Result<T, VssSyncError>
where
    F: Future<Output = Result<T, capnp::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(capnp_err)) => Err(capnp_err.into()),
        Err(_elapsed) => Err(VssSyncError::Timeout(name.to_string())),
    }
}

/// Map a Cap'n Proto ok-or-error reader to a `Result`, converting API errors.
fn check_ok_or_error(r: v1::ok_or_error::Reader<'_>) -> Result<(), VssSyncError> {
    match r.which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => Ok(()),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            Err(VssSyncError::from(api_err))
        }
    }
}

/// Send a batch of visa ops (grants and/or revokes) via the VSS `push_visa_op`
/// call. Returns the number of ops positively ack'd by the node. Treats zero
/// ops processed as an error.
async fn vss_do_visa_ops(
    vss_handle: &v1::v_s_s_handle::Client,
    ops: &[VisaOp],
) -> Result<usize, VssSyncError> {
    let mut req = vss_handle.push_visa_op_request();
    let req_builder = req.get();
    let mut ops_list_builder = req_builder.init_ops(ops.len() as u32);

    // Each VisaOp writes itself as either a Grant or a RevokeVisaId.
    for (i, op) in ops.iter().enumerate() {
        let mut op_builder = ops_list_builder.reborrow().get(i as u32);
        op.write_to(&mut op_builder);
    }

    let push_response_rdr =
        rpc_with_timeout("push-visas", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    // Response is an Ack struct (TODO: Add this to the vsapi types in zpr-common)
    let ack_response = push_response_rdr.get()?.get_ack()?;
    if ack_response.get_ok() {
        // At least one op was processed. In this case we return the number processed and
        // log the error (if any).
        let processed = ack_response.get_processed() as usize;
        if processed < ops.len() {
            let err_rdr = ack_response.get_error()?;
            let err_obj = ApiResponseError::try_from(err_rdr)?;
            error!(target: VSS, "visa-ops partially succeeded: {} of {} processed, error code={:?} msg={}",
            processed, ops.len(), err_obj.code, err_obj.message);
        }
        return Ok(processed);
    } else {
        // No ops were processed.  Return error or zero ?? Not sure.
        let err_rdr = ack_response.get_error()?;
        let err_obj = ApiResponseError::try_from(err_rdr)?;
        return Err(err_obj.into());
    }
}

/// Push visa grants to the node, returning the number positively ack'd.
async fn vss_do_push_visas(
    vss_handle: &v1::v_s_s_handle::Client,
    visas: &[Visa],
) -> Result<usize, VssSyncError> {
    let ops: Vec<VisaOp> = visas.iter().cloned().map(VisaOp::Grant).collect();
    vss_do_visa_ops(vss_handle, &ops).await
}

/// Revoke visas on the node by ID, returning the number positively ack'd.
async fn vss_do_revoke_visas(
    vss_handle: &v1::v_s_s_handle::Client,
    ids: &[u64],
) -> Result<usize, VssSyncError> {
    let ops: Vec<VisaOp> = ids.iter().map(|id| VisaOp::RevokeVisaId(*id)).collect();
    vss_do_visa_ops(vss_handle, &ops).await
}

/// Revoke authentications on the node for the given ZPR addresses via the
/// `revokeAuthentication` RPC, returning the number positively ack'd. The ack
/// handling mirrors [vss_do_visa_ops]: ok with a short count logs the partial
/// success, `ok = false` maps the carried error.
async fn vss_do_revoke_auths(
    vss_handle: &v1::v_s_s_handle::Client,
    addrs: &[IpAddr],
) -> Result<usize, VssSyncError> {
    let mut req = vss_handle.revoke_authentication_request();
    let req_builder = req.get();
    let mut addrs_list_builder = req_builder.init_addrs(addrs.len() as u32);
    for (i, addr) in addrs.iter().enumerate() {
        let mut addr_builder = addrs_list_builder.reborrow().get(i as u32);
        addr.write_to(&mut addr_builder);
    }

    let revoke_response_rdr =
        rpc_with_timeout("revoke-auths", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let ack_response = revoke_response_rdr.get()?.get_ack()?;
    if ack_response.get_ok() {
        // At least one revocation was processed. Return the number processed and
        // log the error (if any) for a partial success.
        let processed = ack_response.get_processed() as usize;
        if processed < addrs.len() {
            let err_rdr = ack_response.get_error()?;
            let err_obj = ApiResponseError::try_from(err_rdr)?;
            error!(target: VSS, "revoke-auths partially succeeded: {} of {} processed, error code={:?} msg={}",
            processed, addrs.len(), err_obj.code, err_obj.message);
        }
        Ok(processed)
    } else {
        // No revocations were processed.
        let err_rdr = ack_response.get_error()?;
        let err_obj = ApiResponseError::try_from(err_rdr)?;
        Err(err_obj.into())
    }
}

/// Ask the node to start re-authentication for the given ZPR addresses via
/// the `requestAuthentication` RPC, returning the number positively ack'd
/// (contract K1, zipline#123). Ack handling mirrors [vss_do_revoke_auths]:
/// the ack means the node *started* re-auth for `processed` addresses —
/// unknown addresses are skipped and not counted; outcomes are judged later
/// by `zpr.vinst`, never by this ack.
async fn vss_do_request_auths(
    vss_handle: &v1::v_s_s_handle::Client,
    addrs: &[IpAddr],
) -> Result<usize, VssSyncError> {
    let mut req = vss_handle.request_authentication_request();
    let req_builder = req.get();
    let mut addrs_list_builder = req_builder.init_addrs(addrs.len() as u32);
    for (i, addr) in addrs.iter().enumerate() {
        let mut addr_builder = addrs_list_builder.reborrow().get(i as u32);
        addr.write_to(&mut addr_builder);
    }

    let request_response_rdr =
        rpc_with_timeout("request-auths", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let ack_response = request_response_rdr.get()?.get_ack()?;
    if ack_response.get_ok() {
        // At least one request was accepted. Return the number accepted and
        // log the error (if any) for a partial acceptance.
        let processed = ack_response.get_processed() as usize;
        if processed < addrs.len() {
            let err_rdr = ack_response.get_error()?;
            let err_obj = ApiResponseError::try_from(err_rdr)?;
            error!(target: VSS, "request-auths partially accepted: {} of {} processed, error code={:?} msg={}",
            processed, addrs.len(), err_obj.code, err_obj.message);
        }
        Ok(processed)
    } else {
        // No requests were accepted.
        let err_rdr = ack_response.get_error()?;
        let err_obj = ApiResponseError::try_from(err_rdr)?;
        Err(err_obj.into())
    }
}

async fn vss_do_set_services(
    vss_handle: &v1::v_s_s_handle::Client,
    services: Vec<ServiceDescriptor>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.set_services_request();
    let req_builder = req.get();
    let mut svc_list_builder = req_builder.init_svcs(services.len() as u32);
    for (i, svc) in services.iter().enumerate() {
        let mut svc_builder = svc_list_builder.reborrow().get(i as u32);
        svc.write_to(&mut svc_builder);
    }
    let set_response_rdr =
        rpc_with_timeout("set-services", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;
    let set_response_ok_or_err = set_response_rdr.get()?;
    check_ok_or_error(set_response_ok_or_err.get_res().unwrap())
}

async fn vss_do_configure(
    vss_handle: &v1::v_s_s_handle::Client,
    params: Vec<Param>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.configure_request();
    let req_builder = req.get();
    let mut params_builder = req_builder.init_params(params.len() as u32);
    for (i, param) in params.iter().enumerate() {
        let mut param_builder = params_builder.reborrow().get(i as u32);
        param.write_to(&mut param_builder);
    }
    let configure_response_rdr =
        rpc_with_timeout("configure", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;
    let configure_response_ok_or_err = configure_response_rdr.get()?;
    check_ok_or_error(configure_response_ok_or_err.get_res().unwrap())
}

/// Send the node's links via the `setTopology` RPC, built from `psnap`
/// ([proposed_links]). No links means no peers.
///
/// This is the one place the wire-level vsapi `Link` structs are built and sent.
/// `node_addr` is the ZPR address of the node on the other end of `vss_handle`; the
/// links are that node's view of the topology.
///
/// A failed address lookup fails the send, so the caller leaves the topology unsynced
/// and the worker's heartbeat sends it again: no link goes out with a guessed address.
async fn vss_do_set_topology(
    vss_handle: &v1::v_s_s_handle::Client,
    asm: Arc<Assembly>,
    node_addr: &IpAddr,
    psnap: PolicySnapshot,
) -> Result<(), VssSyncError> {
    // Each link names its peer's ZPR address and CN. It carries no visas (J8): a relay asks
    // for a joining peer's bootstrap visas when that peer's link comes up
    // (`requestBootstrapVisas`, see [crate::visa_bootstrap]).
    let links = proposed_links(&asm, &psnap, node_addr)
        .await
        .map_err(|e| VssSyncError::Internal(format!("building the topology: {e}")))?;

    let mut req = vss_handle.set_topology_request();
    let req_builder = req.get();
    let mut peer_list_builder = req_builder.init_links(links.len() as u32);

    for (i, link) in links.iter().enumerate() {
        let mut peer_builder = peer_list_builder.reborrow().get(i as u32);
        link.write_to(&mut peer_builder);
    }
    let set_response_rdr =
        rpc_with_timeout("set-topology", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;
    let set_response_ok_or_err = set_response_rdr.get()?;
    check_ok_or_error(set_response_ok_or_err.get_res().unwrap())
}

/// The `Link`s the visa service proposes to `node_addr`, all read from `psnap`
/// (ZODE_LINKS.md rule 13b, zl-zipline#255): it proposes a link only when it can work,
/// and never asks a Zode to dial an address it does not know.
///
/// The candidates are [topology_links] (R13a and the CN rule apply there). Of those:
/// - a **relay link** -- one end is the relay, the node the visa service docks on
///   ([crate::visa_bootstrap::is_relay]; the v1 relay, §5.6) -- is always proposed:
///   an endpoint dials its configured initial link, and the relay must know a joiner's
///   CN before the joiner connects (J2). `peer` is the other end's known address, or
///   unset if there is none (the relay never dials a joiner);
/// - a **direct link** is proposed only when both ends have a known address, and its
///   `peer` is the other end's. Which end dials is the Zodes' rule, not copied here.
///
/// A known address is [known_substrate_addr]. A lookup that fails is an error: the
/// caller leaves the topology unsynced and it is sent again, never with a guess.
pub(crate) async fn proposed_links(
    asm: &Assembly,
    psnap: &PolicySnapshot,
    node_addr: &IpAddr,
) -> Result<Vec<Link>, ServiceError> {
    let candidates = topology_links(
        asm,
        psnap.policy(),
        node_addr,
        psnap.resolved_peers_for_node(node_addr),
    );
    let node_is_relay = crate::visa_bootstrap::is_relay(asm, node_addr);
    let own_addr = known_substrate_addr(
        asm,
        crate::connection_control::substrate_addr_from_topology(psnap, node_addr),
        node_addr,
    )
    .await?;
    let mut links = Vec::with_capacity(candidates.len());
    for mut link in candidates {
        // `link.peer` holds the peer's policy address, if policy declares one.
        let peer_addr =
            known_substrate_addr(asm, link.peer.clone().map(SocketAddr::from), &link.zpr_addr)
                .await?;
        let is_relay_link = node_is_relay || crate::visa_bootstrap::is_relay(asm, &link.zpr_addr);
        if !is_relay_link && (own_addr.is_none() || peer_addr.is_none()) {
            let missing = if own_addr.is_none() {
                node_addr
            } else {
                &link.zpr_addr
            };
            info!(target: VSS, "direct link {} between {node_addr} and {}: no known address for {missing}; left out of topology", link.link_id, link.zpr_addr);
            continue;
        }
        link.peer = peer_addr.map(|addr| SockAddr {
            addr: addr.ip(),
            port: addr.port(),
        });
        links.push(link);
    }
    Ok(links)
}

/// The known substrate address of `node` (plan p37 rule 3): `policy_addr`, its
/// DNS-resolved policy address, if policy declares one; else the `SUBSTRATE_ADDR`
/// claim of its VS-API session, the stored node actor (a node with no stored node actor
/// has no session; see `core_visas::require_current_session`). Nothing else: `None`
/// means unknown.
///
/// The claim was checked when it was recorded (`accept_reported_substrate`). Trusting it
/// steers only where a peer dials; the link still needs the node's CA-signed
/// certificate with the expected CN. Whether a Zode can misuse the address it reports
/// is zl-zipline#264.
async fn known_substrate_addr(
    asm: &Assembly,
    policy_addr: Option<SocketAddr>,
    node: &IpAddr,
) -> Result<Option<SocketAddr>, ServiceError> {
    if policy_addr.is_some() {
        return Ok(policy_addr);
    }
    let Some(actor) = asm.actor_mgr.get_actor_by_zpr_addr(node).await? else {
        return Ok(None);
    };
    if !actor.is_node() {
        return Ok(None);
    }
    let Some(claim) = actor
        .get_attribute(libeval::attribute::key::SUBSTRATE_ADDR)
        .and_then(|attr| attr.get_single_value().ok())
    else {
        return Ok(None);
    };
    claim.parse::<SocketAddr>().map(Some).map_err(|e| {
        ServiceError::Internal(format!(
            "node {node}: stored substrate address {claim:?}: {e}"
        ))
    })
}

/// The candidate `Link`s of `node_addr`'s topology message: one per resolved peer, each
/// naming the peer's ZPR address and CN, with `peer` = the peer's policy address if
/// policy declares one. No link carries visas (J8). A link whose owner reported it
/// `failed` is left out until the pair is cleared (R13a, `TopologyMgr::is_failed_pair`).
/// [proposed_links] decides which candidates are sent, and with which `peer`.
///
/// `policy` must be the snapshot `peers` was computed from.
pub(crate) fn topology_links(
    asm: &Assembly,
    policy: &Policy,
    node_addr: &IpAddr,
    peers: Vec<ResolvedPeer>,
) -> Vec<Link> {
    // Both ends of an edge share a link_id, and each end's `remote_zpr_addr` is only
    // meaningful under its own node key -- so resolve the link within `node_addr`'s peers.
    let node_peers = policy.get_peers_for_node(node_addr).unwrap_or_default();
    let mut links: Vec<Link> = Vec::with_capacity(peers.len());
    for (link_id, sock_addr) in peers {
        // `zpr_addr` is required on the wire (the reader rejects a link without it), so a
        // link with no peer entry cannot be sent at all: skip it.
        let Some(peer) = node_peers.iter().find(|p| p.link_id == link_id) else {
            warn!(target: VSS, "no peer entry for link {link_id} under node {node_addr}; skipping it (zprAddr unknown)");
            continue;
        };
        // R13a (ZODE_LINKS.md): the visa service owns the retry policy. The owner reported
        // this link failed, so neither end is told about it until something about the pair
        // changes; dropping it from topology also closes it (R12).
        if asm
            .topo_mgr
            .is_failed_pair(node_addr, &peer.remote_zpr_addr)
        {
            info!(target: VSS, "link {link_id} between {node_addr} and {} was reported failed; left out of topology", peer.remote_zpr_addr);
            continue;
        }
        // The CN the peer's link certificate must carry (zl-zipline#221). A peer policy does
        // not name is left out (operator, pd g44 q2): its node would refuse an unnamed peer
        // (zl-zipline#220), and a relay could not ask for its bootstrap visas by CN (J2).
        let Some(peer_cn) = policy.node_cn_for_addr(&peer.remote_zpr_addr) else {
            warn!(target: VSS, "no CN in policy for peer {} of node {node_addr} (link {link_id}); skipping the link", peer.remote_zpr_addr);
            continue;
        };
        links.push(Link {
            link_id,
            role: LinkRole::Active, // only "active" support at the moment.
            peer: sock_addr.map(|sock_addr| SockAddr {
                addr: sock_addr.ip(),
                port: sock_addr.port(),
            }),
            zpr_addr: peer.remote_zpr_addr,
            peer_cn: peer_cn.to_string(),
        });
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// In-process capnp `VSSHandle` server whose `revoke_authentication` records
    /// the received addresses and answers with a configurable `Ack` — the same
    /// local-stub spirit as `oidc/jwks.rs` `test_support`.
    struct StubVss {
        seen: Rc<RefCell<Vec<IpAddr>>>,
        ack_ok: bool,
        processed: u32,
        error_msg: Option<String>,
    }

    impl v1::v_s_s_handle::Server for StubVss {
        async fn revoke_authentication(
            self: Rc<Self>,
            params: v1::v_s_s_handle::RevokeAuthenticationParams,
            mut results: v1::v_s_s_handle::RevokeAuthenticationResults,
        ) -> Result<(), capnp::Error> {
            let addrs_rdr = params.get()?.get_addrs()?;
            for addr_rdr in addrs_rdr.iter() {
                let addr = IpAddr::try_from(addr_rdr)
                    .map_err(|e| capnp::Error::failed(format!("bad addr: {e}")))?;
                self.seen.borrow_mut().push(addr);
            }
            let mut ack = results.get().init_ack();
            ack.set_ok(self.ack_ok);
            ack.set_processed(self.processed);
            if let Some(msg) = &self.error_msg {
                let mut err = ack.init_error();
                err.set_code(v1::ErrorCode::Internal);
                err.set_message(msg);
            }
            Ok(())
        }
    }

    /// Wire a [StubVss] to a `VSSHandle` client over an in-memory duplex pipe
    /// (twoparty RPC both ways). Must run inside a `LocalSet`.
    fn start_stub(stub: StubVss) -> v1::v_s_s_handle::Client {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);

        // Server vat.
        let (sr, sw) = tokio::io::split(server_side);
        let server_network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(sr).compat(),
            tokio::io::BufWriter::new(sw).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );
        let server_client: v1::v_s_s_handle::Client = capnp_rpc::new_client(stub);
        let server_rpc =
            capnp_rpc::RpcSystem::new(Box::new(server_network), Some(server_client.clone().client));
        tokio::task::spawn_local(server_rpc);

        // Client vat.
        let (cr, cw) = tokio::io::split(client_side);
        let client_network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(cr).compat(),
            tokio::io::BufWriter::new(cw).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Client,
            capnp::message::ReaderOptions::new(),
        );
        let mut client_rpc = capnp_rpc::RpcSystem::new(Box::new(client_network), None);
        let handle: v1::v_s_s_handle::Client =
            client_rpc.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
        tokio::task::spawn_local(client_rpc);

        handle
    }

    /// An ok ack with `processed = n` maps to `Ok(n)`, and the node saw exactly
    /// the addresses we sent, in order.
    #[tokio::test]
    async fn test_revoke_auths_sends_addrs_and_returns_processed_count() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let seen = Rc::new(RefCell::new(Vec::new()));
                let handle = start_stub(StubVss {
                    seen: seen.clone(),
                    ack_ok: true,
                    processed: 2,
                    error_msg: None,
                });

                let addrs: Vec<IpAddr> = vec![
                    "fd5a:5052:4000::a".parse().unwrap(),
                    "10.1.2.3".parse().unwrap(),
                ];
                let n = vss_do_revoke_auths(&handle, &addrs)
                    .await
                    .expect("revoke-auths should succeed on an ok ack");
                assert_eq!(n, 2, "processed count must come from the ack");
                assert_eq!(
                    *seen.borrow(),
                    addrs,
                    "node must see exactly the sent addrs"
                );
            })
            .await;
    }

    /// An `ok = false` ack with an error maps to `Err(VssSyncError)`.
    #[tokio::test]
    async fn test_revoke_auths_error_ack_maps_to_err() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let seen = Rc::new(RefCell::new(Vec::new()));
                let handle = start_stub(StubVss {
                    seen: seen.clone(),
                    ack_ok: false,
                    processed: 0,
                    error_msg: Some("revocation rejected".to_string()),
                });

                let addrs: Vec<IpAddr> = vec!["fd5a:5052:4000::a".parse().unwrap()];
                let res = vss_do_revoke_auths(&handle, &addrs).await;
                match res {
                    Err(VssSyncError::ApiResponse(_, msg, _)) => {
                        assert!(msg.contains("revocation rejected"), "unexpected msg: {msg}");
                    }
                    other => panic!("expected ApiResponse error, got {other:?}"),
                }
            })
            .await;
    }

    /// The VSS connection must leave from the visa service's own address
    /// (`vs_addr`), not whichever local address the kernel would pick. On
    /// Linux the whole of 127/8 is local, so 127.0.0.2 is a second address on
    /// the same interface — the relay Zode's two-addresses-on-one-TUN case.
    /// The listener does not speak TLS, so the connect itself fails after
    /// the TCP handshake; only the source address the listener saw matters.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn vss_connect_originates_from_vs_addr() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (_sock, peer) = listener.accept().await.unwrap();
            peer.ip()
        });

        let vs_addr: IpAddr = "127.0.0.2".parse().unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), vss_connect(vs_addr, listen_addr))
            .await
            .expect("vss_connect hung");
        assert!(
            res.is_err(),
            "the listener does not speak TLS, so connect must fail"
        );

        let peer_ip = accepted.await.unwrap();
        assert_eq!(
            peer_ip, vs_addr,
            "VSS connection must originate from vs_addr"
        );
    }

    /// A source address that is not local cannot be bound: the connect must
    /// fail rather than silently fall back to a kernel-chosen source.
    #[tokio::test]
    async fn connect_from_reports_unbindable_source() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // 192.0.2.1 is TEST-NET-1 (RFC 5737): never assigned to a host.
        let not_local: IpAddr = "192.0.2.1".parse().unwrap();
        let res = connect_from(not_local, listen_addr).await;
        assert!(
            res.is_err(),
            "binding a non-local source must fail, got {res:?}"
        );
    }

    /// Tests for which links the visa service proposes and with which `peer`
    /// (ZODE_LINKS.md rule 13b, zl-zipline#255).
    mod proposed {
        use super::*;
        use crate::db::{FakeDb, FaultMode};
        use crate::test_helpers::{make_node_actor_defexp, make_peering};
        use std::collections::HashMap;
        use zpr::policy_types::{NetAddr, Peering};

        /// The relay: the visa service docks on it. Policy declares its address.
        const R: &str = "fd5a:5052:3000::1";
        /// Endpoints with no address in policy: they report their own when they connect.
        const A: &str = "fd5a:5052:3000::a";
        const B: &str = "fd5a:5052:3000::b";
        /// Nodes whose address policy declares.
        const C: &str = "fd5a:5052:3000::c";
        const D: &str = "fd5a:5052:3000::d";

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn sa(s: &str) -> SocketAddr {
            s.parse().unwrap()
        }

        /// The policy address of `node` on its links, if policy declares one.
        fn policy_port(node: &str) -> Option<u16> {
            match node {
                R => Some(7000),
                C => Some(7003),
                D => Some(7004),
                _ => None,
            }
        }

        /// A peering of `a` and `b`, each end at its own ZPR address with its
        /// [policy_port], or with no address where policy declares none.
        fn peering(a: &str, b: &str, link_id: &str) -> Peering {
            let mut peering = make_peering(ip(a), ip(b), link_id, vec![]);
            peering.substrate_a = policy_port(a).map(|port| NetAddr::new_for_ip_or_host(a, port));
            peering.substrate_b = policy_port(b).map(|port| NetAddr::new_for_ip_or_host(b, port));
            peering
        }

        /// An assembly whose policy links the relay R to A, B and C, and declares the
        /// direct links A-B and C-D, with a CN for every node. The visa service docks
        /// on R. No node has a VS-API session yet; see [connect].
        async fn build() -> (Arc<Assembly>, Arc<FakeDb>) {
            let (asm, event_rx, db) =
                crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
            std::mem::forget(event_rx);
            let peerings = [
                peering(R, A, "link-ra"),
                peering(R, B, "link-rb"),
                peering(R, C, "link-rc"),
                peering(A, B, "link-ab"),
                peering(C, D, "link-cd"),
            ];
            let cns = [R, A, B, C, D].map(|n| (ip(n), n));
            asm.policy_mgr
                .update_policy_from_container_bytes(
                    crate::test_helpers::policy_with_peerings_and_node_cns(&peerings, &cns),
                )
                .await
                .unwrap();
            asm.topo_mgr.add_node(ip(R)).unwrap();
            asm.actor_mgr
                .hack_set_vs_docking_node(&ip(R))
                .await
                .unwrap();
            (Arc::new(asm), db)
        }

        /// `node` starts a VS-API session that reported `substrate`.
        async fn connect(asm: &Assembly, node: &str, substrate: &str) {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(node, node, substrate),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
        }

        /// `node`'s proposed links, by peer ZPR address: `peer -> Link.peer`.
        async fn links_of(asm: &Assembly, node: &str) -> HashMap<IpAddr, Option<SocketAddr>> {
            let psnap = asm.policy_mgr.get_current_snapshot();
            proposed_links(asm, &psnap, &ip(node))
                .await
                .expect("no lookup fails")
                .into_iter()
                .map(|link| (link.zpr_addr, link.peer.map(SocketAddr::from)))
                .collect()
        }

        /// The relay's topology names a joiner that policy gives no address and that
        /// has not connected yet, with `peer` unset: the relay never dials it, and must
        /// know the joiner's CN before the joiner connects (J2).
        #[tokio::test]
        async fn a_relay_link_to_an_unaddressed_unconnected_joiner_has_no_peer() {
            let (asm, _db) = build().await;
            let relay = links_of(&asm, R).await;
            assert_eq!(relay.get(&ip(A)), Some(&None), "{relay:?}");
            assert_eq!(relay.get(&ip(B)), Some(&None), "{relay:?}");
        }

        /// Once the joiner connects, the relay's link to it names its reported address,
        /// and the joiner's link to the relay names the relay's policy address.
        #[tokio::test]
        async fn a_relay_link_names_the_joiners_reported_address_once_it_connects() {
            let (asm, _db) = build().await;
            connect(&asm, A, "192.0.2.10:7000").await;
            assert_eq!(
                links_of(&asm, R).await.get(&ip(A)),
                Some(&Some(sa("192.0.2.10:7000")))
            );
            assert_eq!(
                links_of(&asm, A).await.get(&ip(R)),
                Some(&Some(sa("[fd5a:5052:3000::1]:7000")))
            );
        }

        /// A direct link (neither end is the relay) with one end's address unknown is
        /// proposed to neither end: no Zode is asked to dial a link it cannot make.
        #[tokio::test]
        async fn a_direct_link_with_one_end_unknown_is_left_out_at_both_ends() {
            let (asm, _db) = build().await;
            connect(&asm, A, "192.0.2.10:7000").await;
            let a = links_of(&asm, A).await;
            assert!(!a.contains_key(&ip(B)), "{a:?}");
            let b = links_of(&asm, B).await;
            assert!(!b.contains_key(&ip(A)), "{b:?}");
            assert!(b.contains_key(&ip(R)), "B's relay link stays: {b:?}");
        }

        /// A direct link with both ends' reported addresses known is proposed to both
        /// ends, each naming the other's address.
        #[tokio::test]
        async fn a_direct_link_with_both_ends_reported_names_the_other_end() {
            let (asm, _db) = build().await;
            connect(&asm, A, "192.0.2.10:7000").await;
            connect(&asm, B, "198.51.100.20:7001").await;
            assert_eq!(
                links_of(&asm, A).await.get(&ip(B)),
                Some(&Some(sa("198.51.100.20:7001")))
            );
            assert_eq!(
                links_of(&asm, B).await.get(&ip(A)),
                Some(&Some(sa("192.0.2.10:7000")))
            );
        }

        /// A policy address is a known address with or without a session, and wins over
        /// a session's claim: links between policy-addressed nodes are unchanged.
        #[tokio::test]
        async fn a_policy_address_wins_and_needs_no_session() {
            let (asm, _db) = build().await;
            connect(&asm, C, "192.0.2.99:1").await;
            assert_eq!(
                links_of(&asm, R).await.get(&ip(C)),
                Some(&Some(sa("[fd5a:5052:3000::c]:7003")))
            );
            assert_eq!(
                links_of(&asm, C).await.get(&ip(D)),
                Some(&Some(sa("[fd5a:5052:3000::d]:7004")))
            );
            assert_eq!(
                links_of(&asm, D).await.get(&ip(C)),
                Some(&Some(sa("[fd5a:5052:3000::c]:7003")))
            );
        }

        /// A stored claim that names no dialable address (a bare IP from an adapter-path
        /// connect, an unspecified IP, port 0) is not a known address, and it does not
        /// fail the topology: the relay link is still proposed, with `peer` unset, and
        /// the direct link left out (visaservice#68 review, Copilot).
        #[tokio::test]
        async fn a_claim_that_is_not_a_dialable_address_is_unknown() {
            let (asm, _db) = build().await;
            connect(&asm, B, "198.51.100.20:7001").await;
            for claim in ["192.0.2.10", "0.0.0.0:7000", "192.0.2.10:0"] {
                connect(&asm, A, "192.0.2.10:7000").await;
                let mut actor = asm
                    .actor_mgr
                    .get_actor_by_zpr_addr(&ip(A))
                    .await
                    .unwrap()
                    .unwrap();
                actor
                    .add_attribute(
                        libeval::attribute::Attribute::builder(
                            libeval::attribute::key::SUBSTRATE_ADDR,
                        )
                        .value(claim),
                    )
                    .unwrap();
                asm.actor_mgr
                    .update_actor(&actor, &asm.policy_service_names())
                    .await
                    .unwrap();
                assert_eq!(links_of(&asm, R).await.get(&ip(A)), Some(&None), "{claim}");
                let b = links_of(&asm, B).await;
                assert!(!b.contains_key(&ip(A)), "{claim}: {b:?}");
            }
        }

        /// A session lookup that fails is an error, never a guessed or missing address:
        /// the send fails and the topology stays unsynced, so the worker retries it.
        #[tokio::test]
        async fn a_failed_lookup_fails_the_topology() {
            let (asm, db) = build().await;
            db.set_exists_fault(FaultMode::Reject);
            let psnap = asm.policy_mgr.get_current_snapshot();
            assert!(proposed_links(&asm, &psnap, &ip(R)).await.is_err());
        }
    }
}
