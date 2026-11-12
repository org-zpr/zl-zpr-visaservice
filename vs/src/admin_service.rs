//! HTTPS admin service implementation.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    Extension,
    Json,
    Router,
    //routing::post,
    extract::{Json as EJson, Path as EPath, Query, Request, State},
    //extract::Form,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    //response::Response,
    routing::{delete, get, post},
};

use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower_service::Service;

use zpr::policy_types::{NetAddr, NetworkHost, PolicyBundle, Scope};
use zpr::vsapi_types::{DockPepType, KeyFormat, KeySet, Visa};

use libeval::attribute::{Attribute, ROLE_NODE, key};
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use serde::Deserialize;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::admin_apikeys::Permission;
use crate::apikey::ApiKey;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::db::Role;
use crate::error::ServiceError;
use crate::event_mgr::VsEvent;
use crate::logging::targets::ADMIN;
use crate::policy_mgr::DEFAULT_POLICY_ID;
use crate::visa_mgr::VisaMgr;

use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use admin_api_types::{
    ActorDescriptor, ActorEntry, ApiAttribute, ApiKeyFormat, ApiKeySet, AuthRevokeDescriptor,
    AuthRevokeResult, ConnectionType, DenyRecord, HostDescriptor, ListEntry, NamedListEntry,
    NetworkDetails, NodeConnection, NodeRecordBrief, Revokes, ServiceDescriptor, Stats,
    VisaDescriptor,
};

// Must use tokio RwLock here becuase we need state to be Send.
type SharedState = Arc<tokio::sync::RwLock<AdminState>>;

#[allow(dead_code)]
struct AdminState {
    asm: Arc<Assembly>,
}

#[derive(Deserialize, Debug)]
struct RoleFilter {
    role: Option<ActorRole>,
}

/// Query args for `GET /admin/visas/denies`. `since` is epoch milliseconds.
#[derive(Deserialize, Debug)]
struct DenyFilter {
    since: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ActorRole {
    Node,
    Adapter,
}

struct ProtocolDetails {
    /// Human readable protocol name, e.g. "TCP", "UDP", "ICMP"
    protocol: String,
    source_port: Option<u16>,
    dest_port: Option<u16>,
}

/// Blocking start of the admin server.
/// TODO: Do I need a handle or something to stop this cleanly?
pub async fn start_admin_server(
    key_file: &Path,
    cert_file: &Path,
    listen: SocketAddr,
    asm: &Arc<Assembly>,
) {
    debug!(target: ADMIN, "admin service starting");
    let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
    serve(
        rustls_tls_acceptor(key_file, cert_file),
        listen,
        shared_state,
    )
    .await;
}

impl AdminState {
    pub fn new(asm: Arc<Assembly>) -> Self {
        AdminState { asm }
    }
}

fn rustls_tls_acceptor(key_file: &Path, cert_file: &Path) -> TlsAcceptor {
    let cert_pem = std::fs::read(cert_file).expect("failed to read admin cert file");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("failed to parse admin cert PEM");

    let key_pem = std::fs::read(key_file).expect("failed to read admin key file");
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse admin key PEM")
        .expect("no private key found in admin key file");

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("failed to build rustls ServerConfig");

    TlsAcceptor::from(Arc::new(cfg))
}

/// Check the passed API key. Returns the key's permission level and, for
/// notify keys (zipline#79), its bound trusted-service id.
async fn validate_api_key(
    state: &SharedState,
    api_key: &str,
) -> Result<(Permission, Option<String>), StatusCode> {
    let rstate = state.read().await;

    let apikey = ApiKey::parse(api_key).map_err(|_| StatusCode::UNAUTHORIZED)?;

    match rstate
        .asm
        .admin_api_keys
        .lookup_permission_and_service(&apikey)
    {
        Ok(Some((perm, service))) => Ok((perm, service)),
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            error!(target: ADMIN, "error validating API key {}: {}", apikey.key_id_hex(), e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The service binding of the presented API key (zipline#79): `Some(id)` for a
/// notify key, `None` otherwise. Inserted by [require_api_key] beside the
/// [Permission] extension; only the notification endpoint reads it.
#[derive(Clone)]
struct ApiKeyServiceBinding(Option<String>);

// Check the API key and if all good inserts a Permission (and the key's
// service binding) as request extensions.
async fn require_api_key(
    State(state): State<SharedState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|hv| hv.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // TODO: Add exponential backoff on unauthorizied requests.

    let (perm, service) = validate_api_key(&state, api_key).await?;
    req.extensions_mut().insert(perm);
    req.extensions_mut().insert(ApiKeyServiceBinding(service));
    Ok(next.run(req).await)
}

fn admin_app(state: SharedState) -> Router {
    Router::new()
        .route("/admin/policies", get(get_policies))
        .route("/admin/policies/{capture}", get(get_policy))
        .route("/admin/policies/curr", get(get_curr_policy))
        .route("/admin/policies", post(install_policy))
        .route("/admin/visas", get(get_visas).with_state(state.clone()))
        .route("/admin/visas/denies", get(get_denies))
        .route("/admin/visas/{capture}", get(get_visa))
        .route("/admin/visas/{capture}", delete(revoke_visa))
        .route("/admin/actors", get(get_actors).with_state(state.clone()))
        .route("/admin/actors/{capture}", get(get_actor))
        .route("/admin/actors/{capture}/visas", get(get_related_visas))
        .route("/admin/actors/{capture}", delete(revoke_actor))
        .route("/admin/nodes/{capture}/visas", get(get_visas_on_node))
        .route("/admin/services", get(get_services))
        .route("/admin/services/{capture}", get(get_service))
        .route(
            "/admin/services/{capture}/cache",
            delete(flush_service_cache),
        )
        .route(
            "/admin/services/{capture}/changed",
            post(service_changed).with_state(state.clone()),
        )
        .route("/admin/hosts/{capture}", get(get_host))
        .route("/admin/authrevoke", get(get_revokes))
        .route("/admin/authrevoke/{capture}", get(get_revoke))
        .route("/admin/authrevoke/{capture}", post(add_revoke))
        .route("/admin/authrevoke/clear", post(clear_revokes))
        .route("/admin/authrevoke/{capture}", delete(remove_revoke))
        .route("/admin/network", get(get_network))
        .route("/admin/stats", get(get_stats))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .with_state(state.clone())
}

async fn serve(tls_acceptor: TlsAcceptor, listen: SocketAddr, state: SharedState) {
    let app = admin_app(state);
    let listener = TcpListener::bind(listen).await.unwrap_or_else(|e| {
        panic!("failed to bind admin https listener on {listen}: {e}");
    });
    info!(target: ADMIN, "admin https service listening on {listen} (TLS)");

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();
        let (cnx, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // Exponential backoff saved for later.
                error!(target: ADMIN, "admin accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        tokio::spawn(async move {
            let stream = match tls_acceptor.accept(cnx).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!(target: ADMIN, "error during TLS handshake from {addr}, Error {e}");
                    return;
                }
            };

            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
                tower_service.clone().call(req)
            });

            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(e) = ret {
                warn!(target: ADMIN, "error serving admin connection from {addr}: {}", e);
            }
        });
    }
}

/// TODO: Placeholder - Only returns ID(0) which is for the current policy.
async fn get_policies(
    Extension(perm): Extension<Permission>,
) -> Result<Json<ListEntry>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies");
    let le = ListEntry {
        id: DEFAULT_POLICY_ID,
    };
    Ok(Json(le))
}

/// TODO: Handle multiple policies. Right now only accepts ID(0).
async fn get_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(id): EPath<u64>,
) -> Result<Json<PolicyBundle>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies/{id}");
    get_policy_by_id(&state.read().await.asm, id).await
}

async fn get_curr_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<PolicyBundle>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/policies/curr");
    get_policy_by_id(&state.read().await.asm, DEFAULT_POLICY_ID).await
}

/// Helper function used by [get_policy] and [get_curr_policy].
async fn get_policy_by_id(asm: &Assembly, id: u64) -> Result<Json<PolicyBundle>, StatusCode> {
    if id != DEFAULT_POLICY_ID {
        return Err(StatusCode::NOT_FOUND);
    }

    let bundle = {
        let pmgr = &asm.policy_mgr;
        let container = pmgr.get_current_container();
        match PolicyBundle::new_from_policy_container(0, container) {
            Ok(pb) => pb,
            Err(e) => {
                error!(target: ADMIN, "error creating policy bundle for policy {id}: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    };
    Ok(Json(bundle))
}

async fn install_policy(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EJson(body): EJson<PolicyBundle>,
) -> Result<Json<ListEntry>, StatusCode> {
    if !perm.can_write() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "POST /admin/policies");

    let container_bytes = body.decode().map_err(|e| {
        error!(target: ADMIN, "error decoding policy bundle: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let rstate = state.read().await;
    match rstate
        .asm
        .policy_mgr
        .update_policy_from_container_bytes(container_bytes)
        .await
    {
        Ok(vinst) => {
            info!(target: ADMIN, "policy updated successfully, new vinst={vinst}");
            // fire event!
            let evt = VsEvent::PolicyUpdated(vinst);
            if let Err(e) = rstate.asm.event_mgr.record_event(evt).await {
                warn!(target: ADMIN, "failed to record policy updated event: {}", e);
            }
        }
        Err(e) => {
            error!(target: ADMIN, "failed to update policy: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    drop(rstate);

    // what do we use as the policy identifier?
    // In the future maybe it will be possible to add policies to system without activating them.
    // In delegating model we mave have several policies installed for different domains.
    // For now we punt on this and just use identifier 0.
    let le = ListEntry {
        id: DEFAULT_POLICY_ID,
    };
    Ok(Json(le))
}

/// Returns a list of visa IDs in ListEntry structs or empty list.
async fn get_visas(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/visas");
    let rstate = state.read().await;

    // TODO: The API does not include details on how to do pagination.
    match rstate.asm.visa_mgr.list_all_visa_ids().await {
        Err(e) => {
            error!(target: ADMIN, "error listing visa IDs: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            );
        }
        Ok(visa_ids) => {
            let le_list: Vec<ListEntry> = visa_ids.into_iter().map(|id| ListEntry { id }).collect();
            return (StatusCode::OK, Json(le_list));
        }
    }
}

/// Returns the recent-denies window, newest request first, optionally filtered
/// by `since` (epoch milliseconds, inclusive) and capped by `limit`.
async fn get_denies(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    Query(q): Query<DenyFilter>,
) -> (StatusCode, Json<Vec<DenyRecord>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<DenyRecord>::new()));
    }
    debug!(target: ADMIN, "GET /admin/visas/denies since={:?} limit={:?}", q.since, q.limit);
    let rstate = state.read().await;

    let records = rstate
        .asm
        .deny_log
        .recent(q.since, q.limit)
        .into_iter()
        .map(|e| DenyRecord {
            source_addr: e.source_addr,
            dest_addr: e.dest_addr,
            protocol: e.protocol,
            dest_port: e.dest_port,
            count: e.count,
            last_deny_ms: e.last_deny_ms,
            deny_code: e.deny_code,
        })
        .collect();

    (StatusCode::OK, Json(records))
}

async fn get_visa(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(id): EPath<u64>,
) -> Result<Json<VisaDescriptor>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/visas/{}", id);
    let rstate = state.read().await;

    match rstate.asm.visa_mgr.get_visa_with_metadata_by_id(id).await {
        Err(e) => {
            error!(target: ADMIN, "error getting visa {}: {}", id, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(opt_visa_and_md) => match opt_visa_and_md {
            None => Err(StatusCode::NOT_FOUND),
            Some(visa_and_md) => {
                let visa = &visa_and_md.visa;
                let metadata = &visa_and_md.metadata;
                let proto_deets = protocol_details_for_visa(visa);

                let vd = VisaDescriptor {
                    id: visa.issuer_id,
                    expires: visa.expires,
                    created: metadata.ctime,
                    requesting_node: metadata.requesting_node.to_string(),
                    policy_id: metadata.policy_version.to_string(),
                    zpl: metadata.zpl.to_string(),
                    direction: match metadata.direction {
                        libeval::eval_result::Direction::Forward => {
                            admin_api_types::VisaMatchDirection::Forward
                        }
                        libeval::eval_result::Direction::Reverse => {
                            admin_api_types::VisaMatchDirection::Reverse
                        }
                    },
                    source_addr: if let Some(ref dock_pep) = visa.dock_pep {
                        Some(dock_pep.source_addr.to_string())
                    } else {
                        None
                    },
                    dest_addr: if let Some(ref dock_pep) = visa.dock_pep {
                        Some(dock_pep.dest_addr.to_string())
                    } else {
                        None
                    },
                    source_port: proto_deets.source_port,
                    dest_port: proto_deets.dest_port,
                    proto: proto_deets.protocol,
                    signals: metadata.signal_msgs.clone(),
                    session_key: if let Some(ref dock_pep) = visa.dock_pep {
                        to_api_keyset(&dock_pep.session_key)
                    } else {
                        ApiKeySet::default()
                    },
                };
                return Ok(Json(vd));
            }
        },
    }
}

fn protocol_details_for_visa(visa: &Visa) -> ProtocolDetails {
    if visa.dock_pep.is_none() {
        return ProtocolDetails {
            protocol: "N/A".to_string(),
            source_port: None,
            dest_port: None,
        };
    }
    let (proto_name, source_port, dest_port) = match &visa.dock_pep.as_ref().unwrap().pep {
        DockPepType::ICMP(icmp_pep) => (
            "ICMP".to_string(),
            Some(icmp_pep.icmp_type as u16),
            Some(icmp_pep.icmp_code as u16),
        ),
        DockPepType::UDP(tu_pep) => (
            "UDP".to_string(),
            Some(tu_pep.source_port),
            Some(tu_pep.dest_port),
        ),
        DockPepType::TCP(tu_pep) => (
            "TCP".to_string(),
            Some(tu_pep.source_port),
            Some(tu_pep.dest_port),
        ),
    };

    ProtocolDetails {
        protocol: proto_name,
        source_port,
        dest_port,
    }
}

async fn revoke_visa(EPath(id): EPath<u64>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/visas/{}", id);
    let r = Revokes {
        id: id.to_string(),
        revoked: vec![0],
    };

    (StatusCode::OK, Json(r)).into_response()
}

/// Returns the connected actors as ActorEntry structs (ZPR address plus optional
/// CN display label) or an empty list.
async fn get_actors(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    Query(q): Query<RoleFilter>,
) -> (StatusCode, Json<Vec<ActorEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ActorEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/actors {:?}", q);
    let db_filter = match q.role {
        Some(ActorRole::Node) => Some(Role::Node),
        Some(ActorRole::Adapter) => Some(Role::Adapter),
        None => None,
    };

    let rstate = state.read().await;
    match rstate.asm.actor_mgr.list_actors(db_filter).await {
        Err(e) => {
            error!(target: ADMIN, "error listing connected actors: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ActorEntry>::new()),
            )
        }
        Ok(actors) => {
            let entries: Vec<ActorEntry> = actors
                .into_iter()
                .map(|(addr, cn)| ActorEntry {
                    zpr_addr: addr.to_string(),
                    cn,
                })
                .collect();
            (StatusCode::OK, Json(entries))
        }
    }
}

async fn get_actor(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(addr): EPath<String>,
) -> Result<Json<ActorDescriptor>, StatusCode> {
    debug!(target: ADMIN, "GET /admin/actors/{}", addr);
    let rstate = state.read().await;
    let asm = rstate.asm.clone();
    drop(rstate);

    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    // The path segment is a ZPR address; a malformed one is a bad request, not a miss.
    let zpr_addr = IpAddr::from_str(&addr).map_err(|_| StatusCode::BAD_REQUEST)?;

    match asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(opt_a) => match opt_a {
            None => Err(StatusCode::NOT_FOUND),
            Some(actor) => {
                let ident = match actor.get_identity() {
                    Some(id) => id.join("|"),
                    None => "".to_string(),
                };

                let is_node = match actor.get_attribute(key::ROLE) {
                    Some(role_attr) => {
                        if let Ok(role_val) = role_attr.get_single_value() {
                            role_val == ROLE_NODE
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                let zpr_addr_str = match actor.get_zpr_addr() {
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                };

                let attrs = actor.attrs_iter().map(|a| to_api_attribute(a)).collect();

                let auth_exp = actor.get_authentication_expiration();

                let node_details = match is_node {
                    true => Some(build_node_record_brief(&asm, &actor).await?),
                    false => None,
                };

                // Display data (zipline#54): refused hostname claims, read from
                // the field #53 writes. Missing or unreadable is empty, never
                // an error.
                let hostname_conflicts = asm
                    .actor_mgr
                    .get_hostname_conflicts(&zpr_addr)
                    .await
                    .unwrap_or_default();

                let descriptor = ActorDescriptor {
                    // The path no longer carries a name: the CN comes from the
                    // actor record itself, and may legitimately be absent.
                    cn: actor.get_cn().map(str::to_string),
                    ctime: SystemTime::UNIX_EPOCH, // TODO: Not tracked yet
                    ident,
                    node: is_node,
                    zpr_addr: zpr_addr_str,
                    attrs,
                    auth_exp,
                    node_details,
                    hostname_conflicts,
                };
                return Ok(Json(descriptor));
            }
        },
    }
}

async fn build_node_record_brief(
    asm: &Assembly,
    actor: &libeval::actor::Actor,
) -> Result<NodeRecordBrief, StatusCode> {
    let counters = asm.counters.clone();
    let actor_mgr = asm.actor_mgr.clone();
    let visa_mgr = &asm.visa_mgr;
    let topo_mgr = &asm.topo_mgr;

    let zpr_addr = match actor.get_zpr_addr() {
        Some(addr) => addr,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let pending_install = visa_mgr
        .get_num_pending_install_visas(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let last_contact = actor_mgr
        .get_node_last_seen(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let visa_requests = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequests)
        .unwrap_or(0);
    let approved_vreqs = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequestsApproved)
        .unwrap_or(0);
    let denied_vreqs = counters
        .get_node_counter(zpr_addr, CounterType::VisaRequestsDenied)
        .unwrap_or(0);
    let last_vreq = counters.get_last_request_time(zpr_addr);
    let adapters = actor_mgr
        .get_adapters_connected_to_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(|addr| addr.to_string())
        .collect();
    let links: Vec<String> = topo_mgr
        .get_peers(zpr_addr)
        .into_iter()
        .map(|addr| addr.to_string())
        .collect();
    let visas = visa_mgr
        .get_installed_visa_ids_for_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let visas_enqueued = visa_mgr
        .get_pending_visa_ids_for_node(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pending_revocation = visa_mgr
        .get_num_pending_revoked_visas(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // vss_port comes from the node DB VSS record, which outlives the worker
    // (ping uses it to start a new one). in_sync comes from the live worker
    // map, so an exited worker reads false (zipline#187).
    let vss_port = actor_mgr
        .get_node_vss(zpr_addr)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(|socket_addr| socket_addr.port());
    let in_sync = asm.vss_mgr.has_live_worker(zpr_addr);

    Ok(NodeRecordBrief {
        pending_install,
        last_contact,
        visa_requests,
        connect_requests: 0, // TODO blocked on tracking calls to authorize_connect
        in_sync,
        approved_vreqs,
        denied_vreqs,
        last_vreq,
        adapters,
        links,
        visas,
        visas_enqueued,
        pending_revocation,
        vss_port,
    })
}

/// DELETE /admin/actors/{addr} -- validation-only placeholder, no side effect.
/// Parses the address (400 malformed), confirms the actor exists (404 unknown),
/// and returns a fixed Revokes value; it does NOT kick, disconnect, or otherwise
/// touch the actor's live session or credential. Kicking the live session is the
/// intended behavior once implemented (credential revocation stays
/// /admin/authrevoke).
async fn revoke_actor(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(addr): EPath<String>,
) -> Result<Json<Revokes>, StatusCode> {
    if !perm.can_write() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "DELETE /admin/actors/{}", addr);

    let zpr_addr = IpAddr::from_str(&addr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let rstate = state.read().await;
    match rstate.asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Ok(Some(_)) => {}
    }

    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0, 1, 2],
    };
    Ok(Json(r))
}

/// Parse and resolve a ZPR-address path segment, returning the address and a cloned
/// (Arc-backed) visa manager, releasing the state read-lock before returning so callers
/// can do longer work without blocking writers. A malformed address is `BAD_REQUEST`;
/// an unknown one is `NOT_FOUND`. When `require_node` is set, non-node actors are
/// rejected with `BAD_REQUEST`.
async fn resolve_actor_addr(
    state: &SharedState,
    addr: &str,
    require_node: bool,
) -> Result<(IpAddr, VisaMgr), StatusCode> {
    let zpr_addr = IpAddr::from_str(addr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let rstate = state.read().await;

    let actor = match rstate.asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
        Err(e) => {
            error!(target: ADMIN, "error getting actor at {}: {}", zpr_addr, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Ok(Some(actor)) => actor,
    };

    if require_node && !actor.is_node() {
        warn!(target: ADMIN, "actor at {} is not a node", zpr_addr);
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok((zpr_addr, rstate.asm.visa_mgr.clone()))
}

/// List of visa IDs
async fn get_related_visas(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(addr): EPath<String>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/actors/{}/visas", addr);

    let (actor_addr, visa_mgr) = match resolve_actor_addr(&state, &addr, false).await {
        Ok(pair) => pair,
        Err(code) => return (code, Json(Vec::<ListEntry>::new())),
    };

    match visa_mgr.get_visa_ids_for_actors(&[actor_addr]).await {
        Ok(ids) => (
            StatusCode::OK,
            Json(ids.into_iter().map(|id| ListEntry { id }).collect()),
        ),
        Err(e) => {
            error!(target: ADMIN, "get_visa_ids_for_actors failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            )
        }
    }
}

/// List of visa IDs
async fn get_visas_on_node(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(addr): EPath<String>,
) -> (StatusCode, Json<Vec<ListEntry>>) {
    if !perm.can_read() {
        return (StatusCode::FORBIDDEN, Json(Vec::<ListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/nodes/{}/visas", addr);

    let (actor_addr, visa_mgr) = match resolve_actor_addr(&state, &addr, true).await {
        Ok(pair) => pair,
        Err(code) => return (code, Json(Vec::<ListEntry>::new())),
    };

    let visa_ids = match visa_mgr.get_installed_visa_ids_for_node(&actor_addr).await {
        Ok(ids) => ids,
        Err(e) => {
            error!(target: ADMIN, "get_installed_visa_ids_for_node failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            );
        }
    };
    let related_visas: Vec<ListEntry> = visa_ids.into_iter().map(|id| ListEntry { id }).collect();
    (StatusCode::OK, Json(related_visas))
}

async fn get_services(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> (StatusCode, Json<Vec<NamedListEntry>>) {
    if !perm.can_resolve() {
        return (StatusCode::FORBIDDEN, Json(Vec::<NamedListEntry>::new()));
    }
    debug!(target: ADMIN, "GET /admin/services");
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_services_list().await {
        Err(e) => {
            error!(target: ADMIN, "error listing services: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<NamedListEntry>::new()),
            )
        }
        Ok(services) => {
            let sle_list: Vec<NamedListEntry> = services
                .into_iter()
                .map(|se| NamedListEntry { id: se.name })
                .collect();
            (StatusCode::OK, Json(sle_list))
        }
    }
}

async fn get_service(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(svc_name): EPath<String>,
) -> Result<Json<ServiceDescriptor>, StatusCode> {
    if !perm.can_resolve() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/service name={}", svc_name);
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_service_detail(&svc_name).await {
        Err(e) => {
            error!(target: ADMIN, "error getting service detail for service {}: {}", svc_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(opt_detail) => {
            if let Some(detail) = opt_detail {
                let connect_via = match detail.connect_via.as_ref() {
                    Some(cv_addr) => cv_addr.to_string(),
                    None => "".to_string(),
                };
                let cp = rstate.asm.policy_mgr.get_current();

                let (svc_kind, svc_endpoints) = if let Some(psvc) = cp.service_by_id(&svc_name) {
                    (
                        format!("{:?}", psvc.kind),
                        service_endpoints_to_string(&psvc.endpoints),
                    )
                } else {
                    ("".to_string(), "".to_string())
                };

                let sd = ServiceDescriptor {
                    service_name: detail.service_name,
                    zpr_addr: detail.zpr_addr.to_string(),
                    actor_cn: detail.actor_cn,
                    dock_zpr_addr: connect_via,
                    service_kind: svc_kind,
                    service_endpoints: svc_endpoints,
                };
                Ok(Json(sd))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
    }
}

/// GET /admin/hosts/{name} — resolve one claimed hostname to its holder
/// (zipline#54). Gated by the existing `can_resolve()`, alongside the two
/// service-resolution endpoints — a `resolve` key reaches exactly these three.
/// The lookup goes through the same `host:<NAME>` index the claim side writes
/// (zipline#53), so query-side spelling matches claim-side exactly: no
/// mangling of the caller's input. An unclaimed or invalid name is the same
/// "not in the index" 404 — no new error surface.
async fn get_host(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(host_name): EPath<String>,
) -> Result<Json<HostDescriptor>, StatusCode> {
    if !perm.can_resolve() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/hosts name={}", host_name);
    let rstate = state.read().await;

    let addr = match rstate
        .asm
        .actor_mgr
        .get_zpr_addr_for_hostname(&host_name)
        .await
    {
        Err(e) => {
            error!(target: ADMIN, "error resolving hostname {}: {}", host_name, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Ok(Some(addr)) => addr,
    };

    // A hit in the hostname index whose holder no longer loads is a departing
    // actor observed mid-`clean_up`: the base record is deleted before the
    // `host:<NAME>` entries are released (see `ActorRepo::clean_up`), so the
    // index can briefly name a holder that is already gone. That window is a
    // miss — same 404 as an unclaimed name — never a 200 carrying a dead ZPR
    // address. A *present* actor's CN is a display label and may legitimately
    // be absent; only that case yields an empty `actor_cn`.
    let actor_cn = match rstate.asm.actor_mgr.get_actor_by_zpr_addr(&addr).await {
        Err(e) => {
            error!(target: ADMIN, "error loading actor {} for hostname {}: {}", addr, host_name, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Ok(Some(a)) => a.get_cn().map(str::to_string).unwrap_or_default(),
    };

    Ok(Json(HostDescriptor {
        hostname: host_name,
        zpr_addr: addr.to_string(),
        actor_cn,
    }))
}

/// DELETE /admin/services/{id}/cache — reload a trusted service's attribute data and
/// reconcile against it: the actors behind live visas are refreshed and their visas
/// re-checked, so no visa keeps relying on the old data.
///
/// The reload is synchronous (its failure is reported to the caller); the reconciliation
/// runs on the event worker, so success returns `202 Accepted` and the outcome shows up
/// in the log rather than the response.
async fn flush_service_cache(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
    EPath(svc_id): EPath<String>,
) -> StatusCode {
    if !perm.can_write() {
        return StatusCode::FORBIDDEN;
    }
    debug!(target: ADMIN, "DELETE /admin/services/{}/cache", svc_id);

    // Clone the Arcs and drop the read guard before awaiting the flush.
    let (ts_mgr, event_mgr) = {
        let rstate = state.read().await;
        (rstate.asm.ts_mgr.clone(), rstate.asm.event_mgr.clone())
    };

    match ts_mgr.flush_one(&svc_id).await {
        Ok(()) => {
            // The flush itself is done. If the event cannot be queued we lose only the
            // sweep of existing visas -- new visa decisions are still protected by the
            // per-actor revision check. The event carries no source id (the reconcile
            // is unscoped), so name the source here where it is known.
            info!(target: ADMIN, "flushed trusted service {}, queueing revalidation", svc_id);
            if let Err(e) = event_mgr.record_event(VsEvent::TrustedServiceChange).await {
                error!(target: ADMIN, "flushed trusted service {} but could not queue revalidation: {}", svc_id, e);
            }
            StatusCode::ACCEPTED
        }
        Err(ServiceError::TrustedServiceNotFound(_)) => StatusCode::NOT_FOUND,
        Err(e) => {
            error!(target: ADMIN, "error flushing trusted service {}: {}", svc_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Request body of `POST /admin/services/{id}/changed` (zipline#79).
///
/// `{}` (no `identities` key) means "everything changed". A present
/// `identities` list targets the connected actors carrying any listed
/// identity pair. Unknown fields are rejected: a misspelled `identities`
/// silently meaning "flush everything" would be a nasty surprise.
///
/// The double `Option` distinguishes an absent field (outer `None` via
/// `#[serde(default)]`) from an explicit `"identities": null` (outer `Some`,
/// inner `None`) — the documented full-change form is an ABSENT field, so an
/// explicit null is malformed and must be 400, not a global flush (PR #29
/// review, P2).
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ServiceChangedBody {
    #[serde(default, deserialize_with = "deserialize_some")]
    identities: Option<Option<Vec<HashMap<String, String>>>>,
}

/// Wrap any present value in `Some`, so `#[serde(default)]` (outer `None`) is
/// reached only when the field is absent and an explicit `null` becomes
/// `Some(None)`. The standard serde double-Option pattern.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// POST /admin/services/{id}/changed — a trusted service reports that its data
/// changed (zipline#79, spec ATTRIBUTE_SERVICE.md contract 4).
///
/// Body `{}`: everything changed — same effect as `DELETE .../cache`
/// ([flush_service_cache]): reload the service and queue the reconcile.
///
/// Body `{"identities": [{"<zpr key>": "<value>"}, ...]}`: only the actors
/// carrying a listed identity pair changed — forget those actors' recorded
/// revision for this source ([crate::trusted_services::TrustedServicesMgr::forget_source_revision])
/// and queue the reconcile; the service's own snapshot is NOT flushed (an
/// attribute service pushing a notification vends current data already).
///
/// Auth: `can_notify()` (notify and readwrite). A notify key is bound to one
/// service id; a mismatch is 403 checked BEFORE the 404 existence check, so a
/// bound key cannot probe which ids exist.
async fn service_changed(
    Extension(perm): Extension<Permission>,
    Extension(binding): Extension<ApiKeyServiceBinding>,
    State(state): State<SharedState>,
    EPath(svc_id): EPath<String>,
    body: axum::body::Bytes,
) -> StatusCode {
    if !perm.can_notify() {
        return StatusCode::FORBIDDEN;
    }
    // The notify key's service binding gates BEFORE existence: a key bound to
    // `a` posting to any other id — real or not — sees the same 403.
    if perm == Permission::Notify && binding.0.as_deref() != Some(svc_id.as_str()) {
        return StatusCode::FORBIDDEN;
    }
    debug!(target: ADMIN, "POST /admin/services/{}/changed", svc_id);

    let body: ServiceChangedBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            debug!(target: ADMIN, "malformed change notification for {}: {}", svc_id, e);
            return StatusCode::BAD_REQUEST;
        }
    };
    let identities = match body.identities {
        // Absent field: the documented "everything changed" form.
        None => None,
        // Explicit `"identities": null` is malformed (PR #29 review, P2): the
        // full-change form is an ABSENT field, and a client emitting null for
        // an unavailable target list must not trigger a global flush.
        Some(None) => {
            debug!(target: ADMIN, "explicit null identities in change notification for {}", svc_id);
            return StatusCode::BAD_REQUEST;
        }
        Some(Some(identities)) => {
            // An empty identity object matches nothing it could mean; reject it
            // rather than guess.
            if identities.iter().any(|pairs| pairs.is_empty()) {
                return StatusCode::BAD_REQUEST;
            }
            Some(identities)
        }
    };

    // Clone the Arcs and drop the read guard before awaiting.
    let (ts_mgr, event_mgr, actor_mgr) = {
        let rstate = state.read().await;
        (
            rstate.asm.ts_mgr.clone(),
            rstate.asm.event_mgr.clone(),
            rstate.asm.actor_mgr.clone(),
        )
    };

    if !ts_mgr.has_source(&svc_id) {
        return StatusCode::NOT_FOUND;
    }

    match identities {
        // "Everything changed": same effect as DELETE .../cache.
        None => match ts_mgr.flush_one(&svc_id).await {
            Ok(()) => {
                info!(target: ADMIN, "trusted service {} reported change, flushed, queueing revalidation", svc_id);
            }
            Err(ServiceError::TrustedServiceNotFound(_)) => return StatusCode::NOT_FOUND,
            Err(e) => {
                error!(target: ADMIN, "error flushing trusted service {}: {}", svc_id, e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        },
        // Targeted: forget the revision for each connected actor carrying a
        // listed pair, so the reconcile re-queries exactly those actors.
        Some(identities) => {
            let actors = match actor_mgr.list_actors(None).await {
                Ok(actors) => actors,
                Err(e) => {
                    error!(target: ADMIN, "error listing actors for change notification: {}", e);
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            };
            let mut forgotten = 0usize;
            for (zpr_addr, _cn) in actors {
                let actor = match actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
                    Ok(Some(actor)) => actor,
                    // Departed mid-listing, or a load error: skip — a missed
                    // actor stays lazily protected by the TTL refresh.
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(target: ADMIN, "error loading actor {} for change notification: {}", zpr_addr, e);
                        continue;
                    }
                };
                // The actor "carries" a listed pair when its stored attributes
                // contain that exact key=value.
                let carries = actor.attrs_iter().any(|attr| {
                    identities.iter().any(|pairs| {
                        pairs
                            .get(attr.get_key())
                            .is_some_and(|v| attr.get_value().iter().any(|av| av == v))
                    })
                });
                if carries {
                    ts_mgr.forget_source_revision(&zpr_addr, &svc_id);
                    forgotten += 1;
                }
            }
            info!(
                target: ADMIN,
                "trusted service {} reported change for {} identity pair(s); {} actor(s) marked stale, queueing revalidation",
                svc_id,
                identities.len(),
                forgotten
            );
        }
    }

    // Same failure posture as flush_service_cache: losing the event loses only
    // the sweep of existing visas; new decisions still hit the revision check.
    if let Err(e) = event_mgr.record_event(VsEvent::TrustedServiceChange).await {
        error!(target: ADMIN, "trusted service {} change recorded but could not queue revalidation: {}", svc_id, e);
    }
    StatusCode::ACCEPTED
}

fn service_endpoints_to_string(endpoints: &[Scope]) -> String {
    let mut ep_strs: Vec<String> = Vec::new();
    for ep in endpoints {
        let port_str = if let Some(port) = ep.port {
            port.to_string()
        } else if let Some(port_range) = ep.port_range {
            format!("{}-{}", port_range.0, port_range.1)
        } else {
            "".to_string()
        };
        match ep.protocol {
            ip_proto::TCP => ep_strs.push(format!("TCP/{}", port_str)),
            ip_proto::UDP => ep_strs.push(format!("UDP/{}", port_str)),
            ip_proto::ICMP => ep_strs.push(format!("ICMP/{}", port_str)),
            ip_proto::IPV6_ICMP => ep_strs.push(format!("IPV6_ICMP/{}", port_str)),
            _ => ep_strs.push(format!("PROTO_{}/{}", ep.protocol, port_str)),
        }
    }
    ep_strs.join(",")
}

/// GET /admin/authrevoke (zipline#136): the bootstrap-key denylist as
/// `ListEntry` ids, ascending. Resolve an id with GET /admin/authrevoke/{id}.
async fn get_revokes(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
) -> impl IntoResponse {
    if !perm.can_read() {
        return StatusCode::FORBIDDEN.into_response();
    }
    debug!(target: ADMIN, "GET /admin/authrevoke");
    let asm = state.read().await.asm.clone();
    match crate::db::BootstrapDenylist::new(asm.state_db.clone())
        .list()
        .await
    {
        Ok(mut entries) => {
            entries.sort();
            let list: Vec<ListEntry> = entries
                .into_iter()
                .map(|(id, _cn)| ListEntry { id })
                .collect();
            (StatusCode::OK, Json(list)).into_response()
        }
        Err(e) => {
            error!(target: ADMIN, "failed to list the bootstrap denylist: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /admin/authrevoke/{id} (zipline#136): the descriptor behind one
/// denylist entry. 400 for a non-numeric id, 404 for an unknown one.
async fn get_revoke(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(id): EPath<String>,
) -> impl IntoResponse {
    if !perm.can_read() {
        return StatusCode::FORBIDDEN.into_response();
    }
    debug!(target: ADMIN, "GET /admin/authrevoke/{}", id);
    let Ok(id) = id.parse::<u64>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let asm = state.read().await.asm.clone();
    match crate::db::BootstrapDenylist::new(asm.state_db.clone())
        .cn_by_id(id)
        .await
    {
        Ok(Some(cn)) => (
            StatusCode::OK,
            Json(AuthRevokeDescriptor {
                ty: AUTHREVOKE_TYPE_BOOTSTRAP.to_string(),
                cn,
            }),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(target: ADMIN, "failed to read the bootstrap denylist: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// POST /admin/authrevoke/clear (zipline#136): empty the denylist. Returns
/// the removed entries as `ListEntry` ids. Revoked keys become connectable
/// again wherever policy still carries them.
async fn clear_revokes(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
) -> impl IntoResponse {
    if !perm.can_write() {
        return StatusCode::FORBIDDEN.into_response();
    }
    debug!(target: ADMIN, "POST /admin/authrevoke/clear");
    let asm = state.read().await.asm.clone();
    let denylist = crate::db::BootstrapDenylist::new(asm.state_db.clone());
    let entries = match denylist.list().await {
        Ok(entries) => entries,
        Err(e) => {
            error!(target: ADMIN, "failed to list the bootstrap denylist: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if let Err(e) = denylist.clear().await {
        error!(target: ADMIN, "failed to clear the bootstrap denylist: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut removed: Vec<ListEntry> = entries
        .into_iter()
        .map(|(id, cn)| {
            info!(target: ADMIN, "bootstrap denylist cleared: cn {cn} may authenticate again");
            ListEntry { id }
        })
        .collect();
    removed.sort_by_key(|e| e.id);
    (StatusCode::OK, Json(removed)).into_response()
}

/// DELETE /admin/authrevoke/{id} (zipline#136): remove one denylist entry —
/// the explicit un-revocation. 400 for a non-numeric id, 404 for an unknown
/// one.
async fn remove_revoke(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(id): EPath<String>,
) -> impl IntoResponse {
    if !perm.can_write() {
        return StatusCode::FORBIDDEN.into_response();
    }
    debug!(target: ADMIN, "DELETE /admin/authrevoke/{}", id);
    let Ok(id) = id.parse::<u64>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let asm = state.read().await.asm.clone();
    match crate::db::BootstrapDenylist::new(asm.state_db.clone())
        .remove(id)
        .await
    {
        Ok(Some(cn)) => {
            info!(target: ADMIN, "bootstrap denylist entry {id} removed: cn {cn} may authenticate again");
            (StatusCode::OK, Json(ListEntry { id })).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(target: ADMIN, "failed to remove bootstrap denylist entry {id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The only `ty` the revocation surface accepts (zipline#136): the built-in
/// RSA bootstrap authentication root. Other roots (OIDC) are revoked at the
/// provider, not here.
const AUTHREVOKE_TYPE_BOOTSTRAP: &str = "bootstrap";

/// POST /admin/authrevoke/{cn} (zipline#136): revoke a bootstrap
/// authentication root. The CN goes on the persisted denylist — consulted by
/// the connect and SS-renewal paths, surviving policy installs until
/// explicitly removed — and every connected actor the key admitted is revoked
/// immediately through the zipline#123 pipeline: nodes are disconnected with
/// their docked adapters, adapters are revoked on their docking node and
/// removed on the positive ack. A revocation the node did not ack is retried
/// by the periodic sweep; the response lists only what was revoked now.
async fn add_revoke(
    State(state): State<SharedState>,
    Extension(perm): Extension<Permission>,
    EPath(cn): EPath<String>,
    body: axum::body::Bytes,
) -> Result<Json<AuthRevokeResult>, StatusCode> {
    if !perm.can_write() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "POST /admin/authrevoke/{}", cn);
    // Body parsed after the permission gate, so a bad body on a forbidden key
    // is still a 403 (matches the zipline#36 permission sweep).
    let desc: AuthRevokeDescriptor =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if desc.ty != AUTHREVOKE_TYPE_BOOTSTRAP {
        warn!(target: ADMIN, "authrevoke: unsupported credential type {:?}", desc.ty);
        return Err(StatusCode::BAD_REQUEST);
    }
    if desc.cn != cn {
        warn!(target: ADMIN, "authrevoke: body cn {:?} does not match path cn {:?}", desc.cn, cn);
        return Err(StatusCode::BAD_REQUEST);
    }

    let asm = state.read().await.asm.clone();
    let id = crate::db::BootstrapDenylist::new(asm.state_db.clone())
        .add(&cn)
        .await
        .map_err(|e| {
            error!(target: ADMIN, "failed to add {cn} to the bootstrap denylist: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    info!(target: ADMIN, "bootstrap key revoked for cn {cn} (denylist entry {id}); revoking admitted actors");

    // Enforce immediately — no policy install, no reauth_deadline wait. The
    // sweep covers every denylisted CN; report the actors revoked under THIS
    // one. Deferred entries (VSS outage) are retried by the periodic sweep.
    let stats = crate::auth_sweep::sweep_denylisted_actors(&asm).await;
    let revoked: Vec<String> = stats
        .revoked
        .into_iter()
        .filter(|(_, revoked_cn)| revoked_cn == &cn)
        .map(|(addr, _)| addr.to_string())
        .collect();
    Ok(Json(AuthRevokeResult {
        id,
        ty: AUTHREVOKE_TYPE_BOOTSTRAP.to_string(),
        cn,
        revoked,
    }))
}

/// Stringify a substrate address as a parseable `host:port`. IPv6 hosts get bracketed
/// (`[fd5a:5052::1]:5000`); IPv4 and hostname forms are left plain. An address that policy
/// does not give (`None`: the node reports its own, zl-zipline#225) is the empty string,
/// which no parser of this API can mistake for an address.
fn stringify_netaddr(addr: Option<&NetAddr>) -> String {
    match addr {
        None => String::new(),
        Some(addr) => match &addr.host {
            NetworkHost::Ip(ip) => SocketAddr::new(*ip, addr.port).to_string(),
            NetworkHost::Hostname(h) => format!("{}:{}", h, addr.port),
        },
    }
}

async fn get_network(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<NetworkDetails>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }
    debug!(target: ADMIN, "GET /admin/network");
    let rstate = state.read().await;

    // Start with the desired topology setup, then we will mark which ones are up.

    // Only track link(a,b) once (ie, do not also store link(b,a)).
    let mut pairs = HashSet::new();

    let mut topo = Vec::new();
    let psnap = rstate.asm.policy_mgr.get_current_snapshot();

    for node_addr in psnap.policy().all_peered_nodes() {
        if let Some(peers) = psnap.policy().get_peers_for_node(node_addr) {
            for peer in peers {
                let pair_id = if node_addr < &peer.remote_zpr_addr {
                    (node_addr.clone(), peer.remote_zpr_addr.clone())
                } else {
                    (peer.remote_zpr_addr.clone(), node_addr.clone())
                };

                if pairs.contains(&pair_id) {
                    continue;
                }
                pairs.insert(pair_id);

                // Each peer has a link_id, remote_zpr_addr, and a remote_substrate NetAddr.
                // Ok so a desired link is node_addr to peer

                let mut bldr =
                    NodeConnection::builder(node_addr.clone(), peer.remote_zpr_addr.clone())
                        .link_id(peer.link_id.clone())
                        .node_a_substrate(stringify_netaddr(peer.local_substrate.as_ref()))
                        .node_b_substrate(stringify_netaddr(peer.remote_substrate.as_ref()));

                if let Ok(link_desc) = psnap
                    .policy()
                    .describe_link(node_addr, &peer.remote_zpr_addr)
                {
                    let api_attrs = link_desc
                        .attrs
                        .iter()
                        .map(to_api_attribute)
                        .collect::<Vec<ApiAttribute>>();

                    bldr = bldr.link_attrs(api_attrs).link_cost(link_desc.cost);
                }
                topo.push(bldr.build());
            }
        }
    }

    // Now we have constructed the ideal topology, lets see what we've actually got
    // starting with our connected nodes.

    let node_addrs = match rstate.asm.actor_mgr.list_node_addrs().await {
        Ok(addrs) => addrs,
        Err(e) => {
            error!(target: ADMIN, "Error {} getting node list", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Everything in topo so far is policy-declared, so only those entries can go UP.
    // Links appended past this point were reported by a node but never declared.
    let declared = topo.len();

    for node_addr in node_addrs {
        for peer_addr in rstate.asm.topo_mgr.get_peers(&node_addr) {
            // Ok we have node_addr <-> peer_addr, so update the node connection to UP
            // Or if it does not exist, insert it as INVALID.
            let mut matched = false;
            for (i, nc) in topo.iter_mut().enumerate() {
                if nc.is_link_between(&node_addr, &peer_addr) {
                    // A link that link-state reports put down stays in the router
                    // graph (zl-zipline#224) but is not UP.
                    if i < declared && rstate.asm.topo_mgr.link_up(&node_addr, &peer_addr) {
                        nc.set_status(ConnectionType::UP);
                    }
                    matched = true;
                }
            }
            if !matched {
                topo.push(
                    NodeConnection::builder(node_addr.clone(), peer_addr.clone())
                        .invalid()
                        .build(),
                );
            }
        }
    }

    Ok(Json(NetworkDetails { network: topo }))
}

async fn get_stats(
    Extension(perm): Extension<Permission>,
    State(state): State<SharedState>,
) -> Result<Json<Stats>, StatusCode> {
    if !perm.can_read() {
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(target: ADMIN, "GET /admin/stats");

    let mut stat_map = HashMap::new();

    let rstate = state.read().await;

    stat_map.insert(
        "uptime".to_string(),
        rstate.asm.get_uptime().as_secs().to_string(),
    );
    for (key, ref value) in &rstate.asm.counters.counters {
        stat_map.insert(key.name().to_string(), value.get_count().to_string());
    }

    Ok(Json(Stats { stats: stat_map }))
}

fn to_api_attribute(attr: &Attribute) -> ApiAttribute {
    ApiAttribute {
        key: attr.get_key().to_string(),
        value: attr.get_value().to_vec(),
        expires_at: attr.get_expires(),
    }
}

fn to_api_keyset(ks: &KeySet) -> ApiKeySet {
    ApiKeySet {
        format: to_api_keyformat(&ks.format),
        ingress_key: ks.ingress_key.clone(),
        egress_key: ks.egress_key.clone(),
    }
}

fn to_api_keyformat(kf: &KeyFormat) -> ApiKeyFormat {
    match kf {
        KeyFormat::ZprKF01 => ApiKeyFormat::ZprKF01,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Visa expiration used by the tests in this module.
    const DEFAULT_VISA_EXPIRATION: std::time::Duration =
        std::time::Duration::from_secs(4 * 60 * 60);

    use crate::apikey::ApiKey;
    use admin_api_types::VisaMatchDirection;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use libeval::eval_result::{Direction, Hit, Signal};
    use libeval::route::Route;
    use std::net::IpAddr;
    use tower::ServiceExt;
    use zpr::vsapi_types::{DenyCode, PacketDesc};

    use crate::admin_apikeys::{ApiKeyRecord, KeyStatus};
    use crate::assembly::tests::{new_assembly_for_tests, new_assembly_with_event_rx};
    use crate::test_helpers::{
        make_actor_with_services_defexp, make_adapter_actor_defexp, make_node_actor_defexp,
        make_oidc_only_adapter_defexp, make_peering, policy_with_peerings,
    };
    use libeval::attribute::ROLE_ADAPTER;
    use zpr::policy_types::AttrExp;

    /// Insert a readwrite test key into the assembly's key store and return the
    /// key string to use in the X-API-Key header.
    fn setup_test_api_rw_key(asm: &Arc<Assembly>) -> String {
        setup_test_api_key_with_perm(asm, Permission::ReadWrite)
    }

    fn setup_test_api_r_key(asm: &Arc<Assembly>) -> String {
        setup_test_api_key_with_perm(asm, Permission::Read)
    }

    /// Insert a resolve-only test key into the assembly's key store and return
    /// the key string to use in the X-API-Key header (zipline#36).
    fn setup_test_api_resolve_key(asm: &Arc<Assembly>) -> String {
        setup_test_api_key_with_perm(asm, Permission::Resolve)
    }

    /// Insert a test key with the given permission into the assembly's key store
    /// and return the key string to use in the X-API-Key header.
    fn setup_test_api_key_with_perm(asm: &Arc<Assembly>, permission: Permission) -> String {
        setup_test_api_key_full(asm, permission, None, 0xaabbccdd)
    }

    /// Insert a notify test key bound to `service` (zipline#79) and return the
    /// key string. `key_id` must differ between keys inserted into the same
    /// assembly.
    fn setup_test_api_notify_key(asm: &Arc<Assembly>, service: &str, key_id: u32) -> String {
        setup_test_api_key_full(asm, Permission::Notify, Some(service.to_string()), key_id)
    }

    /// Insert a test key with the given permission, service binding and key id
    /// into the assembly's key store and return the key string to use in the
    /// X-API-Key header.
    fn setup_test_api_key_full(
        asm: &Arc<Assembly>,
        permission: Permission,
        service: Option<String>,
        key_id: u32,
    ) -> String {
        let secret_bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let apikey = ApiKey::new(key_id, secret_bytes);
        let record = ApiKeyRecord {
            owner: "test".to_string(),
            permission,
            status: KeyStatus::Active,
            created: "2026-01-01".to_string(),
            secret_hash: apikey.secret_hash().unwrap(),
            description: "test key".to_string(),
            service,
        };
        asm.admin_api_keys
            .insert_for_test(apikey.key_id_hex(), record);
        apikey.to_key_string()
    }

    /// Build a valid `PolicyBundle` carrying a minimal policy (no topology, so the
    /// FakeResolver in the test assembly resolves it cleanly) at the minimum
    /// supported compiler version, for use as `install_policy` request input.
    fn make_valid_policy_bundle() -> PolicyBundle {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<zpr::policy::v1::policy::Builder>();
            policy.set_created("2026-01-01T00:00:00Z");
            policy.set_version(1);
            policy.set_metadata("");
        }
        let mut inner = Vec::new();
        capnp::serialize::write_message(&mut inner, &msg).unwrap();
        let container = crate::test_helpers::make_container_bytes(
            crate::config::POLICY_MIN_COMPILER_MAJOR,
            crate::config::POLICY_MIN_COMPILER_MINOR,
            crate::config::POLICY_MIN_COMPILER_PATCH,
            &inner,
        );
        PolicyBundle::new_from_policy_container(0, container.into()).unwrap()
    }

    /// GET /admin/policies returns the single current policy id (0) with a read key.
    #[tokio::test]
    async fn test_get_policies_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entry: ListEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(entry.id, DEFAULT_POLICY_ID);
    }

    /// GET /admin/policies/curr returns the current policy as a base64;zip PolicyBundle.
    #[tokio::test]
    async fn test_get_curr_policy_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/curr")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let bundle: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundle.config_id, DEFAULT_POLICY_ID);
        assert!(bundle.format.starts_with("base64;zip;"));
        assert!(!bundle.container.is_empty());
    }

    /// GET /admin/policies/0 returns the current policy bundle (id 0 is the default).
    #[tokio::test]
    async fn test_get_policy_by_id_zero_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/0")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let bundle: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert!(bundle.format.starts_with("base64;zip;"));
    }

    /// GET /admin/policies/<non-zero> is rejected because only id 0 currently exists.
    #[tokio::test]
    async fn test_get_policy_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/1")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// POST /admin/policies installs a valid bundle and the new policy is then
    /// served by GET /admin/policies/curr.
    #[tokio::test]
    async fn test_install_policy_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        let bundle = make_valid_policy_bundle();
        let body = serde_json::to_vec(&bundle).unwrap();

        let app = admin_app(shared_state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entry: ListEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(entry.id, DEFAULT_POLICY_ID);

        // The installed policy should now be the current one.
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/policies/curr")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let curr: PolicyBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(curr.decode().unwrap(), bundle.decode().unwrap());
    }

    /// POST /admin/policies rejects a bundle whose container can't be decoded.
    #[tokio::test]
    async fn test_install_policy_bad_bundle() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        // Valid JSON shape, but an unsupported format makes decode() fail.
        let bad = PolicyBundle {
            config_id: 0,
            version: String::new(),
            format: "hex;zip;0.11.1".to_string(),
            container: String::new(),
        };
        let body = serde_json::to_vec(&bad).unwrap();

        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// POST /admin/policies is forbidden for a read-only key (no write permission).
    #[tokio::test]
    async fn test_install_policy_forbidden_without_write() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));

        let bundle = make_valid_policy_bundle();
        let body = serde_json::to_vec(&bundle).unwrap();

        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/policies")
                    .header("X-API-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_visas_no_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert!(visas.is_empty());
    }

    #[tokio::test]
    async fn test_get_visas_one_visa() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        let route = Route::new_direct(node_addr.into());

        // Add a visa.
        let vwmd = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();

        let created_id = vwmd.visa.issuer_id;
        assert!(created_id > 0);

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 1);
        assert_eq!(visas[0].id, created_id);
    }

    /// Drives `GET /admin/visas/denies` with the given query string and returns
    /// the status plus the decoded body.
    async fn fetch_denies(
        asm: &Arc<Assembly>,
        api_key: &str,
        query: &str,
    ) -> (StatusCode, Vec<DenyRecord>) {
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/admin/visas/denies{query}"))
                    .header("X-API-Key", api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        // A non-OK response has no DenyRecord list body.
        let records = if status == StatusCode::OK {
            serde_json::from_slice(&body).unwrap()
        } else {
            Vec::new()
        };
        (status, records)
    }

    /// Records three denies at known times so the ordering and query-filter
    /// assertions below are deterministic.
    fn seed_denies(asm: &Arc<Assembly>) {
        for (i, dport) in [80u16, 443, 8080].into_iter().enumerate() {
            let ft = PacketDesc::new_tcp(
                "fd5a:5052:3000::1",
                "fd5a:5052:3000::2",
                12345,
                dport.into(),
            )
            .unwrap()
            .five_tuple;
            asm.deny_log
                .record_at_ms(&ft, &DenyCode::NoMatch, 1_000 + i as u64 * 1_000);
        }
    }

    #[tokio::test]
    async fn test_get_denies_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let (status, denies) = fetch_denies(&asm, &api_key, "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(denies.is_empty());
    }

    #[tokio::test]
    async fn test_get_denies_newest_first() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        seed_denies(&asm);

        let (status, denies) = fetch_denies(&asm, &api_key, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            denies.iter().map(|d| d.dest_port).collect::<Vec<_>>(),
            vec![8080, 443, 80]
        );

        let newest = &denies[0];
        assert_eq!(
            newest.source_addr,
            "fd5a:5052:3000::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            newest.dest_addr,
            "fd5a:5052:3000::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(newest.protocol, ip_proto::TCP);
        assert_eq!(newest.count, 1);
        assert_eq!(newest.last_deny_ms, 3_000);
        assert_eq!(newest.deny_code, "NoMatch");
    }

    #[tokio::test]
    async fn test_get_denies_since_and_limit() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        seed_denies(&asm);

        // `since` is inclusive, so the entry recorded exactly at 2000 is returned.
        let (status, denies) = fetch_denies(&asm, &api_key, "?since=2000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            denies.iter().map(|d| d.last_deny_ms).collect::<Vec<_>>(),
            vec![3_000, 2_000]
        );

        let (_, denies) = fetch_denies(&asm, &api_key, "?limit=1").await;
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].last_deny_ms, 3_000);

        let (_, denies) = fetch_denies(&asm, &api_key, "?since=1000&limit=2").await;
        assert_eq!(
            denies.iter().map(|d| d.last_deny_ms).collect::<Vec<_>>(),
            vec![3_000, 2_000]
        );
    }

    #[tokio::test]
    async fn test_get_denies_rejects_malformed_query() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        for query in ["?since=-1", "?since=abc", "?limit=-5", "?limit=1.5"] {
            let (status, _) = fetch_denies(&asm, &api_key, query).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "expected 400 for query {query}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_visas_three_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add three visas with distinct packet descriptors.
        let pdesc0 =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let pdesc1 =
            PacketDesc::new_tcp("fd5a:5052:3000::3", "fd5a:5052:3000::4", 12346, 443).unwrap();
        let pdesc2 =
            PacketDesc::new_tcp("fd5a:5052:3000::5", "fd5a:5052:3000::6", 12347, 22).unwrap();

        let route = Route::new_direct(node_addr.into());

        let v0 = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc0,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();
        let v1 = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc1,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();
        let v2 = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc2,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();

        let mut created_ids = vec![v0.visa.issuer_id, v1.visa.issuer_id, v2.visa.issuer_id];
        created_ids.sort_unstable();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 3);

        let mut returned_ids: Vec<u64> = visas.into_iter().map(|v| v.id).collect();
        returned_ids.sort_unstable();
        assert_eq!(returned_ids, created_ids);
    }

    #[tokio::test]
    async fn test_get_actors_no_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<ActorEntry> = serde_json::from_slice(&body).unwrap();
        assert!(actors.is_empty());
    }

    #[tokio::test]
    async fn test_get_actors_one_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let actor = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&actor, false, &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<ActorEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 1);
        assert_eq!(actors[0].zpr_addr, "fd5a:5052::10");
        assert_eq!(actors[0].cn, Some("node-1".to_string()));
    }

    /// F1 endpoint view (zipline#29 / zipline#30, A1 gate): `GET /admin/actors` must
    /// represent a CN-less actor (OIDC-only connect). This encodes the reported
    /// symptom directly: an OIDC-only actor connects and no dashboard row appears.
    /// Pre-A2 `list_actor_cns` skipped the actor (warn + continue on the missing
    /// `cn` attribute), so the endpoint returned only the CN-bearing actor.
    /// Re-keyed by zipline#31 (A2): every actor appears as an `ActorEntry` with its
    /// ZPR address and an optional CN.
    #[tokio::test]
    async fn test_admin_actors_lists_cn_less_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_actor =
            make_node_actor_defexp("fd5a:5052::30", "node-f1", "[fd5a:5052::130]:1234");
        let cn_less_adapter = make_oidc_only_adapter_defexp("fd5a:5052::31");
        asm.actor_mgr
            .add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &cn_less_adapter,
                node_actor.get_zpr_addr().unwrap(),
                &Default::default(),
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let mut actors: Vec<ActorEntry> = serde_json::from_slice(&body).unwrap();
        // Both connected actors must have an entry; the CN-less adapter must not be
        // omitted from the admin listing. It carries its address and a null cn.
        actors.sort_by(|a, b| a.zpr_addr.cmp(&b.zpr_addr));
        assert_eq!(
            actors.len(),
            2,
            "CN-less actor omitted from GET /admin/actors: {actors:?}"
        );
        assert_eq!(actors[0].zpr_addr, "fd5a:5052::30");
        assert_eq!(actors[0].cn, Some("node-f1".to_string()));
        assert_eq!(actors[1].zpr_addr, "fd5a:5052::31");
        assert_eq!(actors[1].cn, None, "CN-less actor must carry a null cn");
        // Every listed address is parseable.
        for entry in &actors {
            entry
                .zpr_addr
                .parse::<IpAddr>()
                .expect("zpr_addr must be a parseable IP address");
        }
    }

    #[tokio::test]
    async fn test_get_actors_multiple_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let actor0 = make_node_actor_defexp("fd5a:5052::11", "node-1", "[fd5a:5052::101]:1234");
        let actor1 = make_node_actor_defexp("fd5a:5052::12", "node-2", "[fd5a:5052::102]:1234");
        let actor2 = make_node_actor_defexp("fd5a:5052::13", "node-3", "[fd5a:5052::103]:1234");

        asm.actor_mgr
            .add_node(&actor0, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&actor1, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&actor2, false, &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let mut actors: Vec<ActorEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 3);
        actors.sort_by(|a, b| a.zpr_addr.cmp(&b.zpr_addr));
        let actor_addrs: Vec<String> = actors.into_iter().map(|a| a.zpr_addr).collect();
        assert_eq!(
            actor_addrs,
            vec![
                "fd5a:5052::11".to_string(),
                "fd5a:5052::12".to_string(),
                "fd5a:5052::13".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_get_actors_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node_actor = make_node_actor_defexp("fd5a:5052::20", "node-1", "[fd5a:5052::120]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::21", "adapter-1");

        asm.actor_mgr
            .add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &adapter_actor,
                node_actor.get_zpr_addr().unwrap(),
                &Default::default(),
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response_nodes = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=node")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_nodes.status(), StatusCode::OK);

        let body_nodes = response_nodes
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_nodes: Vec<ActorEntry> = serde_json::from_slice(&body_nodes).unwrap();
        assert_eq!(actors_nodes.len(), 1);
        assert_eq!(actors_nodes[0].zpr_addr, "fd5a:5052::20");
        assert_eq!(actors_nodes[0].cn, Some("node-1".to_string()));

        let response_adapters = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=adapter")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_adapters.status(), StatusCode::OK);

        let body_adapters = response_adapters
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_adapters: Vec<ActorEntry> = serde_json::from_slice(&body_adapters).unwrap();
        assert_eq!(actors_adapters.len(), 1);
        assert_eq!(actors_adapters[0].zpr_addr, "fd5a:5052::21");
        assert_eq!(actors_adapters[0].cn, Some("adapter-1".to_string()));
    }

    #[tokio::test]
    async fn test_get_visa_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas/9999")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_visa_fields_forward_no_signal() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let zpl_str = "permit tcp from groupA to groupB port 80";
        let policy_version: u64 = 42;
        let hit = Hit::new_no_signal(0, Direction::Forward);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc,
                &hit,
                &route,
                zpl_str,
                policy_version,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();

        assert_eq!(vd.id, v.visa.issuer_id);
        assert_eq!(vd.policy_id, "42");
        assert_eq!(vd.zpl, zpl_str);
        assert_eq!(vd.direction, VisaMatchDirection::Forward);
        assert!(vd.signals.is_empty());

        // Verify JSON encodes direction as lowercase string.
        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(raw["direction"], "forward");
    }

    #[tokio::test]
    async fn test_get_visa_direction_reverse() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Reverse);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(vd.direction, VisaMatchDirection::Reverse);

        let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(raw["direction"], "reverse");
    }

    #[tokio::test]
    async fn test_get_visa_with_signal() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let signal = Signal {
            message: "alert: suspicious traffic".to_string(),
            service: "svc1".to_string(),
        };
        let hit = Hit::new_with_signal(0, Direction::Forward, signal);
        let route = Route::new_direct(node_addr.into());

        let v = asm
            .visa_mgr
            .create_visa(
                &asm,
                &node_addr,
                &pdesc,
                &hit,
                &route,
                "",
                0,
                0,
                SystemTime::now() + DEFAULT_VISA_EXPIRATION,
            )
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/admin/visas/{}", v.visa.issuer_id))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let vd: VisaDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(vd.signals, vec!["alert: suspicious traffic".to_string()]);
    }

    #[tokio::test]
    async fn test_get_actors_invalid_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=invalid")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// The test policy declares no topology, so there are no links to report.
    async fn test_get_network_empty() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let details = fetch_network(&asm).await;
        assert!(details.network.is_empty());
    }

    /// GET /admin/network and deserialize the response body.
    async fn fetch_network(asm: &Arc<Assembly>) -> NetworkDetails {
        let api_key = setup_test_api_r_key(asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let response = admin_app(shared_state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/network")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Install a policy peering `a` and `b` over `link-ab`, with a link cost attribute.
    async fn install_ab_peering(asm: &Arc<Assembly>, a: IpAddr, b: IpAddr) {
        let attrs = vec![AttrExp {
            key: libeval::attribute::key::LINK_COST.to_string(),
            op: zpr::policy_types::AttrOp::Eq,
            value: vec!["7".to_string()],
        }];
        asm.policy_mgr
            .update_policy_from_container_bytes(policy_with_peerings(&[make_peering(
                a, b, "link-ab", attrs,
            )]))
            .await
            .unwrap();
    }

    #[tokio::test]
    /// A link the policy declares but that no connected node reports is DOWN, and it
    /// carries the link detail (id, substrate, cost, attrs) taken from policy.
    async fn test_get_network_declared_link_down() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();
        install_ab_peering(&asm, addr_a, addr_b).await;

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        for nc in &details.network {
            assert!(nc.is_link_between(&addr_a, &addr_b));
            assert!(matches!(nc.ctype, ConnectionType::DOWN));
            assert_eq!(nc.link_id, "link-ab");
            assert_eq!(nc.link_cost, 7);
            // The fixture uses each node's ZPR (IPv6) address as its substrate, so both
            // ends must come back bracketed and parseable.
            assert_eq!(nc.node_a_substrate, format!("[{}]:0", nc.node_a_addr));
            assert_eq!(nc.node_b_substrate, format!("[{}]:0", nc.node_b_addr));
            assert_eq!(nc.link_attrs.len(), 1);
        }
    }

    #[tokio::test]
    /// A declared link whose link-state reports put it down is DOWN, even though it
    /// stays in the router graph (zl-zipline#224).
    async fn test_get_network_link_reported_down_is_down() {
        use libeval::route::LinkId;

        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();
        install_ab_peering(&asm, addr_a, addr_b).await;
        for (addr, cn) in [("fd5a:5052::10", "node-a"), ("fd5a:5052::11", "node-b")] {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(addr, cn, "[fd5a:5052::100]:1234"),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
        }
        asm.topo_mgr.add_node(addr_a).unwrap();
        asm.topo_mgr.add_node(addr_b).unwrap();
        asm.topo_mgr
            .add_link(addr_a, addr_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        // A reports an empty snapshot: its link to B is not up.
        asm.topo_mgr
            .record_link_states_with_cns(&addr_a, None, vec![], &|_: &IpAddr| None);

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        for nc in &details.network {
            assert!(nc.is_link_between(&addr_a, &addr_b));
            assert!(matches!(nc.ctype, ConnectionType::DOWN));
        }
    }

    #[tokio::test]
    /// A declared link that the connected nodes also report is UP.
    async fn test_get_network_declared_link_up() {
        use libeval::route::LinkId;

        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();
        install_ab_peering(&asm, addr_a, addr_b).await;

        let actor_a = make_node_actor_defexp("fd5a:5052::10", "node-a", "[fd5a:5052::100]:1234");
        let actor_b = make_node_actor_defexp("fd5a:5052::11", "node-b", "[fd5a:5052::101]:1234");
        asm.actor_mgr
            .add_node(&actor_a, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&actor_b, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(addr_a).unwrap();
        asm.topo_mgr.add_node(addr_b).unwrap();
        asm.topo_mgr
            .add_link(addr_a, addr_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        for nc in &details.network {
            assert!(nc.is_link_between(&addr_a, &addr_b));
            assert!(matches!(nc.ctype, ConnectionType::UP));
        }
    }

    #[tokio::test]
    /// A link the nodes report but that the policy does not declare is INVALID.
    async fn test_get_network_undeclared_link_invalid() {
        use libeval::route::LinkId;

        let asm = Arc::new(new_assembly_for_tests(None).await);
        let addr_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let addr_b: IpAddr = "fd5a:5052::11".parse().unwrap();

        // Note: no policy peering installed, so this link is undeclared.
        let actor_a = make_node_actor_defexp("fd5a:5052::10", "node-a", "[fd5a:5052::100]:1234");
        let actor_b = make_node_actor_defexp("fd5a:5052::11", "node-b", "[fd5a:5052::101]:1234");
        asm.actor_mgr
            .add_node(&actor_a, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&actor_b, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(addr_a).unwrap();
        asm.topo_mgr.add_node(addr_b).unwrap();
        asm.topo_mgr
            .add_link(addr_a, addr_b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        let details = fetch_network(&asm).await;

        assert_eq!(details.network.len(), 1);
        assert!(
            matches!(details.network[0].ctype, ConnectionType::INVALID),
            "got {:?}",
            details.network[0].ctype
        );
    }

    /// Build a Scope with the given protocol, single port, and port range.
    fn scope(protocol: u8, port: Option<u16>, port_range: Option<(u16, u16)>) -> Scope {
        Scope {
            protocol,
            flag: None,
            port,
            port_range,
        }
    }

    /// service_endpoints_to_string formats known protocols, port ranges, unknown
    /// protocols, and the empty list as expected.
    #[test]
    fn test_service_endpoints_to_string() {
        // Empty list -> empty string.
        assert_eq!(service_endpoints_to_string(&[]), "");

        // Single port with each known protocol.
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::TCP, Some(80), None)]),
            "TCP/80"
        );
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::UDP, Some(53), None)]),
            "UDP/53"
        );

        // Port range.
        assert_eq!(
            service_endpoints_to_string(&[scope(ip_proto::TCP, None, Some((8000, 8080)))]),
            "TCP/8000-8080"
        );

        // Unknown protocol falls back to PROTO_<n>.
        assert_eq!(
            service_endpoints_to_string(&[scope(200, Some(1), None)]),
            "PROTO_200/1"
        );

        // Multiple endpoints are comma-joined in order.
        assert_eq!(
            service_endpoints_to_string(&[
                scope(ip_proto::TCP, Some(80), None),
                scope(ip_proto::UDP, Some(53), None),
            ]),
            "TCP/80,UDP/53"
        );
    }

    /// GET /admin/nodes/{addr}/visas for a node with no installed visas returns OK
    /// with an empty list.
    #[tokio::test]
    async fn test_get_visas_on_node_empty_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::30", "node-1", "[fd5a:5052::130]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/fd5a:5052::30/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert!(visas.is_empty());
    }

    /// GET /admin/nodes/{addr}/visas for a non-node actor is rejected with BAD_REQUEST.
    #[tokio::test]
    async fn test_get_visas_on_node_non_node_bad_request() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::31", "node-1", "[fd5a:5052::131]:1234");
        let adapter = make_adapter_actor_defexp("fd5a:5052::32", "adapter-1");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/fd5a:5052::32/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// GET /admin/nodes/{addr}/visas for an unknown address returns NOT_FOUND.
    #[tokio::test]
    async fn test_get_visas_on_node_unknown_addr_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/nodes/fd5a:5052::999/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/actors/{addr}/visas for an unknown address returns NOT_FOUND
    /// (exercises the shared resolve_actor_addr helper with require_node = false).
    #[tokio::test]
    async fn test_get_related_visas_unknown_addr_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors/fd5a:5052::999/visas")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    const FLUSH_TS_ID: &str = "ts-file";

    /// Minimal trusted service that only records whether it was flushed.
    struct FlushCountingService {
        flushes: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FlushCountingService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        // Holds no snapshot; its flush count doubles as the revision.
        fn current_revision(&self) -> u64 {
            self.flushes.load(std::sync::atomic::Ordering::SeqCst) as u64
        }

        fn get_source_id(&self) -> &str {
            FLUSH_TS_ID
        }
    }

    /// Register one flush-counting trusted service on the assembly and return it for
    /// assertions.
    fn register_flush_counting_service(asm: &Arc<Assembly>) -> Arc<FlushCountingService> {
        let svc = Arc::new(FlushCountingService {
            flushes: std::sync::atomic::AtomicUsize::new(0),
        });
        asm.ts_mgr.update_services(vec![svc.clone()]);
        svc
    }

    /// DELETE /admin/services/{id}/cache flushes the named trusted service.
    #[tokio::test]
    async fn test_flush_service_cache_ok() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/services/{FLUSH_TS_ID}/cache"))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The revalidation of existing visas is queued for the event worker.
        match event_rx.try_recv() {
            Ok(VsEvent::TrustedServiceChange) => {}
            other => panic!("expected TrustedServiceChange event, got {other:?}"),
        }
    }

    /// DELETE /admin/services/{id}/cache for an unregistered service returns NOT_FOUND.
    #[tokio::test]
    async fn test_flush_service_cache_unknown_not_found() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/services/does-not-exist/cache")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Nothing was invalidated, so nothing needs revalidating.
        assert!(event_rx.try_recv().is_err());
    }

    /// POST /admin/services/{id}/changed with the given key and body
    /// (zipline#79); returns the response status.
    async fn post_service_changed(
        app: Router,
        api_key: &str,
        svc_id: &str,
        body: &str,
    ) -> StatusCode {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/services/{svc_id}/changed"))
                    .header("X-API-Key", api_key)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.status()
    }

    /// The notification endpoint's permission matrix (zipline#79):
    /// read/resolve keys never notify; a readwrite key notifies any id (404
    /// on an unknown one); a notify key notifies exactly its bound id, and a
    /// mismatch is 403 BEFORE the 404 existence check so a bound key cannot
    /// probe which ids exist.
    #[tokio::test]
    async fn test_service_changed_permission_matrix() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        register_flush_counting_service(&asm);
        let rw_key = setup_test_api_key_full(&asm, Permission::ReadWrite, None, 0x0000_0001);
        let r_key = setup_test_api_key_full(&asm, Permission::Read, None, 0x0000_0002);
        let resolve_key = setup_test_api_key_full(&asm, Permission::Resolve, None, 0x0000_0003);
        let notify_bound = setup_test_api_notify_key(&asm, FLUSH_TS_ID, 0x0000_0004);
        let notify_other = setup_test_api_notify_key(&asm, "other-svc", 0x0000_0005);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        // Keys without can_notify are refused outright.
        assert_eq!(
            post_service_changed(app.clone(), &r_key, FLUSH_TS_ID, "{}").await,
            StatusCode::FORBIDDEN,
            "read key must not notify"
        );
        assert_eq!(
            post_service_changed(app.clone(), &resolve_key, FLUSH_TS_ID, "{}").await,
            StatusCode::FORBIDDEN,
            "resolve key must not notify"
        );
        // A readwrite key notifies any id; unknown ids are 404.
        assert_eq!(
            post_service_changed(app.clone(), &rw_key, FLUSH_TS_ID, "{}").await,
            StatusCode::ACCEPTED,
            "readwrite key notifies any service"
        );
        assert_eq!(
            post_service_changed(app.clone(), &rw_key, "does-not-exist", "{}").await,
            StatusCode::NOT_FOUND,
            "readwrite key on unknown id sees the 404"
        );
        // A notify key works exactly on its bound id.
        assert_eq!(
            post_service_changed(app.clone(), &notify_bound, FLUSH_TS_ID, "{}").await,
            StatusCode::ACCEPTED,
            "notify key bound to the id notifies it"
        );
        assert_eq!(
            post_service_changed(app.clone(), &notify_other, FLUSH_TS_ID, "{}").await,
            StatusCode::FORBIDDEN,
            "notify key bound elsewhere is refused"
        );
        // Binding mismatch beats existence: 403, not 404 — no id probing.
        assert_eq!(
            post_service_changed(app.clone(), &notify_other, "does-not-exist", "{}").await,
            StatusCode::FORBIDDEN,
            "bound notify key must get 403 before the 404 existence check"
        );
    }

    /// `{}` means "everything changed": same effect as DELETE .../cache —
    /// the service is flushed and the unscoped revalidation is queued
    /// (zipline#79).
    #[tokio::test]
    async fn test_service_changed_empty_body_flushes_and_queues_event() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let status = post_service_changed(app, &api_key, FLUSH_TS_ID, "{}").await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 1);
        match event_rx.try_recv() {
            Ok(VsEvent::TrustedServiceChange) => {}
            other => panic!("expected TrustedServiceChange event, got {other:?}"),
        }
    }

    /// A targeted body forgets the listed actor's revision for this source
    /// and leaves an unlisted actor's record intact (zipline#79); the
    /// reconcile event is still queued.
    #[tokio::test]
    async fn test_service_changed_targeted_forgets_listed_actor_only() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);

        // Two connected actors, both fully caught up on the source.
        let alice = make_node_actor_defexp("fd5a:5052::61", "alice", "[fd5a:5052::161]:1234");
        let bob = make_node_actor_defexp("fd5a:5052::62", "bob", "[fd5a:5052::162]:1234");
        asm.actor_mgr
            .add_node(&alice, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&bob, false, &Default::default())
            .await
            .unwrap();
        let alice_addr: IpAddr = "fd5a:5052::61".parse().unwrap();
        let bob_addr: IpAddr = "fd5a:5052::62".parse().unwrap();
        let rev = {
            use crate::trusted_services::TrustedServiceInterface;
            svc.current_revision()
        };
        asm.ts_mgr.record_revision(&alice_addr, FLUSH_TS_ID, rev);
        asm.ts_mgr.record_revision(&bob_addr, FLUSH_TS_ID, rev);

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let body = r#"{"identities":[{"device.zpr.adapter.cn":"alice"}]}"#;
        let status = post_service_changed(app, &api_key, FLUSH_TS_ID, body).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        // Alice's record for this source is gone (source now stale for her)...
        assert_eq!(
            asm.ts_mgr.stale_sources_for_actor(&alice_addr),
            vec![(FLUSH_TS_ID.to_string(), rev)],
            "listed actor's revision for this source must be forgotten"
        );
        // ...Bob's is intact.
        assert!(
            asm.ts_mgr.stale_sources_for_actor(&bob_addr).is_empty(),
            "unlisted actor's revision must be left alone"
        );
        // Targeted notification does NOT flush the whole service.
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);
        match event_rx.try_recv() {
            Ok(VsEvent::TrustedServiceChange) => {}
            other => panic!("expected TrustedServiceChange event, got {other:?}"),
        }
    }

    /// Malformed bodies are 400 (zipline#79): non-JSON, an unknown field, and
    /// an empty identity object. Nothing is flushed and no event is queued.
    #[tokio::test]
    async fn test_service_changed_malformed_body_bad_request() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        // `{"identities":null}` is in this list deliberately (PR #29 review,
        // P2): the documented full-change form is an ABSENT field, and an
        // explicit null must not silently trigger a global flush.
        for body in [
            "not json",
            r#"{"bogus":1}"#,
            r#"{"identities":[{}]}"#,
            r#"{"identities":null}"#,
        ] {
            assert_eq!(
                post_service_changed(app.clone(), &api_key, FLUSH_TS_ID, body).await,
                StatusCode::BAD_REQUEST,
                "body {body:?} must be rejected"
            );
        }
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(event_rx.try_recv().is_err());
    }

    /// GET /admin/actors/{addr} returns the actor's descriptor, keyed on the
    /// address, with the CN read from the actor record (not echoed from the path).
    #[tokio::test]
    async fn test_get_actor_detail_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::40", "node-detail", "[fd5a:5052::140]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors/fd5a:5052::40")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: ActorDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(descriptor.zpr_addr, "fd5a:5052::40");
        assert_eq!(descriptor.cn, Some("node-detail".to_string()));
        assert!(descriptor.node);
        assert!(
            descriptor.node_details.is_some(),
            "node actors carry node_details"
        );
    }

    /// A CN-less actor (OIDC-only connect) is fetchable by address and its
    /// descriptor carries a null cn -- the acceptance case for the re-key.
    #[tokio::test]
    async fn test_get_actor_detail_cn_less_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::41", "node-x", "[fd5a:5052::141]:1234");
        let cn_less = make_oidc_only_adapter_defexp("fd5a:5052::42");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&cn_less, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors/fd5a:5052::42")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: ActorDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(descriptor.zpr_addr, "fd5a:5052::42");
        assert_eq!(descriptor.cn, None, "CN-less actor must carry a null cn");
        assert!(!descriptor.node);
        assert!(descriptor.node_details.is_none());
    }

    /// A CN-less adapter appears in its node's NodeRecordBrief.adapters, listed by
    /// ZPR address (acceptance: the F2 fix as seen through the detail endpoint).
    #[tokio::test]
    async fn test_get_actor_detail_node_brief_lists_cn_less_adapter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::43", "node-brief", "[fd5a:5052::143]:1234");
        let cn_less = make_oidc_only_adapter_defexp("fd5a:5052::44");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&cn_less, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors/fd5a:5052::43")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: ActorDescriptor = serde_json::from_slice(&body).unwrap();
        let brief = descriptor.node_details.expect("node carries node_details");
        assert_eq!(
            brief.adapters,
            vec!["fd5a:5052::44".to_string()],
            "the CN-less adapter must appear in NodeRecordBrief.adapters by address"
        );
    }

    /// GET /admin/actors/{addr} for a node and return its `node_details`.
    async fn get_node_brief(asm: &Arc<Assembly>, api_key: &str, addr: &str) -> NodeRecordBrief {
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/admin/actors/{addr}"))
                    .header("X-API-Key", api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: ActorDescriptor = serde_json::from_slice(&body).unwrap();
        descriptor.node_details.expect("node carries node_details")
    }

    /// zipline#187: a node that has gone silent -- its VSS worker exited after
    /// its ping failures and the handle was cleared, and no vsapi `ping` from
    /// the node follows to start a new worker -- must report `in_sync: false`.
    /// The node DB VSS record is kept (Q1), so `vss_port` still reports the
    /// port, and `last_contact` does not advance across the exit.
    #[tokio::test]
    async fn test_node_brief_in_sync_false_after_vss_worker_exit_silent_node() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::46", "node-silent", "[fd5a:5052::146]:1234");
        let node_addr = *node.get_zpr_addr().unwrap();
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052::146]:9877".parse().unwrap();
        asm.actor_mgr
            .set_node_vss(&node_addr, &vss_addr)
            .await
            .unwrap();

        // A live worker: the handle's command channel is open.
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<crate::vss::VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node_addr, cmd_tx);
        let before = get_node_brief(&asm, &api_key, "fd5a:5052::46").await;
        assert!(before.in_sync, "a live worker reports in_sync");

        // The worker exits (its receiver drops) and run_vss_job clears the
        // handle. The node is silent: no ping follows, nothing restarts it.
        drop(cmd_rx);
        asm.vss_mgr.clear_handle_for_test(&node_addr);

        let after = get_node_brief(&asm, &api_key, "fd5a:5052::46").await;
        assert!(
            !after.in_sync,
            "a node whose VSS worker exited must not report in_sync"
        );
        assert_eq!(
            after.vss_port,
            Some(9877),
            "the node DB VSS record is kept, so vss_port still reports it"
        );
        assert_eq!(
            after.last_contact, before.last_contact,
            "a silent node's last_contact must not advance across the worker exit"
        );
    }

    /// zipline#187: a live worker reports `in_sync: true`, and a worker restart
    /// (`restart_vss_worker`) does not cause a false `false`: the old worker
    /// exits and runs `clear_handle` after the replacement is installed. The
    /// replacement sits in its start delay, which counts as running (Q2).
    #[tokio::test]
    async fn test_node_brief_in_sync_true_live_and_across_restart() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::48", "node-restart", "[fd5a:5052::148]:1234");
        let node_addr = *node.get_zpr_addr().unwrap();
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052::148]:9877".parse().unwrap();
        asm.actor_mgr
            .set_node_vss(&node_addr, &vss_addr)
            .await
            .unwrap();

        let (old_tx, old_rx) = tokio::sync::mpsc::channel::<crate::vss::VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node_addr, old_tx);
        let live = get_node_brief(&asm, &api_key, "fd5a:5052::48").await;
        assert!(live.in_sync, "a live worker reports in_sync");

        // Restart: the replacement waits an hour before it connects, so it
        // never touches the network in this test.
        asm.vss_mgr
            .restart_vss_worker(
                asm.clone(),
                &node_addr,
                &vss_addr,
                std::time::Duration::from_secs(3600),
            )
            .unwrap();
        let mid = get_node_brief(&asm, &api_key, "fd5a:5052::48").await;
        assert!(
            mid.in_sync,
            "the replacement in its start delay counts as running"
        );

        // The old worker exits after the replacement is installed.
        drop(old_rx);
        asm.vss_mgr.clear_handle_for_test(&node_addr);
        let after = get_node_brief(&asm, &api_key, "fd5a:5052::48").await;
        assert!(
            after.in_sync,
            "a restart must not cause a false in_sync=false"
        );
        assert_eq!(after.vss_port, Some(9877));
    }

    /// zipline#187: a VSS record with no worker ever started is the same state
    /// with no history -- `in_sync: false`, `vss_port` set.
    #[tokio::test]
    async fn test_node_brief_in_sync_false_with_vss_record_and_no_worker() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node =
            make_node_actor_defexp("fd5a:5052::47", "node-noworker", "[fd5a:5052::147]:1234");
        let node_addr = *node.get_zpr_addr().unwrap();
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052::147]:9877".parse().unwrap();
        asm.actor_mgr
            .set_node_vss(&node_addr, &vss_addr)
            .await
            .unwrap();

        let brief = get_node_brief(&asm, &api_key, "fd5a:5052::47").await;
        assert!(!brief.in_sync, "no VSS worker means not in_sync");
        assert_eq!(brief.vss_port, Some(9877));
    }

    /// GET /admin/actors/{addr}: a malformed address is a 400 (new behaviour --
    /// a CN path accepted any string) and an unknown one is a 404.
    #[tokio::test]
    async fn test_get_actor_detail_malformed_400_unknown_404() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for (path, expected) in [
            ("/admin/actors/not-an-address", StatusCode::BAD_REQUEST),
            ("/admin/actors/fd5a:5052::999", StatusCode::NOT_FOUND),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "for {path}");
        }
    }

    /// DELETE /admin/actors/{addr}: 200 with the placeholder Revokes body for a
    /// known actor, 400 for a malformed address, 404 for an unknown one.
    #[tokio::test]
    async fn test_revoke_actor_ok_and_errors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::45", "node-rvk", "[fd5a:5052::145]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for (path, expected) in [
            ("/admin/actors/fd5a:5052::45", StatusCode::OK),
            ("/admin/actors/not-an-address", StatusCode::BAD_REQUEST),
            ("/admin/actors/fd5a:5052::999", StatusCode::NOT_FOUND),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "for {path}");
            if expected == StatusCode::OK {
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let _revokes: Revokes = serde_json::from_slice(&body).unwrap();
            }
        }
    }

    /// The visa endpoints share resolve_actor_addr: a malformed address is a 400
    /// on both /admin/actors/{addr}/visas and /admin/nodes/{addr}/visas.
    #[tokio::test]
    async fn test_visa_endpoints_malformed_address_bad_request() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for path in [
            "/admin/actors/not-an-address/visas",
            "/admin/nodes/not-an-address/visas",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {path}");
        }
    }

    /// A read-only key may not flush a trusted service.
    #[tokio::test]
    async fn test_flush_service_cache_read_key_forbidden() {
        let (asm, mut event_rx) = new_assembly_with_event_rx(None).await;
        let asm = Arc::new(asm);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_r_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/services/{FLUSH_TS_ID}/cache"))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(event_rx.try_recv().is_err());
    }

    /// GET /admin/services returns the service list with a resolve-only key
    /// (zipline#36): the two service-resolution endpoints accept any active
    /// key, including the least-privilege `resolve` permission.
    #[tokio::test]
    async fn test_get_services_resolve_key_ok() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let adapter =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::3", &["svc:one"], "actor-1");
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/services")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let services: Vec<NamedListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].id, "svc:one");
    }

    /// GET /admin/services/{name} with a resolve-only key (zipline#36): 200
    /// with a descriptor for a registered service, 404 for an unknown name —
    /// i.e. the resolve key gets the endpoint's normal behavior, not a 403.
    #[tokio::test]
    async fn test_get_service_resolve_key_ok_and_unknown_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let adapter =
            make_actor_with_services_defexp(ROLE_ADAPTER, "fd5a:5052::3", &["svc:one"], "actor-1");
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/services/svc:one")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sd: ServiceDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(sd.service_name, "svc:one");
        assert_eq!(sd.zpr_addr, "fd5a:5052::3");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/services/no-such-service")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/hosts/{name} with a resolve-only key (zipline#54): 200 with
    /// a HostDescriptor for a claimed name, 404 for an unclaimed one, and 404
    /// for an invalid label (never claimable — #53 rejects it at claim time,
    /// so it is the same "not in the index" answer, no new error surface).
    #[tokio::test]
    async fn test_get_host_resolve_key_ok_and_unknown_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let mut adapter = make_adapter_actor_defexp("fd5a:5052::3", "host-cn-1");
        adapter
            .add_attribute(Attribute::builder("device.hostname").values(&["somename"]))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/hosts/somename")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let hd: HostDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(hd.hostname, "somename");
        assert_eq!(hd.zpr_addr, "fd5a:5052::3");
        assert_eq!(hd.actor_cn, "host-cn-1");

        // Unclaimed and invalid labels get the same "not in the index" 404.
        for path in ["/admin/hosts/unclaimed", "/admin/hosts/Not_A_Label"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "for {path}");
        }
    }

    /// GET /admin/hosts/{name} while the holder is departing (PR #26 review):
    /// `ActorRepo::clean_up` deletes the actor's base record before releasing
    /// its `host:<NAME>` entries, so the hostname index can name a holder
    /// whose record is already gone. That window must read as a miss — 404,
    /// the same answer as an unclaimed name — never a 200 carrying a dead
    /// ZPR address and an empty `actor_cn`.
    #[tokio::test]
    async fn test_get_host_missing_holder_is_not_found() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let mut adapter = make_adapter_actor_defexp("fd5a:5052::3", "host-cn-1");
        adapter
            .add_attribute(Attribute::builder("device.hostname").values(&["somename"]))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        // Reproduce the mid-departure window: the base record is deleted
        // (clean_up's first pipeline) while the host:<NAME> entry is still
        // in the index (released later in clean_up).
        asm.state_db.del("actor:fd5a-5052--3").await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/hosts/somename")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/hosts/{name} sits on the resolve surface (zipline#54): like
    /// the two service-resolution endpoints it is gated by the existing
    /// `can_resolve()`, which admits ANY active key — so a read key gets the
    /// endpoint's normal behavior (200), exactly as it does on /admin/services.
    ///
    /// NOTE: the approved plan's RED list said "read key -> 403" here, but that
    /// contradicts the same plan's GREEN step (and the issue), both of which
    /// mandate the existing `can_resolve()` (admin_apikeys.rs) — a gate that
    /// returns true for every active key. The mechanism wins; deviation
    /// recorded on the issue and in the PR.
    #[tokio::test]
    async fn test_get_host_read_key_allowed() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let mut adapter = make_adapter_actor_defexp("fd5a:5052::3", "host-cn-1");
        adapter
            .add_attribute(Attribute::builder("device.hostname").values(&["somename"]))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/hosts/somename")
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let hd: HostDescriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(hd.zpr_addr, "fd5a:5052::3");
    }

    /// GET /admin/actors/{addr} surfaces hostname_conflicts (zipline#54):
    /// after two actors claim the same name, the loser's descriptor carries
    /// the refused value and the winner's carries an empty vector.
    #[tokio::test]
    async fn test_get_actor_hostname_conflicts() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_r_key(&asm);
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        let mut winner = make_adapter_actor_defexp("fd5a:5052::3", "winner");
        winner
            .add_attribute(Attribute::builder("device.hostname").values(&["somename"]))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&winner, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();
        let mut loser = make_adapter_actor_defexp("fd5a:5052::4", "loser");
        loser
            .add_attribute(Attribute::builder("device.hostname").values(&["somename"]))
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&loser, node.get_zpr_addr().unwrap(), &Default::default())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for (addr, expected) in [
            ("fd5a:5052::3", Vec::<String>::new()),
            ("fd5a:5052::4", vec!["somename".to_string()]),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/admin/actors/{addr}"))
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "for {addr}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let descriptor: ActorDescriptor = serde_json::from_slice(&body).unwrap();
            assert_eq!(descriptor.hostname_conflicts, expected, "for {addr}");
        }
    }

    /// A resolve-only key is least-privilege (zipline#36): every read
    /// endpoint other than the resolve surface stays 403. The list includes
    /// the per-item reads (zipline#54): the perm gate runs before any path
    /// parsing, so even a malformed address is a 403 for this key.
    #[tokio::test]
    async fn test_read_endpoints_resolve_key_forbidden() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for path in [
            "/admin/visas",
            "/admin/visas/denies",
            "/admin/visas/1",
            "/admin/actors",
            "/admin/actors/fd5a:5052::10",
            "/admin/actors/fd5a:5052::10/visas",
            "/admin/nodes/fd5a:5052::10/visas",
            "/admin/policies",
            "/admin/policies/curr",
            "/admin/network",
            "/admin/stats",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "for {path}");
        }
    }

    /// A resolve-only key may not flush a trusted service (zipline#36): the
    /// write gate stays closed and the flush counter never moves.
    #[tokio::test]
    async fn test_flush_service_cache_resolve_key_forbidden() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let svc = register_flush_counting_service(&asm);
        let api_key = setup_test_api_resolve_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/services/{FLUSH_TS_ID}/cache"))
                    .header("X-API-Key", &api_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(svc.flushes.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// A resolve-only key may not touch the auth-revocation surface
    /// (zipline#36): every /admin/authrevoke route returns 403, not the
    /// handler's normal (stub) behavior. Guards the guarantee that resolve
    /// keys reach only the two service-resolution GETs.
    #[tokio::test]
    async fn test_authrevoke_endpoints_resolve_key_forbidden() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_resolve_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        for (method, path) in [
            ("GET", "/admin/authrevoke"),
            ("GET", "/admin/authrevoke/some-id"),
            ("POST", "/admin/authrevoke/some-id"),
            ("POST", "/admin/authrevoke/clear"),
            ("DELETE", "/admin/authrevoke/some-id"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("X-API-Key", &api_key)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "for {method} {path}"
            );
        }
    }

    // ---- bootstrap-key revocation endpoints (zipline#136) ----

    use crate::db::BootstrapDenylist;
    use crate::test_helpers::make_adapter_actor;
    use crate::vss::VssCmd;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// Add an adapter docked at `node`, admitted by bootstrap under `cn`.
    async fn add_bootstrap_adapter(asm: &Arc<Assembly>, zpr_addr: &str, node: &IpAddr, cn: &str) {
        let mut actor = make_adapter_actor(zpr_addr, cn, Duration::from_secs(3600));
        actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(crate::config::VS_AUTH_EXPIRATION)
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor, node, &Default::default())
            .await
            .unwrap();
    }

    /// Install a fake VSS handle for `node` that acks every revoke, recording
    /// the address batches it saw.
    fn install_acking_vss(asm: &Arc<Assembly>, node: IpAddr) -> Arc<Mutex<Vec<Vec<IpAddr>>>> {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<VssCmd>(8);
        asm.vss_mgr.insert_test_handle(node, cmd_tx);
        let revokes = Arc::new(Mutex::new(Vec::new()));
        let revokes_task = revokes.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx) => {
                        revokes_task.lock().unwrap().push(addrs.clone());
                        let _ = resp_tx.send(Ok(addrs.len()));
                    }
                    VssCmd::RequestAuthsByZprAddr(addrs, resp_tx) => {
                        let _ = resp_tx.send(Ok(addrs.len()));
                    }
                    _ => {}
                }
            }
        });
        revokes
    }

    /// One admin request with an optional JSON body; returns the response.
    async fn admin_request(
        app: &Router,
        method: &str,
        path: &str,
        api_key: &str,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("X-API-Key", api_key);
        let request = match body {
            Some(json) => builder
                .header("content-type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        app.clone().oneshot(request).await.unwrap()
    }

    /// POST /admin/authrevoke/{cn} (zipline#136): the CN lands on the
    /// persisted denylist, every actor it admitted is revoked immediately
    /// through the revoke pipeline (the docking node's VSS sees the batch,
    /// the actors are gone), actors under other CNs are untouched, and the
    /// response names the revoked actors.
    #[tokio::test]
    async fn test_authrevoke_add_revokes_actors_immediately() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let node: IpAddr = "fd5a:5052::61".parse().unwrap();
        let bad: IpAddr = "fd5a:5052::62".parse().unwrap();
        let good: IpAddr = "fd5a:5052::63".parse().unwrap();
        let node_actor =
            make_node_actor_defexp("fd5a:5052::61", "node-ar", "[fd5a:5052::161]:1234");
        asm.actor_mgr
            .add_node(&node_actor, false, &Default::default())
            .await
            .unwrap();
        add_bootstrap_adapter(&asm, "fd5a:5052::62", &node, "laptop-7.zpr").await;
        add_bootstrap_adapter(&asm, "fd5a:5052::63", &node, "innocent.zpr").await;
        let revokes = install_acking_vss(&asm, node);

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = admin_request(
            &app,
            "POST",
            "/admin/authrevoke/laptop-7.zpr",
            &api_key,
            Some(serde_json::json!({"ty": "bootstrap", "cn": "laptop-7.zpr"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp["cn"], "laptop-7.zpr");
        assert_eq!(resp["ty"], "bootstrap");
        assert!(resp["id"].as_u64().is_some(), "the entry id is numeric");
        let revoked: Vec<String> = resp["revoked"]
            .as_array()
            .expect("revoked is an array")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            revoked,
            vec![bad.to_string()],
            "the response lists exactly the actors the CN admitted"
        );

        // The revoke went through the pipeline (no deadline wait) and only
        // the denylisted CN's actor is gone.
        assert_eq!(revokes.lock().unwrap().as_slice(), &[vec![bad]]);
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&bad)
                .await
                .unwrap()
                .is_none(),
            "the revoked actor must be gone"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&good)
                .await
                .unwrap()
                .is_some(),
            "an actor under another CN must survive"
        );

        // And the CN is persisted on the denylist.
        assert!(
            BootstrapDenylist::new(asm.state_db.clone())
                .contains("laptop-7.zpr")
                .await
                .unwrap(),
            "the CN must be on the persisted denylist"
        );
    }

    /// The denylist read surface (zipline#136): GET lists the entry ids, GET
    /// {id} returns the descriptor, DELETE {id} removes exactly that entry,
    /// and POST clear empties the list.
    #[tokio::test]
    async fn test_authrevoke_list_get_delete_clear_lifecycle() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        // Two entries via the API (no connected actors needed).
        for cn in ["laptop-7.zpr", "sensor-3.zpr"] {
            let response = admin_request(
                &app,
                "POST",
                &format!("/admin/authrevoke/{cn}"),
                &api_key,
                Some(serde_json::json!({"ty": "bootstrap", "cn": cn})),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "add {cn}");
        }

        // GET /admin/authrevoke lists both ids.
        let response = admin_request(&app, "GET", "/admin/authrevoke", &api_key, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 2, "both entries are listed");
        let ids: Vec<u64> = entries.iter().map(|e| e["id"].as_u64().unwrap()).collect();

        // GET /admin/authrevoke/{id} returns the descriptor.
        let response = admin_request(
            &app,
            "GET",
            &format!("/admin/authrevoke/{}", ids[0]),
            &api_key,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let desc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(desc["ty"], "bootstrap");
        assert!(
            desc["cn"]
                .as_str()
                .is_some_and(|cn| cn == "laptop-7.zpr" || cn == "sensor-3.zpr"),
            "the descriptor names a denylisted cn, got {desc}"
        );

        // DELETE removes exactly that entry.
        let response = admin_request(
            &app,
            "DELETE",
            &format!("/admin/authrevoke/{}", ids[0]),
            &api_key,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = admin_request(
            &app,
            "GET",
            &format!("/admin/authrevoke/{}", ids[0]),
            &api_key,
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a removed entry is gone"
        );
        let response = admin_request(&app, "GET", "/admin/authrevoke", &api_key, None).await;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 1, "the other entry survives");

        // Clear empties the list.
        let response = admin_request(&app, "POST", "/admin/authrevoke/clear", &api_key, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = admin_request(&app, "GET", "/admin/authrevoke", &api_key, None).await;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(entries.is_empty(), "clear must empty the denylist");
        assert!(
            !BootstrapDenylist::new(asm.state_db.clone())
                .contains("sensor-3.zpr")
                .await
                .unwrap()
        );
    }

    /// Error shapes (zipline#136): a body whose `ty` is not `bootstrap` or
    /// whose `cn` disagrees with the path is a 400; a non-numeric id on
    /// GET/DELETE is a 400; an unknown id is a 404.
    #[tokio::test]
    async fn test_authrevoke_bad_requests() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let api_key = setup_test_api_rw_key(&asm);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        // ty must be "bootstrap".
        let response = admin_request(
            &app,
            "POST",
            "/admin/authrevoke/laptop-7.zpr",
            &api_key,
            Some(serde_json::json!({"ty": "oidc", "cn": "laptop-7.zpr"})),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "ty != bootstrap"
        );

        // The body cn must match the path.
        let response = admin_request(
            &app,
            "POST",
            "/admin/authrevoke/laptop-7.zpr",
            &api_key,
            Some(serde_json::json!({"ty": "bootstrap", "cn": "other.zpr"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "cn mismatch");

        // Nothing was added by the rejected requests.
        assert!(
            BootstrapDenylist::new(asm.state_db.clone())
                .list()
                .await
                .unwrap()
                .is_empty(),
            "a rejected add must not touch the denylist"
        );

        for (method, path, expected) in [
            (
                "GET",
                "/admin/authrevoke/not-a-number",
                StatusCode::BAD_REQUEST,
            ),
            (
                "DELETE",
                "/admin/authrevoke/not-a-number",
                StatusCode::BAD_REQUEST,
            ),
            ("GET", "/admin/authrevoke/9999", StatusCode::NOT_FOUND),
            ("DELETE", "/admin/authrevoke/9999", StatusCode::NOT_FOUND),
        ] {
            let response = admin_request(&app, method, path, &api_key, None).await;
            assert_eq!(response.status(), expected, "for {method} {path}");
        }
    }
}

/// End-to-end guard on the admin actor surface (zipline#33, A4 — final
/// sub-issue of zipline#29).
///
/// This exercises the REAL admin HTTPS server — `start_admin_server` with
/// rustls TLS, the API-key middleware reading a `vsapikey`-format keys file,
/// and the real router — over the FakeDb-backed test assembly, after an
/// OIDC-only connect driven through the real connect entry point
/// (`authenticate_adapter_or_node`). The connected actor is the exact defect
/// class of the original report (A1): it authenticates successfully and has
/// **no CN**.
///
/// The two assertions come verbatim from the issue:
///  1. `GET /admin/actors` contains an entry whose `zpr_addr` is the
///     connected actor's address, with a **null** `cn`.
///  2. `GET /admin/actors/<that address>` returns 200 and a descriptor
///     carrying the actor's `user.*` attributes.
///
/// Responses are asserted through `serde_json::Value` rather than the
/// admin-api-types structs, so this module compiles unchanged against pre-A2
/// revisions of the server — which is what makes the revert-RED proof against
/// `e1b7c2d` possible (quoted in the PR): there, `GET /admin/actors` returns
/// CN entries and silently skips the CN-less actor, and
/// `GET /admin/actors/{addr}` is CN-keyed so the address lookup misses.
#[cfg(test)]
mod e2e_actor_guard {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken as jwt;
    use serde_json::{Value, json};

    use libeval::attribute::key;
    use zpr::vsapi_types::{AuthBlob, ConnectRequest, OidcBlob, PublicKey};

    use super::start_admin_server;
    use crate::admin_apikeys::{ApiKeyRecord, KeyStatus, KeysFile, Permission, ReloadableApiKeys};
    use crate::apikey::sha256_hex;
    use crate::assembly::Assembly;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::oidc::mint::{TEST_KID, test_rsa_pem, token as mint_token};
    use crate::test_helpers::{
        make_node_actor_defexp, make_oidc_connect_policy, make_test_oidc_config,
    };

    /// Issuer/client of the fixture config ([make_test_oidc_config]).
    const ISSUER: &str = "https://accounts.google.com";
    const CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    const NONCE: &str = "e2e-guard-nonce";
    const SUB: &str = "e2e-guard-sub-33";
    /// The ZPR address of the node the adapter connects through.
    const NODE_ADDR: &str = "fd5a:5052:3000::1";

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build the FakeDb assembly with the admin API keys loaded from a real
    /// on-disk keys file (the same TOML format `vsapikey` writes), returning
    /// the assembly and the key string for the `X-API-Key` header. The key
    /// string is assembled by hand in the documented `zpr_vsapi.<id>.<secret>`
    /// wire format, so this covers the real parse-and-hash path in the
    /// middleware rather than a test-only insertion hook.
    async fn make_asm_with_keyfile(dir: &Path) -> (Arc<Assembly>, String) {
        let secret_bytes: [u8; 32] = (100u8..132).collect::<Vec<_>>().try_into().unwrap();
        let key_id_hex = format!("{:08x}", 0x33a4_e2e1u32);
        let header_value = format!(
            "zpr_vsapi.{key_id_hex}.{}",
            URL_SAFE_NO_PAD.encode(secret_bytes)
        );
        let record = ApiKeyRecord {
            owner: "e2e".to_string(),
            permission: Permission::Read,
            status: KeyStatus::Active,
            created: "2026-09-15".to_string(),
            secret_hash: sha256_hex(&secret_bytes).unwrap(),
            description: "zipline#33 e2e guard".to_string(),
            service: None,
        };
        let mut keys = HashMap::new();
        keys.insert(key_id_hex, record);
        let keys_path = dir.join("vs_keys.toml");
        std::fs::write(&keys_path, toml::to_string(&KeysFile { keys }).unwrap()).unwrap();

        let mut asm = new_assembly_for_tests(None).await;
        asm.admin_api_keys = Arc::new(ReloadableApiKeys::new_from_file(keys_path, false).unwrap());
        (Arc::new(asm), header_value)
    }

    /// Drive an OIDC-only connect through the real connect path and store the
    /// resulting actor the way `authorize_connect` does. Returns the actor's
    /// assigned ZPR address. The actor authenticates with an OIDC blob only —
    /// no bootstrap key, no CN claim (the real wire shape of a
    /// bootstrap-key-less adapter) — so the stored actor has NO `cn`.
    async fn connect_oidc_only_actor(asm: &Arc<Assembly>) -> IpAddr {
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                43200,
                &["sub -> user.oidc-subject", "email -> user.email"],
                &["sub"],
                make_test_oidc_config(),
                &[],
                &[],
            ))
            .await
            .expect("OIDC test policy must install");

        // The node the adapter docks through, stored like a connected node.
        let node_addr: IpAddr = NODE_ADDR.parse().unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp(NODE_ADDR, "node-a", "10.0.0.1:1"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();

        let claims = json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": SUB,
            "exp": unix_now() + 3600,
            "iat": unix_now(),
            "nonce": NONCE,
            "email": "e2e@example.com",
            "email_verified": true,
        });
        let signing_key = jwt::EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        let id_token = mint_token(claims, TEST_KID, jwt::Algorithm::RS256, &signing_key);

        let req = ConnectRequest {
            blobs: vec![AuthBlob::Oidc(OidcBlob {
                issuer: ISSUER.to_string(),
                id_token,
                nonce: NONCE.to_string(),
            })],
            // A bootstrap-key-less adapter sends no claims at all.
            claims: Vec::new(),
            substrate_addr: "127.0.0.1".parse().unwrap(),
            dock_interface: 0,
            a2a_dh_public_key: PublicKey::new(&[7u8; 32]),
        };

        let actor = asm
            .cc
            .authenticate_adapter_or_node(asm.clone(), req, &node_addr)
            .await
            .expect("OIDC-only connect must authorize");
        assert!(
            actor.get_attribute(key::CN).is_none(),
            "fixture must be CN-less; the defect class is a CN-less actor"
        );
        // Store it exactly the way vsapi_worker::authorize_connect does.
        asm.actor_mgr
            .add_adapter_via_node(&actor, &node_addr, &Default::default())
            .await
            .unwrap();
        *actor
            .get_zpr_addr()
            .expect("connect must assign a ZPR address")
    }

    /// Start the real HTTPS admin server (self-signed cert written to disk,
    /// exactly the `admin-tls-cert.pem`/`admin-tls-key.pem` shape the VS
    /// writes out) and return the base URL plus a client trusting that cert.
    /// The server is verified up and serving OUR cert before this returns.
    ///
    /// Port selection under cargo's parallel test harness is inherently racy:
    /// the OS-assigned probe listener must be dropped before
    /// `start_admin_server` re-binds the port, and another test or process can
    /// claim it in that gap, panicking the server task. `start_admin_server`
    /// takes only a `SocketAddr` — threading a pre-bound listener through it
    /// would be a production-code change, and zipline#33 is docs-and-tests
    /// only — so instead the race is made detectable-and-retryable here: a
    /// lost bind panics the spawned task, `JoinHandle::is_finished()` exposes
    /// that, and the loop probes a fresh port. A successful response on the
    /// cert-pinned client proves the port is served by THIS server (no other
    /// process holds this test's freshly generated key), so the returned base
    /// URL can never point at a foreign squatter.
    async fn start_real_admin_server(asm: &Arc<Assembly>, dir: &Path) -> (String, reqwest::Client) {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_path = dir.join("admin-tls-cert.pem");
        let key_path = dir.join("admin-tls-key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        for _ in 0..10 {
            // Ephemeral port: bind-and-release, then hand it to the real server.
            let port = {
                let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                probe.local_addr().unwrap().port()
            };
            let listen: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
            let asm = asm.clone();
            let (key_path, cert_path) = (key_path.clone(), cert_path.clone());
            let handle = tokio::spawn(async move {
                start_admin_server(&key_path, &cert_path, listen, &asm).await;
            });

            let base = format!("https://127.0.0.1:{port}");
            for _ in 0..250 {
                if handle.is_finished() {
                    // The bind panicked: something else claimed the port in
                    // the probe-to-bind gap. Retry with a fresh port.
                    break;
                }
                // Any HTTP status back (401 — no API key) proves the TLS
                // server on `port` presented our pinned cert; a connect or
                // handshake error means not up yet (or a foreign squatter,
                // in which case our task's bind panic ends the inner loop).
                if client
                    .get(format!("{base}/admin/stats"))
                    .send()
                    .await
                    .is_ok()
                {
                    return (base, client);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                handle.is_finished(),
                "admin server on {base} neither served nor failed within 5s"
            );
        }
        panic!("could not win a free port for the admin server in 10 attempts");
    }

    /// GET `url` with the API key, retrying while the server task binds.
    async fn admin_get(client: &reqwest::Client, url: &str, api_key: &str) -> reqwest::Response {
        for _ in 0..100 {
            match client.get(url).header("X-API-Key", api_key).send().await {
                Ok(resp) => return resp,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        panic!("admin server never became reachable at {url}");
    }

    /// Issue assertion 1: after an OIDC-only connect, `GET /admin/actors`
    /// (over real HTTPS, real API-key auth) lists the actor keyed by its ZPR
    /// address, with a null `cn`. This is the check that would have caught
    /// the original report: an actor that connects but is invisible to every
    /// operator-facing tool.
    #[tokio::test]
    async fn e2e_cnless_actor_listed_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let (asm, api_key) = make_asm_with_keyfile(dir.path()).await;
        let actor_addr = connect_oidc_only_actor(&asm).await;
        let (base, client) = start_real_admin_server(&asm, dir.path()).await;

        let resp = admin_get(&client, &format!("{base}/admin/actors"), &api_key).await;
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        let list = body
            .as_array()
            .unwrap_or_else(|| panic!("GET /admin/actors must return a JSON array, got: {body}"));
        let addr_str = actor_addr.to_string();
        let entry = list
            .iter()
            .find(|e| e.get("zpr_addr").and_then(Value::as_str) == Some(addr_str.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "connected actor {addr_str} missing from GET /admin/actors \
                     (the A1 defect: connected but invisible): {body}"
                )
            });
        assert!(
            entry.get("cn").is_some_and(Value::is_null),
            "CN-less actor must carry a null cn, got: {entry}"
        );
    }

    /// Issue assertion 2: `GET /admin/actors/<address>` returns 200 and a
    /// descriptor carrying the actor's `user.*` attributes (the mapped OIDC
    /// claims), with a null `cn`.
    #[tokio::test]
    async fn e2e_actor_descriptor_fetched_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let (asm, api_key) = make_asm_with_keyfile(dir.path()).await;
        let actor_addr = connect_oidc_only_actor(&asm).await;
        let (base, client) = start_real_admin_server(&asm, dir.path()).await;

        let resp = admin_get(
            &client,
            &format!("{base}/admin/actors/{actor_addr}"),
            &api_key,
        )
        .await;
        assert_eq!(
            resp.status(),
            200,
            "GET /admin/actors/{{addr}} must resolve the actor by ZPR address"
        );
        let desc: Value = resp.json().await.unwrap();
        assert_eq!(
            desc.get("zpr_addr").and_then(Value::as_str),
            Some(actor_addr.to_string().as_str())
        );
        assert!(
            desc.get("cn").is_some_and(Value::is_null),
            "OIDC-only actor has no CN; descriptor must say so: {desc}"
        );
        let attrs = desc
            .get("attrs")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("descriptor must carry attrs: {desc}"));
        let sub_attr = attrs
            .iter()
            .find(|a| a.get("key").and_then(Value::as_str) == Some("user.oidc-subject"))
            .unwrap_or_else(|| panic!("descriptor must carry the user.* attributes: {desc}"));
        assert_eq!(
            sub_attr
                .get("value")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .and_then(Value::as_str),
            Some(SUB)
        );
    }

    /// Not an assertion-carrying test: the server-side launcher for
    /// `integration-test/admin-actor-test.sh`, which drives the same two
    /// checks through the `vs-admin` CLI. Ignored by default so `cargo test`
    /// never runs it; the script invokes it by exact name with `--ignored`.
    ///
    /// When `ZPR_E2E_HARNESS_DIR` is set, this builds the exact fixture the
    /// tests above use (FakeDb assembly, on-disk keys file, OIDC-only
    /// connected actor, real HTTPS admin server — no ValKey, no root, no
    /// docker), probes the server for readiness, writes `harness.json`
    /// (`base_url`, `api_key`, `actor_addr`; the TLS cert is already in the
    /// directory as `admin-tls-cert.pem`), and serves until `<dir>/stop`
    /// appears or a 120 s safety timeout expires.
    #[tokio::test]
    #[ignore = "harness launcher for integration-test/admin-actor-test.sh, not a test"]
    async fn serve_admin_for_cli_harness() {
        let dir = match std::env::var("ZPR_E2E_HARNESS_DIR") {
            Ok(d) => std::path::PathBuf::from(d),
            // Not invoked by the harness script: nothing to do.
            Err(_) => return,
        };
        let (asm, api_key) = make_asm_with_keyfile(&dir).await;
        let actor_addr = connect_oidc_only_actor(&asm).await;
        let (base, client) = start_real_admin_server(&asm, &dir).await;

        // Only publish the manifest once the server actually answers, so the
        // script never races the TLS listener coming up.
        let probe = admin_get(&client, &format!("{base}/admin/actors"), &api_key).await;
        assert_eq!(probe.status(), 200, "harness server must be up and keyed");

        let manifest = json!({
            "base_url": base,
            "api_key": api_key,
            "actor_addr": actor_addr.to_string(),
        });
        // Write-then-rename so the script never reads a half-written manifest.
        let tmp = dir.join("harness.json.tmp");
        std::fs::write(&tmp, manifest.to_string()).unwrap();
        std::fs::rename(&tmp, dir.join("harness.json")).unwrap();

        let stop = dir.join("stop");
        for _ in 0..1200 {
            if stop.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
