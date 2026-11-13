//! ConnectionControl is for handling new connections to the ZPRnet.
//! Nodes and adapters.  The two steps to a connection are authentication
//! and then authorization via policy.
//!
//! Nodes are authenticated using keys found in policy that are tied to
//! their CN.
//!
//! Adapters may be authenticated like nodes (using booststrap keys in policy),
//! or more commonly they will be authenticated by an authentication service
//! on th network.
//!
//! The authorization step runs through policy and attaches any special attributes
//! to the actor -- things like services offered.
//!
//! Finally, if everything goes well an address is assigned and the actor is
//! returned.

use chrono::Utc;
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::usize;
use tracing::{debug, error, info, warn};

use libeval::actor::{Actor, Role};
use libeval::attribute::{Attribute, AttributeSource, key};
use libeval::eval::EvalContext;
use libeval::policy::Policy;

use zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::{
    ApiResponseError, AuthBlob, ChallengeAlg, Claim, ConnectRequest, ErrorCode, OidcBlob,
    PublicKey, SelfSignedBlob,
};

use crate::assembly::Assembly;
use crate::auth;
use crate::config;
use crate::error::ServiceError;
use crate::logging::targets::CC;
use crate::login_nonce::LoginNonceStore;
use crate::net_mgr;
use crate::oidc::{NonceExpectation, OidcError, OidcTrustedService, validate_id_token};
use crate::policy_mgr::PolicySnapshot;
use crate::topology_mgr::TopoOps;
use crate::trusted_services::{TrustedServicesMgr, derive_user_authority, lookup_identities};
use crate::visa_reconciler::{SweepReason, revalidate_visas};
use crate::vss_mgr::VssHandle;

// TODO: move to libeval
const CLASS_DEVICE: &str = "device";
const CLASS_USER: &str = "user";
const CLASS_SERVICE: &str = "service";

pub(crate) const ATTR_KEY_VS_IDENT: &str = "zpr.vs.bootstrap.ident";

/// Expiration window for every bootstrap (RSA-verified) `device.zpr.authority`
/// stamp (zipline#119): bootstrap authentication does not expire, so every
/// bootstrap stamp gets the same far-future window the visa service's own
/// self-authentication always got ([config::VS_AUTH_EXPIRATION]). A bootstrap
/// key is policy state, not a session credential — removing the key from
/// policy is the revocation path — and dead nodes are culled by last-seen age
/// at startup (`actor_mgr::refresh_state`), not by authentication expiry.
fn bootstrap_authority_expiration() -> Duration {
    config::VS_AUTH_EXPIRATION
}

/// Expiration for the `zpr.vs.bootstrap.ident` identity token (zipline#119):
/// the minimum of the actor's device/user authority expiries. The token is a
/// proxy for those credentials, so it must never gate the actor's
/// authentication window on its own — `get_authentication_expiration()` takes
/// the minimum across authority AND identity attributes, and an ident stamped
/// shorter than the authorities would cap the actor at its own lifetime.
/// Falls back to [config::DEFAULT_AUTH_EXPIRATION] when the actor carries no
/// authority attribute at all.
fn vs_ident_expiration(actor: &Actor) -> SystemTime {
    [key::DEVICE_AUTHORITY, key::USER_AUTHORITY]
        .iter()
        .filter_map(|k| actor.get_attribute(k).map(|a| a.get_expires()))
        .min()
        .unwrap_or_else(|| SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
}

/// Identity namespace one auth blob authenticates. A connection may present at most
/// one blob per namespace (zipline#7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Namespace {
    Device,
    User,
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Namespace::Device => write!(f, "device"),
            Namespace::User => write!(f, "user"),
        }
    }
}

/// What one successfully-validated auth blob contributes to the connection: the
/// claims it authenticated and the identity namespace it covers (zipline#7).
/// An OIDC blob additionally carries the session anchors to record once the
/// actor's session id (its ZPR address) exists — anchors are per actor
/// session, not per subject (PR #19 review).
pub(crate) struct BlobOutcome {
    pub(crate) authd: Vec<Attribute>,
    #[allow(dead_code)] // read by the connect path's duplicate-namespace check
    pub(crate) namespace: Namespace,
    pub(crate) session: Option<OidcSessionRecord>,
}

/// The dual-clock renewal anchors one validated OIDC blob yields, pending the
/// actor's session id. The connect and reauthorize paths call
/// [OidcSessionRecord::record] once the ZPR address is known (and, on reauth,
/// only after the whole renewal succeeded, so a failed policy re-run does not
/// advance the anchors).
pub(crate) struct OidcSessionRecord {
    svc: Arc<OidcTrustedService>,
    sub: String,
    auth_time: SystemTime,
    iat: SystemTime,
    expires: SystemTime,
}

impl OidcSessionRecord {
    /// Record these anchors for the actor session behind `zpr_addr`.
    pub(crate) fn record(&self, zpr_addr: &IpAddr) {
        self.svc.record_session(
            &zpr_addr.to_string(),
            &self.sub,
            self.auth_time,
            self.iat,
            self.expires,
        );
    }
}

/// What [recheck_before_commit] found about the policy generation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommitRecheck {
    /// The live generation is the one the write was prepared under.
    Current,
    /// A policy install landed since the write was prepared; the caller
    /// refuses, or (a logout) commits a reduced actor instead.
    PolicyMoved,
}

/// The one commit-time recheck for every write to a node's own actor that was
/// prepared from an earlier read (#63 review audit): reauthorize (login,
/// renewal, logout and its fallbacks), the node authenticate persist, the
/// login-nonce mint and the attribute-refresh write. The caller holds
/// [crate::policy_mgr::PolicyMgr::node_commit_lock] -- which every writer of a node's own
/// actor takes -- and calls this right before it commits:
///
/// - `expected_session`: when `Some`, the stored actor must still exist and
///   carry exactly that `zpr.session`; otherwise the node re-authenticated (or
///   was disconnected) since the write was prepared, and committing would
///   write an old session or a removed actor back. Generic `AuthError`.
/// - `prepared_vinst`: when `Some`, the policy generation the write was
///   prepared (validated, authorized, enriched) under. A different live
///   generation is [CommitRecheck::PolicyMoved]: that install's reconciliation
///   may already have looked at the pre-write actor.
pub(crate) async fn recheck_before_commit(
    asm: &Assembly,
    zpr_addr: &IpAddr,
    expected_session: Option<&str>,
    prepared_vinst: Option<u64>,
) -> Result<CommitRecheck, ServiceError> {
    if let Some(expected) = expected_session {
        let stored = asm.actor_mgr.get_actor_by_zpr_addr(zpr_addr).await?;
        let stored_session = stored
            .as_ref()
            .and_then(|a| a.get_attribute(key::SESSION))
            .and_then(|a| a.get_single_value().ok());
        if stored_session.as_deref() != Some(expected) {
            info!(target: CC, "write to {zpr_addr} refused: the node re-authenticated or left while it was prepared");
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::AuthError,
                "authentication rejected",
            )
            .into());
        }
    }
    if let Some(vinst) = prepared_vinst
        && asm.policy_mgr.get_current_snapshot().vinst() != vinst
    {
        info!(target: CC, "write to {zpr_addr}: policy changed while it was prepared");
        return Ok(CommitRecheck::PolicyMoved);
    }
    Ok(CommitRecheck::Current)
}

/// The refusal for a write whose policy generation moved before it committed:
/// `temporarilyUnavailable` with a short retry, so the node repeats the
/// operation under the new policy (#63 review). A login also needs a fresh
/// nonce, since the old one is spent.
pub(crate) fn policy_moved_error() -> ServiceError {
    ApiResponseError::new(
        ErrorCode::TemporarilyUnavailable,
        "policy changed; retry",
        config::LOGIN_POLICY_CHANGED_RETRY_SECS,
    )
    .into()
}

/// The `zpr.vinst` an actor was last authorized under, if stamped.
pub(crate) fn actor_prepared_vinst(actor: &Actor) -> Option<u64> {
    actor
        .get_attribute(key::VINST)
        .and_then(|a| a.get_single_value().ok())
        .and_then(|v| v.parse().ok())
}

/// Whether a `reauthorize` targets the calling node's OWN actor: the target
/// address is the caller's address and the actor there is a node
/// (zl-zipline#232). Only such a request may change the `user` namespace.
fn is_self_renewal(actor: &Actor, zpr_addr: &IpAddr, connect_via: &IpAddr) -> bool {
    zpr_addr == connect_via && actor.is_node()
}

/// Decide what a `reauthorize` blob set does to the actor's `user` namespace,
/// or `None` when the set is not allowed (a `paramError`). This is the
/// vs.capnp "Re-Authorization" contract (zl-zipline#232):
///
/// - the `device` blob is present exactly when the actor holds the device
///   authority -- never gained, never dropped, always re-proved;
/// - an adapter (or any non-self target) keeps the exact-set rule: an OIDC
///   blob is present exactly when the actor's user authority is
///   credential-backed;
/// - a node renewing its own actor may also gain the user namespace (OIDC
///   blob, no user authority at all) or drop it (no OIDC blob, any user
///   authority -- including one whose OIDC provider policy no longer
///   declares). A gain on an actor whose user authority was synthesized by
///   trusted-service enrichment is refused: one user authority per actor.
fn classify_user_namespace_change(
    has_ss_blob: bool,
    has_oidc_blob: bool,
    actor_has_device: bool,
    user_credential_backed: bool,
    actor_has_user_authority: bool,
    self_renewal: bool,
) -> Option<UserNamespaceChange> {
    if has_ss_blob != actor_has_device {
        return None;
    }
    match (has_oidc_blob, user_credential_backed) {
        // A node's own device-only renewal drops ANY user authority it holds
        // (#63 review): an OIDC authority whose provider policy no longer
        // declares is not credential-backed any more, yet its attributes must
        // not survive. An authority synthesized by trusted-service enrichment
        // from the device identity is re-derived by the policy re-run, so
        // dropping it costs nothing but the visa sweep.
        (false, _) if self_renewal && actor_has_device && actor_has_user_authority => {
            Some(UserNamespaceChange::Drop)
        }
        (true, true) | (false, false) => Some(UserNamespaceChange::Keep),
        (true, false) if self_renewal && actor_has_device && !actor_has_user_authority => {
            Some(UserNamespaceChange::Gain)
        }
        _ => None,
    }
}

/// The actor a logout persists when its policy re-run failed (#63 review): the
/// loaded actor reduced by the same carry-over rule as a normal logout
/// ([survives_logout]: only internal-source attributes, nothing in `user.`),
/// so no trusted-service attribute -- keyed on the dropped subject or not,
/// inside `user.*` or mapped elsewhere -- survives. Only identity keys whose
/// attribute survives are kept. The actor stays a node (its role is fixed at
/// connect) and is granted only the services a node gets from what remains.
/// Address, session, device authority, CN and VS identity token are internal
/// and unchanged; trusted-service attributes come back on the next refresh.
fn logout_without_reauthorization(actor: &Actor, policy: &Policy) -> Actor {
    let mut reduced = Actor::new();
    for attr in actor
        .attrs_iter()
        .filter(|a| survives_logout(a) || a.get_key() == key::ROLE)
    {
        let _ = reduced.add_attribute(attr.clone());
    }
    for identity_key in actor.identity_keys_iter() {
        if reduced.get_attribute(identity_key).is_some() {
            let _ = reduced.add_identity_key(usize::MAX, identity_key);
        }
    }
    let claims: Vec<Attribute> = reduced
        .attrs_iter()
        .filter(|a| !key::POLICY_STAMPED.contains(&a.get_key()))
        .cloned()
        .collect();
    reduced.set_services(policy.join_services_for_role(&claims, true));
    reduced
}

/// Whether an attribute is carried over a logout (zl-zipline#232): only
/// attributes the visa service itself stamped (internal source), and never
/// one in the `user.` namespace.
fn survives_logout(attr: &Attribute) -> bool {
    attr.get_source() == libeval::attribute::SOURCE_ZPR && !attr.get_key().starts_with("user.")
}

/// Dual-clock OIDC credential expiry (zipline#42): the renewal window
/// `iat + lifetime` (advances on refresh), capped by the fixed per-login
/// session ceiling (`auth_time + max_auth_age`; `None` = unbounded). The
/// token's `exp` is reject-only at validation and plays no part here
/// (OIDC.md: the `<ns>.zpr.authority` invariant).
pub(crate) fn compute_authority_expiry(
    iat: SystemTime,
    session_ceiling: Option<SystemTime>,
    lifetime: Duration,
) -> SystemTime {
    // Total on any representable input (PR #18 review): an `iat + lifetime`
    // sum past the representable range collapses to `iat` — fail closed (an
    // immediately-expired credential for nonsense input), never a panic.
    let renewal_expires = iat.checked_add(lifetime).unwrap_or(iat);
    match session_ceiling {
        Some(ceiling) => renewal_expires.min(ceiling),
        None => renewal_expires,
    }
}

/// The endpoint CN for logging/JWT purposes: the authenticated CN when a device blob
/// verified one, else the (unauthenticated) claimed CN, else empty.
fn authd_or_claimed_cn(authd_claims: &[Attribute], unauthd_claims: &[Attribute]) -> String {
    authd_claims
        .iter()
        .chain(unauthd_claims.iter())
        .find(|a| a.get_key() == key::CN)
        .and_then(|a| a.get_single_value().ok())
        .unwrap_or_default()
        .to_string()
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String, // Issuer eg, 'vs.zpr/<IDENT>'
    sub: String, // Subject (user id), eg 'node/<CN>'
    exp: u64,    // Expiration time (as UNIX timestamp)
    iat: u64,    // Issued at time (as UNIX timestamp)
    jti: String, // JWT ID - unique identifier for the token, can be used for revocation
}

pub struct ConnectionControl {
    jwt_key: jwt::EncodingKey,
    authority: String,
    /// Outstanding visa-service-minted OIDC login nonces (`getLoginNonce`):
    /// a node's own login on `reauthorize` must spend one (zl-zipline#232).
    pub(crate) login_nonces: LoginNonceStore,
}

/// What one `reauthorize` request does to the actor's `user` namespace
/// (zl-zipline#232; vs.capnp "Re-Authorization").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UserNamespaceChange {
    /// The namespace set is unchanged: a renewal (or a device-only actor).
    Keep,
    /// A node renewing its own actor logs a user in.
    Gain,
    /// A node renewing its own actor logs its user out.
    Drop,
}

impl ConnectionControl {
    pub fn new(vs_ident: String) -> Self {
        // massage ident into valid chars -> [a-zA-Z0-9.-_]
        let vs_ident: String = vs_ident
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let jwt_key = jwt::EncodingKey::from_secret(vs_ident.as_bytes());

        ConnectionControl {
            authority: format!("vs.zpr/{}", &vs_ident),
            jwt_key,
            login_nonces: LoginNonceStore::default(),
        }
    }

    /// VS uses this to create an "identity" token for bootstrap authenticated actors.
    ///
    /// `sub` should be 'node/<CN>' or 'adapter/<CN>'
    /// `lifetime` is how long the token is valid for.
    fn gen_jwt(&self, sub: String, lifetime: Duration) -> Result<String, ServiceError> {
        let expiration = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(lifetime.as_secs() as i64))
            .expect("valid timestamp")
            .timestamp() as u64;
        let claims = JwtClaims {
            iss: self.authority.clone(),
            sub,
            exp: expiration,
            iat: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs(),
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = jwt::encode(&jwt::Header::default(), &claims, &self.jwt_key).map_err(|e| {
            error!(target: CC, "failed to generate JWT: {}", e);
            ServiceError::Internal("JWT generation failed".into())
        })?;
        Ok(token)
    }

    /// Perform node specific authentication and run the connect request through policy.
    /// If successful you get an authenticated Actor back. This does not update our
    /// actor database.
    ///
    /// Currently a node must pass a request address and it must match policy.
    ///
    /// This does not update our actor database, or do anything with the nodes services.
    ///
    /// TODO: This needs more thought. This code path which is via the VSAPI 'authenticate' endpoint
    /// is only available to nodes, and this code assumes the node has bootstrap auth.  It is theoretically
    /// possible for a node to use external auth -- as long as it isn't the first node.
    ///
    /// This is a little odd mostly because this VSAPI authentication is the way that the
    /// first node establishes its identity (since before that there is no access to a vias service).
    ///
    /// However, it feels like once we have done that, future nodes should not have to actually
    /// authenticate with the VSAPI since they should have already authenticated just like an adapter
    /// does.
    ///
    /// See https://github.com/org-zpr/zpr-visaservice/issues/205
    ///
    /// `reported_substrate` is the substrate address the node advertised in its connect
    /// params (the address peers dial). When policy topology also declares a substrate for
    /// this node the two must agree; when it declares none (e.g. a single-node deploy with
    /// no peerings) the reported value is used as-is. Either way the resolved value becomes
    /// the node's `key::SUBSTRATE_ADDR` claim -- there is no longer a TCP-peer-address
    /// fallback (see https://github.com/org-zpr/zpr-visaservice/issues/299).
    ///
    pub async fn authenticate_node(
        &self,
        asm: Arc<Assembly>,
        challenge_presented: &[u8],
        timestamp: u64,
        cn: &str,
        challenge_response: &[u8],
        node_req_addr: IpAddr,
        reported_substrate: SocketAddr,
        a2a_dh_pubkey: Option<&PublicKey>,
    ) -> Result<Actor, ServiceError> {
        // Massage this node authentication request into something that looks like a generic
        // adapter request.

        let mut authd_claims: Vec<Attribute> = Vec::new();

        // Policy topology may declare this node's substrate address; if so the node's
        // advertised value must match it. With no topology entry (single-node deploy,
        // no peerings) the advertised value is all we have, and it is trusted operator
        // config just like a policy-declared substrate.
        let substrate_addr = match substrate_addr_from_topology(&asm, &node_req_addr) {
            Some(sa) => {
                if sa != reported_substrate {
                    return Err(ServiceError::Param(format!(
                        "substrate address mismatch: policy declares {sa}, node reported {reported_substrate}"
                    )));
                }
                sa
            }
            None => reported_substrate,
        };
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(substrate_addr.to_string()));
        match a2a_dh_pubkey.and_then(a2a_dh_pubkey_claim) {
            Some(attr) => authd_claims.push(attr),
            None => warn!(target: CC, "node {cn} sent no usable A2A DH public key"),
        }

        let mut unauthd_claims: Vec<Attribute> = Vec::new();
        unauthd_claims.push(Attribute::builder(key::ZPR_ADDR).value(node_req_addr.to_string()));
        unauthd_claims.push(Attribute::builder(key::CN).value(cn.to_string()));

        let ss_blob = SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: challenge_presented.to_vec(),
            cn: cn.to_string(),
            timestamp,
            signature: challenge_response.to_vec(),
        };

        // Built-in RSA verification is the device authority
        // (OIDC.md: the `<ns>.zpr.authority` invariant). Bootstrap
        // authentication does not expire (zipline#119).
        authd_claims.push(
            Attribute::builder(key::DEVICE_AUTHORITY)
                .expires_in(bootstrap_authority_expiration())
                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
        );

        let node_actor = self
            .authenticate_zpr_entity_rsa(asm, &ss_blob, unauthd_claims, authd_claims, 0)
            .await?;

        // We only let nodes in here.
        if !node_actor.is_node() {
            info!(target: CC, "connection not approved for cn {}: not a node", cn);
            return Err(ServiceError::AuthenticationFailed("not authorized".into()));
        }

        Ok(node_actor)
    }

    /// Confirm adapter/node authentication and then get policy authorization, resulting in an Actor if
    /// everything checks out.
    ///
    /// This is used during a connection attempt to ZPR (as opposed to the VSAPI connection which right
    /// now is serviced by [ConnectionControl::authenticate_node]).
    ///
    pub async fn authenticate_adapter_or_node(
        &self,
        asm: Arc<Assembly>,
        req: ConnectRequest,
        connect_via: &IpAddr,
    ) -> Result<Actor, ServiceError> {
        if req.blobs.is_empty() {
            return Err(ServiceError::Param(
                "at least one auth blob is required".into(),
            ));
        }

        // Only a device (self-signed) blob carries a CN, so only a connect that
        // presents one is required to claim it. A user-only login (OIDC blob, no
        // bootstrap key) has no device identity at all and the node sends no CN
        // claim for it; demanding one here would make user-only connects impossible.
        // The claim is unauthenticated either way -- it is the validated blob, not
        // the claim, that authenticates the CN.
        if req.blobs.iter().any(|blob| matches!(blob, AuthBlob::SS(_))) {
            check_required_claims(&req.claims, &[key::CN])?;
        }

        let scrubbed_claims = scrub_adapter_claims(req.claims)?;

        let mut authd_claims = Vec::new();
        authd_claims.push(Attribute::builder(key::CONNECT_VIA).value(connect_via.to_string()));
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(req.substrate_addr.to_string()));
        match a2a_dh_pubkey_claim(&req.a2a_dh_public_key) {
            Some(attr) => authd_claims.push(attr),
            None => warn!(target: CC, "adapter via {connect_via} sent no usable A2A DH public key"),
        }

        // One coherent policy view for the whole operation: blob validation,
        // trusted-service lookups, and authorization all read this snapshot,
        // so a concurrent policy update cannot validate a credential under
        // one revision and authorize it under another (PR #6 review).
        let psnap = asm.policy_mgr.get_current_snapshot();

        // Validate every presented blob (spec: presented-and-invalid fails the whole
        // connection; absent is not a failure). Each arm authenticates one identity
        // namespace and yields its authenticated claims; the first error aborts, and
        // a repeated namespace is a protocol error.
        let mut seen_namespaces: Vec<Namespace> = Vec::new();
        let mut oidc_sessions: Vec<OidcSessionRecord> = Vec::new();
        for blob in &req.blobs {
            let outcome = match blob {
                AuthBlob::SS(ssb) => match ssb.alg {
                    ChallengeAlg::RsaSha256Pkcs1v15 => {
                        // A revoked bootstrap root never authenticates, even
                        // while a stale policy still carries the key
                        // (zipline#136). Checked before signature work: the
                        // credential is administratively dead.
                        Self::check_bootstrap_denylist(&asm, &ssb.cn).await?;
                        // Built-in RSA verification is the device authority
                        // (OIDC.md: the `<ns>.zpr.authority` invariant).
                        // Bootstrap authentication does not expire (zipline#119).
                        let mut authd = vec![
                            Attribute::builder(key::DEVICE_AUTHORITY)
                                .expires_in(bootstrap_authority_expiration())
                                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
                        ];
                        authd.extend(self.authenticate_ss_blob(
                            psnap.policy(),
                            ssb,
                            &scrubbed_claims,
                        )?);
                        BlobOutcome {
                            authd,
                            namespace: Namespace::Device,
                            session: None,
                        }
                    }
                },
                AuthBlob::AC(_acb) => {
                    return Err(ServiceError::Internal(
                        "external auth not yet supported".into(),
                    ));
                }
                // A user login: validate the id_token offline against the declared
                // provider and stamp the user authority (zipline#11).
                AuthBlob::Oidc(oidc_blob) => self.authenticate_oidc_blob(&psnap, oidc_blob).await?,
            };
            if seen_namespaces.contains(&outcome.namespace) {
                return Err(ServiceError::Param(format!(
                    "duplicate {} authentication",
                    outcome.namespace
                )));
            }
            seen_namespaces.push(outcome.namespace);
            if let Some(session) = outcome.session {
                oidc_sessions.push(session);
            }
            authd_claims.extend(outcome.authd);
        }

        // Every presented blob validated -- now run through policy.
        let endpoint_cn = authd_or_claimed_cn(&authd_claims, &scrubbed_claims);
        let mut actor = self
            .authorize_connection(
                asm,
                &psnap,
                &endpoint_cn,
                scrubbed_claims,
                authd_claims,
                req.dock_interface,
            )
            .await?;

        // The actor's session id (its ZPR address) now exists: record the
        // OIDC session anchors under it, per actor session (PR #19 review).
        if let Some(addr) = actor.get_zpr_addr() {
            for session in &oidc_sessions {
                session.record(addr);
            }
        }

        // The `zpr.vs.bootstrap.ident` token follows the actor's authority
        // expiries (zipline#119): it is a proxy credential and must not gate
        // the authentication window on its own.
        let ident_expires = vs_ident_expiration(&actor);
        let jwt_lifetime = ident_expires
            .duration_since(SystemTime::now())
            .unwrap_or(config::DEFAULT_AUTH_EXPIRATION);
        let actor_jwt = if actor.is_node() {
            self.gen_jwt(format!("node/{}", endpoint_cn), jwt_lifetime)?
        } else {
            self.gen_jwt(format!("adapter/{}", endpoint_cn), jwt_lifetime)?
        };
        let _ = actor.add_attribute(
            Attribute::builder(ATTR_KEY_VS_IDENT)
                .expires(ident_expires)
                .value(actor_jwt),
        );
        let _ = actor.add_identity_key(0, ATTR_KEY_VS_IDENT);

        // Our own adapter connects late: the node self-authorizes it during bootstrap and
        // sends the real request once it has VSAPI access.
        if actor.get_cn() == Some(config::VS_CN) {
            let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
            if actor.get_zpr_addr() != Some(&vs_addr) {
                return Err(ServiceError::AuthenticationFailed(format!(
                    "visa service adapter claimed address {:?}, expected {vs_addr}",
                    actor.get_zpr_addr()
                )));
            }
            // The ordinary adapter path already stamped DEVICE_AUTHORITY with the
            // bootstrap expiration; re-add it so the (single-valued) attribute is
            // not duplicated. Both stamps share bootstrap_authority_expiration()
            // since zipline#119.
            actor.add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(bootstrap_authority_expiration())
                    .value(key::AUTHORITY_METHOD_BOOTSTRAP),
            )?;
        }

        Ok(actor)
    }

    pub async fn authenticate_visa_service(
        &self,
        asm: Arc<Assembly>,
        claims: Vec<Claim>,
    ) -> Result<Actor, ServiceError> {
        let mut authd_claims = Vec::new();

        // The VS authenticates itself by construction; that is the device authority.
        // Bootstrap authentication does not expire (zipline#119).
        authd_claims.push(
            Attribute::builder(key::DEVICE_AUTHORITY)
                .expires_in(bootstrap_authority_expiration())
                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
        );
        // The VS authorizes itself: its own CN is authenticated by construction, so it
        // is promoted here (authorize_connection no longer promotes the CN).
        authd_claims.push(Attribute::builder(key::CN).value(config::VS_CN));

        for claim in claims {
            authd_claims.push(Attribute::builder(claim.key).value(claim.value));
        }

        let psnap = asm.policy_mgr.get_current_snapshot();

        // Ok checks out -- now run through policy.
        let vs_actor = self
            .authorize_connection(asm, &psnap, &config::VS_CN, Vec::new(), authd_claims, 0)
            .await?;

        // authorize_connection no longer stamps a blanket authority, so the
        // VS-expiration DEVICE_AUTHORITY pushed above survives as-is.

        Ok(vs_actor)
    }

    /// Verify one self-signed (RSA bootstrap) auth blob: the claimed CN must match
    /// the blob's CN, `ssb.timestamp` must be within the
    /// ±[config::MAX_CLOCK_SKEW_SECS] window (zipline#137), and the blob signature
    /// must verify against the policy's bootstrap key for that CN. On success
    /// returns the claims this blob authenticated -- the CN, promoted at the point
    /// where the authentication actually happened (authorize_connection never
    /// promotes it).
    ///
    /// The skew bound here is the ONE implementation for every SS path -- the
    /// adapter connect path, the node connect path, and the zipline#120 reauth arm
    /// all reach it through this function. There is no monotonic-timestamp rule:
    /// freshness comes from the node-minted challenge; this only bounds
    /// drift/replay-window. The rejection is generic -- no timestamp echo.
    fn authenticate_ss_blob(
        &self,
        policy: &Policy,
        ssb: &SelfSignedBlob,
        unauthd_claims: &[Attribute],
    ) -> Result<Vec<Attribute>, ServiceError> {
        self.authenticate_ss_blob_at(policy, ssb, unauthd_claims, SystemTime::now())
    }

    /// [Self::authenticate_ss_blob] with the verifier's clock injected. The
    /// production path always passes `SystemTime::now()`; the parameter exists
    /// so the skew-boundary test can pin `now` and deterministically tell the
    /// intended `>` comparison from `>=` — sampling the wall clock twice (once
    /// to stamp the blob, once here) leaves a window in which a clock tick
    /// turns a skew of exactly [config::MAX_CLOCK_SKEW_SECS] into MAX+1.
    fn authenticate_ss_blob_at(
        &self,
        policy: &Policy,
        ssb: &SelfSignedBlob,
        unauthd_claims: &[Attribute],
        now: SystemTime,
    ) -> Result<Vec<Attribute>, ServiceError> {
        {
            // Make sure there is a CN attribute.
            if !unauthd_claims.iter().any(|c| c.get_key() == key::CN) {
                warn!(target: CC, "adapter auth blob missing cn claim");
                return Err(ServiceError::AuthenticationFailed(
                    "cn claim is required".into(),
                ));
            }
            let claimed_cn = unauthd_claims
                .iter()
                .find(|c| c.get_key() == key::CN)
                .unwrap()
                .get_single_value()
                .unwrap(); // ok becuase checked earlier

            if claimed_cn != ssb.cn {
                warn!(target: CC, "cn mismatch: claim '{}' != blob '{}'", claimed_cn, ssb.cn);
                return Err(ServiceError::AuthenticationFailed(
                    "cn mismatch between claim and blob".into(),
                ));
            }
        }

        // Clock-skew window on the blob timestamp (zipline#137): the single
        // enforcement point for every SS path. Checked before any signature
        // work; generic rejection, timestamp goes to the log only.
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs.abs_diff(ssb.timestamp) > config::MAX_CLOCK_SKEW_SECS {
            info!(
                target: CC,
                "ss blob rejected for cn {}: timestamp outside the clock-skew window", ssb.cn
            );
            return Err(ServiceError::AuthenticationFailed(
                "authentication rejected".into(),
            ));
        }

        let pubkey = policy.get_bootstrap_key_by_cn(&ssb.cn).ok_or_else(|| {
            ServiceError::AuthenticationFailed(format!("no key found in policy for cn {}", ssb.cn))
        })?;

        if !auth::verify_ss_blob_signature(&ssb.cn, ssb, pubkey)? {
            info!(target: CC, "blob signature verification failed for cn {}", ssb.cn);
            return Err(ServiceError::AuthenticationFailed(
                "invalid signature".into(),
            ));
        }

        // The RSA blob signature verified against the bootstrap key policy binds to
        // this CN, so the CN is authenticated.
        Ok(vec![Attribute::builder(key::CN).value(&ssb.cn)])
    }

    /// Verify one OIDC auth blob (zipline#11): resolve the declared provider by
    /// the blob's issuer (a selector, not a trust input -- client_id and
    /// allowed_domains always come from policy), validate the `id_token` offline
    /// against the provider's cached JWKS, admit the mapped claims into the
    /// provider's store, and yield the user-namespace outcome.
    ///
    /// The outcome carries the namespaced user authority plus the mapped subject:
    /// the authority names the vouching service and the subject anchors the
    /// trusted-service lookup in [Self::authorize_connection] that serves the
    /// remaining mapped claims (zipline#10). Token claims are never pushed directly.
    ///
    /// Failures are classified per the `ErrorCode` table in vs.capnp (zipline#3) and returned as
    /// [ServiceError::ApiResponse] so the real code and retry hint reach the wire.
    /// Wire messages stay generic -- no claim values, no issuer echo, no
    /// validation internals -- so error responses cannot become a claim-probing
    /// oracle; the classified detail (claim names only, never values) goes to the
    /// log.
    async fn authenticate_oidc_blob(
        &self,
        psnap: &PolicySnapshot,
        blob: &OidcBlob,
    ) -> Result<BlobOutcome, ServiceError> {
        // Resolve the provider from the pinned snapshot, not the live ts_mgr
        // list, so validation cannot straddle a concurrent policy update
        // relative to the authorization step (PR #6 review).
        let Some(svc) = psnap.oidc_service_for_issuer(&blob.issuer) else {
            // The blob's issuer is attacker-supplied bytes: neither logged nor echoed.
            warn!(target: CC, "OIDC blob names an issuer with no declared trusted service");
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "no identity provider declared for issuer",
            )
            .into());
        };

        let now = SystemTime::now();
        let mut result = validate_id_token(
            &blob.id_token,
            &svc.keys().current(),
            &svc.params(),
            NonceExpectation::Required(&blob.nonce),
            now,
        );
        if matches!(
            result,
            Err(OidcError::UnknownKid(_)) | Err(OidcError::NoKeys)
        ) {
            // Two cache states are recoverable by fetching (zipline#9): UnknownKid
            // (the provider rotated its signing keys) and NoKeys (policy
            // shipped an empty seed_jwks, so the very first login finds an
            // empty cache). Refresh once and retry once. Both triggers derive
            // from unverified input, so the refresh is coalesced and
            // rate-limited (see [KeySource::refresh_coalesced]); a failed or
            // cooldown-refused refresh keeps the cached keys serving and the
            // retry then fails the same way and is classified below.
            if let Err(e) = svc.keys().refresh_coalesced().await {
                warn!(target: CC, "JWKS refresh after validation failure failed for provider '{}': {e}", svc.id());
            }
            result = validate_id_token(
                &blob.id_token,
                &svc.keys().current(),
                &svc.params(),
                NonceExpectation::Required(&blob.nonce),
                now,
            );
        }
        let token = match result {
            Ok(token) => token,
            Err(err) => {
                // The OidcError detail carries claim names, never values (zipline#8), so
                // it is safe to log -- but not to send.
                info!(target: CC, "OIDC token rejected for provider '{}': {err}", svc.id());
                let api = match err {
                    OidcError::NoKeys => ApiResponseError::new(
                        ErrorCode::TemporarilyUnavailable,
                        "identity provider keys unavailable",
                        config::OIDC_NO_KEYS_RETRY_SECS,
                    ),
                    // UnknownKid after the one refresh+retry is a signature-class
                    // failure (`ErrorCode` in vs.capnp).
                    OidcError::Signature(_) | OidcError::UnknownKid(_) => {
                        ApiResponseError::new_code_msg(
                            ErrorCode::InvalidSignature,
                            "token validation failed",
                        )
                    }
                    OidcError::Rejected(_) => ApiResponseError::new_code_msg(
                        ErrorCode::AuthError,
                        "authentication rejected",
                    ),
                };
                return Err(api.into());
            }
        };

        // Dual-clock credential lifetime (zipline#42): the renewal window
        // anchors on the token mint moment (`iat + lifetime`, so a refreshed
        // token restarts the window), capped by the fixed per-login session
        // ceiling (`auth_time + max_auth_age`, absent when the knob is 0).
        // The ceiling is auth_time-anchored because the authentication event
        // is what policy bounds — refreshes must not extend it. The token's
        // `exp` was reject-only during validation and plays no part here
        // (OIDC.md: the `<ns>.zpr.authority` invariant).
        let expires = compute_authority_expiry(
            token.iat,
            svc.session_ceiling(token.auth_time),
            svc.lifetime(),
        );
        let mapped = svc.admit(&token, expires)?;

        let src = AttributeSource::new(svc.id());
        let mut authd = vec![
            src.builder(key::USER_AUTHORITY)
                .expires(expires)
                .value(svc.id()),
        ];
        if let Some(sub_key) = svc.mapped_sub_key()
            && let Some(sub_attr) = mapped.into_iter().find(|a| a.get_key() == sub_key)
        {
            authd.push(sub_attr);
        }
        Ok(BlobOutcome {
            authd,
            namespace: Namespace::User,
            session: Some(OidcSessionRecord {
                svc: svc.clone(),
                sub: token.sub.clone(),
                auth_time: token.auth_time,
                iat: token.iat,
                expires,
            }),
        })
    }

    /// Renew one OIDC user authentication (zipline#43): validate the
    /// refreshed `id_token` with the nonce check replaced by session binding.
    /// A refresh-grant token SHOULD NOT carry a `nonce` claim, and one it
    /// does carry MUST equal the *original* login nonce (OIDC Core
    /// §12.2) — absent or original, never fresh — so it can never match a
    /// fresh challenge; the token is instead
    /// bound to the live session recorded at admission: same provider, same
    /// `sub`, strictly increasing `iat` (replay guard) and unchanged
    /// `auth_time` (a different login session must reconnect). Every other
    /// validation check — signature, `iss`, `aud`, `exp`, `kid`, `alg`, `hd`,
    /// `email_verified` — runs exactly as on the connect path, including the
    /// one JWKS refresh-and-retry and the `ErrorCode` classification (vs.capnp).
    ///
    /// Session-binding failures are a clean `AuthError` with the generic
    /// "authentication rejected" wire message — the node's cue to tear down
    /// and reconnect, with no internals echoed. Session anchors live in the
    /// in-memory admission cache, so after a VS restart reauth fails the same
    /// way and the node reconnects. Token contents are never logged.
    ///
    /// On success the mapped claims are re-admitted under the recomputed
    /// dual-clock expiry and the fresh user-namespace outcome is returned,
    /// exactly as the connect arm builds it.
    pub(crate) async fn reauthenticate_oidc_blob(
        &self,
        psnap: &PolicySnapshot,
        actor: &Actor,
        blob: &OidcBlob,
    ) -> Result<BlobOutcome, ServiceError> {
        /// The uniform session-binding rejection: `authError`, generic
        /// message, nothing echoed (a probing caller learns only "rejected").
        fn reject() -> ServiceError {
            ApiResponseError::new_code_msg(ErrorCode::AuthError, "authentication rejected").into()
        }

        // The provider must be declared by the pinned snapshot AND be the
        // same trusted service that admitted the actor (its stamped
        // user.zpr.authority). A renewal presented to any other provider is a
        // credential rejection, not a parameter error: the blob's issuer is
        // attacker-supplied bytes and is neither logged nor echoed.
        let Some(svc) = psnap.oidc_service_for_issuer(&blob.issuer) else {
            warn!(target: CC, "reauth blob names an issuer with no declared trusted service");
            return Err(reject());
        };
        let vouched_here = actor
            .get_attribute(key::USER_AUTHORITY)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|authority| authority == svc.id());
        if !vouched_here {
            info!(target: CC, "reauth rejected: provider '{}' did not admit this actor", svc.id());
            return Err(reject());
        }

        // Validate under SessionBound: only the nonce equality is skipped —
        // same JWKS refresh-and-retry and same `ErrorCode` classification as
        // the connect path.
        let now = SystemTime::now();
        let mut result = validate_id_token(
            &blob.id_token,
            &svc.keys().current(),
            &svc.params(),
            NonceExpectation::SessionBound,
            now,
        );
        if matches!(
            result,
            Err(OidcError::UnknownKid(_)) | Err(OidcError::NoKeys)
        ) {
            if let Err(e) = svc.keys().refresh_coalesced().await {
                warn!(target: CC, "JWKS refresh after validation failure failed for provider '{}': {e}", svc.id());
            }
            result = validate_id_token(
                &blob.id_token,
                &svc.keys().current(),
                &svc.params(),
                NonceExpectation::SessionBound,
                now,
            );
        }
        let token = match result {
            Ok(token) => token,
            Err(err) => {
                // The OidcError detail carries claim names, never values (zipline#8),
                // so it is safe to log -- but not to send.
                info!(target: CC, "reauth token rejected for provider '{}': {err}", svc.id());
                let api = match err {
                    OidcError::NoKeys => ApiResponseError::new(
                        ErrorCode::TemporarilyUnavailable,
                        "identity provider keys unavailable",
                        config::OIDC_NO_KEYS_RETRY_SECS,
                    ),
                    OidcError::Signature(_) | OidcError::UnknownKid(_) => {
                        ApiResponseError::new_code_msg(
                            ErrorCode::InvalidSignature,
                            "token validation failed",
                        )
                    }
                    OidcError::Rejected(_) => ApiResponseError::new_code_msg(
                        ErrorCode::AuthError,
                        "authentication rejected",
                    ),
                };
                return Err(api.into());
            }
        };

        // Session binding: the token's subject must be the admitted subject
        // this actor carries (its mapped sub attribute), with anchors
        // recorded for THIS actor session (keyed by its ZPR address — per
        // session, not per subject, PR #19 review).
        let Some(sub_key) = svc.mapped_sub_key() else {
            info!(target: CC, "reauth rejected: provider '{}' maps no sub claim", svc.id());
            return Err(reject());
        };
        let sub_matches_actor = actor
            .get_attribute(&sub_key)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|actor_sub| actor_sub == token.sub);
        if !sub_matches_actor {
            info!(target: CC, "reauth rejected: token sub does not match the actor's admitted sub");
            return Err(reject());
        }
        let Some(session_id) = actor.get_zpr_addr().map(|a| a.to_string()) else {
            info!(target: CC, "reauth rejected: actor has no session id (zpr address)");
            return Err(reject());
        };
        let Some(anchors) = svc.session_anchors(&session_id) else {
            info!(target: CC, "reauth rejected: no session recorded for this actor");
            return Err(reject());
        };
        // The recorded session must belong to the token's subject: a session
        // anchor from a different account never validates another's renewal.
        if anchors.sub != token.sub {
            info!(target: CC, "reauth rejected: token sub does not match the recorded session");
            return Err(reject());
        }
        let (admitted_auth_time, admitted_iat) = (anchors.auth_time, anchors.iat);
        // Liveness (PR #19 review): a renewal only extends a LIVE admission.
        // A recorded session whose admission has lapsed must not be
        // resurrectable by a fresh token — generic rejection (Q2), the node's
        // cue to reconnect. (The record's eventual removal is the zipline#44
        // sweep; this check just refuses to use a stale one.)
        if anchors.expires <= now {
            info!(target: CC, "reauth rejected: the recorded admission has expired");
            return Err(reject());
        }

        // Replay guard: the renewal token must be minted strictly after the
        // one that produced the recorded admission.
        if token.iat <= admitted_iat {
            info!(target: CC, "reauth rejected: token iat is not newer than the admitted iat");
            return Err(reject());
        }
        // Same login session: a token from a NEW authentication event is not
        // a renewal — the endpoint must reconnect.
        if token.auth_time != admitted_auth_time {
            info!(target: CC, "reauth rejected: token auth_time differs from the admitted session");
            return Err(reject());
        }

        // Dual-clock renewal (zipline#42): the window restarts from the fresh
        // iat, capped by the fixed per-login session ceiling. A ceiling (or
        // window) already passed is a clean rejection — the cue to tear down.
        let expires = compute_authority_expiry(
            token.iat,
            svc.session_ceiling(token.auth_time),
            svc.lifetime(),
        );
        if expires <= now {
            info!(target: CC, "reauth rejected for provider '{}': renewed expiry is not in the future", svc.id());
            return Err(reject());
        }

        // Re-admit under the renewed expiry and rebuild the user-namespace
        // outcome exactly as the connect arm does.
        let mapped = svc.admit(&token, expires)?;
        let src = AttributeSource::new(svc.id());
        let mut authd = vec![
            src.builder(key::USER_AUTHORITY)
                .expires(expires)
                .value(svc.id()),
        ];
        if let Some(sub_attr) = mapped.into_iter().find(|a| a.get_key() == sub_key) {
            authd.push(sub_attr);
        }
        Ok(BlobOutcome {
            authd,
            namespace: Namespace::User,
            session: Some(OidcSessionRecord {
                svc: svc.clone(),
                sub: token.sub.clone(),
                auth_time: token.auth_time,
                iat: token.iat,
                expires,
            }),
        })
    }

    /// Renew one SS (bootstrap RSA) device authentication (zipline#120): the
    /// counterpart of [Self::reauthenticate_oidc_blob] for the device
    /// namespace. Reuses [Self::authenticate_ss_blob] against the pinned
    /// snapshot's bootstrap key, with the reauth-specific checks from the
    /// zipline#118 plan's *Decisions*:
    ///
    /// - the live actor holds `device.zpr.authority = zpr-bootstrap` (only a
    ///   bootstrap-authenticated device has an SS renewal semantics);
    /// - `ssb.cn` equals the actor's AUTHENTICATED CN — a valid blob for a
    ///   different device never renews this actor;
    /// - `|now − ssb.timestamp| ≤ MAX_CLOCK_SKEW_SECS` (180 s) — enforced
    ///   inside [Self::authenticate_ss_blob] since zipline#137, the single
    ///   skew check for every SS path. There is no
    ///   monotonic-timestamp rule: freshness comes from the node-minted,
    ///   HMAC'd challenge, and only the docking node could replay
    ///   (SECURITY_MODEL Case 2);
    /// - the signature verifies against the snapshot's bootstrap key for the
    ///   CN — a key removed from policy (the bootstrap revocation path) or
    ///   rotated fails here.
    ///
    /// Every failure is the same generic `AuthError` as OIDC's `reject()`, so
    /// a probing caller learns only "rejected"; the classified detail goes to
    /// the log. On success the outcome re-stamps the far-future bootstrap
    /// device authority (zipline#119) and the authenticated CN, exactly as
    /// the connect arm does.
    pub(crate) fn reauthenticate_ss_blob(
        &self,
        psnap: &PolicySnapshot,
        actor: &Actor,
        ssb: &SelfSignedBlob,
    ) -> Result<BlobOutcome, ServiceError> {
        /// The uniform credential rejection: `authError`, generic message,
        /// nothing echoed — same shape as the OIDC arm's `reject()`.
        fn reject() -> ServiceError {
            ApiResponseError::new_code_msg(ErrorCode::AuthError, "authentication rejected").into()
        }

        // Only a bootstrap-admitted device authority is renewable by an SS
        // blob (the exact-set check in reauthorize_actor already required
        // SOME device authority; this pins the method).
        let bootstrap_admitted = actor
            .get_attribute(key::DEVICE_AUTHORITY)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|method| method == key::AUTHORITY_METHOD_BOOTSTRAP);
        if !bootstrap_admitted {
            info!(target: CC, "SS reauth rejected: the actor's device authority is not bootstrap");
            return Err(reject());
        }

        // The blob must renew THIS actor's device identity: its CN is the
        // authenticated CN the bootstrap connect established.
        let Some(actor_cn) = actor.get_cn() else {
            info!(target: CC, "SS reauth rejected: actor has no authenticated cn");
            return Err(reject());
        };
        if actor_cn != ssb.cn {
            info!(target: CC, "SS reauth rejected: blob cn does not match the actor's cn");
            return Err(reject());
        }

        // Clock-skew enforcement moved into authenticate_ss_blob (zipline#137):
        // that single check now covers this path too, before signature work,
        // and its failure collapses to the generic rejection below.

        // Signature against the PINNED snapshot's bootstrap key: key removed
        // from policy or rotated fails here. The connect arm's classified
        // errors collapse to the generic rejection on the reauth path.
        let cn_claim = vec![Attribute::builder(key::CN).value(actor_cn)];
        let authd = self
            .authenticate_ss_blob(psnap.policy(), ssb, &cn_claim)
            .map_err(|e| {
                info!(target: CC, "SS reauth rejected: {e}");
                reject()
            })?;

        // Re-stamp the far-future bootstrap device authority (zipline#119),
        // exactly as the connect arm does.
        let mut outcome_authd = vec![
            Attribute::builder(key::DEVICE_AUTHORITY)
                .expires_in(bootstrap_authority_expiration())
                .value(key::AUTHORITY_METHOD_BOOTSTRAP),
        ];
        outcome_authd.extend(authd);
        Ok(BlobOutcome {
            authd: outcome_authd,
            namespace: Namespace::Device,
            session: None,
        })
    }

    /// The whole VSAPI `reauthorize` operation (zipline#43, widened by
    /// zipline#120 to contract K3): resolve the live actor behind `zpr_addr`,
    /// renew EVERY authority it holds — one blob per namespace, the namespace
    /// set exactly equal to the actor's `zpr.authority` namespaces — re-run
    /// policy under the same pinned snapshot (stamping the current
    /// `zpr.vinst`), and persist the renewed actor, its ZPR address
    /// unchanged. The SS (bootstrap RSA) arm is
    /// [Self::reauthenticate_ss_blob]; the OIDC arm is
    /// [Self::reauthenticate_oidc_blob].
    ///
    /// Request-shape problems (no blobs, duplicate namespace, namespace set ≠
    /// the actor's authorities, unknown address, wrong calling node) are
    /// caller bugs and reject `ParamError` with explicit text; credential and
    /// session-binding failures come back from the blob arms as
    /// `AuthError`/Contract-2 codes, deliberately indistinguishable to a
    /// probing caller.
    ///
    /// **A node renewing its own actor** (zl-zipline#232, vs.capnp
    /// "Re-Authorization") is the one exception to the exact-set rule: it may
    /// gain the `user` namespace (log a user in) with an OIDC blob whose
    /// nonce is an unexpired, unused login nonce this visa service issued to
    /// that actor in its current VS-API session, or drop it (log out) by
    /// omitting the OIDC blob. The `device` blob is mandatory either way.
    /// After a gain or drop every live visa is re-checked.
    ///
    /// `caller_session` is the VS-API session generation (`zpr.session`) the
    /// calling handle was minted under; a node's renewal of its own actor is
    /// refused unless it is the actor's current one.
    pub(crate) async fn reauthorize_actor(
        &self,
        asm: Arc<Assembly>,
        zpr_addr: IpAddr,
        blobs: Vec<AuthBlob>,
        connect_via: &IpAddr,
        caller_session: Option<&str>,
    ) -> Result<Actor, ServiceError> {
        if blobs.is_empty() {
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "reauthorize requires at least one auth blob",
            )
            .into());
        }

        // Group the blobs by the identity namespace each arm renews: SS =
        // device, OIDC = user. At most one blob per namespace (K3); AC is
        // legacy and cannot connect, so it cannot renew either.
        let mut ss_blob: Option<SelfSignedBlob> = None;
        let mut oidc_blob: Option<OidcBlob> = None;
        for blob in blobs {
            match blob {
                AuthBlob::SS(ssb) => {
                    if ss_blob.replace(ssb).is_some() {
                        return Err(ApiResponseError::new_code_msg(
                            ErrorCode::ParamError,
                            "duplicate device auth blob in reauthorize",
                        )
                        .into());
                    }
                }
                AuthBlob::Oidc(ob) => {
                    if oidc_blob.replace(ob).is_some() {
                        return Err(ApiResponseError::new_code_msg(
                            ErrorCode::ParamError,
                            "duplicate user auth blob in reauthorize",
                        )
                        .into());
                    }
                }
                AuthBlob::AC(_) => {
                    return Err(ApiResponseError::new_code_msg(
                        ErrorCode::ParamError,
                        "reauthorize does not support ac blobs",
                    )
                    .into());
                }
            }
        }

        // A node renewing its own actor holds the self-renewal lock for the
        // whole operation, from loading the actor to recording the OIDC
        // anchors (#63 review): the namespace classification below must still
        // describe the actor that gets persisted.
        let self_reauth_guard = if zpr_addr == *connect_via {
            Some(asm.policy_mgr.node_commit_lock.lock().await)
        } else {
            None
        };

        // The renewal target must be a live actor admitted through the
        // calling node. An unknown address or one behind a different node is
        // a protocol error, not a credential rejection.
        let Some(actor) = asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await? else {
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "no live actor at the given zpr address",
            )
            .into());
        };
        // A node's own actor carries no `zpr.connect_via` (it connected over
        // VS-API, not through a dock); the calling node renewing ITSELF is
        // bound by the node session that carries this call (zl-zipline#232).
        let self_renewal = is_self_renewal(&actor, &zpr_addr, connect_via);
        // A node renewing ITSELF must do so from its current handle (#63
        // review): a handle minted under an earlier session that passed the
        // liveness gate just before a reconnect must not act on the actor of
        // the new session -- e.g. log out a user the new session logged in.
        if self_renewal {
            let loaded_session = actor
                .get_attribute(key::SESSION)
                .and_then(|a| a.get_single_value().ok());
            if caller_session.is_none() || loaded_session.as_deref() != caller_session {
                info!(target: CC, "self-renewal of {zpr_addr} refused: the calling handle's session is not the node's current one");
                return Err(ApiResponseError::new_code_msg(
                    ErrorCode::AuthError,
                    "authentication rejected",
                )
                .into());
            }
        }
        let via_matches = actor
            .get_attribute(key::CONNECT_VIA)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|via| via == connect_via.to_string());
        if !self_renewal && !via_matches {
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "actor is not connected via the calling node",
            )
            .into());
        }

        // One coherent policy view for the whole renewal (PR #6 review):
        // blob validation and re-authorization read this snapshot, so a
        // concurrent policy update cannot admit a credential under one
        // revision and authorize it under another. Read before the exact-set
        // check below, which resolves credential-backedness against it.
        let psnap = asm.policy_mgr.get_current_snapshot();

        // Exact-set rule (K3), on CREDENTIAL-BACKED authorities only: the
        // namespaces the blobs renew must equal the namespaces the actor
        // holds a renewable credential arm for — every credential is
        // re-proved, none silently dropped, none invented. A subset or
        // superset is a caller bug. A `user.zpr.authority` synthesized from
        // trusted-service enrichment ([derive_user_authority]) is excluded
        // (PR #40 review, Codex P1): the device never presented an OIDC
        // credential — the authority names a file or attribute-service store, not an OIDC
        // provider — so demanding a user blob for it would make the actor's
        // only valid renewal (its SS blob) permanently rejected after a
        // policy update. Such authorities are recreated by re-enrichment
        // once the credential-backed identity renews.
        let actor_has_device = actor.get_attribute(key::DEVICE_AUTHORITY).is_some();
        let user_credential_backed = actor
            .get_attribute(key::USER_AUTHORITY)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|authority| psnap.declares_oidc_service(&authority));
        let actor_has_user_authority = actor.get_attribute(key::USER_AUTHORITY).is_some();
        let Some(user_change) = classify_user_namespace_change(
            ss_blob.is_some(),
            oidc_blob.is_some(),
            actor_has_device,
            user_credential_backed,
            actor_has_user_authority,
            self_renewal,
        ) else {
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::ParamError,
                "reauthorize blobs must cover exactly the actor's credential-backed namespaces",
            )
            .into());
        };

        // A login spends its nonce as soon as the request is classified, before
        // either credential arm runs (#63 review): a login that then fails on
        // its device proof or its token cannot retry the same nonce.
        if user_change == UserNamespaceChange::Gain
            && let Some(ob) = &oidc_blob
        {
            self.consume_login_nonce(&actor, &zpr_addr, &ob.nonce)?;
        }

        let mut outcomes: Vec<BlobOutcome> = Vec::new();
        if let Some(ssb) = &ss_blob {
            // A revoked bootstrap root never renews (zipline#136): denylist
            // check before the blob checks, same uniform rejection.
            if let Err(e) = Self::check_bootstrap_denylist(&asm, &ssb.cn).await {
                info!(target: CC, "SS reauth rejected: {e}");
                return Err(ApiResponseError::new_code_msg(
                    ErrorCode::AuthError,
                    "authentication rejected",
                )
                .into());
            }
            outcomes.push(self.reauthenticate_ss_blob(&psnap, &actor, ssb)?);
        }
        if let Some(ob) = &oidc_blob {
            if user_change == UserNamespaceChange::Gain {
                // A login (its nonce already spent above): validate exactly as
                // the connect arm does; its nonce check binds the token to the
                // visa-service nonce.
                outcomes.push(self.authenticate_oidc_blob(&psnap, ob).await?);
            } else {
                outcomes.push(self.reauthenticate_oidc_blob(&psnap, &actor, ob).await?);
            }
        }

        // Rebuild the authenticated claim set: everything the actor already
        // carries, minus what policy re-stamps ([key::ROLE], [key::SERVICES],
        // [key::VINST], [key::CONFIG_ID]) and minus what each renewing arm
        // replaces. For a provider-backed arm (OIDC) that is EVERY attribute
        // the provider previously vouched for — by source, not just the keys
        // the renewal re-asserts (PR #19 review): a refreshed token may omit
        // a formerly mapped claim (e.g. `email_verified` flips false, so
        // `user.email` is no longer admitted); the stale source-stamped
        // attribute must not survive into policy evaluation. The SS arm
        // vends fixed internal-source attributes (the bootstrap device
        // authority and the CN), so for it the outcome's keys ARE the
        // complete prior set, and subtracting them is what re-stamps
        // `device.zpr.authority` with a fresh far-future expiry (zipline#120).
        // The ZPR address rides along as an authenticated claim — the VS
        // assigned it at connect, and reauth never re-allocates it.
        let renewed_sources: Vec<String> = outcomes
            .iter()
            .flat_map(|o| o.authd.iter())
            .map(|a| a.get_source().to_string())
            .filter(|s| s != libeval::attribute::SOURCE_ZPR)
            .collect();
        let renewed_keys: Vec<&str> = outcomes
            .iter()
            .flat_map(|o| o.authd.iter())
            .map(|a| a.get_key())
            .collect();
        //
        // A logout (Drop) carries over ONLY internal-source attributes and
        // nothing in the `user.` namespace: a trusted service may have vended
        // `user.*` attributes keyed on the dropped subject under its own
        // source, and those must not survive. The policy re-run below
        // re-fetches every trusted-service attribute from the remaining
        // (device) identities, exactly as a fresh device-only connect does.
        let dropping_user = user_change == UserNamespaceChange::Drop;
        let mut authd_claims: Vec<Attribute> = actor
            .attrs_iter()
            .filter(|a| {
                !renewed_sources.contains(&a.get_source().to_string())
                    && !renewed_keys.contains(&a.get_key())
                    && !key::POLICY_STAMPED.contains(&a.get_key())
                    && (!dropping_user || survives_logout(a))
            })
            .cloned()
            .collect();
        let renewed_sessions: Vec<OidcSessionRecord> = outcomes
            .iter_mut()
            .filter_map(|o| o.session.take())
            .collect();
        for outcome in outcomes {
            authd_claims.extend(outcome.authd);
        }

        // Re-run policy under the same snapshot: a policy change since
        // connect is applied now, exactly as on a fresh connect. An
        // evaluation denial is "login good, endpoint no longer admitted" and
        // surfaces as PolicyDenied so the caller can tell it from a
        // credential rejection; everything else keeps its classification.
        // `renewal_of` carries the proven session address: this caller loaded
        // the live actor at `zpr_addr` and re-validated its session blob
        // above, which is what authorizes re-accepting an occupied address
        // (PR #33 review, P1).
        let endpoint_cn = actor.get_cn().unwrap_or_default().to_string();
        let reauthorized = self
            .authorize_connection_impl(
                asm.clone(),
                &psnap,
                &endpoint_cn,
                Vec::new(),
                authd_claims,
                0,
                Some(zpr_addr),
            )
            .await;
        // Set when a logout persists without re-enrichment (below); the
        // trusted-service attributes it dropped must then be re-fetched.
        let mut logout_without_enrichment = false;
        let mut renewed = match reauthorized {
            Ok(renewed) => renewed,
            // A logout must not depend on the policy re-run (#63 review): if
            // it fails -- a trusted service is down, say -- persist the
            // loaded actor with its user namespace removed instead of leaving
            // the login in place for the outage. This only removes privilege,
            // and the device proof has already been checked.
            Err(e) if dropping_user => {
                warn!(target: CC, "logout of {zpr_addr}: policy re-run failed ({e}); persisting the logout without re-enrichment");
                logout_without_enrichment = true;
                logout_without_reauthorization(&actor, psnap.policy())
            }
            Err(e) => return Err(Self::classify_reauth_policy_error(e)),
        };

        // A node's role is fixed at connect, as on the attribute-refresh path
        // (`actor_attributes::restamp_services`). If the policy re-run no
        // longer matches a node join policy -- e.g. the only one now requires
        // the user attribute this logout drops -- keep the node role and grant
        // only the services a node would get, instead of failing on a role
        // change and leaving the login in place (#63 review).
        if self_renewal && !renewed.is_node() {
            renewed.add_attribute(
                Attribute::builder(key::ROLE)
                    .expires_in(libeval::attribute::NEVER_EXPIRES)
                    .value(libeval::attribute::ROLE_NODE),
            )?;
            let claims: Vec<Attribute> = renewed
                .attrs_iter()
                .filter(|a| !key::POLICY_STAMPED.contains(&a.get_key()))
                .cloned()
                .collect();
            renewed.set_services(psnap.policy().join_services_for_role(&claims, true));
        }

        // Invariant, not policy: reauth renews credentials in place. The
        // address was passed through as an authenticated claim, so this can
        // only trip if authorize_connection changes shape underneath us.
        if renewed.get_zpr_addr() != Some(&zpr_addr) {
            return Err(ServiceError::Internal(
                "reauthorize must not change the actor's zpr address".into(),
            ));
        }

        // The commit-time recheck (#63 review audit), under the self-renewal
        // lock: the node's session must be the one loaded, and the policy
        // generation the one this renewal was authorized under. A login or
        // renewal under a moved generation is refused (retry under the new
        // policy); a logout is never refused -- that would leave the login in
        // place -- so it commits the reduced actor under the current policy,
        // with no attribute enriched under the superseded snapshot.
        if self_renewal {
            let loaded_session = actor
                .get_attribute(key::SESSION)
                .and_then(|a| a.get_single_value().ok());
            let recheck = recheck_before_commit(
                &asm,
                &zpr_addr,
                Some(loaded_session.as_deref().unwrap_or_default()),
                Some(psnap.vinst()),
            )
            .await?;
            if recheck == CommitRecheck::PolicyMoved {
                if !dropping_user {
                    return Err(policy_moved_error());
                }
                info!(target: CC, "logout of {zpr_addr}: policy changed; persisting it without re-enrichment");
                let current = asm.policy_mgr.get_current_snapshot();
                renewed = logout_without_reauthorization(&actor, current.policy());
                logout_without_enrichment = true;
            }
        }
        // Re-mint the VS identity token with a fresh expiration (PR #19
        // review): the connect-time token rode through as an authenticated
        // claim, but keeping it would cap the renewed actor at the ORIGINAL
        // connect's window — `get_authentication_expiration()` takes the
        // minimum across identity attributes, so after
        // `DEFAULT_AUTH_EXPIRATION` an OIDC-only actor could renew its user
        // authority yet still be denied new visas. Same minting rules as
        // connect; re-registered as the first identity key, exactly as
        // connect does. Minted here, after the commit-time recheck has chosen
        // the actor that is persisted, so a logout's reduced actor gets a
        // fresh token too (#63 review): the pre-logout one was capped by the
        // user authority's expiry, and a refresh holding a pre-logout copy
        // matches on it.
        if renewed.get_attribute(ATTR_KEY_VS_IDENT).is_some() {
            // The token follows the renewed actor's authority expiries
            // (zipline#119) — same minting rule as connect.
            let ident_expires = vs_ident_expiration(&renewed);
            let jwt_lifetime = ident_expires
                .duration_since(SystemTime::now())
                .unwrap_or(config::DEFAULT_AUTH_EXPIRATION);
            let actor_jwt = if renewed.is_node() {
                self.gen_jwt(format!("node/{}", endpoint_cn), jwt_lifetime)?
            } else {
                self.gen_jwt(format!("adapter/{}", endpoint_cn), jwt_lifetime)?
            };
            let _ = renewed.add_attribute(
                Attribute::builder(ATTR_KEY_VS_IDENT)
                    .expires(ident_expires)
                    .value(actor_jwt),
            );
            let _ = renewed.add_identity_key(0, ATTR_KEY_VS_IDENT);
        }

        if let Err(e) = asm
            .actor_mgr
            .update_actor(&renewed, &asm.policy_service_names())
            .await
        {
            // The write can fail after the attributes were committed (a later
            // metadata write failed). For a login or logout, do not drop the
            // follow-up with the error (#63 review):
            // - a login is rolled back to the loaded, pre-login actor so no
            //   login without session anchors stays active; if the rollback
            //   fails too, the node is disconnected (fail closed) and must
            //   re-authenticate;
            // - the revisions a reduced logout dropped are invalidated;
            // - the node commit lock is released BEFORE awaiting the bounded
            //   event queue -- its worker may need that lock -- and the visa
            //   reconciliation is handed to the event manager.
            let mut disconnect_node = false;
            if user_change == UserNamespaceChange::Gain
                && let Err(re) = asm
                    .actor_mgr
                    .update_actor(&actor, &asm.policy_service_names())
                    .await
            {
                error!(target: CC, "rollback of {zpr_addr}'s failed login failed ({re}); disconnecting the node");
                disconnect_node = true;
            }
            if user_change != UserNamespaceChange::Keep && logout_without_enrichment {
                asm.ts_mgr.invalidate_actor_revisions(&zpr_addr);
            }
            // Release the node commit lock before disconnecting: a disconnect
            // takes the topology lock, and the lock order is topology lock, then
            // node commit lock (see `PolicyMgr::node_commit_lock`).
            drop(self_reauth_guard);
            if disconnect_node
                && let Err(de) = self
                    .disconnect(asm.clone(), zpr_addr, vsapi::DisconnectReason::Admin)
                    .await
            {
                error!(target: CC, "failed to disconnect {zpr_addr} after a failed login rollback: {de}");
            }
            if user_change != UserNamespaceChange::Keep {
                warn!(target: CC, "write of {zpr_addr}'s namespace change failed ({e}); queueing an attribute-change reconcile");
                if let Err(qe) = asm
                    .event_mgr
                    .record_event(crate::event_mgr::VsEvent::TrustedServiceChange)
                    .await
                {
                    error!(target: CC, "failed to queue the reconcile after a failed write for {zpr_addr}: {qe}");
                }
            }
            return Err(e);
        }

        // PR #42 review (P1): re-check the denylist now that the renewal is
        // persisted. A revocation landing between the pre-check above and
        // update_actor could race the enforcement sweep's removal (the sweep
        // revokes the OLD record while this write re-persists the actor);
        // this closes that window. Same uniform rejection as the pre-check.
        if Self::denylisted_after_persist(&asm, &renewed).await {
            // Undo the renewal by disconnecting -- after releasing the node
            // commit lock, because a disconnect takes the topology lock (lock
            // order: topology lock, then node commit lock).
            drop(self_reauth_guard);
            if let Some(addr) = renewed.get_zpr_addr()
                && let Err(e) = self
                    .disconnect(asm.clone(), *addr, vsapi::DisconnectReason::Admin)
                    .await
            {
                error!(target: CC, "failed to disconnect revoked actor {addr} after persist: {e}; the denylist sweep will retry");
            }
            info!(target: CC, "SS reauth rejected post-persist: cn revoked");
            return Err(ApiResponseError::new_code_msg(
                ErrorCode::AuthError,
                "authentication rejected",
            )
            .into());
        }

        // The whole renewal succeeded: advance this session's anchors to the
        // fresh token (per actor session — PR #19 review). Recording only on
        // success means a failed policy re-run does not consume the token's
        // strictly-increasing `iat`. Only the OIDC arm carries anchors; the
        // SS arm has no session state.
        for session in renewed_sessions {
            session.record(&zpr_addr);
        }

        // A logout persisted without re-enrichment dropped trusted-service
        // attributes it could not re-fetch -- possibly ones a deny rule
        // depends on. Forget the actor's source revisions so the next refresh
        // re-fetches every source; while one is still down that request is
        // indeterminate and denied, instead of proceeding as if the dropped
        // attributes were known to be absent (#63 review).
        if logout_without_enrichment {
            asm.ts_mgr.invalidate_actor_revisions(&zpr_addr);
        }

        // A logout also forgets the dropped login's session anchors, so a
        // later silent renewal can never bind to them.
        if dropping_user {
            let dropped_authority = actor
                .get_attribute(key::USER_AUTHORITY)
                .and_then(|a| a.get_single_value().ok());
            if let Some(svc) = dropped_authority.and_then(|id| psnap.oidc_service_by_id(&id)) {
                svc.forget_session(&zpr_addr.to_string());
            }
        }

        // Visas follow the namespace change (g27 q4): a logout must revoke
        // visas that needed user attributes, and a login can invalidate visas
        // through a `never allow` on a user attribute. The attribute-change
        // sweep re-checks every live visa against the stored actors.
        // ponytail: full sweep of every live visa per login/logout; logins are
        // rare. Add a per-actor sweep if visa counts make this slow.
        //
        // The sweep uses the CURRENT snapshot, taken after the actor is
        // persisted, and repeats while the policy generation moves under it:
        // a sweep under a superseded generation applies no verdicts, and a
        // policy install whose own sweep ran before this persist re-checked
        // the visas against the pre-logout actor (#63 review).
        //
        // The self-renewal lock covers load -> classify -> persist -> anchors;
        // the fleet-wide sweep needs none of that, so release it first rather
        // than block every node authentication and nonce mint for the sweep's
        // duration (#63 review).
        drop(self_reauth_guard);
        if user_change != UserNamespaceChange::Keep {
            Self::sweep_visas_after_namespace_change(&asm).await;
        }
        Ok(renewed)
    }

    /// Re-check every live visa after a node's login or logout (#63 review):
    /// up to [config::NAMESPACE_SWEEP_ATTEMPTS] attribute-change sweeps, each
    /// under the policy snapshot current when it starts, until one completes
    /// with no failures under a generation that did not move. If none does,
    /// the work is handed to the event manager as an attribute-change
    /// reconcile (refresh, then sweep) rather than dropped: the actor is
    /// already persisted, and a visa whose revocation failed must not stay
    /// usable until it expires.
    async fn sweep_visas_after_namespace_change(asm: &Arc<Assembly>) {
        for _ in 0..config::NAMESPACE_SWEEP_ATTEMPTS {
            let sweep_snap = asm.policy_mgr.get_current_snapshot();
            let failures = revalidate_visas(asm, &sweep_snap, SweepReason::AttributeChange).await;
            if failures == 0 && asm.policy_mgr.get_current_snapshot().vinst() == sweep_snap.vinst()
            {
                return;
            }
        }
        warn!(target: CC, "visa sweep after a node login/logout did not complete; queueing an attribute-change reconcile");
        if let Err(e) = asm
            .event_mgr
            .record_event(crate::event_mgr::VsEvent::TrustedServiceChange)
            .await
        {
            error!(target: CC, "failed to queue the attribute-change reconcile after a node login/logout: {e}");
        }
    }

    /// Spend a node's login nonce for a `user` namespace gain on its own actor
    /// (zl-zipline#232). The nonce must have been issued by
    /// [LoginNonceStore::mint] to exactly this actor in its current VS-API
    /// session (`zpr.session`) and be unexpired; it is spent whatever the
    /// outcome. Every failure is the generic `AuthError` -- a probing caller
    /// learns only "rejected"; the reason goes to the log.
    fn consume_login_nonce(
        &self,
        actor: &Actor,
        zpr_addr: &IpAddr,
        nonce: &str,
    ) -> Result<(), ServiceError> {
        let reject = || -> ServiceError {
            ApiResponseError::new_code_msg(ErrorCode::AuthError, "authentication rejected").into()
        };
        let Some(session) = actor
            .get_attribute(key::SESSION)
            .and_then(|a| a.get_single_value().ok())
        else {
            info!(target: CC, "login rejected for {zpr_addr}: actor has no VS-API session generation");
            return Err(reject());
        };
        if !self
            .login_nonces
            .consume(nonce, *zpr_addr, &session, SystemTime::now())
        {
            info!(target: CC, "login rejected for {zpr_addr}: nonce not issued to this actor session, expired, or already used");
            return Err(reject());
        }
        Ok(())
    }

    /// Classify an `authorize_connection` failure on the REAUTH path for the
    /// wire (zipline#43 acceptance): a policy-evaluation denial means the
    /// login is still good but the endpoint is no longer admitted, and
    /// surfaces as `PolicyDenied` so the caller can tell it from a credential
    /// rejection (`AuthError`). Every other failure — trusted-service
    /// lookups, stores, internals — passes through with its existing
    /// classification. The connect path is deliberately not routed through
    /// this: there a no-join-policy login still connects (#227), so the
    /// evaluation errors this maps simply do not reach its callers.
    fn classify_reauth_policy_error(err: ServiceError) -> ServiceError {
        match err {
            ServiceError::Eval(e) => {
                info!(target: CC, "reauth denied by policy evaluation: {e}");
                ApiResponseError::new_code_msg(ErrorCode::PolicyDenied, "policy denied").into()
            }
            other => other,
        }
    }

    /// Refuse a bootstrap CN on the administrative denylist (zipline#136).
    /// Checked on every bootstrap authentication path — adapter connect, node
    /// connect, SS renewal — BEFORE the policy key lookup, so a revoked key is
    /// refused even while a stale policy still carries it. A store read
    /// failure fails closed: an unreadable denylist must not readmit a
    /// revoked key.
    async fn check_bootstrap_denylist(asm: &Arc<Assembly>, cn: &str) -> Result<(), ServiceError> {
        let denylisted = crate::db::BootstrapDenylist::new(asm.state_db.clone())
            .contains(cn)
            .await
            .unwrap_or_else(|e| {
                warn!(target: CC, "bootstrap denylist read failed for cn {cn}: {e}; failing closed");
                true
            });
        if denylisted {
            info!(target: CC, "bootstrap authentication refused: cn {cn} is administratively revoked (zipline#136)");
            return Err(ServiceError::AuthenticationFailed("not authorized".into()));
        }
        Ok(())
    }

    /// PR #42 review (P1): re-check the denylist AFTER the actor is
    /// persisted, and undo the admission on a hit.
    ///
    /// An admin revocation can land between [Self::check_bootstrap_denylist]
    /// on an auth path and the moment the caller persists the actor. The
    /// revocation's inline enforcement sweep enumerates PERSISTED actors, so
    /// it finds nothing to revoke, and without this gate the in-flight
    /// connect would stand until the next periodic sweep tick. The ordering
    /// argument that closes the window: revocation writes the denylist and
    /// then reads the actor store; admission writes the actor store and then
    /// (here) reads the denylist — whichever ran second sees the other's
    /// write, so either the sweep revokes the persisted actor or this
    /// re-check sees the denylist entry.
    ///
    /// Gated exactly like the sweep: only a bootstrap-admitted actor
    /// (`device.zpr.authority == zpr-bootstrap`) with an authenticated CN is
    /// subject to the bootstrap denylist, and the VS's own actor is exempt.
    /// A hit (or an unreadable denylist — fail closed, as everywhere on this
    /// path) disconnects the just-persisted actor ([Self::disconnect] with
    /// the Admin reason, the same teardown the sweep uses for nodes) and
    /// returns the uniform credential rejection.
    pub(crate) async fn enforce_denylist_after_persist(
        &self,
        asm: &Arc<Assembly>,
        actor: &Actor,
    ) -> Result<(), ServiceError> {
        if !Self::denylisted_after_persist(asm, actor).await {
            return Ok(());
        }
        if let Some(addr) = actor.get_zpr_addr() {
            if let Err(e) = self
                .disconnect(asm.clone(), *addr, vsapi::DisconnectReason::Admin)
                .await
            {
                // The refusal stands either way; the periodic sweep retries
                // the cleanup ([crate::auth_sweep::spawn_auth_expiry_sweeper]).
                error!(target: CC, "failed to disconnect revoked actor {addr} after persist: {e}; the denylist sweep will retry");
            }
        }
        Err(ServiceError::AuthenticationFailed("not authorized".into()))
    }

    /// The check half of [Self::enforce_denylist_after_persist]: whether the
    /// just-persisted actor's bootstrap CN has been denylisted (or the denylist is
    /// unreadable -- fail closed). It disconnects nothing, so a caller holding the
    /// node commit lock (`reauthorize`) can check under it and disconnect after
    /// releasing it (lock order: topology lock, then node commit lock).
    async fn denylisted_after_persist(asm: &Arc<Assembly>, actor: &Actor) -> bool {
        // Same gating as sweep_denylisted_actors: only a bootstrap-admitted
        // device authority is subject to the bootstrap-key denylist, and the
        // VS's own actor is exempt.
        let bootstrap_admitted = actor
            .get_attribute(key::DEVICE_AUTHORITY)
            .and_then(|a| a.get_single_value().ok())
            .is_some_and(|method| method == key::AUTHORITY_METHOD_BOOTSTRAP);
        if !bootstrap_admitted {
            return false;
        }
        let Some(cn) = actor.get_cn() else {
            return false;
        };
        if cn == config::VS_CN {
            return false;
        }
        if Self::check_bootstrap_denylist(asm, cn).await.is_ok() {
            return false;
        }
        // Revoked mid-connect: the caller undoes the admission with the full
        // disconnect teardown (actor record, visas, topology for a node,
        // managed-address release) -- the same path the sweep uses.
        warn!(target: CC, "cn {cn} was revoked during connection setup; undoing the admission (zipline#136, PR #42 review)");
        true
    }

    /// Preform authentication of an adapter or a node, then run through policy.
    /// `unauthed_claims` - must include CN.
    async fn authenticate_zpr_entity_rsa(
        &self,
        asm: Arc<Assembly>,
        ssb: &SelfSignedBlob,
        unauthd_claims: Vec<Attribute>,
        authd_claims: Vec<Attribute>,
        dock_interface: u8,
    ) -> Result<Actor, ServiceError> {
        // a) is the auth correct (check policy for CN, check sig.)
        // b) is connection allowed by policy?
        //
        // Note that (b) is also needed for the AC type auth.

        // A revoked bootstrap root never authenticates (zipline#136).
        Self::check_bootstrap_denylist(&asm, &ssb.cn).await?;

        // One coherent policy view for validation and authorization (PR #6 review).
        let psnap = asm.policy_mgr.get_current_snapshot();
        let mut authd_claims = authd_claims;
        authd_claims.extend(self.authenticate_ss_blob(psnap.policy(), ssb, &unauthd_claims)?);

        // Ok checks out -- now run through policy.
        let mut actor = self
            .authorize_connection(
                asm,
                &psnap,
                &ssb.cn,
                unauthd_claims,
                authd_claims,
                dock_interface,
            )
            .await?;

        // The visa service's own token gets the VS expiration. A 4 hour token would expire its
        // own authentication and it would start denying its own visas.
        // The `zpr.vs.bootstrap.ident` token follows the actor's authority
        // expiries (zipline#119) — same minting rule as connect.
        let ident_expires = vs_ident_expiration(&actor);
        let jwt_lifetime = ident_expires
            .duration_since(SystemTime::now())
            .unwrap_or(config::DEFAULT_AUTH_EXPIRATION);
        let actor_jwt = if actor.is_node() {
            self.gen_jwt(format!("node/{}", ssb.cn), jwt_lifetime)?
        } else {
            self.gen_jwt(format!("adapter/{}", ssb.cn), jwt_lifetime)?
        };
        let _ = actor.add_attribute(
            Attribute::builder(ATTR_KEY_VS_IDENT)
                .expires(ident_expires)
                .value(actor_jwt),
        );
        let _ = actor.add_identity_key(0, ATTR_KEY_VS_IDENT);

        Ok(actor)
    }

    /// Use policy to authorize the connection request. Works for adapters and nodes.
    /// If successful you get an authorized Actor back.
    ///
    /// Is able to use the api=file Trusted service to fetch additional attributes.
    /// Eventually will query trusted services for additional actor attributes.
    ///
    /// Does not alter our actor databases.
    /// May take an IP address.
    ///
    /// Caller should set ROLE in unauthd_claims before calling.
    ///
    /// This does NOT add any authority attribute itself: the authentication path
    /// (blob arm) that verified the entity owns stamping the namespaced authority
    /// (e.g. [key::DEVICE_AUTHORITY] on the RSA bootstrap path). Whichever
    /// namespaced authorities are present are registered as identity attributes.
    ///
    /// An authenticated endpoint that matches no join policy is still authorized --
    /// it just gets no role and no services, so no communication policy admits it
    /// anywhere (#227). This holds for user (OIDC) logins too; see
    /// [EvalContext::approve_connection].
    async fn authorize_connection(
        &self,
        asm: Arc<Assembly>,
        psnap: &PolicySnapshot,
        endpoint_cn: &str,
        unauthd_claims: Vec<Attribute>,
        authd_claims: Vec<Attribute>,
        dock_interface: u8,
    ) -> Result<Actor, ServiceError> {
        self.authorize_connection_impl(
            asm,
            psnap,
            endpoint_cn,
            unauthd_claims,
            authd_claims,
            dock_interface,
            None,
        )
        .await
    }

    /// As [Self::authorize_connection], but for the zipline#43 REAUTH path:
    /// `renewal_of` names the live address whose session the caller has
    /// already proven (blob re-validated, session anchors checked, actor
    /// loaded from that address). Only [Self::reauthorize_actor] may pass
    /// `Some` — it is what authorizes re-accepting an address that is
    /// occupied by its own holder. A fresh connect never proves a session,
    /// so it goes through [Self::authorize_connection] and gets `None`
    /// (PR #33 review, P1).
    #[allow(clippy::too_many_arguments)]
    async fn authorize_connection_impl(
        &self,
        asm: Arc<Assembly>,
        psnap: &PolicySnapshot,
        endpoint_cn: &str,
        unauthd_claims: Vec<Attribute>,
        mut authd_claims: Vec<Attribute>,
        _dock_interface: u8,
        renewal_of: Option<IpAddr>,
    ) -> Result<Actor, ServiceError> {
        // TODO: Check with our revocation tables.
        info!(target: CC, "authorize_connection - TODO: check revocation table");
        // Actor may be denied by CN -- we can detect that before calling into policy.
        // In the future actor may be denied if the credential associated with the auth service is revoked.

        // NOTE: the CN is deliberately NOT promoted to an authenticated claim here.
        // Classification is the caller's job: a path that verified the CN (e.g. an RSA
        // blob signature) pushes it into `authd_claims` itself, and a path that only
        // received a claimed CN leaves it unauthenticated. `endpoint_cn` is log-only.
        let current_policy = psnap.policy();
        authd_claims.push(
            Attribute::builder(key::CONFIG_ID)
                .value(format!("{}", current_policy.get_version().unwrap_or(0))),
        );

        // The trusted-service lookup is keyed on the actor's lookup-identity set: the
        // policy's lookup-identity keys intersected with the *authenticated* claims, as
        // (key, value) pairs so a source can tell a device CN from a user subject. Both
        // are in hand before approve_connection runs and before any ZPR address exists,
        // which matters because the attributes fetched here feed the join decision
        // itself. Nothing is recorded with the revision cache on this fetch (it is
        // keyed on the ZPR address, which does not exist yet); the first post-connect
        // refresh treats every source as stale and re-fetches once.
        let lookup_keys = current_policy.lookup_identity_keys();
        let identities = lookup_identities(&lookup_keys, authd_claims.iter());

        // A lookup failure is indeterminate, not "the actor has no such attribute", and
        // the two are indistinguishable once evaluation starts: a join policy can be
        // satisfied by a missing key. Refuse the connection rather than authorize
        // against a partial claim set. Note this means a trusted-service outage blocks
        // new connections.
        // Query the snapshot's stores, not the live ts_mgr list, so the
        // attributes feeding this join decision come from the same policy
        // revision the decision is evaluated under (PR #6 review). The
        // stores are shared Arcs, so an unchanged store carries the same
        // cached/admitted data either way.
        for (source_id, ts_results) in
            TrustedServicesMgr::get_attributes_for_actor_from(psnap.trusted_services(), &identities)
                .await
        {
            match ts_results {
                Ok(ts_attrs) => {
                    // A source that vends `user.*` attributes is the authority asserting
                    // that user identity, so it installs `user.zpr.authority = <source id>`
                    // alongside them (#324 follow-up); see [derive_user_authority]. The
                    // identity-key registration below then picks it up unchanged.
                    // Recomputed per iteration so the first vouching source in
                    // `policy.list_services()` order wins — and an authority stamped by
                    // the auth-blob arm before this loop wins over all of them
                    // (zipline#26).
                    let existing_authority: Option<String> = authd_claims
                        .iter()
                        .find(|a| a.get_key() == key::USER_AUTHORITY)
                        .and_then(|a| a.get_value().first().cloned());
                    if let Some(authority) =
                        derive_user_authority(&source_id, &ts_attrs, existing_authority.as_deref())
                    {
                        authd_claims.push(authority);
                    }
                    for attr in ts_attrs {
                        authd_claims.push(attr);
                    }
                }
                Err(e) => {
                    error!(target: CC, "ts service attr lookup failed for actor {}: {}", endpoint_cn, e);
                    return Err(ServiceError::AttributesIndeterminate(format!(
                        "trusted service lookup failed for {endpoint_cn}: {e}"
                    )));
                }
            }
        }

        // zipline#102: the visa service's own address is fixed by configuration. It
        // cannot come from a policy pin (zipline#98 rejects pinning it) and a peer's
        // request is scrubbed unless pinned (zipline#97), so an endpoint whose
        // AUTHENTICATED CN is the visa service's is assigned that address here, as
        // an authenticated claim that approve_connection always commits. Only a
        // validated blob (or the VS authorizing itself) promotes the CN into
        // `authd_claims`, so a merely claimed `vs.zpr` gets nothing. The
        // re-authorization and range arms below then treat it like any other
        // pre-set address.
        let authenticated_as_vs = authd_claims
            .iter()
            .any(|a| a.get_key() == key::CN && a.get_value().iter().any(|v| v == config::VS_CN));
        let has_authd_addr = authd_claims.iter().any(|a| a.get_key() == key::ZPR_ADDR);
        if authenticated_as_vs && !has_authd_addr {
            authd_claims.push(
                Attribute::builder(key::ZPR_ADDR).value(asm.config.get_vs_addr().to_string()),
            );
        }

        let ectx = EvalContext::new(psnap.policy_arc());

        // TODO: Need to go in to eval and fix the approve_connection logic w/respect to the ROLE claim.
        // We won't know a priori if this is a node or adapter. Though sometimes we do know it's a node.
        // Anyway, best to let VS sort it out and do not do it in libeval.
        let mut authd_actor =
            match ectx.approve_connection(Some(&authd_claims), Some(&unauthd_claims)) {
                Ok(approved) => approved,
                Err(e) => {
                    info!(target: CC, "connection not approved for cn {}: {}", endpoint_cn, e);
                    return Err(e.into());
                }
            };

        // The blob arms own the authority: register whichever namespaced authority
        // attributes the authentication path stamped as identity attributes, rather
        // than adding a blanket one here (OIDC.md: the `<ns>.zpr.authority` invariant).
        for authority_key in [key::DEVICE_AUTHORITY, key::USER_AUTHORITY] {
            if authd_actor.get_attribute(authority_key).is_some() {
                authd_actor.add_identity_key(usize::MAX, authority_key)?;
            }
        }

        let actor_role = if authd_actor.is_node() {
            Role::Node
        } else {
            Role::Adapter
        };

        // zipline#99 (A3): a trusted service may grant the device's requested ZPR
        // address by vending an authenticated `device.zpr_addr` attribute. Promote
        // the grant to the requested `zpr.addr` HERE — before the pre-set-address
        // checks below — so it flows through exactly the zipline#98 arms (in
        // range, not the VS, outside the pools, unheld, proof arms) with no
        // duplication. Only authenticated attributes reach the actor
        // (approve_connection never commits self-asserted claims to it), so a
        // peer cannot steer its own address by claiming a grant. `addr_source`
        // tells the log/error lines below apart: a rejected pin reads "static",
        // a rejected grant reads "granted" (operator answer on the plan, Q2).
        let mut addr_source = "static";
        // PR #34 review (P1): read the grant from the accumulated authenticated
        // CLAIMS, not from the actor. Actor::add_attribute is a keyed insert,
        // so by the time the actor exists, grants from two trusted services
        // have already collapsed to whichever source was iterated last — and
        // that order comes from policy HashMap iteration, so the surviving
        // address could vary across policy loads. `authd_claims` still holds
        // every vended attribute, so conflicting grants are visible here.
        // Distinct addresses — across sources or within one attribute — are
        // ambiguous and rejected loudly (plan Q1); duplicates that agree are
        // redundancy, not ambiguity.
        let grant_attr_count = authd_claims
            .iter()
            .filter(|a| a.get_key() == key::DEVICE_ZPR_ADDR)
            .count();
        if grant_attr_count > 0 {
            let mut values: Vec<String> = authd_claims
                .iter()
                .filter(|a| a.get_key() == key::DEVICE_ZPR_ADDR)
                .flat_map(|a| a.get_value().iter().cloned())
                .collect();
            values.sort();
            values.dedup();
            // A grant that cannot be understood is an operator error to surface
            // loudly, never something to silently fall back to the pool on (plan
            // Q1): a device the operator meant to place would quietly come up
            // somewhere else.
            let [value] = values.as_slice() else {
                warn!(target: CC, "rejecting {} grant for cn {}: expected exactly one address, got {:?}", key::DEVICE_ZPR_ADDR, endpoint_cn, values);
                return Err(ServiceError::AuthenticationFailed(format!(
                    "{} grant must resolve to exactly one address, got {} distinct values",
                    key::DEVICE_ZPR_ADDR,
                    values.len()
                )));
            };
            let granted: IpAddr = value.parse().map_err(|_| {
                warn!(target: CC, "rejecting {} grant for cn {}: not an IP address: '{}'", key::DEVICE_ZPR_ADDR, endpoint_cn, value);
                ServiceError::AuthenticationFailed(format!(
                    "{} grant is not an IP address: '{value}'",
                    key::DEVICE_ZPR_ADDR
                ))
            })?;
            match authd_actor.get_zpr_addr().copied() {
                // Two sources both claim to own the address decision: a policy
                // pin that survived the join (zipline#97) and a trusted-service
                // grant that disagrees with it. That is an operator error, not a
                // tiebreak to invent — reject naming both.
                Some(pinned) if pinned != granted => {
                    warn!(target: CC, "rejecting connection for cn {}: trusted-service grant {}={} disagrees with the pre-set zpr address {}", endpoint_cn, key::DEVICE_ZPR_ADDR, granted, pinned);
                    return Err(ServiceError::AuthenticationFailed(format!(
                        "trusted-service grant {}={granted} disagrees with the pre-set zpr address {pinned}",
                        key::DEVICE_ZPR_ADDR
                    )));
                }
                // The grant agrees with the pre-set address: redundant, not an
                // error. The address keeps its original (static/pin) source.
                Some(_) => {
                    info!(target: CC, "trusted-service grant {}={} agrees with the pre-set zpr address for cn {}", key::DEVICE_ZPR_ADDR, granted, endpoint_cn);
                }
                None => {
                    authd_actor
                        .add_attribute(Attribute::builder(key::ZPR_ADDR).value(value.as_str()))?;
                    addr_source = "granted";
                    info!(target: CC, "honoring trusted-service grant of zpr address {} for cn {}", granted, endpoint_cn);
                }
            }
        }

        if let Some(addr) = authd_actor.get_zpr_addr() {
            // A pre-set address is either STATIC -- a policy pin committed under a
            // matched join policy (zipline#97) or, later, a trusted-service grant
            // (zipline#99) -- or a VS-assigned address riding back through a
            // re-authorization (session renewal per zipline#43, a node reconnect,
            // the VS adapter's own connect). Who holds the address decides which
            // (zipline#98):
            //
            // - Held by a live actor: accepted ONLY under a proven
            //   re-authorization or reconnect (PR #33 review, P1). CN equality
            //   alone is NOT ownership -- the repository supports multiple
            //   same-CN actors, and two CN-less OIDC actors both report `None`,
            //   which must never count as a match. The proofs accepted:
            //   - the caller proved this endpoint's session against the live
            //     actor at exactly this address (`renewal_of`, the zipline#43
            //     REAUTH path);
            //   - a node reconnecting to its own live node record: node
            //     identity is RSA-proven against the policy bootstrap key for
            //     its CN, and a second holder of that key IS the node;
            //   - the visa service re-authorizing itself at its own address
            //     across a restart (CN authenticated by construction or
            //     against the VS bootstrap key).
            //   Anything else -- including a same-CN adapter -- is a collision:
            //   rejected and logged, never silently renumbered or overwritten.
            //   A rejected same-CN adapter reconnects once its stale record
            //   expires or is disconnected; it must not evict it.
            // - Held by nobody: a fresh static address. It must be inside the
            //   ZPR range, not the visa service's own address (unless this IS
            //   the visa service authorizing itself), and OUTSIDE both managed
            //   pools -- static addresses live in a separate address space, so
            //   the allocator can never double-allocate one and there is
            //   nothing to reserve or undo.
            let addr = *addr;
            match asm.actor_mgr.get_actor_by_zpr_addr(&addr).await? {
                Some(_) if renewal_of == Some(addr) => {
                    info!(target: CC, "re-authorizing {actor_role:?} cn {} at its live ZPR addr {} (proven session renewal)", endpoint_cn, addr);
                }
                Some(holder)
                    if holder.is_node()
                        && authd_actor.is_node()
                        && holder.get_cn().is_some()
                        && holder.get_cn() == authd_actor.get_cn() =>
                {
                    info!(target: CC, "re-authorizing node cn {} at its live ZPR addr {} (RSA-proven node reconnect)", endpoint_cn, addr);
                }
                Some(holder)
                    if addr == asm.config.get_vs_addr()
                        && holder.get_cn() == Some(config::VS_CN)
                        && authd_actor.get_cn() == Some(config::VS_CN) =>
                {
                    info!(target: CC, "re-authorizing the visa service at its own ZPR addr {}", addr);
                }
                Some(_) => {
                    warn!(target: CC, "rejecting {addr_source} zpr address already held by a live actor, claimed by cn {}: {}", endpoint_cn, addr);
                    return Err(ServiceError::AuthenticationFailed(format!(
                        "{addr_source} zpr address already held by a live actor: {addr}"
                    )));
                }
                None => {
                    let is_vs_self = addr == asm.config.get_vs_addr()
                        && authd_actor.get_cn() == Some(config::VS_CN);
                    if !net_mgr::is_zpr_addr(&addr)
                        || (addr == asm.config.get_vs_addr() && !is_vs_self)
                    {
                        warn!(target: CC, "rejecting {addr_source} zpr address out of range for cn {}: {}", endpoint_cn, addr);
                        return Err(ServiceError::AuthenticationFailed(format!(
                            "{addr_source} zpr address out of range: {addr}"
                        )));
                    }
                    if asm.net_mgr.is_managed_address(&addr) {
                        warn!(target: CC, "rejecting {addr_source} zpr address inside a managed pool for cn {}: {}", endpoint_cn, addr);
                        return Err(ServiceError::AuthenticationFailed(format!(
                            "{addr_source} zpr address inside a managed pool: {addr}"
                        )));
                    }
                    info!(target: CC, "authorized connection of {actor_role:?} cn {} with {addr_source} ZPR addr {}", endpoint_cn, addr);
                }
            }
        } else {
            match asm.net_mgr.get_next_zpr_addr(&actor_role) {
                Ok(addr) => {
                    authd_actor
                        .add_attribute(Attribute::builder(key::ZPR_ADDR).value(addr.to_string()))?;
                    info!(target: CC, "authorized adapter/{actor_role:?} cn {} assigned ZPR addr {}", endpoint_cn, addr);
                }
                Err(e) => {
                    error!(target: CC, "failed to assign ZPR addr to authorized adapter/{actor_role:?} cn {}: {}", endpoint_cn, e);
                    return Err(ServiceError::Internal("address assignment failed".into()));
                }
            }
        }

        Ok(authd_actor)
    }

    /// Remove departed adapters: each one's actor record, its recorded trusted-service
    /// revisions and, if it came from our pool, its ZPR address. The docking node's
    /// record (and so its connected-adapters set) is left for the caller.
    ///
    /// **The visa service's own adapter is always spared** (zipline#167): the VS keeps
    /// running across its docking node's departure, and its actor record is re-created
    /// only at VS startup or when its adapter re-docks — so removing it here would
    /// leave the VS unable to mint its own VS→VSS visa until that re-dock, losing the
    /// race against a restarting node's `register_vss`. This filter used to live in
    /// each caller (and the disconnect path was missing it); it lives here so every
    /// teardown path gets it.
    ///
    /// Returns the addresses whose actor records were removed, for the caller to pass
    /// to [crate::visa_mgr::VisaMgr::remove_visas_for_actors]. Failures are logged and
    /// skipped so one bad adapter cannot strand the rest.
    ///
    /// Used by [ConnectionControl::disconnect] for the adapters of a departing node,
    /// by a node's fresh (`ctype=Reset`) connect, whose previously docked adapters
    /// are gone with the node's state (zipline#138), and by the startup cull's
    /// teardown (`teardown_culled_nodes`, zipline#145).
    pub async fn remove_departed_adapters(
        &self,
        asm: &Assembly,
        adapter_addrs: &[IpAddr],
    ) -> Vec<IpAddr> {
        let vs_addr = asm.config.get_vs_addr();
        let mut removed = Vec::with_capacity(adapter_addrs.len());
        for &adapter_addr in adapter_addrs {
            if adapter_addr == vs_addr {
                debug!(target: CC, "sparing the visa service's own adapter {adapter_addr} in departed-adapter teardown");
                continue;
            }
            if let Err(e) = asm.actor_mgr.remove_actor_by_zpr_addr(&adapter_addr).await {
                // Caller can't do anything with this. So just log and continue. The
                // address stays allocated: the actor record may have survived, and a
                // recycled address would collide with it (PR #45 review).
                error!(target: CC, "failed to remove docked adapter with addr {adapter_addr} from actor db: {e}");
                continue;
            }
            // Purge before the adapter's address can be recycled: a later actor at
            // this address must not inherit its revision records.
            asm.ts_mgr.forget_actor_revisions(&adapter_addr);
            removed.push(adapter_addr);
            if asm.net_mgr.is_managed_address(&adapter_addr) {
                if let Err(s) = asm.net_mgr.release_zpr_addr(adapter_addr) {
                    error!(target: CC, "failed to release ZPR addr {adapter_addr} for orphaned adapter: {s}");
                }
            }
        }
        removed
    }

    /// Disconnect logic. Cleans up actor database, visas, and our view of topology. Updates router.
    ///
    /// This is used only for policy disconnect calls over the VSAPI or for a policy instigated disconnect.
    /// In both cases, it is safe to remove all state for the disconnecting actor.
    ///
    /// A topology operation (TopoOps invariant): the local teardown runs under one
    /// guard, from the actor lookup to the last state removal, so a reconnect of the
    /// same node is either fully before it or fully after it and its state is never
    /// torn down by a disconnect that started earlier. A node's VSS worker is stopped
    /// after the guard is released, since stopping waits on that worker.
    ///
    /// ### Errors
    /// Most cleanup failures are logged and swallowed (the caller can't act on them). Only these
    /// propagate as `Err`:
    /// - Looking up the actor (`get_actor_by_zpr_addr`) hits a backing-store error other than
    ///   "not found" — i.e. the DB is unreachable/misbehaving.
    /// - Removing a node record (`remove_node`) may fail on a backing-store error.
    ///
    pub async fn disconnect(
        &self,
        asm: Arc<Assembly>,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
    ) -> Result<(), ServiceError> {
        let ops = asm.topo_mgr.ops().await;
        let (vss, result) = self.disconnect_locked(&ops, &asm, zpr_addr, reason).await;
        drop(ops);
        Self::stop_vss_worker(vss, &zpr_addr);
        result
    }

    /// Stop a disconnected node's VSS worker, if it had one.
    ///
    /// The stop is queued from a detached task, so the caller never waits on the
    /// worker (g101): its command queue may be full behind RPCs waiting out their
    /// timeouts over a link that is gone, and the stop is delivered once there is room.
    pub fn stop_vss_worker(vss: Option<VssHandle>, zpr_addr: &IpAddr) {
        let Some(vss_hndl) = vss else {
            return;
        };
        let zpr_addr = *zpr_addr;
        tokio::spawn(async move {
            if let Err(e) = vss_hndl.stop().await {
                error!(target: CC, "failed to stop VSS worker for disconnected node at addr {zpr_addr}: {e}");
            }
        });
    }

    /// The local teardown of [Self::disconnect], under the caller's topology guard
    /// (for a caller that already holds one, such as the policy pass). Returns the
    /// node's VSS worker handle, which the caller stops with [Self::stop_vss_worker]
    /// after releasing the guard, and the teardown result.
    pub async fn disconnect_locked(
        &self,
        ops: &TopoOps<'_>,
        asm: &Arc<Assembly>,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
    ) -> (Option<VssHandle>, Result<(), ServiceError>) {
        let mut vss = None;
        let result = self
            .teardown_actor(ops, asm, zpr_addr, reason, &mut vss)
            .await;
        (vss, result)
    }

    /// Body of [Self::disconnect_locked]; sets `vss` to the node's VSS worker handle.
    async fn teardown_actor(
        &self,
        ops: &TopoOps<'_>,
        asm: &Arc<Assembly>,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
        vss: &mut Option<VssHandle>,
    ) -> Result<(), ServiceError> {
        info!(target: CC, "disconnect actor at {} for reason {:?}", zpr_addr, reason);
        // The actor record is removed under the node commit lock too (#63
        // review): a node's reauthorization of its own actor holds it from its
        // session check to its write, so a removal landing in between would be
        // undone by that write. Taken inside the caller's topology guard -- lock
        // order: topology lock, then node commit lock -- and never by a path
        // that already holds the node commit lock (`reauthorize` disconnects
        // only after releasing it).
        let removal_guard = asm.policy_mgr.node_commit_lock.lock().await;

        let maybe_actor = asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await?;
        if maybe_actor.is_none() {
            warn!(target: CC, "disconnect for addr {zpr_addr} but no actor found in database");
        }

        match asm.actor_mgr.remove_actor_by_zpr_addr(&zpr_addr).await {
            Ok(()) => {
                // Purge recorded trusted-service revisions before the address returns to
                // the pool: addresses are recycled, and a later actor at this address
                // must not inherit them.
                asm.ts_mgr.forget_actor_revisions(&zpr_addr);
            }
            Err(e) => {
                // Caller can't do anything with this. So just log and continue.
                error!(target: CC, "failed to remove disconnected actor with addr {zpr_addr} from actor db: {e}");
            }
        };
        drop(removal_guard);

        let mut removed_zpr_addrs = Vec::new();
        removed_zpr_addrs.push(zpr_addr);

        if let Some(actor) = maybe_actor {
            if actor.is_node() {
                asm.topo_mgr.remove_node(ops, &zpr_addr).await;
                *vss = asm.vss_mgr.get_handle(&zpr_addr);
                if vss.is_none() {
                    debug!(target: CC, "no VSS worker found for disconnected node at addr {zpr_addr}");
                }
                let connected_adapters = match asm
                    .actor_mgr
                    .get_adapters_connected_to_node(&zpr_addr)
                    .await
                {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        error!(target: CC, "failed to get connected adapters for disconnected node at addr {zpr_addr}: {e}");
                        Vec::new()
                    }
                };
                removed_zpr_addrs.extend(
                    self.remove_departed_adapters(asm, &connected_adapters)
                        .await,
                );
                asm.actor_mgr.remove_node(&zpr_addr).await?;
                if let Err(e) = asm.visa_mgr.remove_visas_for_node(&zpr_addr).await {
                    error!(target: CC, "failed to remove visas for disconnected node at addr {zpr_addr}: {e}");
                }
            }
        }
        if let Err(e) = asm
            .visa_mgr
            .remove_visas_for_actors(&removed_zpr_addrs)
            .await
        {
            error!(target: CC, "failed to remove visas for disconnected actor at addr {zpr_addr}: {e}");
        }

        if asm.net_mgr.is_managed_address(&zpr_addr) {
            // De-allocating an address may error but it only indicates that the
            // address is not part of our pool.  We just log that if it occurs
            // and call the "disconnect" successful anyway.
            if let Err(e) = asm.net_mgr.release_zpr_addr(zpr_addr) {
                warn!(target: CC, "failed to release managed ZPR addr {zpr_addr} for actor disconnect: {e}");
            }
        }
        Ok(())
    }
}

/// A node's own substrate address, taken from the resolved topology: for a peer `P` sharing
/// a link with `node_addr`, `P`'s resolved link points back at `node_addr`'s substrate. That
/// value is authoritative (it is what policy declares and what every peer dials) and is
/// already DNS-resolved, so it parses as a `SocketAddr`.
///
/// Returns `None` when policy declares no peering for the node, or none of its links appear
/// in the resolved topology -- both mean policy cannot tell us.
///
/// Does not support multi-homed nodes!
pub fn substrate_addr_from_topology(asm: &Assembly, node_addr: &IpAddr) -> Option<SocketAddr> {
    let psnap = asm.policy_mgr.get_current_snapshot();
    for peer in psnap.policy().get_peers_for_node(node_addr)? {
        if let Some((_, sock_addr)) = psnap
            .resolved_peers_for_node(&peer.remote_zpr_addr)
            .into_iter()
            .find(|(link_id, _)| *link_id == peer.link_id)
        {
            return Some(sock_addr);
        }
    }
    None
}

/// STUB (tests first): today's policy check only; replaced in the next commit.
pub fn accept_reported_substrate(
    asm: &Assembly,
    node_addr: &IpAddr,
    reported: SocketAddr,
) -> Result<SocketAddr, ServiceError> {
    match substrate_addr_from_topology(asm, node_addr) {
        Some(declared) if declared != reported => Err(ServiceError::Param(format!(
            "substrate address mismatch: policy declares {declared}, node reported {reported}"
        ))),
        Some(declared) => Ok(declared),
        None => Ok(reported),
    }
}

/// Required claims must be present and non-empty.
fn check_required_claims(claims: &[Claim], required: &[&str]) -> Result<(), ServiceError> {
    let mut required_set = std::collections::HashSet::new();
    for rc in required {
        required_set.insert(*rc);
    }

    for claim in claims {
        if required_set.contains(claim.key.as_str()) {
            if claim.value.is_empty() {
                return Err(ServiceError::Param(format!(
                    "{} claim cannot be empty",
                    claim.key
                )));
            }
            required_set.remove(claim.key.as_str());
        }
    }

    if !required_set.is_empty() {
        let missing: Vec<&str> = required_set.into_iter().collect();
        return Err(ServiceError::Param(format!(
            "missing required claims: {:?}",
            missing
        )));
    }

    Ok(())
}

// Gatekeep claims. Claims are considered to be adapter _requests_ which may
// or may not be honored by policy.  But we set attributes from them and
// and some are for internal use only.
//
// Generally no claims that start with "zpr." are allowed except:
//   - zpr.addr -> which is interpreted as a request adapter ZPR address.
//
// Also cannot have <class>.zpr.* except:
//   - device.zpr.adapter.cn -> which is the CN of the adapter as told to the node.
//
// Note classes are device, user, service (as per ZPL and the compiler).
//
// Finally, the incoming VSAPI "Claims" are converted into libeval "Attributes" and returned.
fn scrub_adapter_claims(claims: Vec<Claim>) -> Result<Vec<Attribute>, ServiceError> {
    let mut scrubbed_claims = Vec::new();
    for claim in claims {
        if claim.key == key::ZPR_ADDR {
            // Allow zpr.addr
            scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
            continue;
        }

        if claim.key.starts_with("zpr.") {
            warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
            continue;
        }

        let parts: Vec<&str> = claim.key.split('.').collect();
        if parts.len() >= 2 && parts[1] == "zpr" {
            // Only permissible is device.zpr.adapter.cn
            if claim.key == key::CN {
                // Allow device.zpr.adapter.cn
                scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
                continue;
            }

            // We only check for the defined classes.
            if parts[0] == CLASS_DEVICE || parts[0] == CLASS_USER || parts[0] == CLASS_SERVICE {
                warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
                continue;
            }
        }

        // Note that we don't handle multi-value claims at this point.
        scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
    }
    Ok(scrubbed_claims)
}

/// The A2A DH public key as an attribute claim, or None if it is not a usable X25519 key.
fn a2a_dh_pubkey_claim(key: &PublicKey) -> Option<Attribute> {
    (key.public_key.len() == 32).then(|| {
        Attribute::builder(key::A2A_DH_PUBKEY).value(libeval::pubkey::encode_public_key(key))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// g101: stopping a VSS worker never waits on the worker. Its command queue may
    /// be full behind RPCs waiting out their timeouts over a dead link (a node cut off
    /// by a policy, a rejoiner's previous session); the caller moves on at once, and
    /// the stop is delivered once there is room.
    #[tokio::test]
    async fn test_stop_vss_worker_does_not_wait_on_a_full_queue() {
        let addr: IpAddr = "fd5a:5052::3".parse().unwrap();
        let mgr = crate::vss_mgr::VssMgr::new();
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<crate::vss::VssCmd>(1);
        mgr.insert_test_handle(addr, cmd_tx.clone());
        // The queue is full: the worker is busy with an earlier command.
        cmd_tx.try_send(crate::vss::VssCmd::Stop()).unwrap();

        // Returns at once: it is not async, so it cannot wait for room in the queue.
        ConnectionControl::stop_vss_worker(mgr.get_handle(&addr), &addr);

        // The worker takes the earlier command; then the stop arrives.
        assert!(cmd_rx.recv().await.is_some());
        let stop = tokio::time::timeout(std::time::Duration::from_secs(1), cmd_rx.recv())
            .await
            .expect("the stop is delivered once there is room");
        assert!(matches!(stop, Some(crate::vss::VssCmd::Stop())));
    }

    use crate::test_helpers::make_container_bytes;
    use libeval::pio;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use std::sync::Arc;
    use zpr::policy::v1;

    fn make_cc(ident: &str) -> ConnectionControl {
        ConnectionControl::new(ident.to_string())
    }

    /// A node's substrate address comes from its peer's view of their shared link, and is
    /// `None` when policy declares no peering for it.
    #[tokio::test]
    async fn test_substrate_addr_from_topology() {
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::db::PolicyRepo;
        use crate::policy_mgr::PolicyMgr;
        use crate::test_helpers::{FakeResolver, make_peering, policy_with_peerings};
        use crate::trusted_services::TrustedServicesMgr;
        use std::path::PathBuf;

        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let unpeered: IpAddr = "fd5a:5052:90de:1::9".parse().unwrap();

        let mut asm = new_assembly_for_tests(None).await;
        asm.policy_mgr = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[make_peering(a, b, "link-ab", vec![])]),
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

        // make_peering uses each node's own address as its substrate, port 0.
        assert_eq!(
            substrate_addr_from_topology(&asm, &b),
            Some(SocketAddr::new(b, 0)),
            "node B's substrate is the address peer A dials it at"
        );
        assert_eq!(
            substrate_addr_from_topology(&asm, &unpeered),
            None,
            "a node with no peering has no policy-derived substrate"
        );
    }

    fn decode_jwt(token: &str, secret: &str) -> Result<JwtClaims, jwt::errors::Error> {
        let key = jwt::DecodingKey::from_secret(secret.as_bytes());
        let validation = jwt::Validation::new(jwt::Algorithm::HS256);
        jwt::decode::<JwtClaims>(token, &key, &validation).map(|d| d.claims)
    }

    #[test]
    fn new_preserves_valid_ident_chars() {
        let cc = make_cc("valid-ident_1.2");
        assert_eq!(cc.authority, "vs.zpr/valid-ident_1.2");
    }

    #[test]
    fn new_sanitizes_special_chars() {
        let cc = make_cc("test@host:port/path");
        assert_eq!(cc.authority, "vs.zpr/test_host_port_path");
    }

    #[test]
    fn gen_jwt_node_has_correct_claims() {
        let cc = make_cc("test-vs");
        let token = cc
            .gen_jwt("node/my-node".to_string(), config::DEFAULT_AUTH_EXPIRATION)
            .unwrap();
        let claims = decode_jwt(&token, "test-vs").expect("token must decode");

        assert_eq!(claims.sub, "node/my-node");
        assert_eq!(claims.iss, "vs.zpr/test-vs");
    }

    #[test]
    fn gen_jwt_jti_is_unique_per_call() {
        let cc = make_cc("test-vs");
        let exp = config::DEFAULT_AUTH_EXPIRATION;
        let t1 = decode_jwt(&cc.gen_jwt("node/cn".to_string(), exp).unwrap(), "test-vs").unwrap();
        let t2 = decode_jwt(&cc.gen_jwt("node/cn".to_string(), exp).unwrap(), "test-vs").unwrap();
        assert_ne!(t1.jti, t2.jti);
    }

    fn claim(key: &str, value: &str) -> Claim {
        Claim::new(key.to_string(), value.to_string())
    }

    fn keys(claims: &[Attribute]) -> Vec<String> {
        claims
            .iter()
            .map(|claim| claim.get_key().to_string())
            .collect()
    }

    #[test]
    fn scrub_adapter_claims_allows_addr_and_cn() {
        let claims = vec![
            claim(key::ZPR_ADDR, "fd5a:5052:90de::1"),
            claim(key::CN, "adapter.example"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, key::CN]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_zpr_prefix_except_addr() {
        let claims = vec![
            claim("zpr.role", "adapter"),
            claim("zpr.services", "svc-a"),
            claim(key::ZPR_ADDR, "fd5a:5052:90de::2"),
            claim("device.label", "edge"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, "device.label"]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_class_zpr_for_known_classes() {
        let claims = vec![
            claim("device.zpr.adapter.token", "nope"),
            claim("user.zpr.name", "nope"),
            claim("service.zpr.name", "nope"),
            claim(key::CN, "allowed-cn"),
            claim("custom.zpr.value", "ok"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::CN, "custom.zpr.value"]);
    }

    // --- authenticate_node helpers ---

    fn gen_rsa_test_keypair() -> (PKey<Private>, Vec<u8>) {
        let rsa = Rsa::generate(2048).unwrap();
        let privkey = PKey::from_rsa(rsa).unwrap();
        let pubkey_der = privkey.public_key_to_der().unwrap();
        (privkey, pubkey_der)
    }

    fn sign_node_challenge(
        privkey: &PKey<Private>,
        timestamp: u64,
        cn: &str,
        challenge: &[u8],
    ) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), privkey).unwrap();
        signer.update(&timestamp.to_be_bytes()).unwrap();
        signer.update(cn.as_bytes()).unwrap();
        signer.update(challenge).unwrap();
        signer.sign_to_vec().unwrap()
    }

    /// Returns container bytes for Capn Proto `PolicyContainer`
    fn make_policy_with_bootstrap_key(cn: &str, pubkey_der: &[u8]) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            let mut keys = policy_bldr.reborrow().init_keys(1);
            keys.reborrow().get(0).set_id(cn);
            keys.reborrow()
                .get(0)
                .set_key_type(v1::KeyMaterialT::RsaPub);
            keys.reborrow()
                .get(0)
                .init_key_allows(1)
                .set(0, v1::KeyAllowance::Bootstrap);
            keys.reborrow().get(0).set_key_data(pubkey_der);
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        let container = make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        );
        container
    }

    // --- authenticate_node tests ---

    #[tokio::test]
    async fn test_make_policy_with_bootstrap_key() {
        // Make sure our helper serializes Capn Proto properly.
        let cn = "test-node.zpr";
        let (_privkey, pubkey_der) = gen_rsa_test_keypair();
        let container_bytes = make_policy_with_bootstrap_key(cn, &pubkey_der);

        pio::load_policy_from_container(&container_bytes, &config::POLICY_MIN_VERSION)
            .expect("should load policy from container bytes");
    }

    /// A trusted service whose lookups always fail, standing in for an unreadable
    /// attribute file or an unreachable service.
    struct FailingTrustedService;

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FailingTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Err(ServiceError::Internal("service is down".to_string()))
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "failing"
        }
    }

    /// A trusted-service lookup failure must reject the connection rather than
    /// authorize against a partial claim set -- a join policy can be satisfied by a
    /// missing key, so falling through would let an outage approve an actor.
    /// Drives `authorize_connection` with a snapshot carrying the failing store:
    /// the connect path reads the snapshot's stores, not the live ts_mgr list
    /// (PR #6 review), so that is the seam an outage flows through.
    #[tokio::test]
    async fn authorize_connection_rejects_on_trusted_service_failure() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let authd = vec![Attribute::builder(key::CN).value(config::VS_CN)];

        // Baseline: the same call with no trusted services succeeds, so the
        // rejection below is caused by the failure and not the setup.
        cc.authorize_connection(
            asm.clone(),
            &snap(policy.clone(), Vec::new()),
            config::VS_CN,
            Vec::new(),
            authd.clone(),
            0,
        )
        .await
        .expect("should authorize with no trusted services");

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, vec![Arc::new(FailingTrustedService)]),
                config::VS_CN,
                Vec::new(),
                authd,
                0,
            )
            .await;
        assert!(matches!(
            result,
            Err(ServiceError::AttributesIndeterminate(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_node_unknown_cn() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let result = cc
            .authenticate_node(
                asm,
                b"challenge",
                unix_now(),
                "unknown.zpr",
                &[],
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    #[tokio::test]
    async fn authenticate_node_invalid_signature() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (_, pubkey_der) = gen_rsa_test_keypair();
        match asm
            .policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
        {
            Ok(_vinst) => (),
            Err(e) => panic!("failed to update policy for test: {}", e),
        }

        let cc = make_cc("test-vs");
        let result = cc
            .authenticate_node(
                asm,
                b"challenge",
                unix_now(),
                cn,
                b"not-a-valid-rsa-sig",
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    #[tokio::test]
    async fn authenticate_node_signature_wrong_content() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let bad_sig = sign_node_challenge(&privkey, timestamp + 1, cn, challenge);
        let result = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &bad_sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ServiceError::AuthenticationFailed(_))));
    }

    fn make_policy_with_node_join_policy(cn: &str, pubkey_der: &[u8]) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            {
                let mut keys = policy_bldr.reborrow().init_keys(1);
                keys.reborrow().get(0).set_id(cn);
                keys.reborrow()
                    .get(0)
                    .set_key_type(v1::KeyMaterialT::RsaPub);
                keys.reborrow()
                    .get(0)
                    .init_key_allows(1)
                    .set(0, v1::KeyAllowance::Bootstrap);
                keys.reborrow().get(0).set_key_data(pubkey_der);
            }
            {
                // Empty match list → matches any connection; JoinFlag::Node marks this as a node.
                let mut jps = policy_bldr.reborrow().init_join_policies(1);
                jps.reborrow()
                    .get(0)
                    .init_flags(1)
                    .set(0, v1::JoinFlag::Node);
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    /// As [make_policy_with_node_join_policy], but the join policy carries a
    /// `zpr.addr eq <addr>` condition — the shape the compiler emits for a node's
    /// `zpr_address` — so a matching requested address is committed under the pin
    /// (zipline#97) and reaches the static-address checks (zipline#98).
    fn make_policy_with_pinned_node_join(cn: &str, pubkey_der: &[u8], addr: &str) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            {
                let mut keys = policy_bldr.reborrow().init_keys(1);
                keys.reborrow().get(0).set_id(cn);
                keys.reborrow()
                    .get(0)
                    .set_key_type(v1::KeyMaterialT::RsaPub);
                keys.reborrow()
                    .get(0)
                    .init_key_allows(1)
                    .set(0, v1::KeyAllowance::Bootstrap);
                keys.reborrow().get(0).set_key_data(pubkey_der);
            }
            {
                // Raw capnp for the `zpr.addr eq <addr>` condition: the
                // policy_types::Attribute builder rejects the reserved `zpr.`
                // domain, but the compiler emits exactly this expression for a
                // node's `zpr_address` (node_link.rs).
                let mut jps = policy_bldr.reborrow().init_join_policies(1);
                let mut jp = jps.reborrow().get(0);
                {
                    let mut matches = jp.reborrow().init_match(1);
                    let mut cond = matches.reborrow().get(0);
                    cond.set_key(key::ZPR_ADDR);
                    cond.set_op(v1::AttrOp::Eq);
                    cond.init_value(1).set(0, addr);
                }
                jp.init_flags(1).set(0, v1::JoinFlag::Node);
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    #[tokio::test]
    async fn authenticate_node_policy_denied() {
        // Test a valid node, but policy lacking a join policy for it.
        // So join is allowed but node role is denied.
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let result = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(
            matches!(result, Err(ServiceError::AuthenticationFailed(_))),
            "expected failure got {:?}",
            result
        );
    }

    /// As [make_policy_with_node_join_policy], plus a topology peering so the policy
    /// declares a substrate address for the peered nodes.
    fn make_policy_with_node_join_and_peering(
        cn: &str,
        pubkey_der: &[u8],
        peering: &zpr::policy_types::Peering,
    ) -> Vec<u8> {
        use zpr::write_to::WriteTo;
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            {
                let mut keys = policy_bldr.reborrow().init_keys(1);
                keys.reborrow().get(0).set_id(cn);
                keys.reborrow()
                    .get(0)
                    .set_key_type(v1::KeyMaterialT::RsaPub);
                keys.reborrow()
                    .get(0)
                    .init_key_allows(1)
                    .set(0, v1::KeyAllowance::Bootstrap);
                keys.reborrow().get(0).set_key_data(pubkey_der);
            }
            {
                let mut jps = policy_bldr.reborrow().init_join_policies(1);
                jps.reborrow()
                    .get(0)
                    .init_flags(1)
                    .set(0, v1::JoinFlag::Node);
            }
            {
                let mut topo = policy_bldr.reborrow().init_topology(1);
                peering.write_to(&mut topo.reborrow().get(0));
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    /// The RSA-verified (bootstrap) path installs the namespaced device authority
    /// `device.zpr.authority = "zpr-bootstrap"` as an identity attribute, and no
    /// legacy `zpr.authority` or `user.zpr.authority` attribute exists
    /// (OIDC.md: the `<ns>.zpr.authority` invariant).
    #[tokio::test]
    async fn test_rsa_path_installs_device_authority_bootstrap() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("authentication should succeed");

        assert_eq!(
            actor
                .get_attribute(key::DEVICE_AUTHORITY)
                .expect("device authority must be present")
                .get_value(),
            &vec![key::AUTHORITY_METHOD_BOOTSTRAP.to_string()],
            "RSA path must stamp device.zpr.authority = zpr-bootstrap"
        );
        assert!(
            actor.get_attribute("zpr.authority").is_none(),
            "legacy un-namespaced zpr.authority must not exist"
        );
        assert!(
            actor.get_attribute(key::USER_AUTHORITY).is_none(),
            "device-only bootstrap must not assert a user authority"
        );
        assert!(
            actor
                .identity_keys_iter()
                .any(|k| k == key::DEVICE_AUTHORITY),
            "device.zpr.authority must be registered as an identity key"
        );
    }

    /// With no topology entry for the node, the reported substrate address is stored
    /// as the node's `key::SUBSTRATE_ADDR` claim (no TCP-peer fallback exists anymore).
    #[tokio::test]
    async fn authenticate_node_no_topology_stores_reported_substrate() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap();

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                reported,
                None,
            )
            .await
            .expect("authentication should succeed");

        let stored = actor
            .get_attribute(key::SUBSTRATE_ADDR)
            .expect("substrate addr claim must be present")
            .get_value()[0]
            .clone();
        assert_eq!(stored, reported.to_string());
    }

    /// When policy topology declares a substrate for the node and the node reports a
    /// different one, authentication fails with a param error.
    #[tokio::test]
    async fn authenticate_node_topology_mismatch_is_param_error() {
        use crate::test_helpers::make_peering;

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        // make_peering declares each node's own address (port 0) as its substrate.
        let peering = make_peering(a, b, "link-ab", vec![]);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                cn,
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap(); // != policy's [b]:0

        let result = cc
            .authenticate_node(asm, challenge, timestamp, cn, &sig, b, reported, None)
            .await;
        assert!(
            matches!(result, Err(ServiceError::Param(_))),
            "expected param error, got {:?}",
            result
        );
    }

    /// A peering of `a` and `b` whose policy substrate address for each node is its own
    /// ZPR address with `port` ([crate::test_helpers::make_peering] declares port 0).
    fn peering_with_substrate_port(a: IpAddr, b: IpAddr, port: u16) -> zpr::policy_types::Peering {
        let mut peering = crate::test_helpers::make_peering(a, b, "link-ab", vec![]);
        peering.substrate_a = Some(zpr::policy_types::NetAddr::new_for_ip_or_host(
            &a.to_string(),
            port,
        ));
        peering.substrate_b = Some(zpr::policy_types::NetAddr::new_for_ip_or_host(
            &b.to_string(),
            port,
        ));
        peering
    }

    /// Reported substrate addresses that name no place to dial (zl-zipline#255): an
    /// unspecified IP, IPv4 or IPv6 (also the IPv4-mapped form), or port 0.
    fn unusable_substrate_addrs() -> Vec<SocketAddr> {
        [
            "0.0.0.0:7000",
            "[::]:7000",
            "[::ffff:0.0.0.0]:7000",
            "192.0.2.10:0",
            "[fd5a:5052:90de:1::2]:0",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
    }

    /// Plan §7 check 3 (zl-zipline#255): policy declares links for the node but no
    /// substrate address for it (a laptop endpoint). The node's reported address is
    /// accepted and becomes its `key::SUBSTRATE_ADDR` claim.
    #[tokio::test]
    async fn authenticate_node_declared_links_without_substrate_accepts_reported() {
        use crate::test_helpers::make_peering;

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let relay: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let laptop: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let mut peering = make_peering(relay, laptop, "link-relay-laptop", vec![]);
        peering.substrate_b = None; // the laptop reports its own
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                cn,
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap();

        let actor = cc
            .authenticate_node(asm, challenge, timestamp, cn, &sig, laptop, reported, None)
            .await
            .expect("a node with links but no declared substrate authenticates");
        let stored = actor
            .get_attribute(key::SUBSTRATE_ADDR)
            .expect("substrate addr claim must be present")
            .get_value()[0]
            .clone();
        assert_eq!(stored, reported.to_string());
    }

    /// zl-zipline#255: `connect` refuses a reported substrate address that names no
    /// place to dial (an unspecified IP or port 0) with a param error, both for a node
    /// with links but no declared address and for a node with no peering at all.
    #[tokio::test]
    async fn authenticate_node_rejects_an_unusable_reported_substrate() {
        use crate::test_helpers::make_peering;

        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let relay: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let laptop: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let unpeered: IpAddr = "fd5a:5052:90de:1::9".parse().unwrap();
        let mut peering = make_peering(relay, laptop, "link-relay-laptop", vec![]);
        peering.substrate_b = None;
        for node in [laptop, unpeered] {
            for reported in unusable_substrate_addrs() {
                let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
                asm.policy_mgr
                    .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                        cn,
                        &pubkey_der,
                        &peering,
                    ))
                    .await
                    .unwrap();
                let cc = make_cc("test-vs");
                let challenge = b"my-challenge";
                let timestamp = unix_now();
                let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
                let result = cc
                    .authenticate_node(asm, challenge, timestamp, cn, &sig, node, reported, None)
                    .await;
                assert!(
                    matches!(result, Err(ServiceError::Param(_))),
                    "{node} reporting {reported}: expected param error, got {result:?}"
                );
            }
        }
    }

    /// [accept_reported_substrate] is the one rule every path that records a node's
    /// substrate address uses: policy's address when it declares one (the report must
    /// match), the reported one otherwise.
    #[tokio::test]
    async fn accept_reported_substrate_follows_policy_when_it_declares_one() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let (_privkey, pubkey_der) = gen_rsa_test_keypair();
        let relay: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let laptop: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let unpeered: IpAddr = "fd5a:5052:90de:1::9".parse().unwrap();
        let mut peering = peering_with_substrate_port(relay, laptop, 7001);
        peering.substrate_b = None;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                "test-node.zpr",
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let reported: SocketAddr = "192.0.2.10:7000".parse().unwrap();

        // Declared: the relay's own address, port 7001.
        let declared = SocketAddr::new(relay, 7001);
        assert_eq!(
            accept_reported_substrate(&asm, &relay, declared).unwrap(),
            declared
        );
        assert!(matches!(
            accept_reported_substrate(&asm, &relay, reported),
            Err(ServiceError::Param(_))
        ));
        // Links but no declared address, and no peering at all: the report stands.
        assert_eq!(
            accept_reported_substrate(&asm, &laptop, reported).unwrap(),
            reported
        );
        assert_eq!(
            accept_reported_substrate(&asm, &unpeered, reported).unwrap(),
            reported
        );
    }

    /// zl-zipline#255: an unspecified IP or port 0 is a param error whatever policy
    /// says about the node -- declared, links without an address, or no peering.
    /// There is no fallback.
    #[tokio::test]
    async fn accept_reported_substrate_rejects_an_unspecified_ip_or_port_0() {
        let asm = crate::assembly::tests::new_assembly_for_tests(None).await;
        let (_privkey, pubkey_der) = gen_rsa_test_keypair();
        let relay: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let laptop: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        let unpeered: IpAddr = "fd5a:5052:90de:1::9".parse().unwrap();
        let mut peering = peering_with_substrate_port(relay, laptop, 7001);
        peering.substrate_b = None;
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                "test-node.zpr",
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        for node in [relay, laptop, unpeered] {
            for reported in unusable_substrate_addrs() {
                let result = accept_reported_substrate(&asm, &node, reported);
                assert!(
                    matches!(result, Err(ServiceError::Param(_))),
                    "{node} reporting {reported}: expected param error, got {result:?}"
                );
            }
        }
    }

    /// When policy topology declares a substrate and the node reports the same value,
    /// authentication succeeds and that value is stored.
    #[tokio::test]
    async fn authenticate_node_topology_match_succeeds() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let a: IpAddr = "fd5a:5052:90de:1::1".parse().unwrap();
        let b: IpAddr = "fd5a:5052:90de:1::2".parse().unwrap();
        // A real port: a report of port 0 is refused whatever policy says (zl-zipline#255).
        let peering = peering_with_substrate_port(a, b, 7001);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_and_peering(
                cn,
                &pubkey_der,
                &peering,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let reported = SocketAddr::new(b, 7001); // matches the declaration

        let actor = cc
            .authenticate_node(asm, challenge, timestamp, cn, &sig, b, reported, None)
            .await
            .expect("authentication should succeed");

        let stored = actor
            .get_attribute(key::SUBSTRATE_ADDR)
            .expect("substrate addr claim must be present")
            .get_value()[0]
            .clone();
        assert_eq!(stored, reported.to_string());
    }

    #[tokio::test]
    async fn authenticate_node_success() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("authentication should succeed");

        assert!(actor.is_node());

        // zpr.vs.bootstrap.ident must be present and be a valid node JWT
        let jwt_str = actor
            .get_attribute(ATTR_KEY_VS_IDENT)
            .expect("bootstrap ident attribute must be present")
            .get_value()[0]
            .clone();
        let claims = decode_jwt(&jwt_str, "test-vs").expect("ident attribute must be a valid JWT");
        assert_eq!(claims.sub, format!("node/{}", cn));
        assert_eq!(claims.iss, "vs.zpr/test-vs");

        // get_identity() returns [jwt, cn, device authority] in that order
        let identity = actor
            .get_identity()
            .expect("actor must have identity values");
        assert_eq!(identity[0], jwt_str);

        // The CN is an identity key in its own right (established by the builtin RSA
        // authentication; see libeval's approve_connection, #201), so it follows the JWT.
        assert_eq!(identity[1], cn);
    }

    /// A 32-byte X25519 key becomes a claim, any other length does not.
    #[test]
    fn test_a2a_dh_pubkey_claim_length_gate() {
        assert!(a2a_dh_pubkey_claim(&PublicKey::new(&[7u8; 32])).is_some());
        assert!(a2a_dh_pubkey_claim(&PublicKey::new(&[7u8; 31])).is_none());
    }

    // ---- lookup-identity derivation at connect time (#310) ----

    /// A trusted service that records the lookup-identity set of every call and vends
    /// a fixed attribute set for one specific identity value -- standing in for an
    /// attribute store holding a privileged device's attributes.
    struct CapturingTrustedService {
        /// Identity value that owns `vends`.
        known_value: String,
        /// (ZPR attribute key, value) pairs vended when `known_value` matches.
        vends: Vec<(String, String)>,
        calls: std::sync::Mutex<Vec<Vec<(String, String)>>>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for CapturingTrustedService {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            self.calls.lock().unwrap().push(identities.to_vec());
            if identities.iter().any(|(_, v)| *v == self.known_value) {
                // Group `vends` by key so a key listed twice becomes ONE
                // multi-valued attribute: `Actor::add_attribute` replaces per
                // key, so two single-valued attributes with the same key would
                // not accumulate on the actor (zipline#50).
                let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
                for (k, v) in &self.vends {
                    if let Some((_, vals)) = grouped.iter_mut().find(|(gk, _)| gk == k) {
                        vals.push(v.clone());
                    } else {
                        grouped.push((k.clone(), vec![v.clone()]));
                    }
                }
                return Ok(grouped
                    .into_iter()
                    .map(|(k, vals)| {
                        libeval::attribute::AttributeSource::new("capture")
                            .builder(k)
                            .expires_in(Duration::from_secs(600))
                            .values(vals)
                    })
                    .collect());
            }
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "capture"
        }
    }

    /// Register a capturing service on the assembly and return a handle for assertions.
    fn register_capturing_ts(
        asm: &Arc<Assembly>,
        known_value: &str,
        vends: &[(&str, &str)],
    ) -> Arc<CapturingTrustedService> {
        let svc = Arc::new(CapturingTrustedService {
            known_value: known_value.to_string(),
            vends: vends
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        asm.ts_mgr.update_services(vec![svc.clone()]);
        svc
    }

    /// A [PolicySnapshot] over `policy` carrying `services` as its stores, for
    /// driving `authorize_connection` directly (it reads the snapshot's stores,
    /// not the live ts_mgr list — PR #6 review).
    fn snap(
        policy: Arc<Policy>,
        services: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>>,
    ) -> PolicySnapshot {
        PolicySnapshot::for_tests(policy, services)
    }

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        crate::loaded_policy::LoadedPolicy::from_container(
            zpr::policy_types::PolicyContainerBytes::from(container_bytes),
            &config::POLICY_MIN_VERSION,
        )
        .unwrap()
        .policy()
    }

    /// Regression test for the CN-claiming escalation (#310): a user-only actor whose
    /// claimed CN is UNAUTHENTICATED must not have that CN sent to trusted services as
    /// a lookup identity, and must not inherit the claimed device's attributes. The
    /// lookup set handed to the source is the security boundary, so it is what gets
    /// pinned.
    #[tokio::test]
    async fn user_only_actor_cannot_inherit_claimed_cn_attributes() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // Policy declares `sub -> user.sub` as an identity attribute.
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "capture",
                "file",
                Some(3600),
                &["sub -> user.sub"],
                &["sub"],
            ),
        );
        // The store knows the privileged device's CN and vends its attributes.
        let svc = register_capturing_ts(&asm, "privileged.zpr.org", &[("user.privileged", "yes")]);

        // Authenticated: only the user identity. The claimed CN is unauthenticated.
        let authd = vec![
            Attribute::builder("user.sub")
                .expires_in(Duration::from_secs(600))
                .value("google-sub-12345"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("privileged.zpr.org")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, vec![svc.clone()]),
                "privileged.zpr.org",
                unauthd,
                authd,
                0,
            )
            .await
            .expect("user-only connection should authorize");

        // The lookup set contains exactly the authenticated user identity -- the
        // claimed CN never reaches the source.
        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(
                "user.sub".to_string(),
                "google-sub-12345".to_string()
            )]]
        );
        // And the actor carries none of the privileged device's attributes, nor an
        // authenticated CN.
        assert!(actor.get_attribute("user.privileged").is_none());
        assert!(actor.get_attribute(key::CN).is_none());
    }

    /// Existing device-only actors keep working: under the builtin CN identity the
    /// connect-time lookup set is exactly [(device.zpr.adapter.cn, <cn>)] -- CN
    /// survives the switch away from `identity_attr_keys()` (which excludes it).
    #[tokio::test]
    async fn device_only_actor_lookup_set_is_authenticated_cn() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // No policy-declared identity attributes: the builtin CN is the only lookup key.
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "capture",
            "file",
            Some(3600),
            &["color -> user.color"],
        ));
        let svc = register_capturing_ts(&asm, "device-1.zpr.org", &[("user.color", "red")]);

        // As authenticate_zpr_entity_rsa would after signature verification.
        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, vec![svc.clone()]),
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("device connection should authorize");

        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(key::CN.to_string(), "device-1.zpr.org".to_string())]]
        );
        // The vended attribute reached the actor through the authenticated-claims path.
        assert!(actor.get_attribute("user.color").is_some());
    }

    /// A trusted service with a configurable source id that vends a fixed attribute
    /// set for every lookup. Minimal stand-in for the user-authority derivation tests,
    /// where the source id IS the asserted authority value.
    struct NamedTrustedService {
        source_id: String,
        /// (ZPR attribute key, value) pairs vended on every lookup.
        vends: Vec<(String, String)>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for NamedTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(self
                .vends
                .iter()
                .map(|(k, v)| {
                    libeval::attribute::AttributeSource::new(self.source_id.clone())
                        .builder(k)
                        .expires_in(Duration::from_secs(600))
                        .value(v)
                })
                .collect())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            &self.source_id
        }
    }

    /// Build a [NamedTrustedService] for registration with the test assembly.
    fn named_ts(source_id: &str, vends: &[(&str, &str)]) -> Arc<NamedTrustedService> {
        Arc::new(NamedTrustedService {
            source_id: source_id.to_string(),
            vends: vends
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }

    /// #324 follow-up (1): a trusted service vending `user.*` attributes installs
    /// `user.zpr.authority = <source id>` on the actor, and it is registered as an
    /// identity key -- the trusted service is the authority asserting the user
    /// identity, exactly as the RSA bootstrap path asserts the device identity.
    #[tokio::test]
    async fn ts_user_attrs_install_user_authority() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "hr",
            "file",
            Some(3600),
            &["dept -> user.dept"],
        ));
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> =
            vec![named_ts("hr", &[("user.dept", "engineering")])];

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, stores),
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("connection should authorize");

        let authority = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user.zpr.authority should be installed");
        assert_eq!(authority.get_value(), ["hr".to_string()]);
        // Expires with the vended user attributes, so the authority never outlives
        // the user record it vouches for.
        assert_eq!(
            authority.get_expires(),
            actor.get_attribute("user.dept").unwrap().get_expires()
        );
        // And it is registered as an identity key, like any namespaced authority.
        assert!(
            actor.identity_keys_iter().any(|k| k == key::USER_AUTHORITY),
            "user.zpr.authority should be an identity key"
        );
    }

    /// #324 follow-up (2): a trusted service vending only device attributes (or
    /// nothing) installs no `user.zpr.authority` -- a device with no user record in
    /// any trusted service still does not match a bare `allow users ...` rule, so the
    /// fail-closed property of #144 survives.
    #[tokio::test]
    async fn ts_device_only_attrs_install_no_user_authority() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "hr",
            "file",
            Some(3600),
            &["location -> device.zpr.location"],
        ));
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> =
            vec![named_ts("hr", &[("device.zpr.location", "hq")])];

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, stores),
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("connection should authorize");

        assert!(actor.get_attribute("device.zpr.location").is_some());
        assert!(
            actor.get_attribute(key::USER_AUTHORITY).is_none(),
            "device-only trusted-service results must not install user.zpr.authority"
        );
    }

    /// #324 follow-up (3): with two sources of which only one vends user attributes,
    /// exactly that source's id becomes the (single) authority value.
    #[tokio::test]
    async fn ts_two_sources_one_user_authority_value() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "hr",
            "file",
            Some(3600),
            &["dept -> user.dept"],
        ));
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> = vec![
            named_ts("hr", &[("user.dept", "engineering")]),
            named_ts("inventory", &[("device.zpr.location", "hq")]),
        ];

        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, stores),
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("connection should authorize");

        let authority = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user.zpr.authority should be installed");
        assert_eq!(
            authority.get_value(),
            ["hr".to_string()],
            "exactly the user-vending source names the authority"
        );
    }

    /// Disconnect removes the node from the router under the topology operation lock
    /// (TopoOps), so it cannot interleave with a link-state report or policy pass.
    #[tokio::test]
    async fn disconnect_waits_for_the_topology_operation_lock() {
        use crate::test_helpers::make_node_actor_defexp;

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = Arc::new(make_cc("test-vs"));
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(node_addr).unwrap();

        tokio::task::LocalSet::new()
            .run_until(async {
                let held = asm.topo_mgr.ops().await;
                let dc = tokio::task::spawn_local({
                    let (asm, cc) = (asm.clone(), cc.clone());
                    async move {
                        cc.disconnect(asm, node_addr, vsapi::DisconnectReason::Admin)
                            .await
                    }
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                assert!(!dc.is_finished(), "disconnect must wait for the lock");
                assert!(
                    asm.topo_mgr.has_node(&node_addr),
                    "router untouched while held"
                );
                // The whole local teardown is under the guard (round 13, Copilot):
                // a disconnect that has not started cannot have removed the actor.
                assert!(
                    asm.actor_mgr
                        .get_actor_by_zpr_addr(&node_addr)
                        .await
                        .unwrap()
                        .is_some(),
                    "actor untouched while held"
                );
                drop(held);
                dc.await.unwrap().unwrap();
                assert!(!asm.topo_mgr.has_node(&node_addr));
            })
            .await;
    }

    /// Disconnect purges recorded trusted-service revisions for the actor AND for every
    /// cascaded adapter, before the addresses return to the pool -- so a recycled ZPR
    /// address cannot inherit the previous actor's revision records. This same
    /// `disconnect` is the path for API, policy-driven, and node-cascade disconnects,
    /// none of which may rely on an ActorLeaves event.
    #[tokio::test]
    async fn disconnect_purges_revisions_for_actor_and_cascaded_adapters() {
        use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp, register_ts};

        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        register_ts(&asm, &[("user.dept", "eng")]);

        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::11".parse().unwrap();
        let node = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        let adapter = make_adapter_actor_defexp("fd5a:5052::11", "adapter-1");
        asm.actor_mgr
            .add_node(&node, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter, &node_addr, &Default::default())
            .await
            .unwrap();

        // Both actors are caught up with the source.
        for addr in [&node_addr, &adapter_addr] {
            let stale = asm.ts_mgr.stale_sources_for_actor(addr);
            assert_eq!(stale.len(), 1);
            asm.ts_mgr.record_revision(addr, &stale[0].0, stale[0].1);
            assert!(asm.ts_mgr.stale_sources_for_actor(addr).is_empty());
        }

        // Node disconnect cascades to the attached adapter.
        cc.disconnect(asm.clone(), node_addr, vsapi::DisconnectReason::Admin)
            .await
            .unwrap();

        // Every source is stale again for both addresses: the records are gone, so a
        // recycled address starts from scratch.
        assert_eq!(asm.ts_mgr.stale_sources_for_actor(&node_addr).len(), 1);
        assert_eq!(asm.ts_mgr.stale_sources_for_actor(&adapter_addr).len(), 1);
    }

    /// PR #45 review (Codex P2): if an adapter's actor record cannot be removed,
    /// its pool address must stay allocated -- recycling it would collide with the
    /// surviving record -- and it is not reported as removed.
    #[tokio::test]
    async fn remove_departed_adapters_keeps_address_when_removal_fails() {
        use crate::db::FaultMode;
        use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};
        use libeval::actor::Role;

        let (asm, _rx, db) = crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let pooled = asm.net_mgr.get_next_zpr_addr(&Role::Adapter).unwrap();
        asm.actor_mgr
            .add_node(
                &make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234"),
                false,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp(&pooled.to_string(), "pooled"),
                &node_addr,
                &Default::default(),
            )
            .await
            .unwrap();

        // A rejected pipeline makes the actor-record removal fail.
        db.set_set_ex_fault(FaultMode::Reject);
        let removed = asm.cc.remove_departed_adapters(&asm, &[pooled]).await;
        db.set_set_ex_fault(FaultMode::None);

        assert!(
            removed.is_empty(),
            "a failed removal must not be reported as removed"
        );
        assert!(
            asm.net_mgr.take_zpr_addr(&pooled).is_err(),
            "the address of a surviving actor must stay allocated"
        );
    }

    // ---- multi-blob authentication (zipline#7) ----

    fn make_connect_request(blobs: Vec<AuthBlob>, cn: &str) -> ConnectRequest {
        ConnectRequest {
            blobs,
            claims: vec![claim(key::CN, cn)],
            substrate_addr: "127.0.0.1".parse().unwrap(),
            dock_interface: 0,
            a2a_dh_public_key: PublicKey::new(&[7u8; 32]),
        }
    }

    /// An SS blob whose signature verifies against the keypair's policy bootstrap key,
    /// stamped `now`: since zipline#137 every SS path enforces the
    /// ±[config::MAX_CLOCK_SKEW_SECS] window, so a fixed timestamp would never
    /// authenticate. Tests that need a specific timestamp use [make_ss_blob_at].
    fn make_valid_ss_blob(privkey: &PKey<Private>, cn: &str) -> AuthBlob {
        let challenge = b"multi-blob-challenge";
        let timestamp = unix_now();
        let signature = sign_node_challenge(privkey, timestamp, cn, challenge);
        AuthBlob::SS(SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: challenge.to_vec(),
            cn: cn.to_string(),
            timestamp,
            signature,
        })
    }

    /// A valid SS blob carrying an explicit `timestamp`, for exercising the
    /// SS reauth arm's clock-skew window (zipline#120).
    fn make_ss_blob_at(privkey: &PKey<Private>, cn: &str, timestamp: u64) -> AuthBlob {
        let challenge = b"reauth-challenge";
        let signature = sign_node_challenge(privkey, timestamp, cn, challenge);
        AuthBlob::SS(SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: challenge.to_vec(),
            cn: cn.to_string(),
            timestamp,
            signature,
        })
    }

    /// As [make_valid_ss_blob], kept as an alias from before zipline#137
    /// (when `make_valid_ss_blob` still signed a fixed timestamp and only
    /// the reauth arm enforced the skew window).
    fn make_fresh_ss_blob(privkey: &PKey<Private>, cn: &str) -> AuthBlob {
        make_ss_blob_at(
            privkey,
            cn,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }

    /// zipline#137: a stale SS blob timestamp — outside the
    /// ±[config::MAX_CLOCK_SKEW_SECS] window on the past side — is rejected on
    /// the adapter CONNECT path with a generic `AuthenticationFailed` that
    /// echoes no timestamp, mirroring the reauthorize SS arm's bound
    /// (zipline#120).
    #[tokio::test]
    async fn test_connect_rejects_stale_ss_blob_timestamp() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let stale = unix_now() - (crate::config::MAX_CLOCK_SKEW_SECS + 60);
        let req = make_connect_request(vec![make_ss_blob_at(&privkey, cn, stale)], cn);

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::AuthenticationFailed(msg)) => {
                assert!(
                    !msg.contains(&stale.to_string()),
                    "the rejection must not echo the blob timestamp: {msg}"
                );
            }
            other => {
                panic!("a stale SS blob timestamp must fail connect authentication, got {other:?}")
            }
        }
    }

    /// zipline#137: the connect-path skew bound is symmetric (`abs_diff`) — a
    /// FUTURE timestamp beyond the window is rejected the same way.
    #[tokio::test]
    async fn test_connect_rejects_future_ss_blob_timestamp() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let future = unix_now() + crate::config::MAX_CLOCK_SKEW_SECS + 60;
        let req = make_connect_request(vec![make_ss_blob_at(&privkey, cn, future)], cn);

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::AuthenticationFailed(msg)) => {
                assert!(
                    !msg.contains(&future.to_string()),
                    "the rejection must not echo the blob timestamp: {msg}"
                );
            }
            other => {
                panic!("a future SS blob timestamp must fail connect authentication, got {other:?}")
            }
        }
    }

    /// zipline#137: the bound is `>`, not `>=` — a blob stamped exactly
    /// `now − MAX_CLOCK_SKEW_SECS` still authenticates, mirroring the reauth
    /// arm at the boundary.
    ///
    /// Review fix (vs#44): the verifier's clock is PINNED via
    /// [ConnectionControl::authenticate_ss_blob_at]. Sampling the wall clock
    /// twice — once here to stamp the blob and once inside the skew check —
    /// leaves a window where a tick to the next second turns a skew of exactly
    /// MAX into MAX+1, so the earlier connect-path version of this test could
    /// intermittently fail even though the implementation was correct. With a
    /// fixed `now` the test deterministically distinguishes `>` from `>=`:
    /// skew == MAX authenticates, skew == MAX+1 is rejected, on both sides.
    #[tokio::test]
    async fn test_ss_blob_skew_boundary_fixed_clock() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let psnap = asm.policy_mgr.get_current_snapshot();
        let cn_claim = vec![Attribute::builder(key::CN).value(cn)];

        let now_secs = unix_now();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(now_secs);
        let max = crate::config::MAX_CLOCK_SKEW_SECS;
        let ssb_at = |ts: u64| match make_ss_blob_at(&privkey, cn, ts) {
            AuthBlob::SS(ssb) => ssb,
            other => panic!("make_ss_blob_at must yield an SS blob, got {other:?}"),
        };

        // skew == MAX, past and future side: authenticates (the bound is `>`).
        for ts in [now_secs - max, now_secs + max] {
            cc.authenticate_ss_blob_at(psnap.policy(), &ssb_at(ts), &cn_claim, now)
                .expect("a blob at the exact skew boundary must authenticate (the bound is `>`)");
        }

        // skew == MAX + 1, past and future side: rejected.
        for ts in [now_secs - max - 1, now_secs + max + 1] {
            match cc.authenticate_ss_blob_at(psnap.policy(), &ssb_at(ts), &cn_claim, now) {
                Err(ServiceError::AuthenticationFailed(msg)) => {
                    assert!(
                        !msg.contains(&ts.to_string()),
                        "the rejection must not echo the blob timestamp: {msg}"
                    );
                }
                other => panic!(
                    "a blob one second past the skew boundary must be rejected, got {other:?}"
                ),
            }
        }
    }

    /// A syntactically-present OIDC blob naming an issuer no trusted service
    /// declares. Under zipline#11 this is a real validation failure (paramError), which
    /// keeps this fixture useful for the fail-closed property below.
    fn oidc_stub_blob() -> AuthBlob {
        AuthBlob::Oidc(zpr::vsapi_types::OidcBlob {
            issuer: "https://issuer.example".to_string(),
            id_token: "stub-token".to_string(),
            nonce: "stub-nonce".to_string(),
        })
    }

    /// Zero auth blobs is a malformed request: authentication requires at least one.
    #[tokio::test]
    async fn test_zero_blobs_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let req = make_connect_request(Vec::new(), "test-node.zpr");
        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;
        match result {
            Err(ServiceError::Param(msg)) => {
                assert_eq!(msg, "at least one auth blob is required")
            }
            other => panic!("expected Param error, got {:?}", other),
        }
    }

    /// Presented-and-invalid fails closed: a connection carrying a VALID SS blob plus
    /// an OIDC blob naming an undeclared issuer fails as a whole -- the valid device
    /// authentication does not rescue it -- and no actor is persisted.
    #[tokio::test]
    async fn test_two_blobs_ss_and_oidc_stub_fails_whole_connection() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req =
            make_connect_request(vec![make_valid_ss_blob(&privkey, cn), oidc_stub_blob()], cn);

        let result = cc
            .authenticate_adapter_or_node(asm.clone(), req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::ApiResponse(api)) => {
                assert!(
                    matches!(api.code, zpr::vsapi_types::ErrorCode::ParamError),
                    "expected paramError for undeclared issuer, got {:?}",
                    api.code
                )
            }
            other => panic!("expected ApiResponse error, got {:?}", other),
        }
        // The failed connection must not leave an actor behind.
        assert!(
            asm.actor_mgr.list_actors(None).await.unwrap().is_empty(),
            "no actor may be persisted for a failed multi-blob connection"
        );
    }

    /// Two blobs authenticating the same namespace are a protocol error, even when
    /// both are individually valid.
    #[tokio::test]
    async fn test_duplicate_device_blob_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                make_valid_ss_blob(&privkey, cn),
            ],
            cn,
        );

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        match result {
            Err(ServiceError::Param(msg)) => {
                assert_eq!(msg, "duplicate device authentication")
            }
            other => panic!("expected Param error, got {:?}", other),
        }
    }

    /// A connection with no device blob must not end up with an authenticated CN: the
    /// claimed CN stays unauthenticated through authorize_connection. Pins the
    /// no-CN-promotion behaviour the multi-blob loop relies on (zipline#7).
    #[tokio::test]
    async fn test_cn_not_authenticated_without_device_blob() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "idp",
                "file",
                Some(3600),
                &["oidc-subject -> user.oidc-subject"],
                &["oidc-subject"],
            ),
        );

        // Authenticated: user identity only (as the zipline#11 OIDC arm will produce).
        let authd = vec![
            Attribute::builder(key::USER_AUTHORITY)
                .expires_in(Duration::from_secs(600))
                .value("idp"),
            Attribute::builder("user.oidc-subject")
                .expires_in(Duration::from_secs(600))
                .value("alice-sub"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("some-device.zpr")];

        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "some-device.zpr",
                unauthd,
                authd,
                0,
            )
            .await
            .expect("user-only connection should authorize");

        // The claimed CN was never authenticated, so the actor carries no CN
        // attribute and the CN is not an identity key.
        assert!(actor.get_attribute(key::CN).is_none());
        assert!(!actor.identity_keys_iter().any(|k| k == key::CN));
    }

    /// Spec regression (OIDC.md failure rule): a user-only actor claiming a foreign
    /// device CN must not have that CN sent to trusted services as a lookup identity,
    /// and must not inherit the claimed device's attributes.
    #[tokio::test]
    async fn test_user_only_actor_claiming_foreign_cn_gets_no_cn_attributes() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(
            crate::test_helpers::make_trusted_service_policy_with_identity(
                "capture",
                "file",
                Some(3600),
                &["oidc-subject -> user.oidc-subject"],
                &["oidc-subject"],
            ),
        );
        // The store holds the privileged device's attributes, keyed by its CN value.
        let svc = register_capturing_ts(&asm, "server1.zpr", &[("device.role", "admin")]);

        // Authenticated: only the user subject. The foreign CN is a bare claim.
        let authd = vec![
            Attribute::builder("user.oidc-subject")
                .expires_in(Duration::from_secs(600))
                .value("alice-sub"),
        ];
        let unauthd = vec![Attribute::builder(key::CN).value("server1.zpr")];

        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, vec![svc.clone()]),
                "server1.zpr",
                unauthd,
                authd,
                0,
            )
            .await
            .expect("user-only connection should authorize");

        // The lookup identities sent to the source were only the user subject pair.
        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(
                "user.oidc-subject".to_string(),
                "alice-sub".to_string()
            )]]
        );
        // And none of the claimed device's attributes reached the actor.
        assert!(
            actor.get_attribute("device.role").is_none(),
            "actor must not inherit the claimed device's attributes"
        );
    }

    // ---- device.* attributes from a declared trusted service (zipline#50) ----

    /// Test gate for the hostname design (zipline#50, positive): a `device.*`
    /// attribute vended by a DECLARED trusted service, keyed on the builtin
    /// authenticated `device.zpr.adapter.cn` lookup identity, lands on the actor
    /// record — multi-valued, and sourced to the service rather than the peer.
    /// This pins the vending path the hostname design assumes already works; no
    /// production change should be needed for it to pass.
    #[tokio::test]
    async fn device_attr_from_declared_service_reaches_actor_multivalued() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        // A declared `file` trusted service mapping `h -> device.hostname{}`
        // (multi-valued). No policy-declared identity attributes: the builtin
        // `device.zpr.adapter.cn` is the lookup identity, as for an
        // RSA-authenticated device.
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "capture",
            "file",
            Some(3600),
            &["h -> device.hostname{}"],
        ));
        // The store knows the device by CN and vends TWO values for the key.
        let svc = register_capturing_ts(
            &asm,
            "device-1.zpr.org",
            &[
                ("device.hostname", "somename"),
                ("device.hostname", "m-7f3a2b"),
            ],
        );

        // As authenticate_zpr_entity_rsa would push after signature verification.
        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, vec![svc.clone()]),
                "device-1.zpr.org",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("device connection should authorize");

        // The lookup call was keyed on the authenticated adapter CN.
        assert_eq!(
            *svc.calls.lock().unwrap(),
            vec![vec![(key::CN.to_string(), "device-1.zpr.org".to_string())]]
        );
        // The attribute reached the actor with BOTH values...
        let hostname = actor
            .get_attribute("device.hostname")
            .expect("device.hostname vended by the declared service must reach the actor");
        assert_eq!(
            hostname.get_value(),
            ["somename".to_string(), "m-7f3a2b".to_string()]
        );
        // ...and it is sourced to the trusted service, not the peer.
        assert_eq!(hostname.get_source(), "capture");
    }

    /// zipline#50, negative: a peer-asserted `device.hostname` is an
    /// unauthenticated claim and must never reach the actor. Only the trusted
    /// service's value survives — the scrub in `approve_connection` commits
    /// unauthenticated claims only for `zpr.addr` under a matched join policy
    /// that pins `zpr.addr`, never for arbitrary `device.*` keys.
    #[tokio::test]
    async fn peer_asserted_device_hostname_is_not_authenticated() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");

        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "capture",
            "file",
            Some(3600),
            &["h -> device.hostname{}"],
        ));
        // The store vends the fleet-recorded hostname for this device.
        let svc = register_capturing_ts(
            &asm,
            "device-1.zpr.org",
            &[("device.hostname", "fleet-name")],
        );

        // Authenticated: the CN. The peer also CLAIMS a hostname of its choosing.
        let authd = vec![Attribute::builder(key::CN).value("device-1.zpr.org")];
        let unauthd = vec![Attribute::builder("device.hostname").value("evil-name")];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, vec![svc.clone()]),
                "device-1.zpr.org",
                unauthd,
                authd,
                0,
            )
            .await
            .expect("device connection should authorize");

        // The actor's hostname is exactly what the trusted service vended --
        // the peer-asserted value appears nowhere, and the source is the
        // service, not the peer.
        let hostname = actor
            .get_attribute("device.hostname")
            .expect("the service-vended hostname should reach the actor");
        assert_eq!(hostname.get_value(), ["fleet-name".to_string()]);
        assert_eq!(hostname.get_source(), "capture");
        assert!(
            !hostname.get_value().iter().any(|v| v == "evil-name"),
            "peer-asserted hostname must not reach the actor"
        );
    }

    // ---- OIDC blob on the connect path (zipline#11) ----

    use crate::oidc::mint::{TEST_KID, test_rsa_pem, token as mint_token};
    use crate::test_helpers::{make_oidc_connect_policy, make_test_oidc_config};
    use serde_json::json;
    use zpr::policy_types::OidcConfig;
    use zpr::vsapi_types::{ApiResponseError, ErrorCode, OidcBlob};

    /// Issuer/client of the fixture config ([make_test_oidc_config]).
    const OIDC_ISSUER: &str = "https://accounts.google.com";
    const OIDC_CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    /// The nonce the connect request binds its token to.
    const OIDC_NONCE: &str = "test-nonce-1";
    /// The subject minted into the test tokens.
    const OIDC_SUB: &str = "test-sub-12345";
    /// The claim -> ZPR attribute mappings the zipline#11 test policies declare.
    const OIDC_MAPPINGS: &[&str] = &[
        "sub -> user.oidc-subject",
        "email -> user.email",
        "hd -> user.domain",
    ];
    /// `expiration_seconds` in the zipline#11 test policies (12 h).
    const OIDC_LIFETIME_SECS: u32 = 43200;

    /// Unix seconds for "now" (the JWT library validates `exp` against real time).
    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A fully valid claim set for the fixture provider; tests override fields.
    fn oidc_base_claims() -> serde_json::Value {
        json!({
            "iss": OIDC_ISSUER,
            "aud": OIDC_CLIENT_ID,
            "sub": OIDC_SUB,
            "exp": unix_now() + 3600,
            "iat": unix_now(),
            "nonce": OIDC_NONCE,
            "hd": "example.com",
            "email": "jane@example.com",
            "email_verified": true,
        })
    }

    /// Sign `claims` with the fixture RSA key under the standard kid.
    fn mint_signed(claims: serde_json::Value) -> String {
        let signing_key = jwt::EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        mint_token(claims, TEST_KID, jwt::Algorithm::RS256, &signing_key)
    }

    /// An OIDC auth blob for the fixture issuer carrying `id_token`.
    fn oidc_blob(id_token: String) -> AuthBlob {
        AuthBlob::Oidc(OidcBlob {
            issuer: OIDC_ISSUER.to_string(),
            id_token,
            nonce: OIDC_NONCE.to_string(),
        })
    }

    /// Install the standard zipline#11 OIDC policy (no bootstrap keys, join-any) on `asm`.
    async fn install_oidc_policy(asm: &Arc<Assembly>, oidc: OidcConfig) {
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                oidc,
                &[],
                &[],
            ))
            .await
            .expect("test policy should install");
    }

    /// Unwrap a connect failure into its wire-classified [ApiResponseError].
    fn expect_api_response(result: Result<Actor, ServiceError>) -> ApiResponseError {
        match result {
            Err(ServiceError::ApiResponse(api)) => api,
            other => panic!("expected ApiResponse error, got {:?}", other),
        }
    }

    /// A valid OIDC-only connect stamps `user.zpr.authority = ["google"]`, the mapped
    /// claims arrive through the trusted-service lookup, the identity keys are the
    /// mapped sub then the user authority (after the VS ident JWT), and nothing in the
    /// device namespace is asserted.
    #[tokio::test]
    async fn test_oidc_only_connect_yields_user_authority_and_claims() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("valid OIDC connect should authorize");

        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
        assert_eq!(
            actor
                .get_attribute("user.oidc-subject")
                .expect("mapped sub must be present")
                .get_single_value()
                .unwrap(),
            OIDC_SUB
        );
        assert_eq!(
            actor
                .get_attribute("user.email")
                .expect("mapped email must be present")
                .get_single_value()
                .unwrap(),
            "jane@example.com"
        );
        assert_eq!(
            actor
                .get_attribute("user.domain")
                .expect("mapped hd must be present")
                .get_single_value()
                .unwrap(),
            "example.com"
        );
        // lookup_identity_keys order (mapped sub) then the namespaced authority;
        // the VS ident JWT is prepended at order 0 by the connect path.
        let ikeys: Vec<&str> = actor.identity_keys_iter().map(|k| k.as_str()).collect();
        assert_eq!(
            ikeys,
            vec![ATTR_KEY_VS_IDENT, "user.oidc-subject", key::USER_AUTHORITY]
        );
        // No device identity was authenticated.
        assert!(actor.get_attribute(key::DEVICE_AUTHORITY).is_none());
        assert!(actor.get_attribute(key::CN).is_none());
        assert!(
            actor
                .attrs_iter()
                .all(|a| !a.get_key().starts_with("device.")),
            "no device.* attribute may be asserted by a user-only login"
        );
    }

    /// Regression (one-node-oidc-test.sh): a user-only adapter presents no device
    /// blob, and the node therefore sends **no** `device.zpr.adapter.cn` claim at all
    /// (zl-zpr-core adapter/ph/src/visa_mgmt.rs only emits the CN claim from a
    /// self-signed blob). The connect entry point must not demand that claim; the
    /// other OIDC-only tests all go through `make_connect_request`, which always
    /// supplies a CN, so they never exercised the real wire shape.
    #[tokio::test]
    async fn test_oidc_only_connect_without_cn_claim_authorizes() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let mut req =
            make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");
        // What a bootstrap-key-less adapter actually sends: no claims at all.
        req.claims = Vec::new();

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("user-only connect without a CN claim should authorize");

        assert!(actor.get_attribute(key::CN).is_none());
        assert_eq!(
            actor
                .get_attribute("user.oidc-subject")
                .expect("mapped sub must be present")
                .get_single_value()
                .unwrap(),
            OIDC_SUB
        );
    }

    /// SS + OIDC in one connect: both namespaced authorities are stamped and both are
    /// registered as identity keys.
    #[tokio::test]
    async fn test_ss_plus_oidc_connect_yields_both_authorities() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(oidc_base_claims())),
            ],
            cn,
        );

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("SS+OIDC connect should authorize");

        assert_eq!(
            actor
                .get_attribute(key::DEVICE_AUTHORITY)
                .expect("device authority must be stamped")
                .get_value(),
            &vec![key::AUTHORITY_METHOD_BOOTSTRAP.to_string()]
        );
        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
        assert!(
            actor
                .identity_keys_iter()
                .any(|k| k == key::DEVICE_AUTHORITY),
            "device authority must be an identity key"
        );
        assert!(
            actor.identity_keys_iter().any(|k| k == key::USER_AUTHORITY),
            "user authority must be an identity key"
        );
    }

    /// A nonce mismatch fails the whole connection with `invalidSignature`, even when a
    /// valid SS blob is also presented, and no actor is persisted (fail closed).
    #[tokio::test]
    async fn test_oidc_wrong_nonce_fails_whole_connection_invalid_signature() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let mut claims = oidc_base_claims();
        claims["nonce"] = json!("some-other-nonce");
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(claims)),
            ],
            cn,
        );

        let result = cc
            .authenticate_adapter_or_node(asm.clone(), req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::InvalidSignature),
            "expected invalidSignature, got {:?}",
            api.code
        );
        assert!(
            asm.actor_mgr.list_actors(None).await.unwrap().is_empty(),
            "no actor may be persisted for a failed multi-blob connection"
        );
    }

    /// A consumer account (no `hd` claim) against a domain-restricted provider is
    /// rejected with `authError`.
    #[tokio::test]
    async fn test_oidc_consumer_account_no_hd_rejected_auth_error() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let restricted = OidcConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..make_test_oidc_config()
        };
        install_oidc_policy(&asm, restricted).await;
        let cc = make_cc("test-vs");
        let mut claims = oidc_base_claims();
        claims.as_object_mut().unwrap().remove("hd");
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::AuthError),
            "expected authError, got {:?}",
            api.code
        );
    }

    /// A blob naming an issuer with no declared trusted service is a `paramError`,
    /// and the error does not echo the attacker-supplied issuer string.
    #[tokio::test]
    async fn test_oidc_unknown_issuer_param_error() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let unknown_issuer = "https://idp.attacker.example";
        let req = make_connect_request(
            vec![AuthBlob::Oidc(OidcBlob {
                issuer: unknown_issuer.to_string(),
                id_token: mint_signed(oidc_base_claims()),
                nonce: OIDC_NONCE.to_string(),
            })],
            "some.cn",
        );

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "expected paramError, got {:?}",
            api.code
        );
        assert!(
            !api.message.contains(unknown_issuer),
            "error must not echo the blob's issuer: {}",
            api.message
        );
    }

    /// With no keys at all (empty seed, fetch never succeeded) the failure is
    /// `temporarilyUnavailable` with a non-zero retry hint.
    #[tokio::test]
    async fn test_oidc_no_keys_temporarily_unavailable() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        // Empty seed; a jwks_uri exists (so the key source is viable) but the
        // endpoint only serves errors, so the on-demand priming refresh fails
        // and the current key set stays empty.
        let addr = spawn_jwks_http_server(500, String::new()).await;
        let keyless = OidcConfig {
            seed_jwks: String::new(),
            jwks_uri: format!("http://{addr}/jwks"),
            ..make_test_oidc_config()
        };
        install_oidc_policy(&asm, keyless).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;

        let api = expect_api_response(result);
        assert!(
            matches!(api.code, ErrorCode::TemporarilyUnavailable),
            "expected temporarilyUnavailable, got {:?}",
            api.code
        );
        assert_eq!(api.retry_in, config::OIDC_NO_KEYS_RETRY_SECS);
    }

    /// Plain-HTTP responder answering `status`/`body` on `/jwks` (connect-path
    /// twin of the jwks.rs test server).
    async fn spawn_jwks_http_server(status: u16, body: String) -> std::net::SocketAddr {
        let status = axum::http::StatusCode::from_u16(status).unwrap();
        let app = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let body = body.clone();
                async move { (status, body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// Review fix (PR #6): a provider with an empty `seed_jwks` but a usable
    /// `jwks_uri` acquires its first key set on demand — the NoKeys outcome
    /// triggers the same one-refresh-and-retry as UnknownKid, so the first
    /// valid login primes the cache instead of every login failing
    /// `temporarilyUnavailable` forever.
    #[tokio::test]
    async fn test_oidc_empty_seed_primes_keys_from_jwks_uri() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let jwks_body = include_str!("../tests/data/oidc-test-jwks.json").to_string();
        let addr = spawn_jwks_http_server(200, jwks_body).await;
        let empty_seed = OidcConfig {
            seed_jwks: String::new(),
            jwks_uri: format!("http://{addr}/jwks"),
            ..make_test_oidc_config()
        };
        install_oidc_policy(&asm, empty_seed).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("first login must prime the empty JWKS cache and authorize");

        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
    }

    /// A fully valid user login that no join policy admits still connects: a join
    /// policy grants a role and services, and an actor without one simply has
    /// neither -- exactly the device-only #227 case. Refusing the connection was
    /// the wrong lever ("only admit logins vouched by service X" is a policy
    /// feature ZPL cannot yet express), so authentication alone admits the
    /// endpoint and communication policy decides what it may reach.
    #[tokio::test]
    async fn test_valid_login_no_join_policy_connects() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        // The only join policy requires a domain this login does not have.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[],
                &[("user.domain", "blocked.example")],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("a validated login must connect without a matching join policy");

        // Authenticated, so the user identity is on the actor ...
        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be stamped")
                .get_value(),
            &vec!["google".to_string()]
        );
        // ... but no join policy matched, so it provides no services.
        assert!(
            actor.get_attribute(key::SERVICES).is_none(),
            "no join policy matched, so the actor must provide no services"
        );
    }

    /// Review fix (PR #6): OIDC validation and authorization must run under one
    /// policy. The provider store is resolved from the same [PolicySnapshot]
    /// that later authorizes the connection, so a concurrent policy update
    /// cannot validate a token under one revision's provider config and
    /// authorize the mapped claims under another. This exercises the seam: a
    /// snapshot taken before an update keeps resolving its own revision's
    /// provider even after ts_mgr has been swapped to a policy without one.
    #[tokio::test]
    async fn test_oidc_validation_pinned_to_policy_snapshot() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let pinned = asm.policy_mgr.get_current_snapshot();

        // A concurrent policy update removes the provider entirely; the
        // manager's live list no longer knows the issuer.
        let (_, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_bootstrap_key(
                "other.zpr",
                &pubkey_der,
            ))
            .await
            .unwrap();
        assert!(
            asm.ts_mgr.oidc_service_for_issuer(OIDC_ISSUER).is_none(),
            "precondition: the live trusted-service list must have dropped the provider"
        );

        // An in-flight authentication that captured `pinned` before the update
        // still validates against that snapshot's provider (and would then
        // authorize under the same snapshot's policy).
        let AuthBlob::Oidc(blob) = oidc_blob(mint_signed(oidc_base_claims())) else {
            unreachable!()
        };
        let outcome = cc
            .authenticate_oidc_blob(&pinned, &blob)
            .await
            .expect("the pinned snapshot's provider must keep serving the in-flight connect");
        assert!(
            outcome
                .authd
                .iter()
                .any(|a| a.get_key() == key::USER_AUTHORITY),
            "outcome must carry the user authority from the pinned provider"
        );
    }

    /// T2 (zipline#42): the dual-clock helper. (a) with the same session
    /// ceiling, a later `iat` yields a strictly later expiry (the renewal
    /// window is iat-anchored); (b) a ceiling sooner than `iat + lifetime`
    /// wins; (e) no ceiling (`max_auth_age_seconds = 0`) means the expiry is
    /// `iat + lifetime` alone.
    #[test]
    fn test_compute_authority_expiry_dual_clock() {
        let lifetime = Duration::from_secs(OIDC_LIFETIME_SECS as u64);
        let auth_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let iat1 = auth_time + Duration::from_secs(600);
        let iat2 = auth_time + Duration::from_secs(1200);
        let far_ceiling = auth_time + Duration::from_secs(1_000_000);

        // (a) same ceiling, later iat => strictly later expiry.
        let e1 = compute_authority_expiry(iat1, Some(far_ceiling), lifetime);
        let e2 = compute_authority_expiry(iat2, Some(far_ceiling), lifetime);
        assert_eq!(e1, iat1 + lifetime);
        assert!(e2 > e1, "renewal window must anchor on iat");

        // (b) ceiling sooner than iat + lifetime => ceiling wins.
        let near_ceiling = iat1 + Duration::from_secs(60);
        assert_eq!(
            compute_authority_expiry(iat1, Some(near_ceiling), lifetime),
            near_ceiling
        );

        // (e) no ceiling => iat + lifetime alone.
        assert_eq!(
            compute_authority_expiry(iat1, None, lifetime),
            iat1 + lifetime
        );
    }

    /// zipline#42 review (PR #18): expiry derivation must be total — no
    /// representable `iat` may panic the `iat + lifetime` sum. Overflow
    /// saturates conservatively (never past the ceiling when one exists).
    #[test]
    fn test_compute_authority_expiry_never_panics_on_extreme_iat() {
        // The latest representable SystemTime on this platform, by descent.
        let mut far = SystemTime::UNIX_EPOCH;
        let mut step = Duration::from_secs(u64::MAX);
        while step > Duration::ZERO {
            match far.checked_add(step) {
                Some(next) => far = next,
                None => step /= 2,
            }
        }
        let lifetime = Duration::from_secs(u64::MAX);

        // No ceiling: saturates instead of panicking.
        let e = compute_authority_expiry(far, None, lifetime);
        assert!(e >= far, "saturation must never move the expiry before iat");

        // With a ceiling, the ceiling still caps the saturated window.
        let ceiling = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        assert_eq!(
            compute_authority_expiry(far, Some(ceiling), lifetime),
            ceiling
        );
    }

    /// T4 (zipline#42): `user.zpr.authority` expires at the dual-clock min.
    /// With `max_auth_age_seconds = 0` (no ceiling) and an `auth_time` an hour
    /// old, the expiry anchors on the fresh `iat` — a renewable session gets a
    /// full lifetime per refresh, regardless of the token's 1 h `exp`
    /// (reject-only) and of the old `auth_time`.
    #[tokio::test]
    async fn test_user_authority_expiry_is_dual_clock_min() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        // Authenticated an hour ago; policy lifetime is 12 h and there is no
        // session ceiling, so the authority must expire ~12 h from the fresh
        // iat (i.e. ~ now + 12 h), NOT auth_time + 12 h.
        let iat = unix_now();
        let auth_time = iat - 3600;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat);
        claims["auth_time"] = json!(auth_time);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("valid OIDC connect should authorize");

        let expires = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user authority must be stamped")
            .get_expires();
        let expected =
            SystemTime::UNIX_EPOCH + Duration::from_secs(iat + OIDC_LIFETIME_SECS as u64);
        let drift = expires
            .duration_since(expected)
            .unwrap_or_else(|e| e.duration());
        assert!(
            drift < Duration::from_secs(30),
            "authority expiry must be iat + lifetime when there is no ceiling (drift {}s)",
            drift.as_secs()
        );
    }

    /// T4 variant (zipline#42): when `auth_time + max_auth_age` lands sooner
    /// than `iat + lifetime`, the fixed session ceiling is what gets stamped.
    #[tokio::test]
    async fn test_user_authority_expiry_capped_by_session_ceiling() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let mut cfg = make_test_oidc_config();
        // Ceiling: auth_time + 2 h, far sooner than iat + 12 h lifetime.
        cfg.max_auth_age_seconds = 7200;
        install_oidc_policy(&asm, cfg).await;
        let cc = make_cc("test-vs");
        let iat = unix_now();
        let auth_time = iat - 3600; // 1 h into a 2 h window: still fresh
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat);
        claims["auth_time"] = json!(auth_time);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("valid OIDC connect should authorize");

        let expires = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("user authority must be stamped")
            .get_expires();
        // The ceiling carries the acceptance clock-skew allowance (PR #18
        // review): auth_time + max_auth_age + clock_skew.
        let expected = SystemTime::UNIX_EPOCH
            + Duration::from_secs(auth_time + 7200 + crate::config::MAX_CLOCK_SKEW_SECS);
        let drift = expires
            .duration_since(expected)
            .unwrap_or_else(|e| e.duration());
        assert!(
            drift < Duration::from_secs(30),
            "authority expiry must be capped at auth_time + max_auth_age + clock_skew (drift {}s)",
            drift.as_secs()
        );
    }

    // ---- user.zpr.authority displacement by a decorating file store (zipline#24) ----

    /// A trusted service with a configurable source id that vends a fixed attribute
    /// set only when one of the lookup-identity values matches `known_value` --
    /// standing in for a file store holding a user record keyed on the mapped OIDC
    /// subject (zipline#24).
    struct KeyedNamedTrustedService {
        source_id: String,
        /// Identity value that owns `vends`.
        known_value: String,
        /// (ZPR attribute key, value) pairs vended when `known_value` matches.
        vends: Vec<(String, String)>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for KeyedNamedTrustedService {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            if identities.iter().any(|(_, v)| *v == self.known_value) {
                return Ok(self
                    .vends
                    .iter()
                    .map(|(k, v)| {
                        libeval::attribute::AttributeSource::new(self.source_id.clone())
                            .builder(k)
                            .expires_in(Duration::from_secs(600))
                            .value(v)
                    })
                    .collect());
            }
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            &self.source_id
        }
    }

    /// zipline#24 (connect-path gate): a valid OIDC login through `google` must
    /// leave `user.zpr.authority == "google"` on the actor even when a second,
    /// decorating trusted service (`happyfile`, a file store vending the tag
    /// `user.zpr.tag.lazy` for the mapped subject) also answers the connect-time
    /// lookup.
    ///
    /// Today this FAILS: `happyfile`'s tag is a `user.*` key, so
    /// `derive_user_authority` mints `user.zpr.authority = happyfile` for it, that
    /// derived claim is pushed into `authd_claims` AFTER the OIDC arm's stamped
    /// `google`, and `approve_connection_detailed` commits claims with `add_attribute`
    /// in slice order -- last writer wins, so the actor ends up with `"happyfile"`.
    ///
    /// The store order handed to [PolicySnapshot::for_tests] is pinned explicitly
    /// (google's OIDC store first, happyfile second): production order is
    /// `policy.list_services()` -- a HashMap iteration upstream, stable per policy
    /// build but not sorted -- so the displacement direction must not be left to
    /// accident in this test.
    #[tokio::test]
    async fn test_oidc_connect_with_decorating_file_store_keeps_google_authority_zipline24() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        // Install a `google` OIDC policy mapping `sub -> user.sub` so the minted blob
        // validates and its subject is admitted into the provider store.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                &["sub -> user.sub"],
                &["sub"],
                make_test_oidc_config(),
                &[],
                &[],
            ))
            .await
            .expect("test policy should install");
        let cc = make_cc("test-vs");
        let pinned = asm.policy_mgr.get_current_snapshot();
        let google_store = pinned
            .oidc_service_for_issuer(OIDC_ISSUER)
            .expect("installed policy must declare the google provider");

        // The OIDC arm validates the token and stamps `user.zpr.authority = google`
        // plus the mapped subject -- exactly what authenticate_adapter_or_node feeds
        // into authorize_connection for a user-only login.
        let AuthBlob::Oidc(blob) = oidc_blob(mint_signed(oidc_base_claims())) else {
            unreachable!()
        };
        let outcome = cc
            .authenticate_oidc_blob(&pinned, &blob)
            .await
            .expect("minted token must validate");
        let authd = outcome.authd;

        // Authorization policy declares BOTH trusted services, so `user.sub` is a
        // lookup-identity key and the join policy (no conditions) admits the login.
        let policy = policy_from_container(crate::test_helpers::make_trusted_services_policy(&[
            crate::test_helpers::TrustedServiceSpec {
                id: "google",
                api: "oidc",
                expiration_seconds: Some(3600),
                mappings: &["sub -> user.sub"],
                identity: &["sub"],
                oidc: Some(make_test_oidc_config()),
                attr_query: None,
            },
            crate::test_helpers::TrustedServiceSpec {
                id: "happyfile",
                api: "file",
                expiration_seconds: Some(3600),
                mappings: &["lazy -> #user.lazy"],
                identity: &[],
                oidc: None,
                attr_query: None,
            },
        ]));
        // happyfile's file-store mapping `lazy -> #user.lazy` produces the ZPR key
        // `user.zpr.tag.lazy` (attribute_mapper.rs), vended for the admitted subject.
        let happyfile = Arc::new(KeyedNamedTrustedService {
            source_id: "happyfile".to_string(),
            known_value: OIDC_SUB.to_string(),
            vends: vec![("user.zpr.tag.lazy".to_string(), String::new())],
        });
        // Store order PINNED: google first, happyfile second, so happyfile's derived
        // authority is pushed after google's stamped one and wins the last-writer race.
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> =
            vec![google_store, happyfile];

        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, stores),
                "user-only",
                Vec::new(),
                authd,
                0,
            )
            .await
            .expect("user login with matching join policy should authorize");

        // The decoration arrived...
        assert!(
            actor.get_attribute("user.zpr.tag.lazy").is_some(),
            "happyfile's tag must reach the actor"
        );
        // ...but the authenticator's authority must survive it. FAILS today with
        // "happyfile" (zipline#24); fixed by zipline#25/#26.
        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be present")
                .get_value(),
            &vec!["google".to_string()],
            "the OIDC authenticator's authority must not be displaced by a decorating store"
        );
    }

    // ---- reauthorize: session-bound OIDC renewal (zipline#43) ----

    /// Unwrap any reauth failure into its wire-classified [ApiResponseError].
    fn api_err<T>(result: Result<T, ServiceError>) -> ApiResponseError {
        match result {
            Err(ServiceError::ApiResponse(api)) => api,
            Err(other) => panic!("expected ApiResponse error, got {other:?}"),
            Ok(_) => panic!("expected an error, got Ok"),
        }
    }

    /// Assert the uniform session-binding rejection: `authError` with the
    /// generic message, nothing echoed.
    fn assert_auth_rejected(api: ApiResponseError) {
        assert!(
            matches!(api.code, ErrorCode::AuthError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(api.message, "authentication rejected");
    }

    /// A raw [OidcBlob] for the fixture issuer (the reauth path takes the blob
    /// directly, not the [AuthBlob] union). The blob-level nonce is unused on
    /// this path.
    fn oidc_raw_blob(id_token: String) -> OidcBlob {
        OidcBlob {
            issuer: OIDC_ISSUER.to_string(),
            id_token,
            nonce: String::new(),
        }
    }

    /// Connect an OIDC-only actor whose token was minted `iat` seconds ago and
    /// persist it behind `connect_via`, returning everything a reauth needs.
    /// The connect token carries no `auth_time`, so the recorded session
    /// anchor falls back to `iat` — reauth tokens must assert it explicitly.
    async fn reauth_fixture(
        iat_age_secs: u64,
    ) -> (Arc<Assembly>, ConnectionControl, Actor, IpAddr, u64) {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let iat1 = unix_now() - iat_age_secs;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat1);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("fixture connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        (asm, cc, actor, connect_via, iat1)
    }

    /// A renewal claim set: fresh `iat`, explicit `auth_time`, and a nonce
    /// that matches no challenge (a refresh-grant token SHOULD NOT carry a
    /// nonce, and one it does carry is the original login nonce, never a
    /// fresh one — OIDC Core §12.2 — so the reauth path must not check it).
    fn renewal_claims(iat: u64, auth_time: u64) -> serde_json::Value {
        let mut c = oidc_base_claims();
        c["iat"] = json!(iat);
        c["auth_time"] = json!(auth_time);
        c["nonce"] = json!("stale-original-login-nonce");
        c
    }

    /// Happy path at the blob level: same sub, strictly newer `iat`, unchanged
    /// `auth_time`, live admission — renews despite the useless nonce, and the
    /// renewed outcome carries the same authority and subject values.
    #[tokio::test]
    async fn test_reauth_session_bound_renews() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        let blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)));

        let outcome = cc
            .reauthenticate_oidc_blob(&psnap, &actor, &blob)
            .await
            .expect("session-bound renewal must validate");

        let authority = outcome
            .authd
            .iter()
            .find(|a| a.get_key() == key::USER_AUTHORITY)
            .expect("renewed outcome must carry the user authority");
        assert_eq!(authority.get_value(), &vec!["google".to_string()]);
        let old_expiry = actor
            .get_attribute(key::USER_AUTHORITY)
            .unwrap()
            .get_expires();
        assert!(
            authority.get_expires() > old_expiry,
            "renewed authority expiry must be strictly later (iat-anchored window)"
        );
        let sub_attr = outcome
            .authd
            .iter()
            .find(|a| a.get_key() == "user.oidc-subject")
            .expect("renewed outcome must carry the mapped sub");
        assert_eq!(sub_attr.get_single_value().unwrap(), OIDC_SUB);
    }

    /// Table row 1: a token from a provider that did not admit this actor is a
    /// credential rejection — generic `authError`, nothing echoed.
    #[tokio::test]
    async fn test_reauth_unknown_provider_rejected() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        let mut blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)));
        blob.issuer = "https://idp.invalid".to_string();

        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// Table row 2: every non-nonce validation check still runs under
    /// SessionBound — a token signed by an unknown key fails with the same
    /// Contract-2 classification as on the connect path.
    #[tokio::test]
    async fn test_reauth_bad_signature_contract2_classified() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        // Signed with a key the provider's JWKS does not carry.
        let (foreign_key, _) = gen_rsa_test_keypair();
        let pem = foreign_key.private_key_to_pem_pkcs8().unwrap();
        let signing_key = jwt::EncodingKey::from_rsa_pem(&pem).unwrap();
        let token = mint_token(
            renewal_claims(unix_now(), iat1),
            "not-a-known-kid",
            jwt::Algorithm::RS256,
            &signing_key,
        );

        let api = api_err(
            cc.reauthenticate_oidc_blob(&psnap, &actor, &oidc_raw_blob(token))
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::InvalidSignature),
            "unexpected code {:?}",
            api.code
        );
    }

    /// Table row 3a: a valid token for a DIFFERENT subject does not renew this
    /// actor's session.
    #[tokio::test]
    async fn test_reauth_sub_mismatch_rejected() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        let mut claims = renewal_claims(unix_now(), iat1);
        claims["sub"] = json!("somebody-else");

        let api = api_err(
            cc.reauthenticate_oidc_blob(&psnap, &actor, &oidc_raw_blob(mint_signed(claims)))
                .await,
        );
        assert_auth_rejected(api);
    }

    /// Table row 3b: no admission recorded for the subject — here the actor
    /// carries the right attributes but the provider store never admitted the
    /// sub (the VS-restart shape: attributes persisted, in-memory cache gone).
    /// The node's cue to reconnect.
    #[tokio::test]
    async fn test_reauth_no_recorded_admission_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let psnap = asm.policy_mgr.get_current_snapshot();
        // An actor that LOOKS admitted (authority + mapped sub) but whose
        // subject has no record in the provider store.
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder(key::USER_AUTHORITY)
                    .expires_in(Duration::from_secs(3600))
                    .value("google"),
            )
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder("user.oidc-subject")
                    .expires_in(Duration::from_secs(3600))
                    .value(OIDC_SUB),
            )
            .unwrap();
        let iat1 = unix_now() - 120;
        let blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)));

        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// Table row 4: `iat` must be strictly greater than the recorded one — the
    /// admitted token itself (or any older one) replayed to reauthorize is
    /// rejected.
    #[tokio::test]
    async fn test_reauth_iat_not_increasing_rejected() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        // Same iat as the admitted token (auth_time defaulted to iat1 there).
        let blob = oidc_raw_blob(mint_signed(renewal_claims(iat1, iat1)));

        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// Table row 5: a changed `auth_time` is a NEW login session, not a
    /// renewal of this one — the endpoint must reconnect.
    #[tokio::test]
    async fn test_reauth_auth_time_changed_rejected() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        let blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1 + 60)));

        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// Table row 6: a renewal whose recomputed expiry is not in the future is
    /// a clean rejection (open question 2: `authError` + generic message).
    /// Forced here with a zero-lifetime policy: the dual-clock window closes
    /// at `iat`, so any real renewal instant is already past it.
    #[tokio::test]
    async fn test_reauth_expired_window_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                0, // expiration_seconds: the renewal window is zero-width
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[],
                &[],
            ))
            .await
            .expect("test policy should install");
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let iat1 = unix_now() - 120;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat1);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "some.cn");
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("connect itself does not require a future expiry");

        let psnap = asm.policy_mgr.get_current_snapshot();
        let blob = oidc_raw_blob(mint_signed(renewal_claims(iat1 + 30, iat1)));

        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// Regression: the connect arm still requires the exact nonce after the
    /// [NonceExpectation] refactor — a mismatched nonce fails
    /// `authenticate_oidc_blob` with the Contract-2 signature classification.
    #[tokio::test]
    async fn test_connect_arm_still_rejects_wrong_nonce_after_refactor() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let psnap = asm.policy_mgr.get_current_snapshot();
        let mut claims = oidc_base_claims();
        claims["nonce"] = json!("not-the-challenge-nonce");
        let AuthBlob::Oidc(blob) = oidc_blob(mint_signed(claims)) else {
            unreachable!()
        };

        let api = api_err(cc.authenticate_oidc_blob(&psnap, &blob).await);
        assert!(
            matches!(api.code, ErrorCode::InvalidSignature),
            "unexpected code {:?}",
            api.code
        );
    }

    // ---- reauthorize_actor: the whole VSAPI operation (zipline#43 step 4) ----

    /// Happy path end to end: the renewed actor keeps its ZPR address and its
    /// `user.*` attribute VALUES, and its authentication expiry moves strictly
    /// later; the persisted record reflects the renewal.
    #[tokio::test]
    async fn test_reauthorize_actor_renews_in_place() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().expect("fixture actor has an address");
        let old_expiry = actor
            .get_attribute(key::USER_AUTHORITY)
            .unwrap()
            .get_expires();
        let old_sub = actor
            .get_attribute("user.oidc-subject")
            .unwrap()
            .get_single_value()
            .unwrap()
            .to_string();

        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(
            unix_now(),
            iat1,
        ))))];
        let renewed = cc
            .reauthorize_actor(asm.clone(), addr, blobs, &connect_via, None)
            .await
            .expect("reauthorize must succeed");

        assert_eq!(
            renewed.get_zpr_addr(),
            Some(&addr),
            "reauth must never re-allocate the address"
        );
        assert_eq!(
            renewed
                .get_attribute("user.oidc-subject")
                .unwrap()
                .get_single_value()
                .unwrap(),
            old_sub,
            "renewed user.* attributes keep their values"
        );
        assert!(
            renewed
                .get_attribute(key::USER_AUTHORITY)
                .unwrap()
                .get_expires()
                > old_expiry,
            "renewed authority expiry must be strictly later"
        );
        // And the renewal was persisted, not just returned.
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .expect("renewed actor must still be stored");
        assert!(
            stored
                .get_attribute(key::USER_AUTHORITY)
                .unwrap()
                .get_expires()
                > old_expiry,
            "the stored record must carry the renewed expiry"
        );
    }

    /// PR #19 review (P1): reauthorization must re-mint the VS identity
    /// token, not carry the connect-time one. `get_authentication_expiration`
    /// takes the MINIMUM across identity attributes, so a stale
    /// `zpr.vs.bootstrap.ident` would cap every renewal at the original
    /// connect's window — after 4 hours an OIDC-only actor could renew its
    /// user authority yet still be denied new visas.
    #[tokio::test]
    async fn test_reauthorize_actor_renews_vs_identity_token() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let old_ident = actor
            .get_attribute(ATTR_KEY_VS_IDENT)
            .expect("connect stamps the VS identity token")
            .clone();

        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(
            unix_now(),
            iat1,
        ))))];
        let renewed = cc
            .reauthorize_actor(asm, addr, blobs, &connect_via, None)
            .await
            .expect("reauthorize must succeed");

        let new_ident = renewed
            .get_attribute(ATTR_KEY_VS_IDENT)
            .expect("the renewed actor must carry a VS identity token");
        assert_ne!(
            new_ident.get_single_value().unwrap(),
            old_ident.get_single_value().unwrap(),
            "the VS identity token must be re-minted (fresh jti), not carried over"
        );
        assert!(
            new_ident.get_expires() > old_ident.get_expires(),
            "the re-minted identity token must carry a fresh expiration"
        );
        // Still registered as the highest-priority identity key.
        assert_eq!(
            renewed.identity_keys_iter().next().map(|k| k.as_str()),
            Some(ATTR_KEY_VS_IDENT)
        );
    }

    /// PR #19 review (P1): a claim the refreshed token no longer admits must
    /// not survive renewal. The fixture's connect admitted a verified email;
    /// the renewal token's email is unverified (the zipline#8 validator strips it),
    /// so the provider no longer vouches `user.email` — the stale
    /// source-stamped attribute must be dropped before policy evaluation,
    /// not carried into the renewed actor.
    #[tokio::test]
    async fn test_reauthorize_actor_drops_claims_the_renewal_no_longer_admits() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        assert!(
            actor.get_attribute("user.email").is_some(),
            "the fixture connect admits the verified email"
        );

        let mut claims = renewal_claims(unix_now(), iat1);
        claims["email_verified"] = json!(false);
        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(claims)))];
        let renewed = cc
            .reauthorize_actor(asm, addr, blobs, &connect_via, None)
            .await
            .expect("reauthorize must succeed");

        assert!(
            renewed.get_attribute("user.email").is_none(),
            "a formerly-mapped claim the refreshed token no longer admits must not survive"
        );
        // Claims the renewal still admits come back through the lookup.
        assert!(
            renewed.get_attribute("user.domain").is_some(),
            "claims the refreshed token still admits are re-served"
        );
    }

    /// PR #19 review (P1): session anchors must be scoped to the actor
    /// session, not globally to the OIDC subject. A second live actor
    /// authenticating as the SAME provider account (a new login session:
    /// later `auth_time`/`iat`) must not overwrite the first actor's
    /// recorded anchors — its renewal within its own login session must
    /// still validate.
    #[tokio::test]
    async fn test_reauth_anchors_scoped_per_actor_session() {
        let (asm, cc, actor1, connect_via, iat1) = reauth_fixture(300).await;

        // Second actor, same subject, NEW login session (fresher iat, and —
        // via the connect fallback — a different auth_time anchor).
        let iat2 = unix_now() - 60;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat2);
        let req = make_connect_request(vec![oidc_blob(mint_signed(claims))], "other.cn");
        let actor2 = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("the second connect for the same subject must authorize");
        assert_ne!(
            actor1.get_zpr_addr(),
            actor2.get_zpr_addr(),
            "two live actors, two addresses"
        );

        // Actor 1 renews within ITS login session (auth_time = iat1). The
        // second admission must not have clobbered actor 1's anchors.
        let psnap = asm.policy_mgr.get_current_snapshot();
        let blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)));
        cc.reauthenticate_oidc_blob(&psnap, &actor1, &blob)
            .await
            .expect("a concurrent session for the same subject must not invalidate this renewal");
    }

    /// With the anchors advancing on the reauthorize operation itself, a
    /// renewal token replayed to a SECOND reauthorize is caught by the
    /// strictly-increasing `iat` guard.
    #[tokio::test]
    async fn test_reauthorize_actor_replayed_renewal_token_rejected() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let token = mint_signed(renewal_claims(unix_now(), iat1));

        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![AuthBlob::Oidc(oidc_raw_blob(token.clone()))],
            &connect_via,
            None,
        )
        .await
        .expect("the first renewal must succeed");

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![AuthBlob::Oidc(oidc_raw_blob(token))],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// PR #19 review (P2): a lapsed admission must not be resurrectable. The
    /// recorded session's `expires` has passed, the actor record still
    /// exists — a fresh, otherwise-valid token must be rejected with the
    /// generic `AuthError` (Q2: passed-ceiling ⇒ generic rejection); the
    /// node's cue to reconnect. (The expiry SWEEP is zipline#44 — out of
    /// scope here; this is only the liveness check on the reauth path.)
    #[tokio::test]
    async fn test_reauth_expired_admission_rejected() {
        let (asm, cc, actor, _via, iat1) = reauth_fixture(120).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        let svc = psnap
            .oidc_service_for_issuer(OIDC_ISSUER)
            .expect("fixture provider");
        // Overwrite the recorded session with one whose admission expired.
        let session_id = actor.get_zpr_addr().unwrap().to_string();
        let anchors = svc.session_anchors(&session_id).expect("recorded session");
        svc.record_session(
            &session_id,
            OIDC_SUB,
            anchors.auth_time,
            anchors.iat,
            SystemTime::now() - Duration::from_secs(1),
        );

        let blob = oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)));
        let api = api_err(cc.reauthenticate_oidc_blob(&psnap, &actor, &blob).await);
        assert_auth_rejected(api);
    }

    /// zipline#119 bug test: an RSA+OIDC actor's authentication window after
    /// a `reauthorize` must extend beyond connect +
    /// `DEFAULT_AUTH_EXPIRATION`. Before #119 it could not: the claim-rebuild
    /// filter (`reauthorize_actor`) passed `device.zpr.authority` through
    /// unchanged, so the bootstrap stamp minted at connect with
    /// `DEFAULT_AUTH_EXPIRATION` pinned `get_authentication_expiration()` at
    /// connect + 4 h no matter how often the user authority renewed.
    /// (zipline#120: the renewal now presents both blobs, since the K3
    /// exact-set rule requires every authenticated namespace re-proved.)
    #[tokio::test]
    async fn test_reauth_rsa_oidc_not_pinned_to_default_window() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let connect_time = SystemTime::now();
        let iat1 = unix_now() - 120;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat1);
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(claims)),
            ],
            cn,
        );
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("RSA+OIDC connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        let addr = *actor.get_zpr_addr().unwrap();

        let blobs = vec![
            make_fresh_ss_blob(&privkey, cn),
            AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)))),
        ];
        let renewed = cc
            .reauthorize_actor(asm, addr, blobs, &connect_via, None)
            .await
            .expect("reauthorize must succeed");

        let exp = renewed
            .get_authentication_expiration()
            .expect("an authenticated actor must carry an expiration");
        assert!(
            exp > connect_time + config::DEFAULT_AUTH_EXPIRATION + Duration::from_secs(3600),
            "an OIDC renewal must extend the actor's authentication window \
             beyond connect + DEFAULT_AUTH_EXPIRATION; the bootstrap \
             device-authority stamp must not pin it (zipline#119)"
        );
    }

    /// zipline#119: an RSA-only (bootstrap) adapter's authentication never
    /// expires — its device authority and its `zpr.vs.bootstrap.ident` are
    /// both stamped far-future, so `get_authentication_expiration()` is
    /// far in the future.
    #[tokio::test]
    async fn test_rsa_only_adapter_auth_expiration_far_future() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        // Bootstrap key + join-any policy WITHOUT the Node flag: the actor is
        // an adapter.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("RSA-only connect must authorize");

        assert!(!actor.is_node(), "fixture must yield an adapter");
        let exp = actor
            .get_authentication_expiration()
            .expect("bootstrap actor must carry an expiration");
        assert!(
            exp > SystemTime::now() + Duration::from_secs(50 * 365 * 24 * 60 * 60),
            "bootstrap authentication must be far-future (zipline#119)"
        );
    }

    /// zipline#119: an OIDC-only actor's lifetimes are UNCHANGED — its
    /// authentication expiration stays within the provider's session window,
    /// nowhere near the bootstrap far-future stamp.
    #[tokio::test]
    async fn test_oidc_only_auth_expiration_unchanged() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        install_oidc_policy(&asm, make_test_oidc_config()).await;
        let cc = make_cc("test-vs");
        let req = make_connect_request(vec![oidc_blob(mint_signed(oidc_base_claims()))], "some.cn");

        let actor = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("OIDC-only connect must authorize");

        let exp = actor
            .get_authentication_expiration()
            .expect("OIDC actor must carry an expiration");
        assert!(
            exp <= SystemTime::now() + Duration::from_secs(OIDC_LIFETIME_SECS as u64 + 60),
            "an OIDC-only actor's window must stay within the provider session \
             lifetime — zipline#119 must not extend OIDC"
        );
    }

    /// zipline#119: a node authenticated over the bootstrap path gets a
    /// far-future authentication expiration.
    #[tokio::test]
    async fn test_node_bootstrap_auth_expiration_far_future() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("node authentication should succeed");

        let exp = actor
            .get_authentication_expiration()
            .expect("node must carry an expiration");
        assert!(
            exp > SystemTime::now() + Duration::from_secs(50 * 365 * 24 * 60 * 60),
            "a bootstrap node's authentication must be far-future (zipline#119)"
        );
    }

    /// An SS blob presented for a namespace the actor never authenticated is
    /// a set mismatch: `paramError` with explicit text (contract K3 — the
    /// namespace set must exactly equal the actor's authorities; this
    /// OIDC-only actor holds no `device.zpr.authority`).
    #[tokio::test]
    async fn test_reauthorize_actor_ss_blob_on_oidc_actor_param_error() {
        let (asm, cc, actor, connect_via, _iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let (privkey, _) = gen_rsa_test_keypair();
        let blobs = vec![make_fresh_ss_blob(&privkey, "some.cn")];

        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(
            api.message,
            "reauthorize blobs must cover exactly the actor's credential-backed namespaces"
        );
    }

    /// Zero blobs: `paramError` — a renewal must re-prove at least one
    /// namespace (and an actor always holds at least one authority).
    #[tokio::test]
    async fn test_reauthorize_actor_wrong_blob_count_param_error() {
        let (asm, cc, actor, connect_via, _iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();

        let api = api_err(
            cc.reauthorize_actor(asm, addr, Vec::new(), &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(api.message, "reauthorize requires at least one auth blob");
    }

    /// An address with no live actor behind it: `paramError` (protocol error,
    /// not a credential rejection).
    #[tokio::test]
    async fn test_reauthorize_actor_unknown_address_param_error() {
        let (asm, cc, _actor, connect_via, iat1) = reauth_fixture(120).await;
        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(
            unix_now(),
            iat1,
        ))))];

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                "fd5a:5052::dead".parse().unwrap(),
                blobs,
                &connect_via,
                None,
            )
            .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
    }

    /// An actor admitted through a DIFFERENT node cannot be reauthorized from
    /// this one (first table row of the issue).
    #[tokio::test]
    async fn test_reauthorize_actor_wrong_node_param_error() {
        let (asm, cc, actor, _connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let other_node: IpAddr = "fd5a:5052::2".parse().unwrap();
        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(
            unix_now(),
            iat1,
        ))))];

        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &other_node, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
    }

    // ---- reauthorize_actor: per-namespace blob set + SS arm (zipline#120) ----

    /// Fixture: an SS-only (bootstrap RSA) adapter, connected and persisted
    /// behind `connect_via`. Returns the bootstrap keypair so tests can mint
    /// reauth blobs and install rotated-key policies.
    async fn ss_reauth_fixture(
        cn: &str,
    ) -> (
        Arc<Assembly>,
        ConnectionControl,
        Actor,
        IpAddr,
        PKey<Private>,
        Vec<u8>,
    ) {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .expect("test policy should install");
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("SS-only connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        (asm, cc, actor, connect_via, privkey, pubkey_der)
    }

    /// Fixture: an SS+OIDC adapter (both authorities), connected and
    /// persisted behind `connect_via`. Returns the bootstrap key and the
    /// connect token's `iat` for minting renewal blobs.
    async fn ss_oidc_reauth_fixture(
        cn: &str,
    ) -> (
        Arc<Assembly>,
        ConnectionControl,
        Actor,
        IpAddr,
        PKey<Private>,
        u64,
    ) {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .expect("test policy should install");
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let iat1 = unix_now() - 120;
        let mut claims = oidc_base_claims();
        claims["iat"] = json!(iat1);
        let req = make_connect_request(
            vec![
                make_valid_ss_blob(&privkey, cn),
                oidc_blob(mint_signed(claims)),
            ],
            cn,
        );
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("SS+OIDC connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        (asm, cc, actor, connect_via, privkey, iat1)
    }

    /// Flip of the old OIDC-only guard (contract K3): a single fresh SS blob
    /// on an SS-only actor renews it in place — address unchanged, device
    /// authority re-stamped far-future — and the policy re-run stamps the
    /// CURRENT `zpr.vinst`.
    #[tokio::test]
    async fn test_reauthorize_actor_ss_only_renews_in_place_stamps_current_vinst() {
        let cn = "ss-adapter.zpr";
        let (asm, cc, actor, connect_via, privkey, pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let old_vinst = actor
            .get_attribute(key::VINST)
            .expect("connect stamps the policy generation")
            .get_single_value()
            .unwrap()
            .to_string();

        // A new policy install (different container bytes, same bootstrap
        // key) advances the generation; the renewal must stamp the new one.
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS - 1,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &pubkey_der)],
                &[],
            ))
            .await
            .expect("second policy install");
        let new_vinst = asm.policy_mgr.get_current_snapshot().vinst().to_string();
        assert_ne!(
            old_vinst, new_vinst,
            "the install must advance the generation"
        );

        let renewed = cc
            .reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &connect_via,
                None,
            )
            .await
            .expect("SS reauthorize must succeed");

        assert_eq!(
            renewed.get_zpr_addr(),
            Some(&addr),
            "reauth must never re-allocate the address"
        );
        assert_eq!(
            renewed
                .get_attribute(key::VINST)
                .expect("the policy re-run stamps the generation")
                .get_single_value()
                .unwrap(),
            new_vinst,
            "the renewal must stamp the CURRENT policy generation"
        );
        let device_exp = renewed
            .get_attribute(key::DEVICE_AUTHORITY)
            .expect("the renewed actor must carry the device authority")
            .get_expires();
        assert!(
            device_exp > SystemTime::now() + Duration::from_secs(50 * 365 * 24 * 60 * 60),
            "the re-stamped bootstrap authority must be far-future (zipline#119)"
        );
    }

    /// Contract K3 happy path for a two-namespace actor: one blob per
    /// namespace renews both authorities, and `authExpires` — the actor's
    /// authentication expiration — is the new minimum across them (the
    /// renewed user authority, since bootstrap is far-future).
    #[tokio::test]
    async fn test_reauthorize_actor_ss_plus_oidc_renews_both() {
        let cn = "ss-node.zpr";
        let (asm, cc, actor, connect_via, privkey, iat1) = ss_oidc_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let old_user_expiry = actor
            .get_attribute(key::USER_AUTHORITY)
            .unwrap()
            .get_expires();

        let blobs = vec![
            make_fresh_ss_blob(&privkey, cn),
            AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)))),
        ];
        let renewed = cc
            .reauthorize_actor(asm, addr, blobs, &connect_via, None)
            .await
            .expect("two-namespace reauthorize must succeed");

        let new_user_expiry = renewed
            .get_attribute(key::USER_AUTHORITY)
            .expect("the renewed actor must carry the user authority")
            .get_expires();
        assert!(
            new_user_expiry > old_user_expiry,
            "the renewed user authority expiry must move strictly later"
        );
        let device_exp = renewed
            .get_attribute(key::DEVICE_AUTHORITY)
            .expect("the renewed actor must carry the device authority")
            .get_expires();
        assert!(
            device_exp > SystemTime::now() + Duration::from_secs(50 * 365 * 24 * 60 * 60),
            "the re-stamped bootstrap authority must be far-future"
        );
        assert_eq!(
            renewed
                .get_authentication_expiration()
                .expect("an authenticated actor carries an expiration"),
            new_user_expiry,
            "authExpires must be the new minimum across the renewed authorities"
        );
    }

    /// PR #40 review (Codex P1): a `user.zpr.authority` synthesized by
    /// trusted-service enrichment ([derive_user_authority]) is NOT
    /// credential-backed — the device never presented an OIDC credential, so
    /// demanding a user blob for it makes the actor's only valid renewal
    /// (its SS blob) a permanent `paramError` and strands it after a policy
    /// update. The SS-only renewal must succeed; post-renewal enrichment is
    /// what re-derives the authority.
    #[tokio::test]
    async fn test_reauthorize_actor_ss_only_with_ts_derived_user_authority() {
        let cn = "enriched-adapter.zpr";
        let (asm, cc, mut actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();

        // What enrichment does when a file or attribute-service store vends a `user.*`
        // attribute for this device: the vended attribute lands on the actor
        // together with the derived authority (source = the store's id).
        let vended = AttributeSource::new("happyfile")
            .builder("user.zpr.tag.lazy")
            .expires_in(Duration::from_secs(3600))
            .value("");
        let derived = derive_user_authority("happyfile", &[vended.clone()], None)
            .expect("a vended user.* attribute derives the authority");
        actor.add_attribute(vended).unwrap();
        actor.add_attribute(derived).unwrap();
        asm.actor_mgr
            .update_actor(&actor, &asm.policy_service_names())
            .await
            .expect("enriched actor must persist");

        // The only credential this actor can ever renew is its SS blob.
        let renewed = cc
            .reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &connect_via,
                None,
            )
            .await
            .expect("SS-only renewal must succeed for a TS-enriched actor");
        assert_eq!(
            renewed.get_zpr_addr(),
            Some(&addr),
            "reauth must never re-allocate the address"
        );
    }

    /// PR #40 review (Codex P1), flip side: an OIDC blob offered for a
    /// TS-derived authority is a set mismatch — no renewable credential arm
    /// backs that authority, so the credential-backed namespace set is
    /// {device} only and the user blob covers nothing. `paramError`, before
    /// any credential is validated.
    #[tokio::test]
    async fn test_reauthorize_actor_oidc_blob_for_ts_derived_authority_param_error() {
        let cn = "enriched-adapter2.zpr";
        let (asm, cc, mut actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let vended = AttributeSource::new("happyfile")
            .builder("user.zpr.tag.lazy")
            .expires_in(Duration::from_secs(3600))
            .value("");
        let derived = derive_user_authority("happyfile", &[vended.clone()], None)
            .expect("a vended user.* attribute derives the authority");
        actor.add_attribute(vended).unwrap();
        actor.add_attribute(derived).unwrap();
        asm.actor_mgr
            .update_actor(&actor, &asm.policy_service_names())
            .await
            .expect("enriched actor must persist");

        let iat1 = unix_now() - 120;
        let blobs = vec![
            make_fresh_ss_blob(&privkey, cn),
            AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)))),
        ];
        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(
            api.message,
            "reauthorize blobs must cover exactly the actor's credential-backed namespaces"
        );
    }

    /// Contract K3: a duplicate namespace in the blob set is a caller bug —
    /// `paramError`, before any credential is validated.
    #[tokio::test]
    async fn test_reauthorize_actor_duplicate_namespace_param_error() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let token = mint_signed(renewal_claims(unix_now(), iat1));
        let blobs = vec![
            AuthBlob::Oidc(oidc_raw_blob(token.clone())),
            AuthBlob::Oidc(oidc_raw_blob(token)),
        ];

        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(api.message, "duplicate user auth blob in reauthorize");
    }

    /// Contract K3: a namespace subset does not renew — an SS+OIDC actor
    /// presenting only the OIDC leg is a `paramError` (every authority must
    /// be re-proved; a partial set would silently drop one).
    #[tokio::test]
    async fn test_reauthorize_actor_namespace_subset_param_error() {
        let cn = "ss-node.zpr";
        let (asm, cc, actor, connect_via, _privkey, iat1) = ss_oidc_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let blobs = vec![AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(
            unix_now(),
            iat1,
        ))))];

        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(
            api.message,
            "reauthorize blobs must cover exactly the actor's credential-backed namespaces"
        );
    }

    /// Contract K3: a namespace superset does not renew either — an OIDC-only
    /// actor presenting SS+OIDC is a `paramError` (the device namespace was
    /// never authenticated for this actor).
    #[tokio::test]
    async fn test_reauthorize_actor_namespace_superset_param_error() {
        let (asm, cc, actor, connect_via, iat1) = reauth_fixture(120).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let (privkey, _) = gen_rsa_test_keypair();
        let blobs = vec![
            make_fresh_ss_blob(&privkey, "some.cn"),
            AuthBlob::Oidc(oidc_raw_blob(mint_signed(renewal_claims(unix_now(), iat1)))),
        ];

        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(
            api.message,
            "reauthorize blobs must cover exactly the actor's credential-backed namespaces"
        );
    }

    /// SS arm, key removed: the pinned snapshot no longer carries a bootstrap
    /// key for the CN — generic `AuthError`, nothing echoed (key removal is
    /// the bootstrap revocation path, zipline#119).
    #[tokio::test]
    async fn test_reauthorize_actor_ss_key_removed_auth_error() {
        let cn = "ss-adapter.zpr";
        let (asm, cc, actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();

        // Install a policy WITHOUT the bootstrap key.
        install_oidc_policy(&asm, make_test_oidc_config()).await;

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// SS arm, key rotated: the snapshot carries a DIFFERENT bootstrap key
    /// for the CN, so the signature no longer verifies — generic `AuthError`.
    #[tokio::test]
    async fn test_reauthorize_actor_ss_key_rotated_auth_error() {
        let cn = "ss-adapter.zpr";
        let (asm, cc, actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();

        // Same CN, new keypair: the old key's signatures stop verifying.
        let (_new_priv, new_pub) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, &new_pub)],
                &[],
            ))
            .await
            .expect("rotated-key policy install");

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// SS arm, CN mismatch: the blob names a CN other than the actor's
    /// authenticated CN — generic `AuthError` (a blob for someone else never
    /// renews this actor, however valid its signature).
    #[tokio::test]
    async fn test_reauthorize_actor_ss_cn_mismatch_auth_error() {
        let cn = "ss-adapter.zpr";
        let (asm, cc, actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, "other.zpr")],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// SS arm, clock skew: a blob timestamp outside ±MAX_CLOCK_SKEW_SECS is a
    /// generic `AuthError` (freshness rides on the node-minted challenge; the
    /// skew window only bounds clock drift).
    #[tokio::test]
    async fn test_reauthorize_actor_ss_skewed_timestamp_auth_error() {
        let cn = "ss-adapter.zpr";
        let (asm, cc, actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let skewed = unix_now() - (crate::config::MAX_CLOCK_SKEW_SECS + 60);

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![make_ss_blob_at(&privkey, cn, skewed)],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// A policy-evaluation denial from `authorize_connection` on the reauth
    /// path surfaces as `PolicyDenied` on the wire (issue acceptance): the
    /// login is still good — the endpoint is no longer admitted — so the
    /// caller must be able to tell it from a credential rejection. Everything
    /// else passes through with its existing classification. Note an
    /// end-to-end denial is unreachable for adapters today: a validated login
    /// matching no join policy still connects (#227, recorded as superseded
    /// in docs/OIDC.md), so this exercises the classification arm directly.
    #[test]
    fn test_reauth_policy_denial_maps_to_policy_denied() {
        use libeval::error::EvalError;

        let denied =
            ConnectionControl::classify_reauth_policy_error(ServiceError::Eval(EvalError::NoMatch));
        let api = match denied {
            ServiceError::ApiResponse(api) => api,
            other => panic!("expected ApiResponse, got {other:?}"),
        };
        assert!(
            matches!(api.code, ErrorCode::PolicyDenied),
            "unexpected code {:?}",
            api.code
        );
        assert_eq!(api.message, "policy denied");

        // Non-evaluation failures keep their existing classification.
        let passthrough =
            ConnectionControl::classify_reauth_policy_error(ServiceError::Internal("x".into()));
        assert!(
            matches!(passthrough, ServiceError::Internal(_)),
            "non-eval errors must pass through unchanged"
        );
    }

    // ---- static-address checks at authorize time (zipline#98) ----
    //
    // A static (pre-set) `zpr.addr` on the approved actor — a policy pin committed
    // under zipline#97, or later a trusted-service grant (zipline#99) — must be
    // inside `fd5a:5052::/32`, not the visa service address, OUTSIDE both managed
    // pools, and not held by a live actor. Static addresses live in a different
    // address space from the pools, so an accepted one never touches the allocator.

    /// Authenticated claims carrying a static ZPR address, as the RSA arm plus a
    /// zipline#97 pin commit (or an A3 trusted-service grant) would produce.
    fn static_addr_claims(cn: &str, addr: &str) -> Vec<Attribute> {
        vec![
            Attribute::builder(key::CN).value(cn),
            Attribute::builder(key::ZPR_ADDR).value(addr),
        ]
    }

    /// A static address inside the ADAPTER pool must be rejected — the pool could
    /// hand the same address to someone else — and the pool must stay untouched:
    /// nothing was taken, so taking it afterwards still succeeds.
    #[tokio::test]
    async fn static_addr_inside_adapter_pool_rejected_pool_untouched() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                static_addr_claims("pinned.zpr", "fd5a:5052:adda:1::42"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("managed pool")),
            "in-pool static address must fail the pool check, got {result:?}"
        );
        // The rejection took nothing out of the pool.
        assert!(
            asm.net_mgr.take_zpr_addr(&addr).is_ok(),
            "pool must be untouched by the rejection"
        );
    }

    /// Same for the NODE pool, via an adapter-shaped claim set: the pool check is
    /// on the address value, not the actor's role.
    #[tokio::test]
    async fn static_addr_inside_node_pool_rejected_pool_untouched() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:90de:1::42".parse().unwrap();

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                static_addr_claims("pinned.zpr", "fd5a:5052:90de:1::42"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("managed pool")),
            "in-pool static address must fail the pool check, got {result:?}"
        );
        assert!(
            asm.net_mgr.take_zpr_addr(&addr).is_ok(),
            "pool must be untouched by the rejection"
        );
    }

    /// A static address outside `fd5a:5052::/32` must be rejected. `fd00:1:2::1`
    /// is the shape the old core integration tests used before P1 (zipline#96)
    /// renumbered them.
    #[tokio::test]
    async fn static_addr_out_of_range_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                static_addr_claims("pinned.zpr", "fd00:1:2::1"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("out of range")),
            "out-of-range static address must fail the range check, got {result:?}"
        );
    }

    /// An IPv4 static address is outside `fd5a:5052::/32` by construction, so the
    /// range check rejects it even though it is inside a managed IPv4 pool.
    #[tokio::test]
    async fn static_addr_ipv4_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                static_addr_claims("pinned.zpr", "10.128.0.5"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("out of range")),
            "IPv4 static address must fail the range check, got {result:?}"
        );
    }

    /// The visa service's own address is in range and outside both pools, so it
    /// needs its own rejection: no peer may claim `fd5a:5052::1`.
    #[tokio::test]
    async fn static_addr_vs_address_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "impostor.zpr",
                Vec::new(),
                static_addr_claims("impostor.zpr", "fd5a:5052::1"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("out of range")),
            "the VS address must be rejected as a static claim, got {result:?}"
        );
    }

    // ---- the visa service's own address (zipline#102) ----
    //
    // The VS address is fixed by configuration: it is neither a policy pin (which
    // zipline#98 forbids for `fd5a:5052::1`) nor a trusted-service grant. Since
    // zipline#97 scrubs any unpinned request, the VS adapter's own connect must be
    // given its address by authorize_connection itself, keyed on the
    // AUTHENTICATED `vs.zpr` CN — never on a claimed one.

    /// The unauthenticated `zpr.addr` request the adapter sends with `--zpr-addr`.
    fn addr_request(addr: &str) -> Vec<Attribute> {
        vec![Attribute::builder(key::ZPR_ADDR).value(addr)]
    }

    /// The VS adapter, authenticated as `vs.zpr` and requesting the VS address
    /// under a policy that pins nothing, lands on the VS address. This is the
    /// connect every netns integration test makes; before the fix the request was
    /// scrubbed and the adapter came up on a pool address.
    #[tokio::test]
    async fn vs_adapter_requesting_vs_addr_gets_vs_addr() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                config::VS_CN,
                addr_request("fd5a:5052::1"),
                vec![Attribute::builder(key::CN).value(config::VS_CN)],
                0,
            )
            .await
            .expect("the VS adapter must be authorized");

        assert_eq!(actor.get_zpr_addr(), Some(&asm.config.get_vs_addr()));
    }

    /// The VS address does not depend on the adapter asking for it: an
    /// authenticated `vs.zpr` with no request still lands on the VS address.
    #[tokio::test]
    async fn vs_adapter_without_request_gets_vs_addr() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                config::VS_CN,
                Vec::new(),
                vec![Attribute::builder(key::CN).value(config::VS_CN)],
                0,
            )
            .await
            .expect("the VS adapter must be authorized");

        assert_eq!(actor.get_zpr_addr(), Some(&asm.config.get_vs_addr()));
    }

    /// A peer that only CLAIMS the `vs.zpr` CN (no validated blob promoted it to
    /// an authenticated claim) must not be given the VS address, whatever it
    /// requests.
    #[tokio::test]
    async fn claimed_vs_cn_does_not_get_vs_addr() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let mut unauthd = addr_request("fd5a:5052::1");
        unauthd.push(Attribute::builder(key::CN).value(config::VS_CN));
        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                config::VS_CN,
                unauthd,
                Vec::new(),
                0,
            )
            .await;

        if let Ok(actor) = result {
            assert_ne!(
                actor.get_zpr_addr(),
                Some(&asm.config.get_vs_addr()),
                "a claimed vs.zpr CN must not be given the VS address"
            );
        }
    }

    /// A static address already held by a live actor is rejected — logged, never
    /// overwritten — and the holder's record survives intact.
    #[tokio::test]
    async fn static_addr_held_by_live_actor_rejected_record_unchanged() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::5".parse().unwrap();

        // A live actor already holds the address.
        let first =
            crate::test_helpers::make_adapter_actor_defexp("fd5a:5052:8888::5", "first.zpr");
        asm.actor_mgr
            .hack_add_adapter_no_node(&first, &asm.policy_service_names())
            .await
            .expect("holder must persist");

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "second.zpr",
                Vec::new(),
                static_addr_claims("second.zpr", "fd5a:5052:8888::5"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("held")),
            "an address held by a live actor must be rejected, got {result:?}"
        );
        // The holder's record is unchanged.
        let still = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .expect("the original actor record must survive");
        assert_eq!(still.get_cn(), Some("first.zpr"));
    }

    /// CN equality is NOT ownership proof (PR #33 review, P1): the repository
    /// supports multiple same-CN actors, so a second adapter sharing the
    /// holder's CN must not take over its live address on a fresh connect —
    /// the fresh-connect path would go on to evict the holder's record in
    /// `add_actor`. Same-CN renewal belongs to `reauthorize_actor`, which
    /// proves the session first.
    #[tokio::test]
    async fn static_addr_held_by_same_cn_adapter_rejected_record_unchanged() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::11".parse().unwrap();

        let holder =
            crate::test_helpers::make_adapter_actor_defexp("fd5a:5052:8888::11", "same.zpr");
        asm.actor_mgr
            .hack_add_adapter_no_node(&holder, &asm.policy_service_names())
            .await
            .expect("holder must persist");

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "same.zpr",
                Vec::new(),
                static_addr_claims("same.zpr", "fd5a:5052:8888::11"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("held")),
            "a same-CN fresh connect must not take over a live address, got {result:?}"
        );
        let still = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .expect("the holder's record must survive");
        assert_eq!(still.get_cn(), Some("same.zpr"));
    }

    /// Two CN-less (OIDC-only) actors both report `None` for CN, and
    /// `None == None` must never count as an ownership match (PR #33 review,
    /// P1): a second user's fresh connect claiming the holder's address must
    /// be rejected.
    #[tokio::test]
    async fn static_addr_held_by_cnless_actor_rejected_for_cnless_claimant() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::12".parse().unwrap();

        let holder = crate::test_helpers::make_oidc_only_adapter_defexp("fd5a:5052:8888::12");
        asm.actor_mgr
            .hack_add_adapter_no_node(&holder, &asm.policy_service_names())
            .await
            .expect("holder must persist");

        // A CN-less claimant, as an OIDC-only connect produces: a ZPR address
        // claim and no CN attribute at all.
        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "",
                Vec::new(),
                vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:8888::12")],
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("held")),
            "None == None must not count as an ownership match, got {result:?}"
        );
        let still = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .expect("the holder's record must survive");
        assert!(still.get_cn().is_none());
    }

    /// A node reconnecting to its own live pinned address must keep working:
    /// node identity is RSA-proven against the policy bootstrap key for its
    /// CN, and the pinned address is bound to that CN's join policy. This
    /// pins the one same-CN carve-out that survives the P1 fix.
    #[tokio::test]
    async fn authenticate_node_reconnect_to_its_live_pinned_address_accepted() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let pinned = "fd5a:5052:90de::7"; // outside both pools
        let addr: IpAddr = pinned.parse().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_pinned_node_join(
                cn,
                &pubkey_der,
                pinned,
            ))
            .await
            .unwrap();

        // The node's own record from its earlier connect is still live.
        asm.actor_mgr
            .add_node(
                &crate::test_helpers::make_node_actor_defexp(pinned, cn, "127.0.0.1:1234"),
                false,
                &Default::default(),
            )
            .await
            .expect("live node record must persist");

        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                addr,
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("a node reconnect to its own live pinned address must authenticate");

        assert!(actor.is_node());
        assert_eq!(actor.get_zpr_addr(), Some(&addr));
    }

    /// The happy path: a static address in range, outside both pools, and unheld
    /// is accepted, and no pool allocation happens for it.
    #[tokio::test]
    async fn static_addr_outside_pools_accepted_pool_untouched() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::7".parse().unwrap();

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                static_addr_claims("pinned.zpr", "fd5a:5052:8888::7"),
                0,
            )
            .await
            .expect("a valid static address must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&addr));
        // Sanity: the accepted address is not pool-managed, so nothing to release.
        assert!(!asm.net_mgr.is_managed_address(&addr));
    }

    // ---- trusted-service address grants (zipline#99, A3) ----
    //
    // An AUTHENTICATED `device.zpr_addr` attribute — vended by a trusted service
    // for the device's identity — is promoted to the requested `zpr.addr` right
    // after approve_connection, so the grant flows through exactly the zipline#98
    // checks above (in range, not the VS, outside the pools, unheld, proof arms).
    // An unauthenticated `device.zpr_addr` claim never reaches the actor (libeval
    // scrubs it; pinned there), so only TS-vouched grants can steer the address.

    /// Authenticated claims carrying a `device.zpr_addr` grant, as the claim set
    /// looks after the trusted-service fetch has appended the vended attributes.
    /// The TS-append path itself is exercised by
    /// [granted_addr_from_trusted_service_store_commits].
    fn granted_addr_claims(cn: &str, granted: &str) -> Vec<Attribute> {
        vec![
            Attribute::builder(key::CN).value(cn),
            Attribute::builder(key::DEVICE_ZPR_ADDR).value(granted),
        ]
    }

    /// The full grant path: a policy-declared trusted service vends
    /// `device.zpr_addr` for the device's CN, and the actor comes out committed
    /// at the granted address — even though the peer requested a different one.
    /// (A1/zipline#97 scrubs the unpinned request, so the grant wins.)
    #[tokio::test]
    async fn granted_addr_from_trusted_service_store_commits() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_service_policy(
            "addresses",
            "file",
            Some(3600),
            &["addr -> device.zpr_addr"],
        ));
        let granted: IpAddr = "fd5a:5052:8888::10".parse().unwrap();
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> =
            vec![named_ts(
                "addresses",
                &[(key::DEVICE_ZPR_ADDR, "fd5a:5052:8888::10")],
            )];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, stores),
                "granted.zpr",
                // The peer requests a different address; no pin matches it, so
                // A1 scrubs it and the grant decides.
                vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:8888::99")],
                vec![Attribute::builder(key::CN).value("granted.zpr")],
                0,
            )
            .await
            .expect("a valid trusted-service grant must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&granted));
        assert!(!asm.net_mgr.is_managed_address(&granted));
    }

    /// A grant with no competing request commits, and the managed pools are
    /// untouched: granted addresses live in the static address space.
    #[tokio::test]
    async fn granted_addr_no_request_accepted_pool_untouched() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let granted: IpAddr = "fd5a:5052:8888::11".parse().unwrap();

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "granted.zpr",
                Vec::new(),
                granted_addr_claims("granted.zpr", "fd5a:5052:8888::11"),
                0,
            )
            .await
            .expect("a valid grant must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&granted));
        assert!(!asm.net_mgr.is_managed_address(&granted));
    }

    /// A granted address outside `fd5a:5052::/32` fails the range check, and the
    /// rejection names the grant as the source (operator answer to plan Q2).
    #[tokio::test]
    async fn granted_addr_out_of_range_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "granted.zpr",
                Vec::new(),
                granted_addr_claims("granted.zpr", "fd00:1:2::1"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains("out of range") && msg.contains("granted")),
            "an out-of-range grant must fail the range check naming the grant, got {result:?}"
        );
    }

    /// A granted address inside a managed pool is rejected — the pool could hand
    /// it to someone else — the pool stays untouched, and the rejection names the
    /// grant as the source.
    #[tokio::test]
    async fn granted_addr_inside_pool_rejected_pool_untouched() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:adda:1::43".parse().unwrap();

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "granted.zpr",
                Vec::new(),
                granted_addr_claims("granted.zpr", "fd5a:5052:adda:1::43"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains("managed pool") && msg.contains("granted")),
            "an in-pool grant must fail the pool check naming the grant, got {result:?}"
        );
        assert!(
            asm.net_mgr.take_zpr_addr(&addr).is_ok(),
            "pool must be untouched by the rejection"
        );
    }

    /// No trusted service may grant the visa service's own address.
    #[tokio::test]
    async fn granted_addr_vs_address_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "impostor.zpr",
                Vec::new(),
                granted_addr_claims("impostor.zpr", "fd5a:5052::1"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains("out of range") && msg.contains("granted")),
            "the VS address must be rejected as a grant, got {result:?}"
        );
    }

    /// A grant that disagrees with a surviving policy pin (zipline#97) is an
    /// operator error: two sources claim to own the address decision. Rejected,
    /// naming both addresses so the operator can see the disagreement.
    #[tokio::test]
    async fn granted_addr_disagreeing_with_policy_pin_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let mut claims = granted_addr_claims("pinned.zpr", "fd5a:5052:8888::12");
        // A pin that survived approve_connection commits zpr.addr on the actor.
        claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:8888::13"));

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                claims,
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains("fd5a:5052:8888::12") && msg.contains("fd5a:5052:8888::13")),
            "a grant/pin disagreement must be rejected naming both addresses, got {result:?}"
        );
    }

    /// A grant that AGREES with the policy pin is redundant, not an error: the
    /// address commits once.
    #[tokio::test]
    async fn granted_addr_agreeing_with_policy_pin_accepted() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::14".parse().unwrap();

        let mut claims = granted_addr_claims("pinned.zpr", "fd5a:5052:8888::14");
        claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:8888::14"));

        let actor = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "pinned.zpr",
                Vec::new(),
                claims,
                0,
            )
            .await
            .expect("a grant agreeing with the pin must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&addr));
    }

    /// A granted address already held by a live actor is rejected on a fresh
    /// connect — first holder wins — and the holder's record survives intact.
    #[tokio::test]
    async fn granted_addr_held_by_live_actor_rejected_record_unchanged() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::15".parse().unwrap();

        let first =
            crate::test_helpers::make_adapter_actor_defexp("fd5a:5052:8888::15", "first.zpr");
        asm.actor_mgr
            .hack_add_adapter_no_node(&first, &asm.policy_service_names())
            .await
            .expect("holder must persist");

        let result = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "second.zpr",
                Vec::new(),
                granted_addr_claims("second.zpr", "fd5a:5052:8888::15"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("held")),
            "a granted address held by a live actor must be rejected, got {result:?}"
        );
        let still = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .expect("the original actor record must survive");
        assert_eq!(still.get_cn(), Some("first.zpr"));
    }

    /// `device.zpr_addr` present only in UNAUTHENTICATED claims is a self-asserted
    /// claim, not a grant: it never reaches the actor (libeval scrubs it), so the
    /// pool allocates as if it were absent.
    #[tokio::test]
    async fn granted_addr_unauthenticated_only_ignored_pool_allocates() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, Vec::new()),
                "claimer.zpr",
                vec![Attribute::builder(key::DEVICE_ZPR_ADDR).value("fd5a:5052:8888::16")],
                vec![Attribute::builder(key::CN).value("claimer.zpr")],
                0,
            )
            .await
            .expect("the connection authorizes; the self-asserted grant is ignored");

        let addr = *actor.get_zpr_addr().expect("pool must have allocated");
        assert_ne!(addr, "fd5a:5052:8888::16".parse::<IpAddr>().unwrap());
        assert!(
            asm.net_mgr.is_managed_address(&addr),
            "the address must come from a managed pool, got {addr}"
        );
    }

    /// An unparsable grant is an operator error to surface, not something to
    /// silently fall back to the pool on (plan Q1: reject loudly).
    #[tokio::test]
    async fn granted_addr_unparsable_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "granted.zpr",
                Vec::new(),
                granted_addr_claims("granted.zpr", "not-an-ip"),
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains(key::DEVICE_ZPR_ADDR)),
            "an unparsable grant must be rejected loudly, got {result:?}"
        );
    }

    /// A multi-valued grant is ambiguous — two trusted-service records, or a
    /// misconfigured store — and is rejected loudly for the same reason (plan Q1).
    #[tokio::test]
    async fn granted_addr_multivalued_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();

        let claims = vec![
            Attribute::builder(key::CN).value("granted.zpr"),
            Attribute::builder(key::DEVICE_ZPR_ADDR)
                .values(&["fd5a:5052:8888::17", "fd5a:5052:8888::18"]),
        ];

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, Vec::new()),
                "granted.zpr",
                Vec::new(),
                claims,
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains(key::DEVICE_ZPR_ADDR)),
            "a multi-valued grant must be rejected loudly, got {result:?}"
        );
    }

    /// PR #34 review (P1): TWO trusted services each granting a single — but
    /// different — `device.zpr_addr` is exactly as ambiguous as one service
    /// granting two, and must be rejected loudly (plan Q1). Without a
    /// pre-collapse check the actor's attribute map keeps only the
    /// last-inserted grant (Actor::add_attribute is a keyed insert), so the
    /// selected address would silently follow source iteration order.
    #[tokio::test]
    async fn granted_addr_conflicting_sources_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_services_policy(&[
            crate::test_helpers::TrustedServiceSpec {
                id: "addresses-a",
                api: "file",
                expiration_seconds: Some(3600),
                mappings: &["addr -> device.zpr_addr"],
                identity: &[],
                oidc: None,
                attr_query: None,
            },
            crate::test_helpers::TrustedServiceSpec {
                id: "addresses-b",
                api: "file",
                expiration_seconds: Some(3600),
                mappings: &["addr -> device.zpr_addr"],
                identity: &[],
                oidc: None,
                attr_query: None,
            },
        ]));
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> = vec![
            named_ts(
                "addresses-a",
                &[(key::DEVICE_ZPR_ADDR, "fd5a:5052:8888::20")],
            ),
            named_ts(
                "addresses-b",
                &[(key::DEVICE_ZPR_ADDR, "fd5a:5052:8888::21")],
            ),
        ];

        let result = cc
            .authorize_connection(
                asm,
                &snap(policy, stores),
                "granted.zpr",
                Vec::new(),
                vec![Attribute::builder(key::CN).value("granted.zpr")],
                0,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg))
                if msg.contains(key::DEVICE_ZPR_ADDR)),
            "conflicting grants from two trusted services must be rejected, got {result:?}"
        );
    }

    /// Two trusted services granting the SAME address agree — redundancy, not
    /// ambiguity — and the grant is honored. Guards the conflict check above
    /// against over-rejection.
    #[tokio::test]
    async fn granted_addr_agreeing_sources_accepted() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = policy_from_container(crate::test_helpers::make_trusted_services_policy(&[
            crate::test_helpers::TrustedServiceSpec {
                id: "addresses-a",
                api: "file",
                expiration_seconds: Some(3600),
                mappings: &["addr -> device.zpr_addr"],
                identity: &[],
                oidc: None,
                attr_query: None,
            },
            crate::test_helpers::TrustedServiceSpec {
                id: "addresses-b",
                api: "file",
                expiration_seconds: Some(3600),
                mappings: &["addr -> device.zpr_addr"],
                identity: &[],
                oidc: None,
                attr_query: None,
            },
        ]));
        let granted: IpAddr = "fd5a:5052:8888::22".parse().unwrap();
        let stores: Vec<Arc<dyn crate::trusted_services::TrustedServiceInterface>> = vec![
            named_ts(
                "addresses-a",
                &[(key::DEVICE_ZPR_ADDR, "fd5a:5052:8888::22")],
            ),
            named_ts(
                "addresses-b",
                &[(key::DEVICE_ZPR_ADDR, "fd5a:5052:8888::22")],
            ),
        ];

        let actor = cc
            .authorize_connection(
                asm.clone(),
                &snap(policy, stores),
                "granted.zpr",
                Vec::new(),
                vec![Attribute::builder(key::CN).value("granted.zpr")],
                0,
            )
            .await
            .expect("agreeing grants must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&granted));
        assert!(!asm.net_mgr.is_managed_address(&granted));
    }

    /// Re-authorization at the granted address keeps working: the live holder
    /// renewing its own session (`renewal_of == granted`) passes the proof arm,
    /// exactly as it does for a static pin.
    #[tokio::test]
    async fn granted_addr_renewal_at_same_addr_accepted() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cc = make_cc("test-vs");
        let policy = asm.policy_mgr.get_current();
        let addr: IpAddr = "fd5a:5052:8888::19".parse().unwrap();

        let holder =
            crate::test_helpers::make_adapter_actor_defexp("fd5a:5052:8888::19", "renewer.zpr");
        asm.actor_mgr
            .hack_add_adapter_no_node(&holder, &asm.policy_service_names())
            .await
            .expect("holder must persist");

        let actor = cc
            .authorize_connection_impl(
                asm.clone(),
                &snap(policy, Vec::new()),
                "renewer.zpr",
                Vec::new(),
                granted_addr_claims("renewer.zpr", "fd5a:5052:8888::19"),
                0,
                Some(addr),
            )
            .await
            .expect("a proven renewal at the granted address must authorize");

        assert_eq!(actor.get_zpr_addr(), Some(&addr));
    }

    /// The node path end to end: a join policy pinning an IN-POOL node address
    /// (the compiler would emit this for an in-pool `zpr_address` in the .zplc)
    /// is a join-time error, and the pool is untouched. The static path never
    /// reaches the node-path in-pool reservation (`undo.took_zpr_addr`), which
    /// stays for pool-ALLOCATED addresses (see vsapi_worker.rs).
    #[tokio::test]
    async fn authenticate_node_with_in_pool_pinned_address_rejected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let pinned = "fd5a:5052:90de:1::9";
        let addr: IpAddr = pinned.parse().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_pinned_node_join(
                cn,
                &pubkey_der,
                pinned,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let result = cc
            .authenticate_node(
                asm.clone(),
                challenge,
                timestamp,
                cn,
                &sig,
                addr,
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;

        assert!(
            matches!(&result, Err(ServiceError::AuthenticationFailed(msg)) if msg.contains("managed pool")),
            "an in-pool node pin must be a join-time error, got {result:?}"
        );
        assert!(
            asm.net_mgr.take_zpr_addr(&addr).is_ok(),
            "pool must be untouched by the rejection"
        );
    }

    /// The node path still accepts a pinned address outside the pools — the shape
    /// every pinned node in the tree uses (e.g. `fd5a:5052:90de::1`, note the
    /// missing `:1` — outside `fd5a:5052:90de:1::/64`).
    #[tokio::test]
    async fn authenticate_node_with_out_of_pool_pinned_address_accepted() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        let pinned = "fd5a:5052:90de::1";
        let addr: IpAddr = pinned.parse().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_pinned_node_join(
                cn,
                &pubkey_der,
                pinned,
            ))
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let actor = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                addr,
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await
            .expect("an out-of-pool pinned node address must authenticate");

        assert!(actor.is_node());
        assert_eq!(actor.get_zpr_addr(), Some(&addr));
    }

    // ---- bootstrap-key denylist on connect and renewal (zipline#136) ----

    /// Install a join-any policy carrying `cn`'s bootstrap key (no Node flag:
    /// SS-only connects yield adapters).
    async fn install_bootstrap_policy(asm: &Arc<Assembly>, cn: &str, pubkey_der: &[u8]) {
        asm.policy_mgr
            .update_policy_from_container_bytes(make_oidc_connect_policy(
                "google",
                OIDC_LIFETIME_SECS,
                OIDC_MAPPINGS,
                &["sub"],
                make_test_oidc_config(),
                &[(cn, pubkey_der)],
                &[],
            ))
            .await
            .unwrap();
    }

    /// A valid SS blob whose CN is on the bootstrap denylist is refused on
    /// CONNECT, even though `get_bootstrap_key_by_cn` still finds the key in
    /// policy — the denylist outranks a stale policy (zipline#136). The same
    /// blob connects fine before the CN is denylisted, so the refusal is the
    /// denylist's doing and nothing else's.
    #[tokio::test]
    async fn test_denylisted_cn_refused_on_connect() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");

        // Sanity: the key works before revocation.
        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        cc.authenticate_adapter_or_node(asm.clone(), req, &"fd5a:5052::1".parse().unwrap())
            .await
            .expect("the key must connect before revocation");

        // Revoke the CN; the policy still carries the key.
        crate::db::BootstrapDenylist::new(asm.state_db.clone())
            .add(cn)
            .await
            .unwrap();
        assert!(
            asm.policy_mgr
                .get_current()
                .get_bootstrap_key_by_cn(cn)
                .is_some(),
            "precondition: the stale policy still carries the key"
        );

        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        let result = cc
            .authenticate_adapter_or_node(asm, req, &"fd5a:5052::1".parse().unwrap())
            .await;
        assert!(
            result.is_err(),
            "a denylisted CN must not connect while a stale policy still carries its key"
        );
    }

    /// The node connect arm refuses a denylisted CN too — a compromised NODE
    /// key cannot re-join the fabric (zipline#136).
    #[tokio::test]
    async fn test_denylisted_cn_refused_on_node_connect() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-node.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .unwrap();
        crate::db::BootstrapDenylist::new(asm.state_db.clone())
            .add(cn)
            .await
            .unwrap();
        let cc = make_cc("test-vs");
        let challenge = b"my-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);

        let result = cc
            .authenticate_node(
                asm,
                challenge,
                timestamp,
                cn,
                &sig,
                "fd5a:5052::1".parse().unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "a denylisted node CN must not authenticate"
        );
    }

    /// The SS RENEWAL path refuses a denylisted CN with the generic
    /// credential rejection: a live actor whose key was revoked between
    /// renewals cannot renew, even though the pinned snapshot still carries
    /// the key (zipline#136).
    #[tokio::test]
    async fn test_denylisted_cn_refused_on_ss_renewal() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();
        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("fixture connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        let addr = *actor.get_zpr_addr().unwrap();

        // Sanity: the renewal works before revocation.
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![make_fresh_ss_blob(&privkey, cn)],
            &connect_via,
            None,
        )
        .await
        .expect("renewal must succeed before revocation");

        crate::db::BootstrapDenylist::new(asm.state_db.clone())
            .add(cn)
            .await
            .unwrap();

        let api = api_err(
            cc.reauthorize_actor(
                asm,
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &connect_via,
                None,
            )
            .await,
        );
        assert_auth_rejected(api);
    }

    /// PR #42 review (P1), the exact reported race: a revocation lands AFTER
    /// the connect path's early denylist check but BEFORE the caller persists
    /// the actor. The revocation's inline sweep finds no actor to revoke (it
    /// is not persisted yet), so without a post-persist gate the connect
    /// stands until the next periodic sweep tick. The post-persist re-check
    /// must refuse the admission and remove the just-persisted actor.
    #[tokio::test]
    async fn test_revocation_landing_before_persist_cannot_stay_connected() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();

        // 1. Authentication passes: the denylist is empty at check time.
        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("connect must authorize before the revocation lands");

        // 2. The revocation lands in the window before the caller persists:
        //    the admin add's inline sweep runs and finds nothing to revoke.
        crate::db::BootstrapDenylist::new(asm.state_db.clone())
            .add(cn)
            .await
            .unwrap();
        let stats = crate::auth_sweep::sweep_denylisted_actors(&asm).await;
        assert!(
            stats.revoked.is_empty(),
            "precondition: the inline sweep ran before the actor was persisted"
        );

        // 3. The caller persists, exactly as vsapi_worker::authorize_connect does.
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        let addr = *actor.get_zpr_addr().unwrap();

        // 4. The post-persist gate — the next thing authorize_connect runs —
        //    must catch the revocation: admission refused, actor removed, NOT
        //    left connected until the next periodic sweep.
        let res = cc.enforce_denylist_after_persist(&asm, &actor).await;
        assert!(
            res.is_err(),
            "the post-persist re-check must refuse a CN revoked mid-connect"
        );
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_none(),
            "the revoked actor must not stay connected until the periodic sweep"
        );
    }

    /// The post-persist re-check is a no-op for a clean CN: admission stands,
    /// the actor stays.
    #[tokio::test]
    async fn test_post_persist_recheck_passes_clean_cn() {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        let cn = "test-adapter.zpr";
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        install_bootstrap_policy(&asm, cn, &pubkey_der).await;
        let cc = make_cc("test-vs");
        let connect_via: IpAddr = "fd5a:5052::1".parse().unwrap();

        let req = make_connect_request(vec![make_valid_ss_blob(&privkey, cn)], cn);
        let actor = cc
            .authenticate_adapter_or_node(asm.clone(), req, &connect_via)
            .await
            .expect("connect must authorize");
        asm.actor_mgr
            .add_adapter_via_node(&actor, &connect_via, &Default::default())
            .await
            .expect("fixture actor must persist");
        let addr = *actor.get_zpr_addr().unwrap();

        cc.enforce_denylist_after_persist(&asm, &actor)
            .await
            .expect("a clean CN must pass the post-persist re-check");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_some(),
            "a clean actor must stay connected"
        );
    }

    /// zipline#167: the node-disconnect teardown must spare the visa service's
    /// own adapter, exactly as the other two teardown paths (`reset_node_state`
    /// in vsapi_worker.rs, `teardown_culled_nodes` in main.rs) already do. The
    /// VS keeps running across its docking node's disconnect; its actor record
    /// is re-created only at VS startup or when its adapter re-docks, so
    /// removing it here opens the re-register race: a restarted node that
    /// connects and calls register_vss before the VS adapter re-docks is denied
    /// SourceNotFound and torn down again.
    mod node_disconnect_reregister_race {
        use super::*;
        use crate::assembly::tests::new_assembly_for_tests;
        use crate::test_helpers::{make_actor_with_services_defexp, make_adapter_actor_defexp};
        use libeval::attribute::ROLE_NODE;
        use std::net::SocketAddr;
        use tokio::sync::mpsc;

        const NODE: &str = "fd5a:5052:3000::2";
        const OTHER_ADAPTER: &str = "fd5a:5052:4000::a";
        const VSS_PORT: u16 = 8183;
        /// The service id the test policy allows and the node actor provides,
        /// standing in for the compiled policy's VSS service.
        const VSS_SERVICE: &str = "vss";

        /// A node actor providing [VSS_SERVICE], with the substrate address a
        /// node record requires.
        fn make_vss_node_actor() -> libeval::actor::Actor {
            let mut node =
                make_actor_with_services_defexp(ROLE_NODE, NODE, &[VSS_SERVICE], "node-1");
            node.add_attribute(
                Attribute::builder(key::SUBSTRATE_ADDR).value("[fd5a:5052:3000::102]:1234"),
            )
            .unwrap();
            node
        }

        /// The focused fix assertion: a node disconnect cascade tears down the
        /// adapters docked through the node but spares the VS's own adapter,
        /// mirroring `test_reset_spares_vs_own_adapter` (vsapi_worker.rs) and
        /// `test_teardown_culled_nodes_spares_vs_own_adapter` (main.rs).
        #[tokio::test]
        async fn disconnect_spares_vs_own_adapter() {
            let asm = Arc::new(new_assembly_for_tests(None).await);
            let cc = make_cc("test-vs");
            let node_addr: IpAddr = NODE.parse().unwrap();
            let other_addr: IpAddr = OTHER_ADAPTER.parse().unwrap();
            let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);

            let node = make_vss_node_actor();
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            asm.actor_mgr
                .add_adapter_via_node(
                    &make_adapter_actor_defexp(OTHER_ADAPTER, "other-adapter"),
                    &node_addr,
                    &Default::default(),
                )
                .await
                .unwrap();
            // The VS's own adapter, docked at the node the way startup +
            // the authenticate handler record it.
            asm.actor_mgr
                .hack_add_adapter_no_node(
                    &make_adapter_actor_defexp(&vs_addr.to_string(), config::VS_CN),
                    &Default::default(),
                )
                .await
                .unwrap();
            asm.actor_mgr
                .hack_set_vs_docking_node(&node_addr)
                .await
                .unwrap();

            cc.disconnect(asm.clone(), node_addr, vsapi::DisconnectReason::LinkError)
                .await
                .unwrap();

            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&vs_addr)
                    .await
                    .unwrap()
                    .is_some(),
                "the VS's own actor record must survive its docking node's disconnect"
            );
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&other_addr)
                    .await
                    .unwrap()
                    .is_none(),
                "other adapters docked through the node are still torn down"
            );
        }

        /// The defect-1 ordering from the issue, without timing: node
        /// disconnects (tearing down the actors docked to it), then the
        /// restarted node re-authenticates and calls register_vss BEFORE the
        /// VS adapter re-docks. The VS→VSS visa mint must succeed — before
        /// the fix the disconnect cascade removed the VS's own actor, so
        /// `post_register_vss_visas_for_node` denied SourceNotFound
        /// ("has no actor and is not a registered AAA address",
        /// visareq_worker.rs) and the node was disconnected again.
        #[tokio::test]
        async fn register_vss_succeeds_when_node_wins_reregister_race() {
            use crate::db::PolicyRepo;
            use crate::policy_mgr::PolicyMgr;
            use crate::test_helpers::{FakeResolver, make_allow_policy_for_tcp_service};
            use crate::trusted_services::TrustedServicesMgr;
            use std::path::PathBuf;

            let (vreq_tx, vreq_rx) = mpsc::channel(8);
            let mut asm_inner = new_assembly_for_tests(Some(vreq_tx)).await;
            // A policy that allows the VS→VSS flow: TCP to VSS_PORT, provider
            // must provide VSS_SERVICE. No conditions.
            asm_inner.policy_mgr = PolicyMgr::new_with_initial_policy(
                make_allow_policy_for_tcp_service(VSS_SERVICE, VSS_PORT),
                PolicyRepo::new(asm_inner.state_db.clone()),
                Arc::new(FakeResolver::ip_only()),
                Arc::new(TrustedServicesMgr::new()),
                PathBuf::from("."),
                PathBuf::from("."),
                Arc::new(crate::db::ActorRepo::new(asm_inner.state_db.clone())),
                None,
                crate::config::VSConfig::default().get_vs_addr(),
            )
            .await
            .unwrap();
            let asm = Arc::new(asm_inner);
            let arena = tokio::spawn(crate::visareq_worker::launch_arena(asm.clone(), vreq_rx, 1));
            let cc = make_cc("test-vs");

            let node_addr: IpAddr = NODE.parse().unwrap();
            let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
            let node = make_vss_node_actor();

            // Initial session: node connected, VS adapter docked at it.
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            asm.topo_mgr.add_node(node_addr).unwrap();
            asm.actor_mgr
                .hack_add_adapter_no_node(
                    &make_adapter_actor_defexp(&vs_addr.to_string(), config::VS_CN),
                    &Default::default(),
                )
                .await
                .unwrap();
            asm.actor_mgr
                .hack_set_vs_docking_node(&node_addr)
                .await
                .unwrap();

            // The node goes away (LinkError disconnect, as in the issue log).
            cc.disconnect(asm.clone(), node_addr, vsapi::DisconnectReason::LinkError)
                .await
                .unwrap();

            // Operator concern (zipline#167 amendment): does the spared VS
            // actor's in-memory connection_table entry stay pointing at the
            // old node? No — `disconnect` ends in `actor_mgr.remove_node`,
            // whose retain() purges every connection-table entry pointing at
            // the departed node, the VS adapter's included. Nothing stale
            // survives; the authenticate handler re-docks the VS to whatever
            // node connects next.
            assert_eq!(
                asm.actor_mgr.get_docking_node_for_adapter(&vs_addr),
                None,
                "the VS adapter's connection-table entry must be purged by \
                 the node disconnect, not left pointing at the dead node"
            );

            // The restarted node re-authenticates FIRST — the VS adapter has
            // not re-docked. Mirror what the authenticate handler does
            // (vsapi_worker.rs): add the node, re-add it to the router, and
            // re-dock the VS adapter only if its actor record exists with no
            // docking node — in the broken state the record is gone, so
            // production skips the re-dock exactly like this does.
            asm.actor_mgr
                .add_node(&node, false, &Default::default())
                .await
                .unwrap();
            asm.topo_mgr.add_node(node_addr).unwrap();
            if let Some(vs_actor) = asm.actor_mgr.get_actor_by_zpr_addr(&vs_addr).await.unwrap() {
                if asm
                    .actor_mgr
                    .get_docking_node_for_actor(&vs_actor)
                    .is_none()
                {
                    asm.actor_mgr
                        .hack_set_vs_docking_node(&node_addr)
                        .await
                        .unwrap();
                }
            }

            // ... and registers its VSS before any VS-adapter re-dock.
            let vss_sockaddr = SocketAddr::new(node_addr, VSS_PORT);
            let visas = asm
                .visa_mgr
                .post_register_vss_visas_for_node(asm.clone(), &node_addr, &vss_sockaddr, None)
                .await
                .expect(
                    "register_vss must not depend on the VS adapter's re-auth \
                     winning the race against the restarted node",
                );
            assert!(
                !visas.is_empty(),
                "the VS→VSS visa must be minted for the re-registering node"
            );

            arena.abort();
        }
    }

    // ---- a Zode's own OIDC login/logout through reauthorize (zl-zipline#232) ----

    /// Address the node fixture requests (and, under its join-any node
    /// policy, is granted).
    const ZODE_ADDR: &str = "fd5a:5052::10";
    /// The VS-API session generation the fixture stamps on the node actor.
    const ZODE_SESSION: &str = "zode-session-1";
    /// Address of the actor providing the `files` service.
    const FILES_ADDR: &str = "fd5a:5052:4000::f";
    /// Port of the `files` service.
    const FILES_PORT: u16 = 8000;

    /// Policy for a Zode with OIDC login: the node CN's bootstrap key, one
    /// NODE join policy providing the `google` OIDC trusted service and the
    /// `files` service (TCP 8000), and one ALLOW rule for `files` whose
    /// client must carry `user.domain = example.com` -- a rule that requires a
    /// user attribute.
    fn make_zode_oidc_policy(cn: &str, pubkey_der: &[u8]) -> Vec<u8> {
        make_zode_oidc_policy_with_join(cn, pubkey_der, None)
    }

    /// As [make_zode_oidc_policy], but the node join policy may require one
    /// `(key, value)` attribute.
    fn make_zode_oidc_policy_with_join(
        cn: &str,
        pubkey_der: &[u8],
        join_condition: Option<(&str, &str)>,
    ) -> Vec<u8> {
        use zpr::policy::v1 as capnp_policy;
        use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType, TrustedService};
        use zpr::write_to::WriteTo;

        let jp = JoinPolicy {
            conditions: join_condition
                .map(|(k, v)| {
                    vec![
                        zpr::policy_types::Attribute::tuple(k)
                            .value(v)
                            .build()
                            .unwrap(),
                    ]
                })
                .unwrap_or_default(),
            flags: PFlags {
                node: true,
                ..Default::default()
            },
            provides: Some(vec![
                Service {
                    id: "google".to_string(),
                    endpoints: Vec::new(),
                    kind: ServiceType::Trusted("oidc".to_string()),
                },
                Service {
                    id: "files".to_string(),
                    endpoints: vec![Scope {
                        protocol: 6,
                        flag: None,
                        port: Some(FILES_PORT),
                        port_range: None,
                    }],
                    kind: ServiceType::Regular,
                },
            ]),
        };
        let record = TrustedService {
            service_id: "google".to_string(),
            expiration_seconds: OIDC_LIFETIME_SECS,
            returns_attrs: OIDC_MAPPINGS
                .iter()
                .map(|m| zpr::policy_types::parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: vec!["sub".to_string()],
            oidc: Some(make_test_oidc_config()),
            attr_query: None,
        };

        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(1);
            policy_bldr.set_metadata("");
            {
                let mut keys = policy_bldr.reborrow().init_keys(1);
                let mut k = keys.reborrow().get(0);
                k.set_id(cn);
                k.set_key_type(capnp_policy::KeyMaterialT::RsaPub);
                k.reborrow()
                    .init_key_allows(1)
                    .set(0, capnp_policy::KeyAllowance::Bootstrap);
                k.set_key_data(pubkey_der);
            }
            jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));
            record.write_to(&mut policy_bldr.reborrow().init_trusted_services(1).get(0));
            let mut coms = policy_bldr.reborrow().init_com_policies(1);
            let mut com = coms.reborrow().get(0);
            com.set_allow(true);
            com.set_service_id("files");
            {
                let mut scope = com.reborrow().init_scope(1).get(0);
                scope.set_protocol(6);
                scope.init_port().set_port_num(FILES_PORT);
            }
            let mut cond = com.reborrow().init_client_conds(1).get(0);
            cond.set_key("user.domain");
            cond.set_op(capnp_policy::AttrOp::Eq);
            cond.init_value(1).set(0, "example.com");
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    /// Fixture: an RSA-only Zode -- a node actor authenticated through
    /// `authenticate_node`, stamped with a VS-API session generation (as
    /// `VSHandleImpl::stamp_new_session` does) and persisted as a node --
    /// plus the `files` provider docked to it. Returns the node's address
    /// and bootstrap key.
    async fn zode_fixture(cn: &str) -> (Arc<Assembly>, ConnectionControl, IpAddr, PKey<Private>) {
        let asm = Arc::new(crate::assembly::tests::new_assembly_for_tests(None).await);
        zode_fixture_on(asm, cn).await
    }

    /// As [zode_fixture], on a caller-built assembly (e.g. one whose fake DB
    /// and event queue the test holds).
    async fn zode_fixture_on(
        asm: Arc<Assembly>,
        cn: &str,
    ) -> (Arc<Assembly>, ConnectionControl, IpAddr, PKey<Private>) {
        let (privkey, pubkey_der) = gen_rsa_test_keypair();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_zode_oidc_policy(cn, &pubkey_der))
            .await
            .expect("zode policy should install");
        let cc = make_cc("test-vs");
        let challenge = b"zode-challenge";
        let timestamp = unix_now();
        let sig = sign_node_challenge(&privkey, timestamp, cn, challenge);
        let mut actor = cc
            .authenticate_node(
                asm.clone(),
                challenge,
                timestamp,
                cn,
                &sig,
                ZODE_ADDR.parse().unwrap(),
                "192.0.2.10:5000".parse().unwrap(),
                None,
            )
            .await
            .expect("node authentication should succeed");
        actor
            .add_attribute(Attribute::builder(key::SESSION).value(ZODE_SESSION))
            .unwrap();
        let addr = *actor.get_zpr_addr().expect("node has an address");
        asm.actor_mgr
            .add_node(&actor, false, &Default::default())
            .await
            .expect("node must persist");
        let files = crate::test_helpers::make_actor_with_services_defexp(
            "adapter",
            FILES_ADDR,
            &["files"],
            "files.zpr",
        );
        asm.actor_mgr
            .add_adapter_via_node(&files, &addr, &Default::default())
            .await
            .expect("files provider must persist");
        (asm, cc, addr, privkey)
    }

    /// Login blobs for the Zode: a fresh device blob plus an OIDC blob whose
    /// token (claims from `claims`) carries `nonce`, the blob echoing it.
    fn zode_login_blobs(
        privkey: &PKey<Private>,
        cn: &str,
        nonce: &str,
        mut claims: serde_json::Value,
    ) -> Vec<AuthBlob> {
        claims["nonce"] = json!(nonce);
        vec![
            make_fresh_ss_blob(privkey, cn),
            AuthBlob::Oidc(OidcBlob {
                issuer: OIDC_ISSUER.to_string(),
                id_token: mint_signed(claims),
                nonce: nonce.to_string(),
            }),
        ]
    }

    /// Mint a login nonce for the fixture Zode's current session.
    fn mint_zode_nonce(cc: &ConnectionControl, addr: IpAddr) -> String {
        cc.login_nonces
            .mint(addr, ZODE_SESSION, SystemTime::now())
            .expect("mint must succeed")
            .0
    }

    /// Log the fixture Zode in (gain) and return the renewed actor.
    async fn zode_login(
        asm: &Arc<Assembly>,
        cc: &ConnectionControl,
        addr: IpAddr,
        privkey: &PKey<Private>,
        cn: &str,
    ) -> Actor {
        let nonce = mint_zode_nonce(cc, addr);
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            zode_login_blobs(privkey, cn, &nonce, oidc_base_claims()),
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("a node's own login must succeed")
    }

    /// Log the fixture Zode out (drop) and return the renewed actor.
    async fn zode_logout(
        asm: &Arc<Assembly>,
        cc: &ConnectionControl,
        addr: IpAddr,
        privkey: &PKey<Private>,
        cn: &str,
    ) -> Actor {
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![make_fresh_ss_blob(privkey, cn)],
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("a node's own logout must succeed")
    }

    /// Whether `actor` carries any attribute in the `user.` namespace.
    fn has_user_attrs(actor: &Actor) -> bool {
        actor.attrs_iter().any(|a| a.get_key().starts_with("user."))
    }

    /// Policy decision for the Zode reaching `files` (TCP 8000).
    async fn zode_may_reach_files(asm: &Arc<Assembly>, addr: IpAddr) -> bool {
        let node = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let files = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&FILES_ADDR.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        let pdesc =
            zpr::vsapi_types::PacketDesc::new_tcp(&addr.to_string(), FILES_ADDR, 40000, FILES_PORT)
                .unwrap();
        let ectx = EvalContext::new(asm.policy_mgr.get_current_snapshot().policy_arc());
        let result = ectx.eval_request(&node, &files, &pdesc).unwrap();
        !matches!(result, libeval::eval_result::PartialEvalResult::Deny(_))
    }

    /// Test 1: an RSA-only node logs in through reauthorize: it gains the
    /// user authority and the mapped subject; its address and device
    /// authority are unchanged.
    #[tokio::test]
    async fn test_reauthorize_node_self_gains_oidc_namespace() {
        let cn = "zode-a.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let renewed = zode_login(&asm, &cc, addr, &privkey, cn).await;

        assert_eq!(renewed.get_zpr_addr(), Some(&addr));
        assert_eq!(
            renewed
                .get_attribute(key::USER_AUTHORITY)
                .expect("login must add the user authority")
                .get_single_value()
                .unwrap(),
            "google"
        );
        assert_eq!(
            renewed
                .get_attribute("user.oidc-subject")
                .expect("login must add the mapped subject")
                .get_single_value()
                .unwrap(),
            OIDC_SUB
        );
        assert!(renewed.get_attribute(key::DEVICE_AUTHORITY).is_some());
        assert!(renewed.is_node(), "the actor stays a node");
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.get_attribute(key::USER_AUTHORITY).is_some(),
            "login must persist"
        );
    }

    /// Test 2: a logged-in node logs out with a device-only reauthorize:
    /// every `user.*` attribute and the session anchors are gone; the device
    /// authority stays.
    #[tokio::test]
    async fn test_reauthorize_node_self_drops_oidc_namespace() {
        let cn = "zode-b.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let svc = asm
            .policy_mgr
            .get_current_snapshot()
            .oidc_service_by_id("google")
            .unwrap();
        assert!(
            svc.session_anchors(&addr.to_string()).is_some(),
            "login records anchors"
        );

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;

        assert!(
            !has_user_attrs(&renewed),
            "logout must strip every user attribute"
        );
        assert!(renewed.get_attribute(key::DEVICE_AUTHORITY).is_some());
        assert_eq!(renewed.get_zpr_addr(), Some(&addr));
        assert!(
            svc.session_anchors(&addr.to_string()).is_none(),
            "logout must forget the session anchors"
        );
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(!has_user_attrs(&stored), "logout must persist");
    }

    /// Test 3 (the issue's acceptance): RSA-only -> RSA+OIDC -> RSA-only; a
    /// rule requiring a user attribute matches only in the middle state.
    #[tokio::test]
    async fn test_node_user_attribute_rule_matches_only_while_logged_in() {
        let cn = "zode-c.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        assert!(!zode_may_reach_files(&asm, addr).await, "RSA-only: denied");
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        assert!(zode_may_reach_files(&asm, addr).await, "RSA+OIDC: allowed");
        zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(
            !zode_may_reach_files(&asm, addr).await,
            "RSA-only again: denied"
        );
    }

    /// Test 4: a `user.*` attribute vended under another source (an attribute
    /// service keyed on the user subject) does not survive logout.
    #[tokio::test]
    async fn test_reauthorize_node_drop_removes_ts_user_attrs_keyed_on_sub() {
        let cn = "zode-d.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let mut actor = zode_login(&asm, &cc, addr, &privkey, cn).await;
        actor
            .add_attribute(
                AttributeSource::new("hr")
                    .builder("user.groups")
                    .expires_in(Duration::from_secs(600))
                    .value("engineering"),
            )
            .unwrap();
        asm.actor_mgr
            .update_actor(&actor, &Default::default())
            .await
            .unwrap();

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(renewed.get_attribute("user.groups").is_none());
        assert!(!has_user_attrs(&renewed));
    }

    /// Create a live visa held by the Zode for the Zode -> `files` flow.
    async fn create_zode_files_visa(asm: &Arc<Assembly>, addr: IpAddr) -> u64 {
        use libeval::eval_result::{Direction, Hit};
        use libeval::route::Route;
        let pdesc =
            zpr::vsapi_types::PacketDesc::new_tcp(&addr.to_string(), FILES_ADDR, 40000, FILES_PORT)
                .unwrap();
        asm.visa_mgr
            .create_visa(
                asm,
                &addr,
                &pdesc,
                &Hit::new_no_signal(0, Direction::Forward),
                &Route::new_direct(addr.into()),
                "",
                0,
                0,
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await
            .expect("visa must be created")
            .visa
            .issuer_id
    }

    /// Test 5: a visa the user attribute allowed is marked for revocation by
    /// the logout's visa sweep.
    #[tokio::test]
    async fn test_reauthorize_node_drop_revokes_user_visas() {
        let cn = "zode-e.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let id = create_zode_files_visa(&asm, addr).await;
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap()
                .is_empty()
        );

        zode_logout(&asm, &cc, addr, &privkey, cn).await;

        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap(),
            vec![id],
            "logout must revoke the visa that needed the user attribute"
        );
    }

    /// Counterpart of test 5: a renewal that does not change the namespace
    /// set runs no visa sweep (the visa, which policy would now deny, is left
    /// alone).
    #[tokio::test]
    async fn test_reauthorize_node_device_only_renewal_runs_no_sweep() {
        let cn = "zode-f.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        create_zode_files_visa(&asm, addr).await;
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![make_fresh_ss_blob(&privkey, cn)],
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("device-only renewal must succeed");
        assert!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Test 6: a valid nonce with a bad token signature is rejected with the
    /// connect arm's classification, and the nonce is spent anyway.
    #[tokio::test]
    async fn test_reauthorize_node_gain_bad_token_rejected() {
        let cn = "zode-g.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        let mut blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        if let AuthBlob::Oidc(ob) = &mut blobs[1] {
            ob.id_token.push('x'); // corrupt the signature
        }
        let api = api_err(
            cc.reauthorize_actor(asm.clone(), addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::InvalidSignature),
            "got {:?}",
            api.code
        );
        assert!(
            !cc.login_nonces
                .consume(&nonce, addr, ZODE_SESSION, SystemTime::now()),
            "the nonce is spent even when the login fails"
        );
    }

    /// Test 7: a logged-in node cannot switch to another user in place; the
    /// OIDC blob goes to the renewal arm, which demands the same subject.
    #[tokio::test]
    async fn test_reauthorize_node_cannot_switch_user_in_place() {
        let cn = "zode-h.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        let mut claims = oidc_base_claims();
        claims["sub"] = json!("another-user");
        claims["iat"] = json!(unix_now() + 1);
        let blobs = zode_login_blobs(&privkey, cn, &nonce, claims);
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 8: a node cannot change the namespaces of an adapter docked to
    /// it: adapters keep the exact-set rule.
    #[tokio::test]
    async fn test_reauthorize_node_cannot_change_docked_adapter_namespaces() {
        let cn = "ss-docked.zpr";
        let (asm, cc, actor, connect_via, privkey, _pubkey_der) = ss_reauth_fixture(cn).await;
        let addr = *actor.get_zpr_addr().unwrap();
        let nonce = cc
            .login_nonces
            .mint(connect_via, ZODE_SESSION, SystemTime::now())
            .unwrap()
            .0;
        let blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        let api = api_err(
            cc.reauthorize_actor(asm, addr, blobs, &connect_via, None)
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "got {:?}",
            api.code
        );
    }

    /// Test 9: an OIDC blob without the device blob is a set mismatch: the
    /// device RSA proof is mandatory for a node's login.
    #[tokio::test]
    async fn test_reauthorize_node_oidc_without_ss_param_error() {
        let cn = "zode-i.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        let mut blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        let oidc_only = vec![blobs.remove(1)];
        let api = api_err(
            cc.reauthorize_actor(asm, addr, oidc_only, &addr, Some(ZODE_SESSION))
                .await,
        );
        assert!(
            matches!(api.code, ErrorCode::ParamError),
            "got {:?}",
            api.code
        );
    }

    /// Test 11: replay -- a token and nonce that logged in once cannot log
    /// in again (after a logout).
    #[tokio::test]
    async fn test_login_nonce_replay_rejected() {
        let cn = "zode-j.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims()),
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("first login succeeds");
        zode_logout(&asm, &cc, addr, &privkey, cn).await;

        // The same token (same claims, same nonce) presented again.
        let replay = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, replay, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 12: a nonce minted for another actor is rejected (and spent).
    #[tokio::test]
    async fn test_login_nonce_wrong_actor_rejected() {
        let cn = "zode-k.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let other: IpAddr = "fd5a:5052::99".parse().unwrap();
        let nonce = cc
            .login_nonces
            .mint(other, ZODE_SESSION, SystemTime::now())
            .unwrap()
            .0;
        let blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
        assert!(
            !cc.login_nonces
                .consume(&nonce, other, ZODE_SESSION, SystemTime::now())
        );
    }

    /// Test 13: a nonce minted under an earlier VS-API session (the node has
    /// re-authenticated since) is rejected.
    #[tokio::test]
    async fn test_login_nonce_wrong_session_rejected() {
        let cn = "zode-l.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = cc
            .login_nonces
            .mint(addr, "an-earlier-session", SystemTime::now())
            .unwrap()
            .0;
        let blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 14 (reauthorize level; the exact boundary is a store test): an
    /// expired nonce is rejected.
    #[tokio::test]
    async fn test_login_nonce_expired_rejected() {
        let cn = "zode-m.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let long_ago = SystemTime::now() - Duration::from_secs(config::LOGIN_NONCE_TTL_SECS + 60);
        let nonce = cc
            .login_nonces
            .mint(addr, ZODE_SESSION, long_ago)
            .unwrap()
            .0;
        let blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 15: a nonce presented once with a bad token cannot be reused with
    /// a good one.
    #[tokio::test]
    async fn test_login_nonce_reused_after_failed_login_rejected() {
        let cn = "zode-n.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        let mut bad = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        if let AuthBlob::Oidc(ob) = &mut bad[1] {
            ob.id_token.push('x');
        }
        let _ = cc
            .reauthorize_actor(asm.clone(), addr, bad, &addr, Some(ZODE_SESSION))
            .await;
        let good = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, good, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 16: a nonce the visa service never issued -- the node minted its
    /// own, as on the adapter connect path -- is rejected.
    #[tokio::test]
    async fn test_login_nonce_not_issued_rejected() {
        let cn = "zode-o.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let blobs = zode_login_blobs(&privkey, cn, "node-minted-nonce", oidc_base_claims());
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
    }

    /// Test 18: login and logout keep the node's VS-API session generation,
    /// so the node's live handle (`node_is_live`) keeps working.
    #[tokio::test]
    async fn test_reauthorize_node_keeps_session_generation() {
        let cn = "zode-p.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        fn session_of(a: &Actor) -> Option<String> {
            a.get_attribute(key::SESSION)
                .and_then(|s| s.get_single_value().ok())
                .map(|s| s.to_string())
        }
        let after_login = zode_login(&asm, &cc, addr, &privkey, cn).await;
        assert_eq!(session_of(&after_login).as_deref(), Some(ZODE_SESSION));
        let after_logout = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert_eq!(session_of(&after_logout).as_deref(), Some(ZODE_SESSION));
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session_of(&stored).as_deref(), Some(ZODE_SESSION));
    }

    /// Review fix (#63, Codex P1): a logged-in node whose OIDC provider was
    /// removed from policy must still lose its user namespace on a
    /// device-only self-renewal; the stale `user.*` attributes must not
    /// survive and the user visa must be revoked.
    #[tokio::test]
    async fn test_reauthorize_node_drop_after_provider_removed() {
        let cn = "zode-q.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let id = create_zode_files_visa(&asm, addr).await;

        // A new policy: same bootstrap key and node join, no OIDC service.
        let pubkey_der = privkey.public_key_to_der().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .expect("policy without the provider installs");

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(
            !has_user_attrs(&renewed),
            "a stale OIDC user namespace must be dropped"
        );
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&addr)
                .await
                .unwrap(),
            vec![id],
            "the stale user's visa must be revoked"
        );
    }

    /// Review fix (#63, Codex P1): two concurrent logins on the same
    /// device-only node must not both succeed (the second would silently
    /// switch users); the persisted subject must match the recorded anchors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_node_logins_serialize() {
        let cn = "zode-r.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let cc = Arc::new(cc);
        let login_as = |sub: &'static str| {
            let (asm, cc, privkey) = (asm.clone(), cc.clone(), privkey.clone());
            async move {
                let nonce = mint_zode_nonce(&cc, addr);
                let mut claims = oidc_base_claims();
                claims["sub"] = json!(sub);
                let blobs = zode_login_blobs(&privkey, cn, &nonce, claims);
                cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                    .await
            }
        };
        let (a, b) = tokio::join!(
            tokio::spawn(login_as("user-a")),
            tokio::spawn(login_as("user-b"))
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(
            a.is_ok() as u8 + b.is_ok() as u8,
            1,
            "exactly one concurrent login may succeed: a={:?} b={:?}",
            a.as_ref().err(),
            b.as_ref().err()
        );
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let stored_sub = stored
            .get_attribute("user.oidc-subject")
            .unwrap()
            .get_single_value()
            .unwrap()
            .to_string();
        let svc = asm
            .policy_mgr
            .get_current_snapshot()
            .oidc_service_by_id("google")
            .unwrap();
        assert_eq!(
            svc.session_anchors(&addr.to_string()).unwrap().sub,
            stored_sub,
            "the recorded anchors must belong to the persisted user"
        );
    }

    /// Review fix (#63, Codex P1), deterministic half: a node's
    /// self-renewal does not start while another one holds the
    /// self-renewal lock, and completes once it is released.
    #[tokio::test]
    async fn test_self_reauth_waits_for_serialization_lock() {
        let cn = "zode-s.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let cc = Arc::new(cc);
        let guard = asm.policy_mgr.node_commit_lock.lock().await;
        let task = tokio::spawn({
            let (asm, cc) = (asm.clone(), cc.clone());
            let blobs = vec![make_fresh_ss_blob(&privkey, cn)];
            async move {
                cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "a self-renewal must wait for the lock");
        drop(guard);
        task.await
            .unwrap()
            .expect("the renewal completes once the lock is free");
    }

    /// Review fix (#63, Copilot): once a request is classified as a login,
    /// the nonce is spent before the device proof is checked, so a login that
    /// fails on its device blob cannot retry the same nonce.
    #[tokio::test]
    async fn test_reauthorize_node_gain_spends_nonce_even_when_device_proof_fails() {
        let cn = "zode-t.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let nonce = mint_zode_nonce(&cc, addr);
        let (other_key, _) = gen_rsa_test_keypair();
        let mut blobs = zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims());
        blobs[0] = make_fresh_ss_blob(&other_key, cn); // wrong device key
        assert_auth_rejected(api_err(
            cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                .await,
        ));
        assert!(
            !cc.login_nonces
                .consume(&nonce, addr, ZODE_SESSION, SystemTime::now()),
            "the nonce must be spent even though the device proof failed"
        );
    }

    /// Review fix (#63, Copilot): a self-renewal is refused when the node
    /// re-authenticated (new `zpr.session`) while it was in flight, so it can
    /// never write the old session back over the new one.
    #[tokio::test]
    async fn test_self_renewal_refused_when_session_changed() {
        let cn = "zode-u.zpr";
        let (asm, _cc, addr, _privkey) = zode_fixture(cn).await;
        assert_eq!(
            recheck_before_commit(&asm, &addr, Some(ZODE_SESSION), None)
                .await
                .unwrap(),
            CommitRecheck::Current
        );
        let mut stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        stored
            .add_attribute(Attribute::builder(key::SESSION).value("a-newer-session"))
            .unwrap();
        asm.actor_mgr
            .update_actor(&stored, &Default::default())
            .await
            .unwrap();
        assert_auth_rejected(api_err(
            recheck_before_commit(&asm, &addr, Some(ZODE_SESSION), None).await,
        ));
    }

    /// Review fix (#63, Copilot): when policy now admits the node as a node
    /// only with a user attribute, a logout keeps the node role (fixed at
    /// connect) instead of failing on a role change and leaving the login in
    /// place; services are recomputed for the node role.
    #[tokio::test]
    async fn test_reauthorize_node_logout_keeps_node_role() {
        let cn = "zode-v.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let pubkey_der = privkey.public_key_to_der().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_zode_oidc_policy_with_join(
                cn,
                &pubkey_der,
                Some(("user.domain", "example.com")),
            ))
            .await
            .expect("policy whose node join needs a user attribute installs");

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(renewed.is_node(), "a logout must not change the node role");
        assert!(!has_user_attrs(&renewed));
        assert!(
            renewed.services_iter().next().is_none(),
            "no node join matches any more, so the node provides nothing"
        );
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(!has_user_attrs(&stored), "the logout must persist");
    }

    /// Review fix (#63, Codex P2): a self-renewal from a stale handle -- its
    /// session is no longer the stored one, because the node re-authenticated
    /// -- is refused, so it cannot log out a user of the new session.
    #[tokio::test]
    async fn test_self_renewal_from_stale_handle_refused() {
        let cn = "zode-w.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let api = api_err(
            cc.reauthorize_actor(
                asm.clone(),
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &addr,
                Some("an-older-session"),
            )
            .await,
        );
        assert_auth_rejected(api);
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(
            has_user_attrs(&stored),
            "the new session's login must survive"
        );
    }

    /// Review fix (#63 round 4, Codex P1): an attribute refresh of a node
    /// copy loaded before a logout must not write the pre-logout attributes
    /// back over the logout.
    #[tokio::test]
    async fn test_stale_refresh_cannot_undo_logout() {
        let cn = "zode-x.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let stale = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(has_user_attrs(&stale));
        zode_logout(&asm, &cc, addr, &privkey, cn).await;

        // The stale copy's refresh re-fetched a user attribute it held.
        let mut refreshed = stale.clone();
        refreshed
            .add_attribute(
                AttributeSource::new("hr")
                    .builder("user.groups")
                    .expires_in(Duration::from_secs(600))
                    .value("engineering"),
            )
            .unwrap();
        let result = crate::actor_attributes::commit_refresh(&asm, &stale, &mut refreshed).await;
        assert!(
            matches!(result, Ok(false)),
            "a stale refresh must not commit (the node was re-authorized), got {result:?}"
        );
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !has_user_attrs(&stored),
            "the logout must survive the stale refresh"
        );

        // A refresh of the current copy still persists.
        let current = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let mut refreshed = current.clone();
        assert!(
            crate::actor_attributes::commit_refresh(&asm, &current, &mut refreshed)
                .await
                .expect("a refresh of the current copy persists"),
            "the current copy commits"
        );
    }

    /// Review fix (#63 round 5, Codex P1): when the logout's visa sweep
    /// cannot record a revocation, the logout still persists but the work is
    /// handed to the event manager (an attribute-change reconcile) instead of
    /// being dropped.
    #[tokio::test]
    async fn test_incomplete_logout_sweep_is_requeued() {
        let (asm, mut event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let cn = "zode-y.zpr";
        let (asm, cc, addr, privkey) = zode_fixture_on(Arc::new(asm), cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        create_zode_files_visa(&asm, addr).await;
        while event_rx.try_recv().is_ok() {} // drain events so far

        // Visa writes fail from here on: the sweep cannot record the revoke.
        // ApplyThenError: the visa write errors, while actor writes (atomic
        // pipelines, which fail only on Reject) are unaffected.
        db.set_set_ex_fault(crate::db::FaultMode::ApplyThenError);
        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(!has_user_attrs(&renewed), "the logout itself persists");

        let mut requeued = false;
        while let Ok(evt) = event_rx.try_recv() {
            requeued |= matches!(evt, crate::event_mgr::VsEvent::TrustedServiceChange);
        }
        assert!(
            requeued,
            "an incomplete sweep must hand its work to the event manager"
        );
    }

    /// Review fix (#63 round 6, Codex P1): a disconnect removes the actor
    /// record under the self-renewal lock, so it cannot land between a
    /// self-renewal's session check and its write (which would recreate the
    /// removed actor).
    #[tokio::test]
    async fn test_disconnect_waits_for_self_renewal_lock() {
        let cn = "zode-z.zpr";
        let (asm, cc, addr, _privkey) = zode_fixture(cn).await;
        let cc = Arc::new(cc);
        let guard = asm.policy_mgr.node_commit_lock.lock().await;
        let task = tokio::spawn({
            let (asm, cc) = (asm.clone(), cc.clone());
            async move {
                cc.disconnect(asm, addr, vsapi::DisconnectReason::Admin)
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "the disconnect must wait for the lock");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_some(),
            "the actor record must still be there while the lock is held"
        );
        drop(guard);
        task.await
            .unwrap()
            .expect("the disconnect completes once the lock is free");
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The commit-time recheck reports a moved policy generation (#63 audit),
    /// and the refusal it maps to for a login or renewal is
    /// `temporarilyUnavailable`.
    #[tokio::test]
    async fn test_recheck_before_commit_reports_moved_generation() {
        let cn = "zode-aa.zpr";
        let (asm, _cc, addr, privkey) = zode_fixture(cn).await;
        let psnap = asm.policy_mgr.get_current_snapshot();
        assert_eq!(
            recheck_before_commit(&asm, &addr, Some(ZODE_SESSION), Some(psnap.vinst()))
                .await
                .unwrap(),
            CommitRecheck::Current
        );
        let pubkey_der = privkey.public_key_to_der().unwrap();
        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_node_join_policy(cn, &pubkey_der))
            .await
            .expect("a new policy installs");
        assert_eq!(
            recheck_before_commit(&asm, &addr, Some(ZODE_SESSION), Some(psnap.vinst()))
                .await
                .unwrap(),
            CommitRecheck::PolicyMoved
        );
        let api = api_err::<()>(Err(policy_moved_error()));
        assert!(matches!(api.code, ErrorCode::TemporarilyUnavailable));
    }

    /// Review fix (#63 round 8, Codex P1): a logout persists even when the
    /// policy re-run fails (a trusted service is down): the stored actor loses
    /// every `user.*` attribute and keeps its node role.
    #[tokio::test]
    async fn test_logout_persists_when_enrichment_fails() {
        let cn = "zode-ab.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;

        let current = asm.policy_mgr.get_current_snapshot();
        let mut services = current.trusted_services().to_vec();
        services.push(Arc::new(FailingTrustedService));
        asm.policy_mgr
            .set_current_snapshot_for_tests(&PolicySnapshot::for_tests(
                current.policy_arc(),
                services,
            ));

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(!has_user_attrs(&renewed));
        assert!(renewed.is_node());
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !has_user_attrs(&stored),
            "the logout must persist despite the failure"
        );
    }

    /// Review fix (#63 round 9, Copilot): the outage fallback carries over
    /// only internal-source attributes, so a subject-keyed trusted-service
    /// attribute mapped outside `user.*` does not survive the logout either.
    #[tokio::test]
    async fn test_outage_logout_drops_non_user_ts_attributes() {
        let cn = "zode-ac.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let mut actor = zode_login(&asm, &cc, addr, &privkey, cn).await;
        actor
            .add_attribute(
                AttributeSource::new("hr")
                    .builder("device.clearance")
                    .expires_in(Duration::from_secs(600))
                    .value("secret"),
            )
            .unwrap();
        asm.actor_mgr
            .update_actor(&actor, &Default::default())
            .await
            .unwrap();

        let current = asm.policy_mgr.get_current_snapshot();
        let mut services = current.trusted_services().to_vec();
        services.push(Arc::new(FailingTrustedService));
        asm.policy_mgr
            .set_current_snapshot_for_tests(&PolicySnapshot::for_tests(
                current.policy_arc(),
                services,
            ));

        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(renewed.get_attribute("device.clearance").is_none());
        assert!(
            renewed.get_attribute(key::DEVICE_AUTHORITY).is_some(),
            "the device authority stays"
        );
        assert!(renewed.get_cn().is_some(), "the authenticated CN stays");
        assert!(
            renewed
                .identity_keys_iter()
                .all(|k| renewed.get_attribute(k).is_some()),
            "every identity key must name a surviving attribute"
        );
    }

    /// A trusted service that starts a policy install (re-installing the Zode
    /// policy, which advances the generation) the first time it is queried --
    /// i.e. in the middle of a reauthorize's enrichment -- and vends
    /// `device.clearance` from its own source. The install runs as its own
    /// task; since policy publication takes the node commit lock, it must wait
    /// until the in-flight commit has written (#63 review, operator decision).
    struct PolicyInstallingTs {
        asm: std::sync::Mutex<Option<Arc<Assembly>>>,
        next_policy: Vec<u8>,
        install: std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for PolicyInstallingTs {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            let asm = self.asm.lock().unwrap().take();
            if let Some(asm) = asm {
                let bytes = self.next_policy.clone();
                let handle = tokio::spawn(async move {
                    asm.policy_mgr
                        .update_policy_from_container_bytes(bytes)
                        .await
                        .expect("the mid-flight policy installs")
                });
                // Give the install every chance to run before the commit.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                *self.install.lock().unwrap() = Some(handle);
            }
            Ok(vec![
                AttributeSource::new("installer")
                    .builder("device.clearance")
                    .expires_in(Duration::from_secs(600))
                    .value("secret"),
            ])
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "installer"
        }
    }

    /// Arm a policy install for the next enrichment on `asm`; returns the hook
    /// so the test can await the install afterwards.
    fn arm_mid_flight_install(
        asm: &Arc<Assembly>,
        cn: &str,
        privkey: &PKey<Private>,
    ) -> Arc<PolicyInstallingTs> {
        let pubkey_der = privkey.public_key_to_der().unwrap();
        let hook = Arc::new(PolicyInstallingTs {
            asm: std::sync::Mutex::new(Some(asm.clone())),
            next_policy: make_zode_oidc_policy(cn, &pubkey_der),
            install: std::sync::Mutex::new(None),
        });
        asm.policy_mgr.add_trusted_service_for_tests(hook.clone());
        hook
    }

    /// Await the install the hook started; returns its generation.
    async fn finish_mid_flight_install(hook: &PolicyInstallingTs) -> u64 {
        let handle = hook
            .install
            .lock()
            .unwrap()
            .take()
            .expect("the hook started an install");
        handle.await.expect("the install task completes")
    }

    /// The `zpr.vinst` stored on the actor at `addr`.
    async fn stored_vinst(asm: &Arc<Assembly>, addr: IpAddr) -> Option<u64> {
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        actor_prepared_vinst(&stored)
    }

    /// #63 review (operator decision): a policy install that starts during a
    /// node's device-only renewal waits for the renewal's commit, so the
    /// renewal commits under the generation it was authorized under and the
    /// install lands afterwards (its re-authentication obligation then covers
    /// the node).
    #[tokio::test]
    async fn test_install_waits_for_in_flight_renewal_commit() {
        let cn = "zode-ad.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let before = asm.policy_mgr.get_current_snapshot().vinst();
        let hook = arm_mid_flight_install(&asm, cn, &privkey);
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![make_fresh_ss_blob(&privkey, cn)],
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("the renewal commits; the install waits for it");
        assert_eq!(
            asm.policy_mgr.get_current_snapshot().vinst(),
            before,
            "not yet published"
        );
        let after = finish_mid_flight_install(&hook).await;
        assert!(after > before);
        assert_eq!(stored_vinst(&asm, addr).await, Some(before));
    }

    /// #63 review (operator decision): a login whose enrichment overlaps a
    /// policy install commits first; the install publishes after it.
    #[tokio::test]
    async fn test_install_waits_for_in_flight_login_commit() {
        let cn = "zode-af.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let before = asm.policy_mgr.get_current_snapshot().vinst();
        let hook = arm_mid_flight_install(&asm, cn, &privkey);
        let nonce = mint_zode_nonce(&cc, addr);
        let renewed = cc
            .reauthorize_actor(
                asm.clone(),
                addr,
                zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims()),
                &addr,
                Some(ZODE_SESSION),
            )
            .await
            .expect("the login commits; the install waits for it");
        assert!(renewed.get_attribute(key::USER_AUTHORITY).is_some());
        assert!(finish_mid_flight_install(&hook).await > before);
        assert_eq!(stored_vinst(&asm, addr).await, Some(before));
    }

    /// #63 review (operator decision): a logout whose enrichment overlaps a
    /// policy install commits its re-authorized actor (no fallback needed),
    /// with a fresh identity token; the install publishes after it.
    #[tokio::test]
    async fn test_install_waits_for_in_flight_logout_commit() {
        let cn = "zode-ag.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let logged_in = zode_login(&asm, &cc, addr, &privkey, cn).await;
        let before = asm.policy_mgr.get_current_snapshot().vinst();
        let hook = arm_mid_flight_install(&asm, cn, &privkey);
        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(!has_user_attrs(&renewed));
        assert!(renewed.is_node());
        let ident = |a: &Actor| {
            a.get_attribute(ATTR_KEY_VS_IDENT)
                .and_then(|i| i.get_single_value().ok())
                .map(|s| s.to_string())
        };
        assert_ne!(
            ident(&renewed),
            ident(&logged_in),
            "the identity token is re-minted"
        );
        assert!(finish_mid_flight_install(&hook).await > before);
        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert!(!has_user_attrs(&stored));
    }

    /// #63 review (operator decision): a policy install blocks while a node
    /// commit holds the node commit lock, and publishes once it is released.
    #[tokio::test]
    async fn test_policy_install_blocks_until_node_commit_finishes() {
        let cn = "zode-aj.zpr";
        let (asm, _cc, _addr, privkey) = zode_fixture(cn).await;
        let before = asm.policy_mgr.get_current_snapshot().vinst();
        let pubkey_der = privkey.public_key_to_der().unwrap();
        let guard = asm.policy_mgr.node_commit_lock.lock().await;
        let task = tokio::spawn({
            let asm = asm.clone();
            let bytes = make_zode_oidc_policy(cn, &pubkey_der);
            async move {
                asm.policy_mgr
                    .update_policy_from_container_bytes(bytes)
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !task.is_finished(),
            "the install must wait for the node commit"
        );
        assert_eq!(asm.policy_mgr.get_current_snapshot().vinst(), before);
        drop(guard);
        task.await
            .unwrap()
            .expect("the install publishes once the lock is free");
        assert!(asm.policy_mgr.get_current_snapshot().vinst() > before);
    }

    /// Review fix (#63 round 10, Copilot): a fallback logout (enrichment
    /// failed) drops trusted-service attributes it could not re-fetch, so it
    /// also forgets the actor's source revisions: the next refresh re-fetches,
    /// and while the source is down the request is indeterminate (denied)
    /// instead of proceeding as if, say, `device.blocked` were absent.
    #[tokio::test]
    async fn test_fallback_logout_forces_reenrichment() {
        use std::sync::atomic::Ordering;
        let cn = "zode-ae.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        let ts = crate::test_helpers::register_ts(&asm, &[("device.blocked", "true")]);
        let mut stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        crate::actor_attributes::refresh_and_persist_actor(&asm, &mut stored)
            .await
            .expect("a healthy refresh records the source revision");

        ts.fail.store(true, Ordering::SeqCst);
        let current = asm.policy_mgr.get_current_snapshot();
        let mut services = current.trusted_services().to_vec();
        services.push(Arc::new(FailingTrustedService));
        asm.policy_mgr
            .set_current_snapshot_for_tests(&PolicySnapshot::for_tests(
                current.policy_arc(),
                services,
            ));
        let renewed = zode_logout(&asm, &cc, addr, &privkey, cn).await;
        assert!(renewed.get_attribute("device.blocked").is_none());

        let mut after = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let result = crate::actor_attributes::refresh_and_persist_actor(&asm, &mut after).await;
        assert!(
            matches!(result, Err(ServiceError::AttributesIndeterminate(_))),
            "with the source still down the next request must be indeterminate, got {result:?}"
        );
    }

    /// #63 audit, after the merge with #224: a node's attribute refresh
    /// commits under the topology lock and the node commit lock. A reconnect
    /// (new session, same identity token) is merged into -- #224's
    /// `commit_refresh` applies only the changed attributes onto the actor as
    /// stored -- while a re-authorization (identity token re-minted, so
    /// `same_actor` fails) commits nothing. A policy install cannot land mid-commit: it publishes under
    /// both locks.
    #[tokio::test]
    async fn test_refresh_commit_merges_reconnect_refuses_reauthorization() {
        let cn = "zode-ah.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let copy = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();

        // A reconnect (open) writes a new session since the copy was read.
        let mut stored = copy.clone();
        stored
            .add_attribute(Attribute::builder(key::SESSION).value("a-newer-session"))
            .unwrap();
        asm.actor_mgr
            .update_actor(&stored, &Default::default())
            .await
            .unwrap();
        let mut refreshed = copy.clone();
        assert!(
            crate::actor_attributes::commit_refresh(&asm, &copy, &mut refreshed)
                .await
                .expect("a reconnect is merged into")
        );
        let session = |a: &Actor| {
            a.get_attribute(key::SESSION)
                .and_then(|s| s.get_single_value().ok())
                .map(|s| s.to_string())
        };
        assert_eq!(session(&refreshed).as_deref(), Some("a-newer-session"));

        // A re-authorization (a device-only renewal re-mints the token).
        let read_before = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let mut ss = read_before.clone();
        ss.add_attribute(Attribute::builder(key::SESSION).value(ZODE_SESSION))
            .unwrap();
        asm.actor_mgr
            .update_actor(&ss, &Default::default())
            .await
            .unwrap();
        cc.reauthorize_actor(
            asm.clone(),
            addr,
            vec![make_fresh_ss_blob(&privkey, cn)],
            &addr,
            Some(ZODE_SESSION),
        )
        .await
        .expect("a device-only renewal");
        let mut refreshed = ss.clone();
        let result = crate::actor_attributes::commit_refresh(&asm, &ss, &mut refreshed).await;
        assert!(
            matches!(result, Ok(false)),
            "a refresh read before a re-authorization must not commit, got {result:?}"
        );
    }

    /// #63 review: a fallback logout invalidates the actor's source revisions
    /// without resetting their generations, so a refresh pass that captured a
    /// generation before the logout cannot record its (pre-logout) revision
    /// afterwards.
    #[tokio::test]
    async fn test_fallback_logout_blocks_in_flight_revision_commit() {
        let cn = "zode-ai.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        crate::test_helpers::register_ts(&asm, &[("device.blocked", "true")]);
        let mut stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        crate::actor_attributes::refresh_and_persist_actor(&asm, &mut stored)
            .await
            .expect("a healthy refresh records the source revision");
        // An in-flight refresh pass captures its generation now ...
        let captured = asm.ts_mgr.invalidation_generation(&addr, "hr");

        // ... then a logout persists without re-enrichment.
        let current = asm.policy_mgr.get_current_snapshot();
        let mut services = current.trusted_services().to_vec();
        services.push(Arc::new(FailingTrustedService));
        asm.policy_mgr
            .set_current_snapshot_for_tests(&PolicySnapshot::for_tests(
                current.policy_arc(),
                services,
            ));
        zode_logout(&asm, &cc, addr, &privkey, cn).await;

        assert!(
            !asm.ts_mgr
                .record_revision_at_generation(&addr, "hr", 1, captured),
            "a commit captured before the logout must be refused"
        );
        assert!(
            asm.ts_mgr
                .stale_sources_for_actor(&addr)
                .iter()
                .any(|(source, _)| source == "hr"),
            "the source stays stale until a post-logout pass commits"
        );
    }

    /// #63 review (Copilot): a logout whose actor write fails part-way (the
    /// attributes may already be committed) still hands its follow-up -- the
    /// visa reconciliation -- to the event manager before returning the error.
    #[tokio::test]
    async fn test_failed_logout_write_queues_reconcile() {
        let (asm, mut event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let cn = "zode-ak.zpr";
        let (asm, cc, addr, privkey) = zode_fixture_on(Arc::new(asm), cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        while event_rx.try_recv().is_ok() {}

        db.set_hset_fault(crate::db::FaultMode::Reject);
        let result = cc
            .reauthorize_actor(
                asm.clone(),
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &addr,
                Some(ZODE_SESSION),
            )
            .await;
        assert!(result.is_err(), "the failed write is reported");
        let mut requeued = false;
        while let Ok(evt) = event_rx.try_recv() {
            requeued |= matches!(evt, crate::event_mgr::VsEvent::TrustedServiceChange);
        }
        assert!(
            requeued,
            "a failed logout write must still queue the reconcile"
        );
    }

    /// #63 review (Copilot): a failed namespace-change write releases the
    /// node commit lock before it awaits the (bounded) event queue, so a
    /// full queue whose worker needs that lock cannot deadlock.
    #[tokio::test]
    async fn test_failed_write_releases_lock_before_queueing() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let cn = "zode-al.zpr";
        let (asm, cc, addr, privkey) = zode_fixture_on(Arc::new(asm), cn).await;
        zode_login(&asm, &cc, addr, &privkey, cn).await;
        // Fill the event queue; nothing drains it, so the next send waits.
        while asm
            .event_mgr
            .try_record_event_for_tests(crate::event_mgr::VsEvent::TrustedServiceChange)
        {}
        db.set_hset_fault(crate::db::FaultMode::Reject);
        let cc = Arc::new(cc);
        let task = tokio::spawn({
            let (asm, cc) = (asm.clone(), cc.clone());
            let blobs = vec![make_fresh_ss_blob(&privkey, cn)];
            async move {
                cc.reauthorize_actor(asm, addr, blobs, &addr, Some(ZODE_SESSION))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!task.is_finished(), "the send waits on the full queue");
        assert!(
            asm.policy_mgr.node_commit_lock.try_lock().is_ok(),
            "the node commit lock must be free while the send waits"
        );
        task.abort();
    }

    /// #63 review (Codex P1): a login whose actor write fails part-way never
    /// leaves an active login behind: the visa service rolls back to the
    /// pre-login actor or, if that fails too, disconnects the node.
    #[tokio::test]
    async fn test_failed_login_write_leaves_no_active_login() {
        let (asm, _event_rx, db) =
            crate::assembly::tests::new_assembly_with_event_rx_and_db(None).await;
        let cn = "zode-am.zpr";
        let (asm, cc, addr, privkey) = zode_fixture_on(Arc::new(asm), cn).await;
        db.set_hset_fault(crate::db::FaultMode::ApplyThenError);
        let nonce = mint_zode_nonce(&cc, addr);
        let result = cc
            .reauthorize_actor(
                asm.clone(),
                addr,
                zode_login_blobs(&privkey, cn, &nonce, oidc_base_claims()),
                &addr,
                Some(ZODE_SESSION),
            )
            .await;
        assert!(result.is_err(), "the failed write is reported");
        let stored = asm.actor_mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
        assert!(
            stored.as_ref().is_none_or(|a| !has_user_attrs(a)),
            "no stored actor may hold the failed login's user attributes"
        );
    }

    /// A trusted service that, the first time it is queried -- during a
    /// renewal's attribute fetch, while the renewal holds the node commit lock
    /// -- denylists `cn` and starts a task that takes the topology lock and
    /// then waits for the node commit lock, the order a policy install or a
    /// refresh commit uses. It gives that task time to take the topology lock
    /// before the renewal continues.
    struct LockOrderProbeTs {
        asm: std::sync::Mutex<Option<Arc<Assembly>>>,
        cn: String,
        task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for LockOrderProbeTs {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            let asm = self.asm.lock().unwrap().take();
            if let Some(asm) = asm {
                crate::db::BootstrapDenylist::new(asm.state_db.clone())
                    .add(&self.cn)
                    .await
                    .unwrap();
                let task = tokio::spawn(async move {
                    let _topology = asm.topo_mgr.ops().await;
                    let _commit = asm.policy_mgr.node_commit_lock.lock().await;
                });
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                *self.task.lock().unwrap() = Some(task);
            }
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            "lock-order-probe"
        }
    }

    /// #224 merge: the lock order is topology lock, then node commit lock. A
    /// renewal holding the node commit lock that must then disconnect (its CN
    /// was denylisted mid-renewal) releases the commit lock first, so it
    /// cannot deadlock with a task that holds the topology lock and waits for
    /// the commit lock. Taking the topology lock under the commit lock (the
    /// wrong order) deadlocks here, which the timeout turns into a failure.
    #[tokio::test]
    async fn test_lock_order_no_deadlock_on_post_persist_disconnect() {
        let cn = "zode-an.zpr";
        let (asm, cc, addr, privkey) = zode_fixture(cn).await;
        let probe = Arc::new(LockOrderProbeTs {
            asm: std::sync::Mutex::new(Some(asm.clone())),
            cn: cn.to_string(),
            task: std::sync::Mutex::new(None),
        });
        asm.policy_mgr.add_trusted_service_for_tests(probe.clone());

        let renewal = tokio::time::timeout(
            Duration::from_secs(5),
            cc.reauthorize_actor(
                asm.clone(),
                addr,
                vec![make_fresh_ss_blob(&privkey, cn)],
                &addr,
                Some(ZODE_SESSION),
            ),
        )
        .await
        .expect("no deadlock between the topology lock and the node commit lock");
        assert_auth_rejected(api_err(renewal));
        let task = probe.task.lock().unwrap().take().expect("the probe ran");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the topology-then-commit task completes")
            .unwrap();
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_none(),
            "the revoked node was disconnected"
        );
    }

    /// #224 merge: a node's refresh commit waits for the node commit lock
    /// (inside the topology guard), so it cannot land between a self-renewal's
    /// read and its write.
    #[tokio::test]
    async fn test_node_refresh_commit_waits_for_node_commit_lock() {
        let cn = "zode-ao.zpr";
        let (asm, _cc, addr, _privkey) = zode_fixture(cn).await;
        let copy = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        let guard = asm.policy_mgr.node_commit_lock.lock().await;
        let task = tokio::spawn({
            let asm = asm.clone();
            async move {
                let mut refreshed = copy.clone();
                crate::actor_attributes::commit_refresh(&asm, &copy, &mut refreshed).await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !task.is_finished(),
            "the refresh commit must wait for the node commit lock"
        );
        drop(guard);
        assert!(
            task.await
                .unwrap()
                .expect("the commit completes once the lock is free")
        );
    }

    /// The namespace-change decision table (vs.capnp "Re-Authorization").
    #[test]
    fn test_classify_user_namespace_change() {
        use UserNamespaceChange::*;
        // (ss, oidc, device, backed, any_user_authority, self) -> result
        let cases = [
            ((true, false, true, false, false, false), Some(Keep)),
            ((true, true, true, true, true, false), Some(Keep)),
            ((true, true, true, false, false, false), None), // adapter gain
            ((true, false, true, true, true, false), None),  // adapter drop
            ((true, true, true, false, false, true), Some(Gain)),
            ((true, false, true, true, true, true), Some(Drop)),
            ((true, false, true, false, true, true), Some(Drop)), // stale or TS-derived authority
            ((true, false, true, false, true, false), Some(Keep)), // adapter: TS-derived kept
            ((false, true, true, false, false, true), None),      // no device blob
            ((true, true, true, false, true, true), None),        // TS-derived authority
            ((false, true, false, true, true, false), Some(Keep)), // OIDC-only adapter renewal
            ((true, true, false, true, true, false), None),       // device never gained
        ];
        for ((ss, oidc, dev, backed, any_user, self_r), want) in cases {
            assert_eq!(
                classify_user_namespace_change(ss, oidc, dev, backed, any_user, self_r),
                want,
                "case ss={ss} oidc={oidc} device={dev} backed={backed} any_user={any_user} self={self_r}"
            );
        }
    }
}
