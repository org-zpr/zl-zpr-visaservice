//! The policy manager is conceived as the one true place where the running visa service
//! can obtain the current policy.  Policy can be updated asynchronously by administrators.
//! A policy update can have many ripple effects on the running visa serivce: visas may no
//! longer be valid, connected actors may be forced to disconnect, services may be taken
//! down, node connections may change etc.
//!
//! The idea here is that clients of the policy will request it with [PolicyMgr::get_current]
//! use it as quickly as possible and then drop it.  In the case of a policy update there
//! should be few processes holding on to an old policy for long.
//!
//! The [libeval::policy::Policy] is designed to be easily cloned (as it is in an Arc) and
//! accessible by concurrent threads.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use libeval::policy::{LinkDescription, Peer, Policy};

use zpr::policy_types::{NetAddr, NetworkHost, PolicyContainerBytes};

use crate::config;
use crate::db;
use crate::error::{ResolverError, ServiceError, StoreError, TopologyError};
use crate::loaded_policy::LoadedPolicy;
use crate::logging::targets::MAIN;
use crate::oidc::{KeySource, OidcTrustedService, ProxyFuture, ProxyResolver};
use crate::trusted_services::{
    TrustedServiceDefinition, TrustedServiceInterface, TrustedServicesMgr, build_services,
    trusted_service_definitions,
};

/// Abstracts DNS hostname resolution so it can be swapped out in tests.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve `host` to a `SocketAddr` on the given `port`.
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError>;
}

/// The identifier of the "current policy" shared over the admin API.
/// This will be reworked in the future where we may have multiple policies, not all
/// active, including policies for different domains.
pub const DEFAULT_POLICY_ID: u64 = 0;

/// A peer link resolved from policy topology: the link id paired with the peer's
/// DNS-resolved substrate address. This is all the policy manager computes; the
/// wire-level vsapi `Link` struct is built from it only when a topology message
/// is actually sent (see `vss_worker::vss_do_set_topology`).
pub type ResolvedPeer = (String, SocketAddr);

/// Combined policy, source container, and resolved topology — swapped atomically
/// as a unit so the three can never drift apart.
struct PolicyState {
    policy: Arc<Policy>,
    container: PolicyContainerBytes,
    resolved_peers_by_node: HashMap<IpAddr, Vec<ResolvedPeer>>,
    /// Attribute stores for the trusted services this policy declares. Republished to
    /// `ts_mgr` on every successful swap so the stores can never outlive their policy.
    trusted_services: Vec<Arc<dyn TrustedServiceInterface>>,
    /// The typed OIDC subset of `trusted_services` (each store is in both), so the
    /// manager can serve `oidc_service_for_issuer` lookups for the connect path.
    oidc_services: Vec<Arc<OidcTrustedService>>,
    /// The declarations `trusted_services` was built from. Carried alongside the stores so
    /// the next policy can be compared against them and reuse the stores when unchanged.
    ts_definitions: Vec<TrustedServiceDefinition>,
    /// Periodic JWKS refresher tasks, one per OIDC store this state owns,
    /// keyed by service id (zipline#19). A store carried over to the next
    /// state takes its running refresher with it (the handle moves maps); the
    /// handles still here when the state drops belong to retired stores and
    /// are aborted so no orphan task keeps fetching forever.
    oidc_refreshers: std::sync::Mutex<HashMap<String, JoinHandle<()>>>,
}

impl Drop for PolicyState {
    fn drop(&mut self) {
        for (_, handle) in self
            .oidc_refreshers
            .lock()
            .expect("oidc_refreshers lock poisoned")
            .drain()
        {
            handle.abort();
        }
    }
}

/// A fully validated policy state that has not yet taken over refresher
/// ownership (PR #7 review). [`PolicyMgr::build_state`] produces one without
/// touching the live state or spawning any task, so dropping a candidate on a
/// later failure (e.g. the DB write) is completely side-effect free: live
/// refreshers keep running under their current owner and nothing was spawned
/// for the rejected policy. [`Self::commit`] is the infallible ownership
/// step, run only once every fallible step has succeeded.
struct CandidateState {
    state: PolicyState,
    /// Service ids of reused OIDC stores whose running refresher must move
    /// over from the previous state at commit.
    carried_over: Vec<String>,
    /// Freshly built OIDC stores' key sources, awaiting a refresher spawn at
    /// commit (when a refresh period is configured).
    to_spawn: Vec<(String, Arc<KeySource>)>,
}

impl CandidateState {
    /// Take ownership of the refresher tasks and return the finished state:
    /// carried-over handles move out of `previous` (the same live state the
    /// candidate was built against), and each newly built store spawns its
    /// refresher — or warns once when the period is disabled. Infallible by
    /// design; callers run it only after construction and persistence have
    /// both succeeded.
    fn commit(self, previous: Option<&PolicyState>, oidc_refresh: Option<Duration>) -> PolicyState {
        let mut handles: HashMap<String, JoinHandle<()>> = HashMap::new();
        if let Some(prev) = previous {
            let mut prev_handles = prev
                .oidc_refreshers
                .lock()
                .expect("oidc_refreshers lock poisoned");
            for id in &self.carried_over {
                if let Some(handle) = prev_handles.remove(id) {
                    handles.insert(id.clone(), handle);
                }
            }
        }
        for (id, keys) in self.to_spawn {
            match oidc_refresh {
                Some(period) => {
                    handles.insert(id, keys.spawn_refresher(period));
                }
                None => {
                    // Operator decision on zipline#19: 0/absent means
                    // disabled, loudly — key rotation is then picked up only
                    // by connect-path misses.
                    warn!(
                        target: MAIN,
                        "periodic JWKS refresh disabled (oidc_refresh_seconds is 0 \
                         or unset): provider '{id}' will refresh keys only on \
                         connect-path misses"
                    );
                }
            }
        }
        *self
            .state
            .oidc_refreshers
            .lock()
            .expect("oidc_refreshers lock poisoned") = handles;
        self.state
    }
}

pub struct PolicyMgr {
    state: ArcSwap<PolicyState>,
    repo: db::PolicyRepo,
    /// Serializes concurrent policy updates; reads remain lock-free via ArcSwap.
    update_lock: tokio::sync::Mutex<()>,
    resolver: PolicyResolver,
    ts_mgr: Arc<TrustedServicesMgr>,
    /// Directory holding the `<service-id>.json` files for `api=file` trusted services.
    file_ts_dir: PathBuf,
    /// Directory holding the `<service-id>.token` bearer-token files for
    /// `api = "zpr-attr/1"` trusted services (config `ts_secrets_dir`).
    ts_secrets_dir: PathBuf,
    /// Actor database handle backing the JWKS proxy resolver: each proxied
    /// refresh re-resolves the actor currently providing the policy-named
    /// `jwks_proxy_service` (zipline#19).
    actor_repo: Arc<db::ActorRepo>,
    /// Period between JWKS refreshes for OIDC stores; `None` disables the
    /// periodic refresher (config `oidc_refresh_seconds` of 0 or unset).
    oidc_refresh: Option<Duration>,
}

/// A consistent, owned snapshot of policy, source container, and resolved topology,
/// all captured in a single atomic load. Cheap to clone (a refcount bump) and safe to
/// hold across awaits: it pins the holder to one coherent view until dropped, so policy
/// and links can never drift apart for the duration of a multi-step operation (e.g.
/// topology revalidation after a policy update).
#[derive(Clone)]
pub struct PolicySnapshot(Arc<PolicyState>);

impl PolicySnapshot {
    /// The policy captured by this snapshot.
    pub fn policy(&self) -> &Policy {
        &self.0.policy
    }

    /// A clone of the policy Arc captured by this snapshot.
    pub fn policy_arc(&self) -> Arc<Policy> {
        self.0.policy.clone()
    }

    /// The version instance number of the captured policy.
    pub fn vinst(&self) -> u64 {
        self.policy().vinst()
    }

    /// A clone of the source container bytes captured by this snapshot.
    pub fn container(&self) -> PolicyContainerBytes {
        self.0.container.clone()
    }

    /// The resolved peers for `node` as captured by this snapshot.
    pub fn resolved_peers_for_node(&self, node: &IpAddr) -> Vec<ResolvedPeer> {
        self.0
            .resolved_peers_by_node
            .get(node)
            .cloned()
            .unwrap_or_default()
    }

    /// The attribute stores for the trusted services this snapshot's policy
    /// declares. Connect-path authorization queries these — not the live
    /// `ts_mgr` list — so an in-flight authentication is pinned to one
    /// coherent policy/store pair (PR #6 review).
    pub fn trusted_services(&self) -> &[Arc<dyn TrustedServiceInterface>] {
        &self.0.trusted_services
    }

    /// The OIDC trusted service pinned to `issuer` in this snapshot, when its
    /// policy declares one. The connect path resolves an incoming token's
    /// provider through the snapshot rather than the live manager so
    /// validation and authorization cannot straddle a policy update
    /// (PR #6 review).
    pub fn oidc_service_for_issuer(&self, issuer: &str) -> Option<Arc<OidcTrustedService>> {
        self.0
            .oidc_services
            .iter()
            .find(|service| service.issuer() == issuer)
            .cloned()
    }

    /// Whether this snapshot's policy declares an OIDC trusted service with
    /// id `id`. The reauth exact-set check resolves whether an actor's
    /// `user.zpr.authority` is credential-backed through this (PR #40 review,
    /// Codex P1): an authority synthesized from trusted-service enrichment
    /// names a file or attribute-service store, which no OIDC declaration matches, so no user
    /// blob is demanded — or accepted — for it.
    pub fn declares_oidc_service(&self, id: &str) -> bool {
        self.oidc_service_by_id(id).is_some()
    }

    /// The OIDC trusted service with id `id` in this snapshot, if its policy
    /// declares one. A node's logout (zl-zipline#232) uses it to forget the
    /// session anchors the dropped `user.zpr.authority` named.
    pub fn oidc_service_by_id(&self, id: &str) -> Option<Arc<OidcTrustedService>> {
        self.0
            .oidc_services
            .iter()
            .find(|service| service.id() == id)
            .cloned()
    }

    /// Build a snapshot directly from a policy and its stores, for unit tests
    /// that drive `authorize_connection` without a full policy install.
    #[cfg(test)]
    pub fn for_tests(
        policy: Arc<Policy>,
        trusted_services: Vec<Arc<dyn TrustedServiceInterface>>,
    ) -> Self {
        PolicySnapshot(Arc::new(PolicyState {
            policy,
            container: PolicyContainerBytes::from(Vec::new()),
            resolved_peers_by_node: HashMap::new(),
            trusted_services,
            oidc_services: Vec::new(),
            ts_definitions: Vec::new(),
            oidc_refreshers: std::sync::Mutex::new(HashMap::new()),
        }))
    }

    /// The abort handle of the periodic JWKS refresher this snapshot's state
    /// owns for `service_id`, when one is running. Test-only observability
    /// for the refresher lifecycle (zipline#19).
    #[cfg(test)]
    pub(crate) fn oidc_refresher_abort_handle(
        &self,
        service_id: &str,
    ) -> Option<tokio::task::AbortHandle> {
        self.0
            .oidc_refreshers
            .lock()
            .expect("oidc_refreshers lock poisoned")
            .get(service_id)
            .map(|handle| handle.abort_handle())
    }

    /// Dispatches to [Policy::describe_link] on the captured policy.
    ///
    /// ## Errors
    /// - `TopologyError::LinkNotFound` if there is no link between `node_a` and
    ///   `node_b` in the captured policy.
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        self.policy()
            .describe_link(node_a, node_b)
            .map_err(|_| TopologyError::LinkNotFound(format!("{node_a} <-> {node_b}")).into())
    }
}

/// Production resolver that uses the OS/system resolver via `tokio::net::lookup_host`.
pub struct SystemResolver;

#[async_trait]
impl DnsResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError> {
        let mut addrs = tokio::net::lookup_host((host, port)).await?;
        addrs
            .next()
            .ok_or_else(|| ResolverError::NoAddresses(host.to_string()))
    }
}

impl PolicyMgr {
    /// Create a new policy manager, initializing it with the given initial policy.
    /// This will store the initial policy into the database if not already present.
    ///
    /// Note that policy is written to DB for backup purposes. It is kept in memory
    /// here for general access by rest of visa service.
    ///
    /// This also runs DNS lookups on all the peerings in the policy. Will throw a
    /// [ResolverError] if any of the peerings fail to resolve.  We may revisit this
    /// later if we decide to eventually pass DNS names down to nodes.
    pub async fn new_with_initial_policy(
        container_bytes: Vec<u8>,
        repo: db::PolicyRepo,
        resolver: Arc<dyn DnsResolver>,
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
        ts_secrets_dir: PathBuf,
        actor_repo: Arc<db::ActorRepo>,
        oidc_refresh: Option<Duration>,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager");

        // Decode and assign the initial vinst while the policy Arc
        // is still uniquely held (before build_state clones it).
        let mut loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &config::POLICY_MIN_VERSION,
        )?;
        // Derive the vinst from any persisted identifier so it is monotonic
        // across restarts. Same container (matching phash) is a plain restart:
        // reuse its vinst. A different container (or a fresh DB) is a new policy
        // install and gets the next vinst.
        let ident = repo.get_current_identifier().await?;
        let vinst = match &ident {
            Some(i) if i.phash == loaded.hash_container_bytes()? => i.vinst,
            Some(i) => i.vinst.checked_add(1).ok_or_else(|| {
                StoreError::InvalidData("persisted vinst is u64::MAX; cannot advance".into())
            })?,
            None => 1,
        };
        loaded.set_vinst(vinst);

        let resolver = PolicyResolver::new(resolver);

        // Resolve topology before persisting so a policy that cannot initialize is never
        // stored as the current policy. build_state borrows `loaded`, leaving it
        // available for the post-resolution persist below. Refreshers are spawned
        // by commit only after the persist succeeds, so a failed write leaves no task.
        let candidate = Self::build_state(
            &resolver,
            &loaded,
            &file_ts_dir,
            &ts_secrets_dir,
            &actor_repo,
            None,
        )
        .await?;
        repo.set_current_policy(&loaded, false).await?;
        let state = candidate.commit(None, oidc_refresh);

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(Self::from_state(
            state,
            repo,
            resolver,
            ts_mgr,
            file_ts_dir,
            ts_secrets_dir,
            actor_repo,
            oidc_refresh,
        ))
    }

    /// Create a new policy manager, initializing it with the current policy in
    /// the database. If there is no policy in the database, this will return an
    /// error.  This will also run DNS on the policy so if there are any DNS
    /// issues with the peer hostnames (or if DNS is required and is not
    /// working) this will fail.
    ///
    /// If the policy contains hostnames and DNS is not working, this returns an
    /// error.
    pub async fn new_from_state(
        repo: db::PolicyRepo,
        resolver: Arc<dyn DnsResolver>,
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
        ts_secrets_dir: PathBuf,
        actor_repo: Arc<db::ActorRepo>,
        oidc_refresh: Option<Duration>,
    ) -> Result<Self, ServiceError> {
        debug!(target: MAIN, "initializing policy manager from state");
        let mut loaded = repo
            .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
            .await?;
        // Restore the persisted vinst.
        let ident = repo.get_current_identifier().await?;
        loaded.set_vinst(ident.map_or(1, |i| i.vinst));
        {
            let policy = loaded.policy();
            info!(target: MAIN, "loaded policy from state version:{}, created:{}", policy.get_version().unwrap_or(0),
                policy.get_created().unwrap_or("unknown").to_string());
        }
        let resolver = PolicyResolver::new(resolver);
        // A trusted service the policy declares but that cannot be configured (e.g. its
        // attribute file is missing) fails startup; the error names the service and file.
        let candidate = Self::build_state(
            &resolver,
            &loaded,
            &file_ts_dir,
            &ts_secrets_dir,
            &actor_repo,
            None,
        )
        .await?;
        let state = candidate.commit(None, oidc_refresh);

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(Self::from_state(
            state,
            repo,
            resolver,
            ts_mgr,
            file_ts_dir,
            ts_secrets_dir,
            actor_repo,
            oidc_refresh,
        ))
    }

    /// This is the placeholder "update policy" function. It only replaces the current policy
    /// with a new current policy. Once the visa service is running this is how policy is
    /// updated.
    pub async fn update_policy_from_container_bytes(
        &self,
        policy_container_bytes: Vec<u8>,
    ) -> Result<u64, ServiceError> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(policy_container_bytes),
            &config::POLICY_MIN_VERSION,
        )?;
        self.update_policy_internal(loaded).await
    }

    /// Build the atomically-swapped policy state after resolving all policy topology.
    ///
    /// Intentionally performs only validation/state construction: it does not write the
    /// DB, store into `self.state`, spawn refresher tasks, or mutate the live state.
    /// This keeps failed DNS/topology/store resolution from leaking partial policy
    /// state — a candidate that is dropped on a later failure has no side effects to
    /// undo (PR #7 review). Borrows `loaded` (cloning only the `Arc<Policy>`
    /// and the `Bytes`-backed container — both refcount bumps) so the caller can still
    /// persist it after resolution succeeds.
    ///
    /// `previous` is the currently live state, when there is one, and is used only to
    /// carry unchanged trusted-service stores forward. Refresher ownership transfer
    /// and fresh spawns are deferred to [`CandidateState::commit`], which the caller
    /// runs only after every remaining fallible step (DB write) has succeeded.
    async fn build_state(
        resolver: &PolicyResolver,
        loaded: &LoadedPolicy,
        file_ts_dir: &Path,
        ts_secrets_dir: &Path,
        actor_repo: &Arc<db::ActorRepo>,
        previous: Option<&PolicyState>,
    ) -> Result<CandidateState, ServiceError> {
        let policy = loaded.policy();
        let resolved_peers_by_node = resolver.resolve_topology(&policy).await?;
        let ts_definitions = trusted_service_definitions(&policy)?;
        // Stores are matched per service definition: a declaration identical to
        // the live one keeps its store (and revision, and any cached/admitted
        // data — an OIDC store rebuilt with an empty admitted cache would strip
        // connected users' attributes until reconnect), while changed or new
        // declarations build fresh. Matching is keyed on the service id, never
        // on definition-vector equality: `Policy::list_services` iterates a
        // HashMap, so vector order is meaningless across installs. The
        // definition's equality key includes the proxy port captured from the
        // `jwks_proxy_service` declaration, so a policy that changes only the
        // proxy service rebuilds the OIDC store whose resolver pinned that
        // port (PR #7 review, P1).
        //
        // A new OIDC store whose policy names a `jwks_proxy_service` gets an
        // ActorDb-backed proxy resolver (zipline#19): every refresh re-resolves
        // the actor currently providing that service and pairs it with the
        // port pinned by this policy's `Service.endpoints` scope. No provider
        // connected (yet) is not an error — the refresh fails "proxy not
        // reachable" and the seed/last-good keys keep serving (C3 stale
        // tolerance) until one connects.
        let mut trusted_services = Vec::with_capacity(ts_definitions.len());
        let mut oidc_services = Vec::new();
        let mut carried_over = Vec::new();
        let mut to_spawn = Vec::new();
        for definition in &ts_definitions {
            let reusable = previous.and_then(|prev| {
                prev.ts_definitions
                    .iter()
                    .find(|prev_def| prev_def.id() == definition.id())
                    .filter(|prev_def| *prev_def == definition)
                    .and_then(|_| {
                        prev.trusted_services
                            .iter()
                            .find(|store| store.get_source_id() == definition.id())
                            .cloned()
                    })
            });
            match reusable {
                Some(store) => {
                    if let Some(prev) = previous {
                        if let Some(oidc) = prev
                            .oidc_services
                            .iter()
                            .find(|oidc| oidc.get_source_id() == definition.id())
                        {
                            // The store moves to the new state unchanged, and
                            // its running refresher will move with it — but
                            // only at commit time, so a candidate that fails
                            // later never strips the live state's handle
                            // (PR #7 review, P2).
                            carried_over.push(definition.id().to_string());
                            oidc_services.push(oidc.clone());
                        }
                    }
                    trusted_services.push(store);
                }
                None => {
                    let (mut built, built_oidc) = build_services(
                        std::slice::from_ref(definition),
                        file_ts_dir,
                        ts_secrets_dir,
                        &policy.lookup_identity_keys(),
                        &|_id| {
                            proxy_resolver_for(
                                actor_repo.clone(),
                                definition
                                    .oidc_config()
                                    .and_then(|cfg| cfg.jwks_proxy_service.as_deref()),
                                definition.jwks_proxy_port(),
                            )
                        },
                    )
                    .await?;
                    // Refresher spawning is deferred to commit: a definition
                    // that fails AFTER this store built must not leave a task
                    // fetching a rejected policy's JWKS endpoint (PR #7
                    // review, P2).
                    for store in &built_oidc {
                        to_spawn.push((store.get_source_id().to_string(), store.keys_arc()));
                    }
                    trusted_services.append(&mut built);
                    oidc_services.extend(built_oidc);
                }
            }
        }
        Ok(CandidateState {
            state: PolicyState {
                policy,
                container: loaded.container().clone(),
                resolved_peers_by_node,
                trusted_services,
                oidc_services,
                ts_definitions,
                oidc_refreshers: std::sync::Mutex::new(HashMap::new()),
            },
            carried_over,
            to_spawn,
        })
    }

    /// Assemble a PolicyMgr from already-built state and constructor-owned parts.
    #[allow(clippy::too_many_arguments)]
    fn from_state(
        state: PolicyState,
        repo: db::PolicyRepo,
        resolver: PolicyResolver,
        ts_mgr: Arc<TrustedServicesMgr>,
        file_ts_dir: PathBuf,
        ts_secrets_dir: PathBuf,
        actor_repo: Arc<db::ActorRepo>,
        oidc_refresh: Option<Duration>,
    ) -> Self {
        ts_mgr
            .update_services_with_oidc(state.trusted_services.clone(), state.oidc_services.clone());
        PolicyMgr {
            state: ArcSwap::from_pointee(state),
            repo,
            update_lock: tokio::sync::Mutex::new(()),
            resolver,
            ts_mgr,
            file_ts_dir,
            ts_secrets_dir,
            actor_repo,
            oidc_refresh,
        }
    }

    /// Swap in `state` and republish its trusted service stores, so the manager's stores
    /// always come from the policy that is currently live.
    fn publish(&self, state: PolicyState) {
        self.ts_mgr
            .update_services_with_oidc(state.trusted_services.clone(), state.oidc_services.clone());
        self.state.store(Arc::new(state));
    }

    /// Update the current policy in state database and memory.  The new policy
    /// will be assigned a new version instance number (vinst) that is one
    /// greater than the current policy's vinst.
    ///
    /// TODO: There is a lot of housekeeping that needs to happen around a
    /// policy update. None of that is implemented here. Right now this is just
    /// to support unit tests.
    ///
    /// Returns the new `vinst` value.
    ///
    /// ### Errors
    /// - `ResolverError` if the new policy's topology contains hostnames that
    ///   fail to resolve.
    /// - `StoreError` if there is a problem writing to the database.
    ///
    async fn update_policy_internal(&self, mut loaded: LoadedPolicy) -> Result<u64, ServiceError> {
        let _guard = self.update_lock.lock().await;

        // Assign the new vinst while the policy Arc is still uniquely held.
        let vinst = self.state.load().policy.vinst() + 1;
        loaded.set_vinst(vinst);

        // Resolve topology before swapping in the new state so a failed update leaves
        // the current policy, container, and topology untouched. The new policy,
        // container, and links swap in together as one PolicyState. The live state is
        // passed in so trusted-service stores whose declaration did not change are
        // carried over rather than rebuilt with a fresh revision. build_state never
        // mutates the live state and never spawns: refresher ownership is transferred
        // and new refreshers spawned only by commit, after the DB write below has
        // succeeded, so a failed update leaves the live refresher set exactly as it
        // was and a rejected policy leaves no task behind (PR #7 review).
        let previous = self.state.load_full();
        let candidate = Self::build_state(
            &self.resolver,
            &loaded,
            &self.file_ts_dir,
            &self.ts_secrets_dir,
            &self.actor_repo,
            Some(&previous),
        )
        .await?;
        self.repo.set_current_policy(&loaded, false).await?;

        self.publish(candidate.commit(Some(&previous), self.oidc_refresh));
        Ok(vinst)
    }

    /// A consistent snapshot of policy, container, and resolved links taken in
    /// one atomic load. Holding it does not block updates, but it pins the
    /// holder to an older view until dropped. Use this when a multi-step
    /// operation must see one coherent policy/links pair; otherwise the
    /// single-shot accessors below suffice.
    ///
    /// `ArcSwap::load_full` is just a refcount bump, and the resulting owned
    /// `Arc<PolicyState>` outlives the load `Guard` so the snapshot is safe to
    /// hold across awaits.
    pub fn get_current_snapshot(&self) -> PolicySnapshot {
        PolicySnapshot(self.state.load_full())
    }

    /// A copy of the current snapshot with one more trusted service appended,
    /// installed as current -- same policy, generation and OIDC stores.
    /// Test-only: lets a test hook into enrichment on a live path.
    #[cfg(test)]
    pub(crate) fn add_trusted_service_for_tests(&self, svc: Arc<dyn TrustedServiceInterface>) {
        let cur = self.state.load_full();
        let mut trusted_services = cur.trusted_services.clone();
        trusted_services.push(svc);
        self.state.store(Arc::new(PolicyState {
            policy: cur.policy.clone(),
            container: cur.container.clone(),
            resolved_peers_by_node: cur.resolved_peers_by_node.clone(),
            trusted_services,
            oidc_services: cur.oidc_services.clone(),
            ts_definitions: cur.ts_definitions.clone(),
            oidc_refreshers: std::sync::Mutex::new(HashMap::new()),
        }));
    }

    /// Make `snapshot` the current one, bypassing a policy install. Test-only:
    /// lets a test run a live path against a snapshot with chosen trusted
    /// services (e.g. one that fails).
    #[cfg(test)]
    pub(crate) fn set_current_snapshot_for_tests(&self, snapshot: &PolicySnapshot) {
        self.state.store(snapshot.0.clone());
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.get_current_snapshot().policy_arc()
    }

    /// Get the source container bytes for the current policy (for the admin API).
    pub fn get_current_container(&self) -> PolicyContainerBytes {
        self.get_current_snapshot().container()
    }

    /// Consult policy to get a description of the link between `node_a` and `node_b`.
    /// Both arguments are ZPR addresses. A convenience single-shot wrapper over
    /// [PolicySnapshot::describe_link]; callers needing a consistent multi-step view
    /// should take a snapshot and call its method directly.
    ///
    /// Only used in unit tests.
    ///
    /// ## Errors
    /// - `TopologyError::LinkNotFound` if there is no link between `node_a` and `node_b` in the policy.
    #[allow(dead_code)]
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        self.get_current_snapshot().describe_link(node_a, node_b)
    }
}

pub struct PolicyResolver {
    resolver: Arc<dyn DnsResolver>,
}

impl PolicyResolver {
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        PolicyResolver { resolver }
    }

    async fn resolve_topology(
        &self,
        policy: &Policy,
    ) -> Result<HashMap<IpAddr, Vec<ResolvedPeer>>, ResolverError> {
        let mut resolved_by_node: HashMap<IpAddr, Vec<ResolvedPeer>> = HashMap::new();
        for node_addr in policy.all_peered_nodes() {
            if let Some(peers) = policy.get_peers_for_node(node_addr) {
                let resolved = self.resolve_peers(peers).await?;
                resolved_by_node.insert(*node_addr, resolved);
            }
        }
        Ok(resolved_by_node)
    }

    /// Peers from policy may include hostnames. Here we run any hostnames through a
    /// DNS lookup, pairing each peer's link id with its concrete socket address.
    /// Returns an error if any peer's address fails to resolve. Building the wire-level
    /// vsapi `Link` struct is deliberately deferred to the topology-message send path.
    ///
    /// A peer whose remote substrate address is not in policy (the node reports its own,
    /// zl-zipline#225) is skipped with a warning: no link can be sent without an address
    /// yet. zl-zipline#227 fills it in from the address the node reports.
    async fn resolve_peers(&self, peers: &[Peer]) -> Result<Vec<ResolvedPeer>, ResolverError> {
        let addressed = peers.iter().filter_map(|peer| match &peer.remote_substrate {
            Some(naddr) => Some((peer, naddr)),
            None => {
                warn!(
                    target: MAIN,
                    "link {}: no substrate address in policy for peer {}; skipping it until the node reports one",
                    peer.link_id, peer.remote_zpr_addr
                );
                None
            }
        });
        // Parallelize the DNS lookups then check for the first error.
        let futs = addressed.map(|(peer, naddr)| async move {
            (peer, resolve_netaddr(naddr, self.resolver.as_ref()).await)
        });

        futures::future::join_all(futs)
            .await
            .into_iter()
            .map(|(peer, result)| result.map(|sock_addr| (peer.link_id.clone(), sock_addr)))
            .collect()
    }
}

/// Build the [ProxyResolver] for one OIDC trusted service (zipline#19).
///
/// `proxy_service` is the policy-named `jwks_proxy_service`; `None` (direct
/// egress) yields a resolver that always answers "no proxy". Otherwise each
/// invocation — one per refresh, per the C3 re-resolution guardrail — looks up
/// the actor currently providing that service in the actor database and pairs
/// its ZPR address with `port`, the port pinned by the policy
/// `Service.endpoints` scope (exactly one scope, with a port), pre-captured into the
/// [TrustedServiceDefinition] so it also participates in store-reuse equality
/// (PR #7 review, P1). No connected provider, a missing or port-less service
/// declaration, or a DB error all resolve to `None`: the refresh then fails
/// "proxy not reachable" and the seed/last-good keys keep serving. A policy
/// changing the proxy declaration rebuilds the store (definition equality
/// breaks), so the resolver never outlives the port it pinned.
fn proxy_resolver_for(
    actor_repo: Arc<db::ActorRepo>,
    proxy_service: Option<&str>,
    port: Option<u16>,
) -> ProxyResolver {
    let Some(service_id) = proxy_service else {
        // Direct egress: no proxy, ever.
        return Arc::new(|| Box::pin(async { None }) as ProxyFuture);
    };
    let service_id = service_id.to_string();

    // The proxy's port comes from the policy service declaration; a
    // declaration this resolver could never complete is warned about once at
    // build time instead of failing every refresh mysteriously.
    if port.is_none() {
        warn!(
            target: MAIN,
            "jwks_proxy_service '{service_id}' is not declared with exactly one \
             single-port endpoint scope in policy; proxied JWKS refresh will fail \
             until policy is fixed (seed/last-good keys keep serving)"
        );
    }

    Arc::new(move || {
        let actor_repo = actor_repo.clone();
        let service_id = service_id.clone();
        Box::pin(async move {
            let port = port?;
            let addr = match actor_repo.get_zpr_addr_for_service(&service_id).await {
                Ok(addr) => addr?,
                Err(e) => {
                    warn!(
                        target: MAIN,
                        "jwks proxy lookup for service '{service_id}' failed: {e}"
                    );
                    return None;
                }
            };
            let url = match addr {
                IpAddr::V4(v4) => format!("http://{v4}:{port}"),
                IpAddr::V6(v6) => format!("http://[{v6}]:{port}"),
            };
            match reqwest::Url::parse(&url) {
                Ok(url) => Some(url),
                Err(e) => {
                    warn!(
                        target: MAIN,
                        "jwks proxy address for service '{service_id}' is not a \
                         valid URL: {e}"
                    );
                    None
                }
            }
        }) as ProxyFuture
    })
}

/// If the passed `NetAddr` contains a hostname, perform a DNS lookup to resolve it to an IP address.
/// Otherwise this quickly just returns a SocketAddr.
async fn resolve_netaddr(
    naddr: &NetAddr,
    resolver: &dyn DnsResolver,
) -> Result<SocketAddr, ResolverError> {
    match &naddr.host {
        NetworkHost::Ip(ip_addr) => Ok(SocketAddr::new(*ip_addr, naddr.port)),
        NetworkHost::Hostname(hostname) => resolver.resolve(hostname, naddr.port).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::{make_peering, make_trusted_service_policy, policy_with_peerings};
    use std::sync::Arc;
    use zpr::policy_types::{NetAddr, Peering};

    use crate::db::{DbConnection, FakeDb, PolicyRepo};
    use crate::test_helpers::FakeResolver;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a minimal valid Policy with no topology.
    fn policy_no_topology() -> Vec<u8> {
        policy_with_peerings(&[])
    }

    /// Create a PolicyMgr backed by a FakeDb with the given policy loaded.
    async fn make_policy_mgr(container_bytes: Vec<u8>) -> PolicyMgr {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        PolicyMgr::new_with_initial_policy(
            container_bytes,
            repo,
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db)),
            None,
        )
        .await
        .unwrap()
    }

    /// A PolicyMgr over a FakeDb that publishes its trusted service stores into `ts_mgr`
    /// and looks for attribute files in `dir`.
    async fn make_policy_mgr_with_ts(
        container_bytes: Vec<u8>,
        ts_mgr: Arc<TrustedServicesMgr>,
        dir: &Path,
    ) -> PolicyMgr {
        let db = Arc::new(FakeDb::new());
        PolicyMgr::new_with_initial_policy(
            container_bytes,
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            ts_mgr,
            dir.to_path_buf(),
            dir.to_path_buf(),
            Arc::new(db::ActorRepo::new(db)),
            None,
        )
        .await
        .unwrap()
    }

    /// A successful update publishes the policy's trusted service stores, and a later
    /// update whose attribute file is missing fails without disturbing the live state.
    #[tokio::test]
    async fn test_update_publishes_stores_and_preserves_state_on_failure() {
        let dir = std::env::temp_dir().join("vs-pm-ts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        )
        .unwrap();

        let ts_mgr = Arc::new(TrustedServicesMgr::new());
        let good = make_trusted_service_policy("attrfile", "file", Some(3600), &[]);
        let mgr = make_policy_mgr_with_ts(good, ts_mgr.clone(), &dir).await;

        // The lookup-identity set for the fixture's "alice" entry.
        let alice = [(libeval::attribute::key::CN.to_string(), "alice".to_string())];

        // The declared store is live: looking it up by source id no longer reports it missing.
        let results = ts_mgr
            .get_attributes_from_source_for_actor("attrfile", &alice)
            .await;
        assert!(results[0].is_ok());

        // An update declaring a service with no attribute file fails...
        let bad = make_trusted_service_policy("nosuchfile", "file", Some(3600), &[]);
        assert!(mgr.update_policy_from_container_bytes(bad).await.is_err());

        // ...leaving the current policy and its published stores untouched.
        assert_eq!(mgr.get_current().vinst(), 1);
        let results = ts_mgr
            .get_attributes_from_source_for_actor("attrfile", &alice)
            .await;
        assert!(results[0].is_ok());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Installing a policy whose trusted-service declarations are unchanged keeps the live
    /// stores, so actors stay caught up. A changed declaration rebuilds the store and makes
    /// them stale again.
    #[tokio::test]
    async fn test_policy_update_preserves_revisions_when_ts_config_unchanged() {
        let dir = std::env::temp_dir().join("vs-pm-ts-rev");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        )
        .unwrap();

        let ts_mgr = Arc::new(TrustedServicesMgr::new());
        let policy = make_trusted_service_policy("attrfile", "file", Some(3600), &[]);
        let mgr = make_policy_mgr_with_ts(policy.clone(), ts_mgr.clone(), &dir).await;

        // Catch the actor at this address up with the store's current revision.
        let addr: std::net::IpAddr = "fd5a:5052::a1".parse().unwrap();
        let stale = ts_mgr.stale_sources_for_actor(&addr);
        assert_eq!(stale.len(), 1);
        ts_mgr.record_revision(&addr, &stale[0].0, stale[0].1);
        assert!(ts_mgr.stale_sources_for_actor(&addr).is_empty());

        // Same trusted-service declarations: the store (and its revision) is carried over.
        mgr.update_policy_from_container_bytes(policy)
            .await
            .unwrap();
        assert!(ts_mgr.stale_sources_for_actor(&addr).is_empty());

        // A changed declaration rebuilds the store, so the actor is stale again.
        let changed = make_trusted_service_policy("attrfile", "file", Some(7200), &[]);
        mgr.update_policy_from_container_bytes(changed)
            .await
            .unwrap();
        assert_eq!(ts_mgr.stale_sources_for_actor(&addr).len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Per-service store reuse (PR #5 review): changing ONE trusted-service
    /// declaration must rebuild only that store. Unchanged declarations — here
    /// an OIDC store whose admitted cache would be emptied by a rebuild — keep
    /// their live store and revision, so connected OIDC users are not pruned.
    #[tokio::test]
    async fn test_policy_update_reuses_unchanged_stores_per_service() {
        use crate::test_helpers::{
            TrustedServiceSpec, make_test_oidc_config, make_trusted_services_policy,
        };

        let dir = std::env::temp_dir().join("vs-pm-ts-per-svc");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        )
        .unwrap();

        let oidc_spec = || TrustedServiceSpec {
            id: "google",
            api: "oidc",
            expiration_seconds: Some(300),
            mappings: &["sub -> user.oidc-subject"],
            identity: &["sub"],
            oidc: Some(make_test_oidc_config()),
            attr_query: None,
        };
        let file_spec = |secs: u32| TrustedServiceSpec {
            id: "attrfile",
            api: "file",
            expiration_seconds: Some(secs),
            mappings: &[],
            identity: &[],
            oidc: None,
            attr_query: None,
        };

        let ts_mgr = Arc::new(TrustedServicesMgr::new());
        let policy = make_trusted_services_policy(&[oidc_spec(), file_spec(3600)]);
        let mgr = make_policy_mgr_with_ts(policy, ts_mgr.clone(), &dir).await;

        // Catch an actor up with both stores' current revisions.
        let addr: std::net::IpAddr = "fd5a:5052::a2".parse().unwrap();
        for (source, revision) in ts_mgr.stale_sources_for_actor(&addr) {
            ts_mgr.record_revision(&addr, &source, revision);
        }
        assert!(ts_mgr.stale_sources_for_actor(&addr).is_empty());

        // Change only the FILE declaration: the oidc store must be carried
        // over (same instance, same revision), only attrfile is stale.
        let changed = make_trusted_services_policy(&[oidc_spec(), file_spec(7200)]);
        mgr.update_policy_from_container_bytes(changed)
            .await
            .unwrap();
        let stale: Vec<String> = ts_mgr
            .stale_sources_for_actor(&addr)
            .into_iter()
            .map(|(source, _)| source)
            .collect();
        assert_eq!(
            stale,
            vec!["attrfile".to_string()],
            "only the changed declaration's store may be rebuilt"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---- zipline#19: ActorDb-backed JWKS proxy resolver ----

    /// One (PolicyMgr, ActorRepo) pair over a shared FakeDb, with the given
    /// policy installed and `oidc_refresh` for the periodic refresher.
    async fn make_policy_mgr_with_actors(
        container_bytes: Vec<u8>,
        oidc_refresh: Option<std::time::Duration>,
    ) -> (PolicyMgr, Arc<db::ActorRepo>) {
        let db = Arc::new(FakeDb::new());
        let actor_repo = Arc::new(db::ActorRepo::new(db.clone()));
        let mgr = PolicyMgr::new_with_initial_policy(
            container_bytes,
            PolicyRepo::new(db),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            actor_repo.clone(),
            oidc_refresh,
        )
        .await
        .unwrap();
        (mgr, actor_repo)
    }

    /// Register an adapter actor in the actor DB providing `service`.
    async fn connect_provider(actor_repo: &db::ActorRepo, zpr_addr: &str, service: &str) {
        use crate::test_helpers::make_actor_with_services_defexp;
        let actor = make_actor_with_services_defexp(
            libeval::attribute::ROLE_ADAPTER,
            zpr_addr,
            &[service],
            &format!("cn-{zpr_addr}"),
        );
        actor_repo
            .add_actor(&actor, &Default::default(), &Default::default())
            .await
            .unwrap();
    }

    /// A proxied OIDC provider refreshes through the ActorDb-backed resolver
    /// (zipline#19): the actor providing the policy-named proxy service is
    /// looked up in the actor DB, the port comes from the policy service
    /// scope, and the fetch tunnels CONNECT through that address.
    #[tokio::test]
    async fn test_proxied_refresh_succeeds_via_actor_backed_resolver() {
        use crate::oidc::test_support::{
            k2_jwks_json, kids, seed_jwks_json, spawn_connect_stub, spawn_tls_jwks_server,
        };
        use crate::test_helpers::{make_oidc_policy_with_proxy_service, make_test_oidc_config};

        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;
        let (proxy_addr, mut lines) = spawn_connect_stub(upstream).await;

        let mut oidc = make_test_oidc_config();
        oidc.seed_jwks = seed_jwks_json().to_string();
        oidc.jwks_uri = format!("https://127.0.0.1:{}/jwks", upstream.port());
        oidc.jwks_proxy_service = Some("egress-proxy".to_string());

        let (mgr, actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy_with_proxy_service("google", oidc, "egress-proxy", proxy_addr.port()),
            None,
        )
        .await;
        // The proxy provider connects at the stub's address.
        connect_provider(&actor_repo, &proxy_addr.ip().to_string(), "egress-proxy").await;

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .expect("policy declares the provider");
        store.keys().add_extra_root(cert);

        store.keys().refresh().await.unwrap();
        assert!(kids(&store.keys().current()).contains(&"k2".to_string()));
        let first = lines.try_recv().expect("proxy stub must see the fetch");
        assert!(first.starts_with("CONNECT "), "{first:?}");
    }

    /// No provider connected for the policy-named proxy service: the refresh
    /// fails "proxy not reachable" and the policy seed keeps serving (stale
    /// tolerance guardrail).
    #[tokio::test]
    async fn test_proxied_provider_not_connected_keeps_seed() {
        use crate::oidc::test_support::kids;
        use crate::test_helpers::{make_oidc_policy_with_proxy_service, make_test_oidc_config};

        let mut oidc = make_test_oidc_config();
        oidc.jwks_uri = "https://idp.invalid/jwks".to_string();
        oidc.jwks_proxy_service = Some("egress-proxy".to_string());

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy_with_proxy_service("google", oidc, "egress-proxy", 3128),
            None,
        )
        .await;

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();
        let err = store
            .keys()
            .refresh()
            .await
            .expect_err("no connected provider must fail the refresh");
        assert!(format!("{err}").contains("proxy not reachable"), "{err}");
        assert_eq!(kids(&store.keys().current()), vec!["k1".to_string()]);
    }

    /// Per-refresh re-resolution (C3 guardrail, ActorDb-grounded): a provider
    /// that reconnects at a new address is picked up by the next refresh with
    /// no store rebuild.
    #[tokio::test]
    async fn test_resolver_follows_provider_reconnect() {
        use crate::oidc::test_support::{
            k2_jwks_json, kids, seed_jwks_json, spawn_connect_stub, spawn_tls_jwks_server,
        };
        use crate::test_helpers::{make_oidc_policy_with_proxy_service, make_test_oidc_config};

        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;
        let (proxy_addr, mut lines) = spawn_connect_stub(upstream).await;

        let mut oidc = make_test_oidc_config();
        oidc.seed_jwks = seed_jwks_json().to_string();
        oidc.jwks_uri = format!("https://127.0.0.1:{}/jwks", upstream.port());
        oidc.jwks_proxy_service = Some("egress-proxy".to_string());

        let (mgr, actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy_with_proxy_service("google", oidc, "egress-proxy", proxy_addr.port()),
            None,
        )
        .await;

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();
        store.keys().add_extra_root(cert);

        // Nobody provides the proxy service yet: refresh fails, seed serves.
        store
            .keys()
            .refresh()
            .await
            .expect_err("refresh must fail while no provider is connected");
        assert_eq!(kids(&store.keys().current()), vec!["k1".to_string()]);

        // The provider connects (at the stub's address). The very next
        // refresh — same store, no rebuild — resolves and succeeds.
        connect_provider(&actor_repo, &proxy_addr.ip().to_string(), "egress-proxy").await;
        store.keys().refresh().await.unwrap();
        assert!(kids(&store.keys().current()).contains(&"k2".to_string()));
        let first = lines.try_recv().expect("proxy stub must see the CONNECT");
        assert!(first.starts_with("CONNECT "), "{first:?}");
    }

    /// A provider with no `jwks_proxy_service` still refreshes direct: the
    /// resolver answers "no proxy" and the plain-HTTP fetch path is used.
    #[tokio::test]
    async fn test_direct_provider_unchanged() {
        use crate::oidc::test_support::{k2_jwks_json, kids, seed_jwks_json, spawn_jwks_server};
        use crate::test_helpers::{make_oidc_policy, make_test_oidc_config};
        use axum::http::StatusCode;

        let addr = spawn_jwks_server(StatusCode::OK, k2_jwks_json()).await;
        let mut oidc = make_test_oidc_config();
        oidc.seed_jwks = seed_jwks_json().to_string();
        oidc.jwks_uri = format!("http://{addr}/jwks");
        // No jwks_proxy_service: direct egress.

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy("google", 300, &["sub -> user.oidc-subject"], &["sub"], oidc),
            None,
        )
        .await;

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();
        store.keys().refresh().await.unwrap();
        assert!(kids(&store.keys().current()).contains(&"k2".to_string()));
    }

    // ---- zipline#19: periodic JWKS refresher ----

    /// With `oidc_refresh_seconds` set, a refresher is spawned per OIDC store
    /// and its ticks fetch the JWKS without any connect-path trigger.
    #[tokio::test]
    async fn test_refresher_spawned_for_oidc_store_with_period_from_config() {
        use crate::oidc::test_support::{k2_jwks_json, kids, seed_jwks_json, spawn_jwks_server};
        use crate::test_helpers::{make_oidc_policy, make_test_oidc_config};
        use axum::http::StatusCode;

        let addr = spawn_jwks_server(StatusCode::OK, k2_jwks_json()).await;
        let mut oidc = make_test_oidc_config();
        oidc.seed_jwks = seed_jwks_json().to_string();
        oidc.jwks_uri = format!("http://{addr}/jwks");

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy("google", 300, &["sub -> user.oidc-subject"], &["sub"], oidc),
            Some(std::time::Duration::from_millis(50)),
        )
        .await;

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();
        assert_eq!(kids(&store.keys().current()), vec!["k1".to_string()]);

        // No refresh() call anywhere: only the spawned refresher can do this.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if kids(&store.keys().current()).contains(&"k2".to_string()) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("periodic refresher never replaced the seed keys");
    }

    /// `oidc_refresh = None` (config 0/unset): no refresher task exists for
    /// the store — the operator-chosen "disabled" semantics (zipline#19 Q2).
    #[tokio::test]
    async fn test_refresher_disabled_when_period_none() {
        use crate::test_helpers::{make_oidc_policy, make_test_oidc_config};

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy(
                "google",
                300,
                &["sub -> user.oidc-subject"],
                &["sub"],
                make_test_oidc_config(),
            ),
            None,
        )
        .await;
        assert!(
            mgr.get_current_snapshot()
                .oidc_refresher_abort_handle("google")
                .is_none(),
            "no refresher may be spawned when the period is disabled"
        );
    }

    /// Refresher lifecycle across policy updates: an update that REBUILDS an
    /// OIDC store aborts the old store's refresher (no orphan task fetching
    /// forever), while an update that leaves the declaration unchanged keeps
    /// the same running task.
    #[tokio::test]
    async fn test_refresher_lifecycle_across_policy_updates() {
        use crate::test_helpers::{make_oidc_policy, make_test_oidc_config};

        let make_container = |client_id: &str| {
            let mut oidc = make_test_oidc_config();
            oidc.client_id = client_id.to_string();
            make_oidc_policy("google", 300, &["sub -> user.oidc-subject"], &["sub"], oidc)
        };

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_container("client-a.apps.googleusercontent.com"),
            Some(std::time::Duration::from_secs(3600)),
        )
        .await;
        let original = mgr
            .get_current_snapshot()
            .oidc_refresher_abort_handle("google")
            .expect("refresher must be spawned with a period configured");
        assert!(!original.is_finished());

        // Unchanged declaration: the store is carried over and so is its
        // refresher — same task, still running.
        mgr.update_policy_from_container_bytes(make_container(
            "client-a.apps.googleusercontent.com",
        ))
        .await
        .unwrap();
        let carried = mgr
            .get_current_snapshot()
            .oidc_refresher_abort_handle("google")
            .expect("carried-over store keeps its refresher");
        assert_eq!(
            original.id(),
            carried.id(),
            "same task must be carried over"
        );
        assert!(!original.is_finished());

        // Changed declaration: the store is rebuilt; the OLD refresher is
        // aborted once the old state drops, and a NEW one is running.
        mgr.update_policy_from_container_bytes(make_container(
            "client-b.apps.googleusercontent.com",
        ))
        .await
        .unwrap();
        let rebuilt = mgr
            .get_current_snapshot()
            .oidc_refresher_abort_handle("google")
            .expect("rebuilt store gets a fresh refresher");
        assert_ne!(
            original.id(),
            rebuilt.id(),
            "rebuilt store must get a new task"
        );
        // The old state (and its handle map) dropped with the swap; abort is
        // asynchronous, so poll briefly.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !original.is_finished() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            original.is_finished(),
            "the replaced store's refresher must be aborted"
        );
        assert!(!rebuilt.is_finished());
    }

    /// PR #7 review (P1): a policy update that changes ONLY the declaration of
    /// the regular service named by `jwks_proxy_service` (here: its port) must
    /// REBUILD the OIDC store — the existing store's resolver captured the old
    /// proxy port, so reusing it would keep dialing the obsolete endpoint. The
    /// rebuilt store's next refresh must dial the NEW proxy endpoint.
    #[tokio::test]
    async fn test_proxy_service_change_rebuilds_oidc_store() {
        use crate::oidc::test_support::{
            k2_jwks_json, kids, seed_jwks_json, spawn_connect_stub, spawn_tls_jwks_server,
        };
        use crate::test_helpers::{make_oidc_policy_with_proxy_service, make_test_oidc_config};

        let (upstream, cert) = spawn_tls_jwks_server(k2_jwks_json()).await;
        let (old_proxy, mut old_lines) = spawn_connect_stub(upstream).await;
        let (new_proxy, mut new_lines) = spawn_connect_stub(upstream).await;

        let mut oidc = make_test_oidc_config();
        oidc.seed_jwks = seed_jwks_json().to_string();
        oidc.jwks_uri = format!("https://127.0.0.1:{}/jwks", upstream.port());
        oidc.jwks_proxy_service = Some("egress-proxy".to_string());

        let (mgr, actor_repo) = make_policy_mgr_with_actors(
            make_oidc_policy_with_proxy_service(
                "google",
                oidc.clone(),
                "egress-proxy",
                old_proxy.port(),
            ),
            None,
        )
        .await;
        connect_provider(&actor_repo, &old_proxy.ip().to_string(), "egress-proxy").await;

        let old_store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();

        // The update changes ONLY the proxy service's port; the OIDC trusted
        // service declaration itself is byte-identical, so definition equality
        // alone would (wrongly) reuse the old store.
        mgr.update_policy_from_container_bytes(make_oidc_policy_with_proxy_service(
            "google",
            oidc,
            "egress-proxy",
            new_proxy.port(),
        ))
        .await
        .unwrap();

        let store = mgr
            .get_current_snapshot()
            .oidc_service_for_issuer("https://accounts.google.com")
            .unwrap();
        assert!(
            !Arc::ptr_eq(&old_store, &store),
            "changing the proxy service declaration must rebuild the OIDC store"
        );
        store.keys().add_extra_root(cert);
        store.keys().refresh().await.unwrap();
        assert!(kids(&store.keys().current()).contains(&"k2".to_string()));
        let line = new_lines
            .try_recv()
            .expect("refresh after the update must dial the NEW proxy endpoint");
        assert!(line.starts_with("CONNECT "), "{line:?}");
        assert!(
            old_lines.try_recv().is_err(),
            "the OLD proxy endpoint must not be dialed after the update"
        );
    }

    /// PR #7 review (P2): a FAILED update must leave the live state's
    /// refresher ownership exactly as it was, even when the failing candidate
    /// reused the OIDC store. Repeats the failing update because definition
    /// order comes from a HashMap: the bug only bit when the OIDC definition
    /// was processed (and its live handle stolen) before the file store failed.
    #[tokio::test]
    async fn test_failed_update_keeps_live_refresher_after_reuse() {
        use crate::test_helpers::{
            TrustedServiceSpec, make_test_oidc_config, make_trusted_services_policy,
        };

        let oidc_spec = || TrustedServiceSpec {
            id: "google",
            api: "oidc",
            expiration_seconds: Some(300),
            mappings: &["sub -> user.oidc-subject"],
            identity: &["sub"],
            oidc: Some(make_test_oidc_config()),
            attr_query: None,
        };

        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            make_trusted_services_policy(&[oidc_spec()]),
            Some(std::time::Duration::from_secs(3600)),
        )
        .await;
        let original = mgr
            .get_current_snapshot()
            .oidc_refresher_abort_handle("google")
            .expect("refresher must be spawned with a period configured");

        // Same OIDC declaration (reused) plus a file store whose attribute
        // file does not exist: every one of these updates must fail...
        let bad = || {
            make_trusted_services_policy(&[
                oidc_spec(),
                TrustedServiceSpec {
                    id: "nosuchfile",
                    api: "file",
                    expiration_seconds: Some(3600),
                    mappings: &[],
                    identity: &[],
                    oidc: None,
                    attr_query: None,
                },
            ])
        };
        for _ in 0..10 {
            assert!(mgr.update_policy_from_container_bytes(bad()).await.is_err());
            // ...and leave the live refresher owned by the live state, alive.
            let live = mgr
                .get_current_snapshot()
                .oidc_refresher_abort_handle("google")
                .expect("a failed update must not strip the live state's refresher");
            assert_eq!(
                original.id(),
                live.id(),
                "the live refresher must be the original task, untouched"
            );
            assert!(
                !original.is_finished(),
                "the live refresher must stay alive"
            );
        }
    }

    /// PR #7 review (P2): a REJECTED policy must never leave a refresher
    /// running. If a freshly built OIDC store spawned its refresher during
    /// construction and a later definition then failed, the task was detached
    /// and kept fetching the rejected policy's JWKS endpoint forever. Spawning
    /// is deferred to the commit step, so a failed build spawns nothing.
    /// Repeats the attempt because definition order comes from a HashMap.
    #[tokio::test]
    async fn test_rejected_policy_never_leaves_refresher_running() {
        use crate::test_helpers::{
            TrustedServiceSpec, make_test_oidc_config, make_trusted_services_policy,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A counting endpoint: any connection to it can only come from a
        // leaked refresher, since nothing else in this test fetches.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        {
            let hits = hits.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((_sock, _)) = listener.accept().await else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        // Live manager with a fast refresh period and no OIDC store.
        let (mgr, _actor_repo) = make_policy_mgr_with_actors(
            policy_no_topology(),
            Some(std::time::Duration::from_millis(10)),
        )
        .await;

        // Every update declares a NEW OIDC store pointed at the counting
        // endpoint plus a file store whose attribute file is missing, so the
        // whole policy is rejected after the OIDC store built successfully.
        let mut oidc = make_test_oidc_config();
        oidc.jwks_uri = format!("http://{addr}/jwks");
        for _ in 0..10 {
            let bad = make_trusted_services_policy(&[
                TrustedServiceSpec {
                    id: "google",
                    api: "oidc",
                    expiration_seconds: Some(300),
                    mappings: &["sub -> user.oidc-subject"],
                    identity: &["sub"],
                    oidc: Some(oidc.clone()),
                    attr_query: None,
                },
                TrustedServiceSpec {
                    id: "nosuchfile",
                    api: "file",
                    expiration_seconds: Some(3600),
                    mappings: &[],
                    identity: &[],
                    oidc: None,
                    attr_query: None,
                },
            ]);
            assert!(mgr.update_policy_from_container_bytes(bad).await.is_err());
        }

        // Give any leaked 10ms-period refresher ample time to tick.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a rejected policy's JWKS endpoint must never be fetched"
        );
    }

    /// Build a Peering whose node_b substrate is an unresolvable hostname, so that
    /// resolving topology with a no-entry FakeResolver fails.
    fn make_peering_bad_host(node_a: IpAddr, node_b: IpAddr, link_id: &str) -> Peering {
        Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: Some(NetAddr::new_for_ip_or_host(&node_a.to_string(), 0)),
            node_b,
            substrate_b: Some(NetAddr::new_for_ip_or_host("unresolvable.invalid", 5000)),
            attributes: vec![],
        }
    }

    #[tokio::test]
    /// A resolver failure during initial policy load must not persist the policy to the DB.
    async fn test_initial_policy_resolver_failure_does_not_write_db() {
        let db = Arc::new(FakeDb::new());
        let peering = make_peering_bad_host(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1");

        let result = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[peering]),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db.clone())),
            None,
        )
        .await;

        assert!(result.is_err());
        // The DB must remain empty: a policy that cannot resolve is never persisted.
        assert!(
            PolicyRepo::new(db)
                .get_current_loaded_policy(&config::POLICY_MIN_VERSION)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    /// A resolver failure during an update must leave the current policy, container,
    /// and topology unchanged (no swapped-in state).
    async fn test_update_resolver_failure_preserves_state() {
        // Start from a valid no-topology policy (vinst 1).
        let initial_container = policy_no_topology();
        let mgr = make_policy_mgr(initial_container.clone()).await;
        assert_eq!(mgr.get_current().vinst(), 1);

        // Attempt an update whose topology cannot be resolved.
        let peering = make_peering_bad_host(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1");
        let result = mgr
            .update_policy_from_container_bytes(policy_with_peerings(&[peering]))
            .await;

        assert!(result.is_err());
        // Current state untouched: vinst stays 1 and the container is still the initial one.
        assert_eq!(mgr.get_current().vinst(), 1);
        assert_eq!(
            mgr.get_current_container().as_bytes(),
            initial_container.as_slice()
        );
    }

    #[tokio::test]
    /// A successful update swaps the policy, topology, and container together.
    async fn test_update_swaps_policy_topology_and_container() {
        // Start from a no-topology policy (vinst 1).
        let mgr = make_policy_mgr(policy_no_topology()).await;
        assert_eq!(mgr.get_current().vinst(), 1);
        assert!(
            mgr.get_current_snapshot()
                .resolved_peers_for_node(&ip("fd5a:5052::1"))
                .is_empty()
        );

        // Update to a policy with topology, all IP-addressed so it resolves.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let new_container = policy_with_peerings(&[peering]);
        let vinst = mgr
            .update_policy_from_container_bytes(new_container.clone())
            .await
            .unwrap();

        assert_eq!(vinst, 2);
        assert_eq!(mgr.get_current().vinst(), 2);
        // Topology swapped in: node now has a resolved link.
        assert!(
            !mgr.get_current_snapshot()
                .resolved_peers_for_node(&ip("fd5a:5052::1"))
                .is_empty()
        );
        // Container swapped in and round-trips.
        assert_eq!(
            mgr.get_current_container().as_bytes(),
            new_container.as_slice()
        );
    }

    #[tokio::test]
    /// PolicyContainerBytes round-trips through as_bytes, and LoadedPolicy decodes
    /// a valid container while preserving the source bytes.
    async fn test_policy_artifact_construction() {
        let container_bytes = policy_no_topology();
        let pcb = PolicyContainerBytes::from(container_bytes.clone());
        assert_eq!(pcb.as_bytes(), container_bytes.as_slice());

        let mut loaded = LoadedPolicy::from_container(pcb, &config::POLICY_MIN_VERSION).unwrap();
        assert_eq!(loaded.container().as_bytes(), container_bytes.as_slice());

        // set_vinst mutates the decoded policy but not the container bytes.
        loaded.set_vinst(7);
        assert_eq!(loaded.policy().vinst(), 7);
        assert_eq!(loaded.container().as_bytes(), container_bytes.as_slice());
    }

    #[tokio::test]
    /// Policies compiled below the 0.16 floor are rejected: they emit bare
    /// `zpr.authority` semantics that this VS no longer implements (issue #324).
    async fn test_policy_below_0_16_rejected() {
        use crate::test_helpers::make_container_bytes;
        let container = make_container_bytes(0, 15, 0, &[]);
        let pcb = PolicyContainerBytes::from(container);
        let result = LoadedPolicy::from_container(pcb, &config::POLICY_MIN_VERSION);
        assert!(result.is_err(), "0.15 policy must be refused, got Ok");
    }

    #[tokio::test]
    /// LoadedPolicy::from_container rejects bytes that are not a valid container.
    async fn test_loaded_policy_rejects_garbage() {
        let pcb = PolicyContainerBytes::from(b"not a capnp container".to_vec());
        let result = LoadedPolicy::from_container(pcb, &config::POLICY_MIN_VERSION);
        assert!(result.is_err());
    }

    /// A snapshot is an internally-consistent, stable, owned view: its policy vinst and
    /// resolved links agree at capture time, and a later update does not mutate a
    /// snapshot already held.
    #[tokio::test]
    async fn test_snapshot_is_consistent_and_stable_across_update() {
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        // Start from a policy with one IP-resolvable link (vinst 1).
        let mgr = make_policy_mgr(policy_with_peerings(&[make_peering(
            a,
            b,
            "link-ab",
            vec![],
        )]))
        .await;

        // The captured policy vinst and links agree at capture time.
        let snap = mgr.get_current_snapshot();
        assert_eq!(snap.vinst(), 1);
        assert!(
            !snap.resolved_peers_for_node(&a).is_empty(),
            "snapshot must see the link its policy describes"
        );

        // Update to a fresh no-topology policy (vinst 2).
        let new_vinst = mgr
            .update_policy_from_container_bytes(policy_no_topology())
            .await
            .unwrap();
        assert_eq!(new_vinst, 2);

        // The already-held snapshot is unchanged: still vinst 1, still has the old link.
        assert_eq!(snap.vinst(), 1, "held snapshot must not see the new vinst");
        assert!(
            !snap.resolved_peers_for_node(&a).is_empty(),
            "held snapshot must retain its captured links"
        );

        // A freshly taken snapshot reflects the update.
        let snap2 = mgr.get_current_snapshot();
        assert_eq!(snap2.vinst(), 2);
        assert!(snap2.resolved_peers_for_node(&a).is_empty());
    }

    /// Build a `Peer` whose substrate is a plain IP address (no hostname), so
    /// `resolve_peers` resolves it without any DNS lookup.
    fn ip_peer(link_id: &str, ip: IpAddr, port: u16) -> Peer {
        let substrate = NetAddr {
            host: NetworkHost::Ip(ip),
            port,
        };
        Peer {
            link_id: link_id.to_string(),
            remote_zpr_addr: "fd5a:5052::1".parse().unwrap(),
            // local end is irrelevant to resolve_peers, so reuse the remote one.
            local_substrate: Some(substrate.clone()),
            remote_substrate: Some(substrate),
        }
    }

    /// Empty peer slice produces an empty resolved-peer list.
    #[tokio::test]
    async fn test_resolve_peers_empty() {
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));
        let resolved = presolver.resolve_peers(&[]).await.unwrap();
        assert!(resolved.is_empty());
    }

    /// A single IP peer maps to a single (link_id, addr) pair with the correct fields.
    #[tokio::test]
    async fn test_resolve_peers_single_ip() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let peer = ip_peer("link-a", ip, 4000);
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let resolved = presolver.resolve_peers(&[peer]).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "link-a");
        assert_eq!(resolved[0].1, SocketAddr::new(ip, 4000));
    }

    /// Multiple IP peers produce one resolved pair each, in the same order.
    #[tokio::test]
    async fn test_resolve_peers_multiple_ips() {
        let ip_a: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.2".parse().unwrap();
        let peers = [ip_peer("link-a", ip_a, 4000), ip_peer("link-b", ip_b, 5000)];
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let resolved = presolver.resolve_peers(&peers).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].0, "link-a");
        assert_eq!(resolved[0].1.ip(), ip_a);
        assert_eq!(resolved[1].0, "link-b");
        assert_eq!(resolved[1].1.ip(), ip_b);
    }

    /// A peer whose remote substrate address is not in policy (the node reports its own,
    /// zl-zipline#225) is skipped, not an error: the other peers still resolve.
    #[tokio::test]
    async fn test_resolve_peers_skips_unset_substrate() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let good = ip_peer("link-good", ip, 4000);
        let mut reported = ip_peer("link-reported", ip, 4001);
        reported.remote_substrate = None;
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let resolved = presolver.resolve_peers(&[good, reported]).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "link-good");
    }

    /// A peer with an unresolvable hostname causes resolve_peers to return an error.
    /// FakeResolver has no entries, so any hostname lookup returns NoAddresses.
    #[tokio::test]
    async fn test_resolve_peers_bad_hostname_errors() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let good = ip_peer("link-good", ip, 4000);
        let bad = Peer {
            link_id: "link-bad".to_string(),
            remote_zpr_addr: "fd5a:5052::2".parse().unwrap(),
            remote_substrate: Some(NetAddr {
                host: NetworkHost::Hostname("some.unresolvable.host".to_string()),
                port: 4000,
            }),
            local_substrate: Some(NetAddr {
                host: NetworkHost::Ip(ip),
                port: 4000,
            }),
        };
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::ip_only()));

        let result = presolver.resolve_peers(&[good, bad]).await;

        assert!(result.is_err());
    }

    /// After an update bumps vinst, a fresh PolicyMgr built from the same DB via
    /// new_from_state restores that vinst rather than the decoded default.
    #[tokio::test]
    async fn test_new_from_state_restores_vinst() {
        let db = Arc::new(FakeDb::new());
        let mgr = PolicyMgr::new_with_initial_policy(
            policy_no_topology(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db.clone())),
            None,
        )
        .await
        .unwrap();
        // Update to a distinct container so vinst advances to 2.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        mgr.update_policy_from_container_bytes(policy_with_peerings(&[peering]))
            .await
            .unwrap();

        let restored = PolicyMgr::new_from_state(
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db)),
            None,
        )
        .await
        .unwrap();
        assert_eq!(restored.get_current().vinst(), 2);
    }

    /// Rebooting with the same container reuses the persisted vinst (plain
    /// restart); a different container advances it (new install).
    #[tokio::test]
    async fn test_new_with_initial_policy_vinst_from_persisted_identifier() {
        let db = Arc::new(FakeDb::new());
        let container = policy_no_topology();
        // First boot: fresh DB → vinst 1.
        let mgr = PolicyMgr::new_with_initial_policy(
            container.clone(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db.clone())),
            None,
        )
        .await
        .unwrap();
        assert_eq!(mgr.get_current().vinst(), 1);

        // Reboot with the same container: same phash → vinst stays 1.
        let same = PolicyMgr::new_with_initial_policy(
            container,
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db.clone())),
            None,
        )
        .await
        .unwrap();
        assert_eq!(same.get_current().vinst(), 1);

        // Reboot with a different container: new phash → vinst advances to 2.
        let peering = make_peering(ip("fd5a:5052::1"), ip("fd5a:5052::2"), "link-1", vec![]);
        let different = PolicyMgr::new_with_initial_policy(
            policy_with_peerings(&[peering]),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db)),
            None,
        )
        .await
        .unwrap();
        assert_eq!(different.get_current().vinst(), 2);
    }

    /// A corrupt DB (policy present, no persisted vinst field) fails startup
    /// rather than silently defaulting the vinst.
    #[tokio::test]
    async fn test_new_from_state_missing_vinst_errors() {
        let db = Arc::new(FakeDb::new());
        // Seed a current policy, then rewrite policy:current without a vinst
        // field to mimic a corrupt state (the container blob is left intact).
        PolicyMgr::new_with_initial_policy(
            policy_no_topology(),
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db.clone())),
            None,
        )
        .await
        .unwrap();
        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        db.del("policy:current").await.unwrap();
        db.hset("policy:current", "phash", &phash).await.unwrap();

        let res = PolicyMgr::new_from_state(
            PolicyRepo::new(db.clone()),
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(db::ActorRepo::new(db)),
            None,
        )
        .await;
        assert!(res.is_err());
    }

    /// A hostname peer is resolved to the expected IP address via the FakeResolver.
    #[tokio::test]
    async fn test_resolve_peers_hostname_resolved() {
        let resolved_ip: IpAddr = "192.0.2.99".parse().unwrap();
        let peer = Peer {
            link_id: "link-h".to_string(),
            remote_zpr_addr: "fd5a:5052::10".parse().unwrap(),
            remote_substrate: Some(NetAddr {
                host: NetworkHost::Hostname("peer.example.com".to_string()),
                port: 5000,
            }),
            local_substrate: Some(NetAddr {
                host: NetworkHost::Ip("192.0.2.1".parse().unwrap()),
                port: 5000,
            }),
        };
        let mut entries = HashMap::new();
        entries.insert(
            ("peer.example.com".to_string(), 5000),
            SocketAddr::new(resolved_ip, 5000),
        );
        let presolver = PolicyResolver::new(Arc::new(FakeResolver::new(entries)));

        let resolved = presolver.resolve_peers(&[peer]).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "link-h");
        assert_eq!(resolved[0].1, SocketAddr::new(resolved_ip, 5000));
    }
}
