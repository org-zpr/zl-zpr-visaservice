// Code reachable only from the runtime `main` path looks unused when the bin
// is compiled as a test harness (which replaces `main`). Suppress that noise;
// real dead-code detection still applies to normal/release builds.
#![cfg_attr(test, allow(dead_code))]

use clap::Parser;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use libeval::attribute::{ROLE_ADAPTER, key};

mod actor_attributes;
mod actor_mgr;
mod admin_apikeys;
mod admin_service;
mod apikey;
mod assembly;
mod auth;
mod auth_sweep;
mod config;
mod connection_control;
mod counters;
mod db;
mod db_worker;
mod deny_log;
mod error;
mod event_mgr;
mod http_util;
mod loaded_policy;
mod logging;
mod net_mgr;
/// Offline OIDC id_token validation (consumed by the connect path in
/// OIDC-C4/C5; until then only its own tests exercise it).
#[allow(dead_code)]
mod oidc;
mod packet;
mod policy_mgr;
mod router;
mod signal_worker;
mod topology_mgr;
mod trusted_services;
mod visa_bootstrap;
mod visa_mgr;
mod visa_policy;
mod visa_reconciler;
mod visareq_worker;
mod vsapi_worker;
mod vss;
mod vss_mgr;
mod vss_worker;

#[cfg(test)]
mod test_helpers;

use crate::actor_mgr::ActorMgr;
use crate::admin_apikeys::ReloadableApiKeys;
use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::counters::Counters;
use crate::db::{DbConnection, LockDescriptor, LockType};
use crate::error::ServiceError;
use crate::event_mgr::EventMgr;
use crate::event_mgr::VsEvent;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;
use crate::net_mgr::NetMgr;
use crate::policy_mgr::{PolicyMgr, SystemResolver};
use crate::topology_mgr::TopologyMgr;
use crate::trusted_services::TrustedServicesMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

use redis::AsyncCommands;
use zpr::vsapi_types::Claim;

const DEFAULT_CONFIG_PATH: &str = "vs.toml";

/// vs - ZPR visa service
#[derive(Parser, Debug)]
#[command(name = "vs")]
#[command(version = build_info::BUILD_VERSION, verbatim_doc_comment)]
struct Cli {
    /// Initial policy file (.bin2 format). If not specified we will load the current policy set in the database.
    /// If there is no policy in the database the visa service will fail to start.
    policy: Option<PathBuf>,

    /// Enable verbose debug output (use twice for more, eg "-vv").
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Clear any existing state in the database and start fresh. WARNING: REMOVES ALL REDIS KEYS INCLUDING LOCK.
    #[arg(long)]
    clear_state: bool,

    /// Force a regeneration of the visa service identity UUID.
    #[arg(long)]
    regen_identity: bool,

    /// Path to the configuration file. If "vs.toml" is present in the current directory, it will be used by default.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Emit a default configuration file and exit.
    #[arg(long)]
    gen_config: bool,

    /// Print the minimum policy compiler version this build accepts (MAJOR.MINOR must match, PATCH >=) and exit.
    #[arg(long)]
    min_compiler_version: bool,
}

/// The line `--min-compiler-version` prints: `MAJOR.MINOR.PATCH` of
/// [config::POLICY_MIN_VERSION] (zipline#184).
fn min_compiler_version_line() -> String {
    config::POLICY_MIN_VERSION.to_string()
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // Handled first, before logging, config, identity or ValKey, so it works
    // on a host with none of them; wins over any other flag (zipline#184).
    if cli.min_compiler_version {
        println!("{}", min_compiler_version_line());
        return std::process::ExitCode::SUCCESS;
    }

    if cli.gen_config {
        let default_cfg = VSConfig::default();
        match toml::to_string_pretty(&default_cfg) {
            Ok(toml_str) => {
                println!("{}", toml_str);
                return std::process::ExitCode::SUCCESS;
            }
            Err(e) => {
                error!(target: MAIN, "failed to generate default configuration: {}", e);
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let verbosity = if cli.verbose >= 2 {
        logging::Verbosity::VeryVerboseIndeed
    } else if cli.verbose == 1 {
        logging::Verbosity::SomewhatVerbose
    } else {
        logging::Verbosity::NotVerbose
    };
    enable_logging(verbosity);
    info!(target: MAIN, "vs version {}", build_info::BUILD_VERSION);
    let cfg = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            error!(target: MAIN, "failed to load configuration: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let identity = match initialize_identity(
        &cfg.core.identity,
        &cli.regen_identity,
        &config::get_data_home(),
    ) {
        Ok(id) => id,
        Err(e) => {
            error!(target: MAIN, "failed to initialize identity: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };
    info!("visa service identity: {}", identity);

    // If a policy path was provided, attempt to load it here. If not provided, we set this None
    // and then later the policy_mgr will attempt to load the current policy from the database.
    let initial_policy_bytes = if let Some(policy_path) = &cli.policy {
        match std::fs::read(policy_path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                error!(
                    target: MAIN,
                    "failed to load initial policy from {}: {}",
                    policy_path.display(),
                    e
                );
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // NOTE: tasks spawned onto this LocalSet (spawn_local) are only queued; they
    // do not start running until the LocalSet is driven by run_until below.
    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(config::VALKEY_URI);
    let vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");
    debug!(target: MAIN, "connecting to ValKey at {}...", vk_uri);

    let mut vk_conn = redis::aio::ConnectionManager::new(vk_client)
        .await
        .expect("failed to get redis connection");

    let res: String = vk_conn.ping().await.expect("failed to ping ValKey server");
    info!(target: MAIN, "connected to ValKey at {vk_uri}, ping response: {}", res);

    let db_handle = Arc::new(db::RedisDb::new(vk_conn));

    let vslock_desc = LockDescriptor::new(
        LockType::VsInstance,
        identity.clone(),
        config::VALKEY_LOCK_TIMEOUT,
    );

    if cli.clear_state {
        if let Err(e) = db_handle.clear_state().await {
            error!(target: MAIN, "failed to clear state in the database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
        info!(target: MAIN, "database state cleared successfully");
    }

    match db_handle.acquire_or_renew_lock(&vslock_desc).await {
        Ok(acquired) => {
            if acquired {
                info!(target: MAIN, "acquired visa service lock in the database, starting up");
            } else {
                error!(target: MAIN, "visa service lock is currently held by another instance, exiting");
                return std::process::ExitCode::FAILURE;
            }
        }
        Err(e) => {
            error!(target: MAIN, "failed to acquire visa service lock on the database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut js = JoinSet::new();

    // Spawn lock renewal immediately after acquisition so it covers hydration
    // (VisaRepo::new) and the rest of startup — otherwise the lock runs on its
    // un-renewed fuse (VALKEY_LOCK_TIMEOUT) through all of startup. This must be
    // a plain spawn (not spawn_local): LocalSet tasks aren't polled until
    // run_until, which is only reached after hydration completes.
    js.spawn(db_worker::launch(db_handle.clone(), vslock_desc));

    let counters = Arc::new(Counters::default());

    let (vreq_tx, vreq_rx) =
        mpsc::channel::<visareq_worker::VisaRequestJob>(config::VISA_REQUEST_QUEUE_DEPTH);

    let actor_mgr = match create_actor_mgr(db_handle.clone(), counters.clone()).await {
        Ok(adb) => adb,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate actor database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    // The policy manager builds the trusted service stores as part of every policy
    // transaction, so it needs the manager and the attribute file directory up front.
    let ts_mgr = Arc::new(TrustedServicesMgr::new());
    let file_ts_dir = cfg
        .core
        .file_ts_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    // Bearer-token directory for `api = "zpr-attr/1"` trusted services.
    let ts_secrets_dir = cfg
        .core
        .ts_secrets_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));

    // JWKS refresh period for OIDC trusted services: 0 or unset disables the
    // periodic refresher (the policy manager warns per provider; connect-path
    // on-demand refresh still works).
    let oidc_refresh = cfg
        .core
        .oidc_refresh_seconds
        .filter(|&secs| secs > 0)
        .map(std::time::Duration::from_secs);

    // Initialize the policy manager either from provided policy-container or from database.
    let policy_mgr = {
        // The policy manager gets its own ActorRepo handle over the shared DB:
        // the JWKS proxy resolver looks up the actor providing a policy-named
        // proxy service on every refresh.
        let actor_repo = Arc::new(db::ActorRepo::new(db_handle.clone()));
        let policy_mgr_res = match initial_policy_bytes {
            Some(p) => {
                PolicyMgr::new_with_initial_policy(
                    p,
                    db::PolicyRepo::new(db_handle.clone()),
                    Arc::new(SystemResolver),
                    ts_mgr.clone(),
                    file_ts_dir,
                    ts_secrets_dir,
                    actor_repo,
                    oidc_refresh,
                    cfg.get_vs_addr(),
                )
                .await
            }
            None => {
                PolicyMgr::new_from_state(
                    db::PolicyRepo::new(db_handle.clone()),
                    Arc::new(SystemResolver),
                    ts_mgr.clone(),
                    file_ts_dir,
                    ts_secrets_dir,
                    actor_repo,
                    oidc_refresh,
                    cfg.get_vs_addr(),
                )
                .await
            }
        };
        match policy_mgr_res {
            Ok(pm) => pm,
            Err(e) => {
                error!(target: MAIN, "failed to instantiate policy manager: {}", e);
                return std::process::ExitCode::FAILURE;
            }
        }
    };

    let net_mgr = NetMgr::new_v6().expect("failed to create NetMgr");

    // Nodes culled at startup; adapter/visa teardown deferred until the
    // Assembly exists (zipline#145).
    let mut culled_nodes = Vec::new();
    if !cli.clear_state {
        // The policy's service-name set gates hostname-claim reconciliation
        // (zipline#53): a persisted claim colliding with a policy service is
        // released rather than rebuilt.
        let policy_service_names: std::collections::HashSet<String> = policy_mgr
            .get_current()
            .list_services()
            .iter()
            .map(|svc| svc.id.clone())
            .collect();
        match synchronize_state(&actor_mgr, &net_mgr, &policy_service_names).await {
            Ok(culled) => culled_nodes = culled,
            Err(e) => {
                error!(target: MAIN, "error during state synchronization: {}", e);
                // For now treat this as a fail.  Force user to reset state.
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let visa_repo = match db::VisaRepo::new(db_handle.clone(), config::INITIAL_VISA_ID).await {
        Ok(vr) => vr,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate visa repository: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let (event_tx, event_rx) = mpsc::channel(config::EVENT_QUEUE_DEPTH);

    let admin_api_keys = match ReloadableApiKeys::new_from_file(
        cfg.core
            .api_keys
            .clone()
            .unwrap_or_else(|| PathBuf::from(config::DEFAULT_API_KEYS_FILE)),
        true,
    ) {
        Ok(keys) => keys,
        Err(e) => {
            error!(target: MAIN, "failed to load admin API keys: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if admin_api_keys.is_empty() {
        warn!(target: MAIN, "no active admin API keys, admin API will be inaccessible until keys file '{}' is created and contains active keys",
            admin_api_keys.get_path().display());
    }

    let asm = Arc::new(Assembly {
        config: cfg.clone(),
        counters,
        system_start_time: std::time::Instant::now(),
        cc: ConnectionControl::new(identity),
        policy_mgr: policy_mgr,
        actor_mgr: Arc::new(actor_mgr),
        state_db: db_handle.clone(),
        vreq_chan: vreq_tx,
        visa_mgr: VisaMgr::new(visa_repo),
        vss_mgr: VssMgr::new(),
        net_mgr: Arc::new(net_mgr),
        event_mgr: EventMgr::new(event_tx),
        admin_api_keys: Arc::new(admin_api_keys),
        topo_mgr: TopologyMgr::new(db::LinkRepo::new(db_handle)),
        ts_mgr,
        deny_log: Default::default(),
    });

    // Tear down what the startup cull left for us, now that the Assembly
    // exists: the culled nodes' adapters (records, visas, pool addresses),
    // their visa refs and router entries (zipline#145). Runs before the
    // topology restore below so a culled node's persisted edges are GC'd.
    teardown_culled_nodes(&asm, &culled_nodes).await;

    // Rebuild the in-memory router topology from persisted state. This runs after
    // synchronize_state/refresh_state (above) has pruned expired nodes, so those nodes
    // are excluded from node_addrs and their persisted edges get GC'd during restore.
    // Startup must load state completely or fail -- if there is garbage in there the
    // admin needs to startup again with clean state.
    let node_addrs = match asm.actor_mgr.list_node_addrs().await {
        Ok(addrs) => addrs,
        Err(e) => {
            error!(target: MAIN, "failed to list node addresses for topology restore: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };
    // Capture one consistent policy snapshot for the whole restore pass so every edge is
    // validated against the same policy/links view.
    let psnap = asm.policy_mgr.get_current_snapshot();
    if let Err(e) = asm.topo_mgr.restore_from_state(&psnap, &node_addrs).await {
        error!(target: MAIN, "failed to restore topology state: {}", e);
        return std::process::ExitCode::FAILURE;
    }

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(event_mgr::launch(asm.clone(), event_rx));

    // The visa service's own ZPR address (`vs_addr`) is used both ways: the
    // VS-API and admin listeners bind it here, and every outbound VSS
    // connection binds it as its source (`vss_worker::connect_from`).
    js.spawn_local(vsapi_worker::launch(
        asm.clone(),
        SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.vsapi_port.unwrap_or(config::VSAPI_PORT),
        ),
    ));

    {
        let admin_key = cfg.core.admin_key.clone();
        let admin_cert = cfg.core.admin_cert.clone();
        let admin_listen = SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.admin_port.unwrap_or(config::ADMIN_HTTPS_PORT),
        );
        let admin_asm = asm.clone();
        js.spawn_local(async move {
            start_admin_server(&admin_key, &admin_cert, admin_listen, &admin_asm).await;
        });
    }

    js.spawn_local(visareq_worker::launch_arena(
        asm.clone(),
        vreq_rx,
        config::MAX_VISA_REQUEST_WORKERS,
    ));

    // Periodic authentication-expiry sweep (zipline#44): notice actors whose
    // authentication ran out, revoke on the docking node, drop them from the
    // store. MIN_VISA_LIFETIME is fine-grained enough that a revocation lands
    // inside the shortest possible visa lifetime.
    let _auth_sweeper =
        auth_sweep::spawn_auth_expiry_sweeper(asm.clone(), config::MIN_VISA_LIFETIME);

    // perform initial self-authorization
    if let Err(e) = self_authorize(asm.clone(), &cfg.get_vs_addr()).await {
        error!(target: MAIN, "self-authorization failed: {}", e);
        return std::process::ExitCode::FAILURE;
    }

    // TODO: Setup/launch the workers for the visa service. Those that will do the actual work
    // of generating visas, and all the housekeeping.

    local_set
        .run_until(async {
            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        })
        .await;

    info!(target: MAIN, "exiting");
    std::process::ExitCode::SUCCESS
}

/// Load configuration from an explicit path, the default path, or fall back to defaults.
fn load_config(explicit: Option<&std::path::Path>) -> Result<VSConfig, ServiceError> {
    match explicit {
        Some(path) => {
            let cfg = VSConfig::from_file(path)?;
            info!(target: MAIN, "using configuration: {}", path.display());
            Ok(cfg)
        }
        None => {
            let default_path = std::path::Path::new(DEFAULT_CONFIG_PATH);
            if default_path.exists() {
                let cfg = VSConfig::from_file(default_path)?;
                info!(target: MAIN, "using configuration: {}", default_path.display());
                Ok(cfg)
            } else {
                info!(target: MAIN, "no configuration file found, using defaults");
                Ok(VSConfig::default())
            }
        }
    }
}

async fn create_actor_mgr(
    dbh: Arc<dyn DbConnection>,
    counters: Arc<Counters>,
) -> Result<ActorMgr, ServiceError> {
    let adb = db::ActorRepo::new(dbh.clone());
    let ndb = db::NodeRepo::new(dbh);
    let mgr = ActorMgr::new(adb, ndb, counters);
    Ok(mgr)
}

// TODO: This belongs somewhere else. Must be run every time we load a new policy.
//
// Also this "authorizes" the visa service actor by fiat, but we do not yet know what
// node the vs adapter is docked to.  We also have no way at the moment to tell the
// vs what node it is docked to.
//
// One idea is to query our local ph (via ph-cli) and get the substrate address of
// the docking node.  We can use that to find the node record.
//
async fn self_authorize(asm: Arc<Assembly>, vs_addr: &IpAddr) -> Result<(), ServiceError> {
    let mut claims = Vec::new();
    claims.push(Claim::new(key::ZPR_ADDR.into(), vs_addr.to_string()));
    claims.push(Claim::new(key::CN.into(), config::VS_CN.into()));
    claims.push(Claim::new(key::ROLE.into(), ROLE_ADAPTER.into()));

    let actor = asm
        .cc
        .authenticate_visa_service(asm.clone(), claims)
        .await?;

    asm.actor_mgr
        .hack_add_adapter_no_node(&actor, &asm.policy_service_names())
        .await?;

    let evt = VsEvent::ActorJoins(vs_addr.clone());
    if let Err(e) = asm.event_mgr.record_event(evt).await {
        warn!(target: MAIN, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
    }

    Ok(())
}

fn initialize_identity(
    config_identity: &Option<String>,
    regen_identity: &bool,
    data_home: &std::path::Path,
) -> Result<String, ServiceError> {
    // Wrap an I/O error with the operation and path being attempted, and --
    // when the problem is permissions -- with the two operator escapes: the
    // `core.identity` config setting (which skips the file entirely) and
    // XDG_DATA_HOME (which relocates it).
    fn io_context(what: &str, path: &std::path::Path, source: std::io::Error) -> ServiceError {
        let mut context = format!("{} {}", what, path.display());
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            context.push_str(
                " (set core.identity in the config file to skip identity storage, \
                 or set XDG_DATA_HOME to a writable directory)",
            );
        }
        ServiceError::IoContext { context, source }
    }

    // If user has supplied a non-empty identity string, use it and ignore any stored
    // identity file.
    if let Some(id) = config_identity {
        if !id.trim().is_empty() {
            return Ok(id.clone());
        }
    }

    // If we have an identity stored locally, use that -- unless user wants a regen.
    let id_path = data_home.join("vs_identity.txt");
    if id_path.exists() && !regen_identity {
        let contents = fs::read_to_string(&id_path)
            .map_err(|e| io_context("could not read visa service identity file", &id_path, e))?;
        let id_str = contents.trim();
        if !id_str.is_empty() {
            debug!(target: MAIN, "loaded existing identity from {}", id_path.display());
            return Ok(id_str.to_string());
        }
    }

    // Else create a new identity, store it, and return it.
    let new_identity = uuid::Uuid::new_v4().to_string();
    fs::create_dir_all(data_home)
        .map_err(|e| io_context("could not create visa service data directory", data_home, e))?;
    fs::write(&id_path, &new_identity)
        .map_err(|e| io_context("could not write visa service identity file", &id_path, e))?;
    debug!(target: MAIN, "created new identity file at {}", id_path.display());
    Ok(new_identity)
}

/// If we are starting with state in the DB, do any housekeeping needed to get in sync.
///
/// Loading of visa state happens in [db::VisaRepo::new].
///
/// Returns the stale nodes [ActorMgr::refresh_state] identified for culling.
/// Nothing has been deleted yet (PR #46 review): the node records — including
/// the connected-adapters sets, the only durable record of the orphaned
/// adapters — stay in the DB until [teardown_culled_nodes] finishes, so an
/// exit anywhere between here and there (e.g. `VisaRepo::new` or API-key
/// loading failing) leaves the next startup able to re-discover and re-cull
/// them. The adapters' teardown needs the `Assembly`, so the caller runs
/// [teardown_culled_nodes] right after constructing it (zipline#145). Note the
/// pool-grab below reserves the culled node's and its orphaned adapters'
/// addresses first (their actor records are still present); the teardown then
/// releases them.
///
/// TODO: If we have state in the db, and we are loading a policy that differs from
/// the saved "curent" policy, we may have visas that are not longer valid.
async fn synchronize_state(
    actor_mgr: &ActorMgr,
    net_mgr: &NetMgr,
    policy_service_names: &std::collections::HashSet<String>,
) -> Result<Vec<crate::actor_mgr::CulledNode>, ServiceError> {
    let culled = actor_mgr.refresh_state().await?;

    // Rebuild the `host:<NAME>` hostname-claim index from persisted actor
    // attributes (zipline#53, PR #24 review): actors persisted before the
    // index existed carry `device.hostname` in `actor:<ZADDR>:attrs` but no
    // index entries, and neither claim write path runs at startup. The pass
    // is idempotent, so running it on every start is a reconstruction, not a
    // migration (project invariant: no database migration burden).
    actor_mgr
        .reconcile_hostname_claims(policy_service_names)
        .await?;

    // Grab all the adapter addresses we have handed out already so that we do not try
    // to hand out the same address to a new adapter. A bad per-actor record does not
    // error the listing (`list_actors` degrades it to an address with no CN), so an
    // Err here is a real DB failure: propagate it rather than silently reserving
    // nothing and letting the allocator hand out occupied addresses.
    for (zpr_addr, _cn) in actor_mgr.list_actors(None).await? {
        if net_mgr.is_managed_address(&zpr_addr) {
            net_mgr.take_zpr_addr(&zpr_addr)?;
        }
    }
    Ok(culled)
}

/// Tear down what a node culled by [ActorMgr::refresh_state] leaves behind,
/// once the `Assembly` exists (zipline#145). `refresh_state` deleted nothing
/// (PR #46 review), so this owns the whole removal, adapters first:
/// - the adapters' actor records, trusted-service revisions and pool
///   addresses (`ConnectionControl::remove_departed_adapters`); that helper
///   itself spares the VS's own adapter (zipline#167): the VS is running
///   right now, and its record is re-created only at startup or when its
///   adapter re-docks;
/// - the removed adapters' visas (`VisaMgr::remove_visas_for_actors`);
/// - the node's visa refs (`VisaMgr::clear_node_state`) and its router entry
///   (`TopologyMgr::remove_node`);
/// - LAST, the node's own actor and node DB records
///   ([ActorMgr::finish_cull]) and its pool address. The node record carries
///   the connected-adapters set — the only durable record of the orphaned
///   adapters — so it must outlive their teardown: a crash before this point
///   leaves the node discoverable and the next startup re-culls it. The
///   node's address was reserved by `synchronize_state`'s pool-grab (its
///   actor record was still present) and is released only after the records
///   are gone, so a surviving record can never collide with a recycled
///   address.
///
/// Failures are logged, not fatal: startup proceeds with whatever teardown
/// succeeded, same as the disconnect path. Every step is idempotent (key
/// deletions and logged-and-skipped releases), so a partial run is completed
/// by the re-cull on the next startup.
async fn teardown_culled_nodes(asm: &Assembly, culled: &[crate::actor_mgr::CulledNode]) {
    for node in culled {
        let removed = asm
            .cc
            .remove_departed_adapters(asm, &node.adapter_addrs)
            .await;
        if let Err(e) = asm.visa_mgr.remove_visas_for_actors(&removed).await {
            error!(target: MAIN, "failed to remove visas for adapters of culled node {}: {e}", node.node_addr);
        }
        if let Err(e) = asm.visa_mgr.clear_node_state(&node.node_addr).await {
            error!(target: MAIN, "failed to clear visa state for culled node {}: {e}", node.node_addr);
        }
        asm.topo_mgr.remove_node(&node.node_addr).await;
        match asm.actor_mgr.finish_cull(&node.node_addr).await {
            Ok(()) => {
                if asm.net_mgr.is_managed_address(&node.node_addr) {
                    if let Err(e) = asm.net_mgr.release_zpr_addr(node.node_addr) {
                        error!(target: MAIN, "failed to release ZPR addr {} for culled node: {e}", node.node_addr);
                    }
                }
            }
            Err(e) => {
                // The records may have survived; keep the address allocated so a
                // recycled address cannot collide with them (same rationale as
                // remove_departed_adapters). The next startup re-culls the node.
                error!(target: MAIN, "failed to remove records of culled node {}: {e}", node.node_addr);
            }
        }
    }
}

/// zipline#184: `vs --min-compiler-version` prints the minimum policy
/// compiler version this build accepts and exits.
#[cfg(test)]
mod min_compiler_version_tests {
    use super::*;

    #[test]
    fn test_cli_parses_min_compiler_version_flag() {
        let cli = Cli::try_parse_from(["vs", "--min-compiler-version"]).unwrap();
        assert!(cli.min_compiler_version);
        let cli = Cli::try_parse_from(["vs"]).unwrap();
        assert!(!cli.min_compiler_version);
    }

    // Tracks the constants, so a compiler minor bump needs no test edit.
    #[test]
    fn test_min_compiler_version_line_matches_constants() {
        assert_eq!(
            min_compiler_version_line(),
            format!(
                "{}.{}.{}",
                config::POLICY_MIN_COMPILER_MAJOR,
                config::POLICY_MIN_COMPILER_MINOR,
                config::POLICY_MIN_COMPILER_PATCH
            )
        );
        assert_eq!(
            min_compiler_version_line(),
            config::POLICY_MIN_VERSION.to_string()
        );
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    // A configured non-empty identity wins and touches no files.
    #[test]
    fn test_config_identity_skips_storage() {
        let id = initialize_identity(
            &Some("my-vs".to_string()),
            &false,
            std::path::Path::new("/nonexistent/should/not/be/touched"),
        )
        .unwrap();
        assert_eq!(id, "my-vs");
    }

    // A fresh data home directory is created (no pre-existence required) and
    // the generated identity is persisted and re-read on the next call.
    #[test]
    fn test_creates_data_home_and_persists_identity() {
        let dir = tempfile::tempdir().unwrap();
        let data_home = dir.path().join("does/not/exist/yet");
        let id1 = initialize_identity(&None, &false, &data_home).unwrap();
        assert!(data_home.join("vs_identity.txt").exists());
        let id2 = initialize_identity(&None, &false, &data_home).unwrap();
        assert_eq!(id1, id2);
    }

    // On permission failure the error must name the operation and the path,
    // and point the operator at the config/env escapes.
    #[test]
    fn test_permission_denied_error_names_path_and_remedies() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Read-only parent so creating the data home fails with EACCES.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root (or CAP_DAC_OVERRIDE, common in build containers) bypasses
        // mode bits, so the setup above cannot produce the permission
        // failure this test is about. Probe for that and skip explicitly
        // rather than let unwrap_err() panic on a spurious Ok.
        let probe = dir.path().join("probe");
        if std::fs::create_dir(&probe).is_ok() {
            std::fs::remove_dir(&probe).unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipping: privileges bypass file permission bits");
            return;
        }
        let data_home = dir.path().join("zpr");
        let err = initialize_identity(&None, &false, &data_home).unwrap_err();
        let msg = err.to_string();
        // Restore permissions so the tempdir can be cleaned up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            msg.contains("could not create visa service data directory"),
            "{msg}"
        );
        assert!(msg.contains(&data_home.display().to_string()), "{msg}");
        assert!(msg.contains("core.identity"), "{msg}");
        assert!(msg.contains("XDG_DATA_HOME"), "{msg}");
    }
}

/// zipline#145: the post-Assembly teardown for nodes culled by
/// `ActorMgr::refresh_state`. Patterned on
/// `remove_departed_adapters_keeps_address_when_removal_fails`
/// (connection_control.rs) and `test_reset_tears_down_docked_adapters`
/// (vsapi_worker.rs): the same #138 teardown, driven from startup.
#[cfg(test)]
mod culled_node_teardown_tests {
    use super::*;
    use crate::actor_mgr::CulledNode;
    use crate::test_helpers::{build_sweep_asm, create_sweep_visa, make_adapter_actor_defexp};
    use libeval::actor::Role;

    /// A culled node's returned adapters, run through the teardown helper:
    /// no adapter actor records survive, their visas are revoked
    /// (`remove_visas_for_actors` path), a pool address is released and
    /// re-allocatable, and the node is out of the router.
    #[tokio::test]
    async fn test_teardown_culled_nodes_tears_down_adapters() {
        let (asm, node_a) = build_sweep_asm(true).await;
        let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let dst: IpAddr = "fd5a:5052:4000::b".parse().unwrap();

        // A second adapter on node B, on a managed pool address (mirrors the
        // pool-grab in synchronize_state, which reserves persisted addresses
        // before the teardown releases the orphaned ones).
        let pooled = asm.net_mgr.get_next_zpr_addr(&Role::Adapter).unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp(&pooled.to_string(), "pooled"),
                &node_b,
                &Default::default(),
            )
            .await
            .unwrap();

        // A visa held by node A from its adapter to node B's adapter.
        let visa_id = create_sweep_visa(&asm, &node_a, 0).await;

        // refresh_state deletes nothing (PR #46 review): node B's actor and
        // node records are still present here, and the teardown removes them.
        let culled = vec![CulledNode {
            node_addr: node_b,
            adapter_addrs: vec![dst, pooled],
        }];
        teardown_culled_nodes(&asm, &culled).await;

        for addr in [dst, pooled] {
            assert!(
                asm.actor_mgr
                    .get_actor_by_zpr_addr(&addr)
                    .await
                    .unwrap()
                    .is_none(),
                "adapter {addr} must not survive its node's startup cull"
            );
        }
        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&node_b)
                .await
                .unwrap()
                .is_none(),
            "the culled node's actor record must be removed by the teardown"
        );
        assert!(
            !asm.actor_mgr
                .list_node_addrs()
                .await
                .unwrap()
                .contains(&node_b),
            "the culled node's node DB record must be removed by the teardown"
        );
        assert!(
            asm.net_mgr.take_zpr_addr(&pooled).is_ok(),
            "the pooled adapter's address must be released and re-allocatable"
        );
        asm.net_mgr.release_zpr_addr(pooled).unwrap();
        assert_eq!(
            asm.visa_mgr
                .get_pending_revoke_visa_ids_for_node(&node_a)
                .await
                .unwrap(),
            vec![visa_id],
            "the visa to the culled node's adapter must be revoked from node A"
        );
        assert!(
            asm.topo_mgr.add_node(node_b).is_ok(),
            "the culled node must have been removed from the router"
        );
    }

    /// The visa service's own adapter is spared, mirroring `reset_node_state`
    /// (vsapi_worker.rs): the VS keeps running across a startup cull of its
    /// docking node's stale record.
    #[tokio::test]
    async fn test_teardown_culled_nodes_spares_vs_own_adapter() {
        let (asm, node_a) = build_sweep_asm(false).await;
        let vs_addr = IpAddr::V6(config::VS_ZPR_ADDR);
        asm.actor_mgr
            .hack_add_adapter_no_node(
                &make_adapter_actor_defexp(&vs_addr.to_string(), config::VS_CN),
                &Default::default(),
            )
            .await
            .unwrap();

        let culled = vec![CulledNode {
            node_addr: node_a,
            adapter_addrs: vec![vs_addr],
        }];
        teardown_culled_nodes(&asm, &culled).await;

        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&vs_addr)
                .await
                .unwrap()
                .is_some(),
            "the VS's own actor record must survive a startup cull of its docking node"
        );
    }
}
