use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::error;

use crate::actor_mgr::ActorMgr;
use crate::admin_apikeys::ReloadableApiKeys;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::counters::Counters;
use crate::db::DbConnection;
use crate::deny_log::DenyLog;
use crate::event_mgr::EventMgr;
use crate::net_mgr::NetMgr;
use crate::policy_mgr::PolicyMgr;
use crate::revocation::RevocationLedger;
use crate::topology_mgr::TopologyMgr;
use crate::trusted_services::TrustedServicesMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

#[allow(dead_code)]
pub struct Assembly {
    pub config: VSConfig,
    pub counters: Arc<Counters>,
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
    pub policy_mgr: PolicyMgr,
    pub actor_mgr: Arc<ActorMgr>,
    pub state_db: Arc<dyn DbConnection>, // TODO: May not actually need this if db_handle is in all the required "managers".
    pub vreq_chan: mpsc::Sender<crate::visareq_worker::VisaRequestJob>,
    pub visa_mgr: VisaMgr,
    pub vss_mgr: VssMgr,
    pub net_mgr: Arc<NetMgr>,
    pub event_mgr: EventMgr,
    pub admin_api_keys: Arc<ReloadableApiKeys>,
    pub topo_mgr: TopologyMgr,
    pub ts_mgr: Arc<TrustedServicesMgr>,
    pub deny_log: DenyLog,
    /// The relay's observation of each joiner's substrate address, by the joiner's ZPR
    /// address: the source of the joiner's initial link, as the relay's socket saw it
    /// (zl-zipline#264). Written when `requestBootstrapVisas` is granted
    /// ([crate::visa_bootstrap::request_bootstrap_visas]), under the issuance and topology
    /// locks; read by [crate::connection_control::substrate_addr_for].
    ///
    /// In memory only, overwritten by each request for that address, and bounded by the
    /// relay's policy peers (the request refuses any other CN). A restart forgets it; the
    /// node actor's persisted claim stands in until the next rejoin observes again.
    pub observed_substrate: dashmap::DashMap<std::net::IpAddr, std::net::SocketAddr>,
    /// Durable visa-revocation obligations and the barrier that orders their writers
    /// against the reconciler (zl-zipline#289). See [crate::revocation].
    pub revocations: Arc<RevocationLedger>,
}

impl Assembly {
    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// The current policy's service-name set, passed into the actor write
    /// paths for the hostname claim (zipline#53): a `device.hostname` value
    /// equal to a policy service name loses to the service.
    pub fn policy_service_names(&self) -> std::collections::HashSet<String> {
        self.policy_mgr
            .get_current()
            .list_services()
            .iter()
            .map(|svc| svc.id.clone())
            .collect()
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {
        if let Err(e) = self.state_db.shutdown_cleanup().await {
            error!("Error during DB shutdown cleanup: {e}");
        }
    }
}

// Note this is "pub" so other tests can use it.
#[cfg(test)]
pub mod tests {
    use super::*;

    use std::path::PathBuf;

    use crate::actor_mgr::ActorMgr;
    use crate::config;
    use crate::connection_control::ConnectionControl;
    use crate::db::FakeDb;
    use crate::db::{ActorRepo, LinkRepo, NodeRepo, PolicyRepo, VisaRepo};
    use crate::event_mgr::VsEvent;
    use crate::policy_mgr::PolicyMgr;
    use crate::test_helpers::FakeResolver;
    use crate::test_helpers::make_container_bytes;
    use crate::visa_mgr::VisaMgr;
    use crate::visareq_worker::VisaRequestJob;
    use crate::vss_mgr::VssMgr;

    use zpr::policy::v1;

    // "pub" as this is used in some other tests too.
    pub fn make_policy(created: &str, version: u64, metadata: Option<&str>) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created(created);
            policy_bldr.set_version(version);
            if let Some(md) = metadata {
                policy_bldr.set_metadata(md);
            } else {
                policy_bldr.set_metadata("");
            }
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

    /// Test assembly with no event manager worker running. The event receiver is kept
    /// alive but never read, so `record_event` succeeds (a dropped receiver would make
    /// every send fail). Use [new_assembly_with_event_rx] to inspect queued events.
    pub async fn new_assembly_for_tests(
        vreq_tx_chan: Option<mpsc::Sender<VisaRequestJob>>,
    ) -> Assembly {
        let (asm, event_rx) = new_assembly_with_event_rx(vreq_tx_chan).await;
        std::mem::forget(event_rx);
        asm
    }

    /// As [new_assembly_for_tests], but hands back the event receiver so a test can
    /// assert which events a handler queued.
    pub async fn new_assembly_with_event_rx(
        vreq_tx_chan: Option<mpsc::Sender<VisaRequestJob>>,
    ) -> (Assembly, mpsc::Receiver<VsEvent>) {
        let (asm, event_rx, _db) = new_assembly_with_event_rx_and_db(vreq_tx_chan).await;
        (asm, event_rx)
    }

    /// As [new_assembly_with_event_rx], but also hands back the [FakeDb] so a
    /// test can inject state-DB faults (see [crate::db::FaultMode]).
    pub async fn new_assembly_with_event_rx_and_db(
        vreq_tx_chan: Option<mpsc::Sender<VisaRequestJob>>,
    ) -> (Assembly, mpsc::Receiver<VsEvent>, Arc<FakeDb>) {
        let db = Arc::new(FakeDb::new());
        let (asm, event_rx) = new_assembly_on(db.clone(), vreq_tx_chan, false).await;
        (asm, event_rx, db)
    }

    /// A new assembly over an existing [FakeDb]: what a visa service restart sees
    /// (state is hydrated from the DB; in-memory state starts empty). Like a visa
    /// service started without a policy file, it loads the stored policy
    /// (`PolicyMgr::new_from_state`).
    pub async fn new_assembly_on_db(db: Arc<FakeDb>) -> (Assembly, mpsc::Receiver<VsEvent>) {
        new_assembly_on(db, None, true).await
    }

    /// The body of the helpers above: an assembly over `db_handle`. Its policy
    /// manager loads the stored policy if `from_state`, or else installs the
    /// default test policy.
    async fn new_assembly_on(
        db_handle: Arc<FakeDb>,
        vreq_tx_chan: Option<mpsc::Sender<VisaRequestJob>>,
        from_state: bool,
    ) -> (Assembly, mpsc::Receiver<VsEvent>) {
        let vreq_tx = if let Some(tx) = vreq_tx_chan {
            tx
        } else {
            let (tx, _rx) = mpsc::channel(100);
            tx
        };
        let db_handle_for_tests = db_handle.clone();

        let policy_repo = PolicyRepo::new(db_handle.clone());
        let policy_container_bytes = make_policy("2024-01-01T00:00:00Z", 1, Some("meta"));

        let actor_repo = ActorRepo::new(db_handle.clone());
        let node_repo = NodeRepo::new(db_handle.clone());
        let visa_repo = VisaRepo::new(db_handle.clone(), 1).await.unwrap();

        let counters: Arc<Counters> = Arc::new(Default::default());

        let (event_tx, event_rx) = mpsc::channel(100);
        // TODO: Start event manager worker?

        // Shared with the PolicyMgr below so it can publish policy-declared stores.
        let ts_mgr = Arc::new(TrustedServicesMgr::new());

        let vs_addr = crate::config::VSConfig::default().get_vs_addr();
        let policy_actor_repo = Arc::new(ActorRepo::new(db_handle.clone()));
        let resolver = Arc::new(FakeResolver::ip_only());
        let policy_mgr = if from_state {
            PolicyMgr::new_from_state(
                policy_repo,
                resolver,
                ts_mgr.clone(),
                PathBuf::from("."),
                PathBuf::from("."),
                policy_actor_repo,
                None,
                vs_addr,
            )
            .await
        } else {
            PolicyMgr::new_with_initial_policy(
                policy_container_bytes,
                policy_repo,
                resolver,
                ts_mgr.clone(),
                PathBuf::from("."),
                PathBuf::from("."),
                policy_actor_repo,
                None,
                vs_addr,
            )
            .await
        }
        .expect("failed to initialize PolicyMgr");

        let asm = Assembly {
            config: VSConfig::default(),
            counters: counters.clone(),
            system_start_time: std::time::Instant::now(),
            cc: ConnectionControl::new("vs_ident".to_string()),
            policy_mgr,
            actor_mgr: Arc::new(ActorMgr::new(actor_repo, node_repo, counters)),
            state_db: db_handle.clone(),
            vreq_chan: vreq_tx,
            visa_mgr: VisaMgr::new(visa_repo),
            vss_mgr: VssMgr::new(),
            net_mgr: Arc::new(NetMgr::new_v6().expect("failed to create NetMgr")),
            event_mgr: EventMgr::new(event_tx),
            admin_api_keys: Arc::new(ReloadableApiKeys::default()),
            topo_mgr: TopologyMgr::new(LinkRepo::new(db_handle)),
            ts_mgr,
            deny_log: Default::default(),
            observed_substrate: Default::default(),
            revocations: Arc::new(RevocationLedger::new(db_handle_for_tests.clone())),
        };
        asm.policy_mgr.bind_topology_lock(asm.topo_mgr.ops_lock());
        asm.policy_mgr.bind_revocations(asm.revocations.clone());
        (asm, event_rx)
    }
}
