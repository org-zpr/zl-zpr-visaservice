use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use tracing::{debug, info};

use zpr::vsapi_types::{ServiceDescriptor, Visa};

use crate::assembly::Assembly;
use crate::error::VssSyncError;
use crate::logging::targets::VSS;
use crate::policy_mgr::PolicySnapshot;
use crate::vss::VssCmd;
use crate::vss_worker;

pub struct VssMgr {
    // Each node has an entry here, handle is a thread monitoring the nodes VSS.
    workers: DashMap<IpAddr, VssHandle>,

    // Only used to spin up VSS handlers.
    jobs_tx: mpsc::Sender<Job>,
}

#[derive(Clone)]
pub struct VssHandle {
    // For sending requests to a VSS handler thread (all the API calls)
    cmd_tx: mpsc::Sender<VssCmd>,
}

enum Job {
    // Params for starting a VssHandle thread.
    StartVssWorker {
        asm: Arc<Assembly>,
        node_addr: IpAddr,
        vss_addr: SocketAddr,
        delay: std::time::Duration,
        cmd_rx: mpsc::Receiver<VssCmd>,
    },
}

/// The Vss Manager manages VSS connections for each node.
impl VssMgr {
    pub fn new() -> Self {
        let (jobs_tx, mut jobs_rx) = mpsc::channel(16);

        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        std::thread::spawn(move || {
            let local = LocalSet::new();
            local.spawn_local(async move {
                while let Some(job) = jobs_rx.recv().await {
                    tokio::task::spawn_local(run_vss_job(job));
                }
            });
            rt.block_on(local);
        });

        VssMgr {
            workers: DashMap::new(),
            jobs_tx,
        }
    }

    /// Start a task to manage the VSS connection to a node.  Waits for `delay` before starting.
    /// Once this starts, the first thing it does is send the services list across and if there
    /// is peer information from topology that is sent too.
    ///
    /// It them will periodically ping the vss API.
    ///
    /// Error is returned if a worker is already running for the node. If that happens caller
    /// should use [VssMgr::get_handle] to obtain the existing handle and then call [VssHandle::stop].
    /// Note that it takes time for handle to respond to stop and clear out state in this manager.
    pub fn start_vss_worker(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VssSyncError> {
        // Return error if we already have a worker for this node.
        if self.workers.contains_key(node_addr) {
            return Err(VssSyncError::DuplicateWorker(*vss_addr));
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);

        let job = Job::StartVssWorker {
            asm,
            node_addr: node_addr.clone(),
            vss_addr: *vss_addr,
            delay,
            cmd_rx,
        };
        let send_result = self.jobs_tx.try_send(job);
        if let Err(e) = send_result {
            return Err(VssSyncError::QueueFull(format!(
                "failed to queue VSS worker start job for {}: {}",
                vss_addr, e
            )));
        }
        let worker = VssHandle { cmd_tx };
        self.workers.insert(node_addr.clone(), worker);
        Ok(())
    }

    /// Start a VSS worker only if none is already running for this node.
    /// Uses DashMap entry to make this thread safe.
    ///
    /// Returns `true` if a new worker was started, `false` if one was already running.
    pub fn start_vss_worker_if_none(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<bool, VssSyncError> {
        // entry() holds the DashMap shard lock for the duration of the match, making the
        // check-and-insert atomic and preventing concurrent callers from both starting a worker.
        match self.workers.entry(*node_addr) {
            dashmap::Entry::Occupied(_) => Ok(false),
            dashmap::Entry::Vacant(slot) => {
                let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);
                let job = Job::StartVssWorker {
                    asm,
                    node_addr: *node_addr,
                    vss_addr: *vss_addr,
                    delay,
                    cmd_rx,
                };
                self.jobs_tx.try_send(job).map_err(|e| {
                    VssSyncError::QueueFull(format!(
                        "failed to queue VSS worker start job for {}: {}",
                        vss_addr, e
                    ))
                })?;
                slot.insert(VssHandle { cmd_tx });
                Ok(true)
            }
        }
    }

    /// Start a fresh VSS worker for the node, replacing any existing one
    /// (zipline#123, K2): the running worker (if any) is told to stop and its
    /// handle is overwritten immediately, so callers holding the old handle
    /// fail fast with `ConnClosed` once the worker exits. Used by
    /// `register_vss` when a reconnecting node re-registers its VSS while the
    /// previous session's worker is still around — the node restarted its VSS
    /// listener, so the old worker's connection is dead weight.
    pub fn restart_vss_worker(
        &self,
        asm: Arc<Assembly>,
        node_addr: &IpAddr,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VssSyncError> {
        if let Some(old) = self.get_handle(node_addr) {
            // Best-effort: a full channel or an already-dead worker both mean
            // the worker is on its way out; the map overwrite below is what
            // actually decommissions it.
            let _ = old.cmd_tx.try_send(VssCmd::Stop());
            self.workers.remove(node_addr);
        }
        self.start_vss_worker(asm, node_addr, vss_addr, delay)
    }

    /// Obtain a handle to the VSS worker for the given node. Using the handle you can
    /// send VSS API messages.
    pub fn get_handle(&self, naddr: &IpAddr) -> Option<VssHandle> {
        self.workers.get(naddr).map(|h| h.clone())
    }

    /// `true` iff a VSS worker for the node is in the map and its command
    /// channel is still open, i.e. the worker has not exited.
    ///
    /// The entry is inserted when the worker is queued, so a worker still in
    /// its start delay or still connecting counts as live. An exited worker
    /// closes its receiver before [VssMgr::clear_handle] removes the entry, so
    /// the closed-channel check also covers that short window. A replacement
    /// installed by [VssMgr::restart_vss_worker] is live as soon as it is in
    /// the map (zipline#187).
    pub fn has_live_worker(&self, naddr: &IpAddr) -> bool {
        self.workers
            .get(naddr)
            .is_some_and(|h| !h.cmd_tx.is_closed())
    }

    /// Install a handle whose commands go to a test-owned channel instead of a real
    /// VSS worker, so tests can answer `VssCmd`s directly (no capnp needed —
    /// [VssHandle] is just an mpsc sender). Overwrites any existing handle.
    #[cfg(test)]
    pub fn insert_test_handle(&self, node_addr: IpAddr, cmd_tx: mpsc::Sender<VssCmd>) {
        self.workers.insert(node_addr, VssHandle { cmd_tx });
    }

    /// Run the worker-exit housekeeping ([VssMgr::clear_handle]) without a real
    /// worker, so tests can model a VSS worker that has exited.
    #[cfg(test)]
    pub fn clear_handle_for_test(&self, naddr: &IpAddr) {
        self.clear_handle(naddr);
    }

    /// Housekeeping function to remove (presumably stale/not-running) worker.
    /// Called when the worker run loop exits.
    ///
    /// Removes the entry only when its command channel is closed — i.e. it
    /// still belongs to the exited worker. If [VssMgr::restart_vss_worker]
    /// already replaced the entry with a live worker's handle, that handle is
    /// left alone (zipline#123): the exiting worker must not tear down its
    /// replacement.
    ///
    /// TODO: May need a way to alert the system when the VSS worker stops unexpectedly.
    fn clear_handle(&self, naddr: &IpAddr) {
        self.workers.remove_if(naddr, |_, h| h.cmd_tx.is_closed());
    }
}

/// Each VSS thread has a handle to it stored in the [VssMgr] `workers` map.
impl VssHandle {
    async fn send_command(&self, cmd: VssCmd) -> Result<(), VssSyncError> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VssSyncError::ConnClosed)
    }

    /// Stop the worker.
    pub async fn stop(&self) -> Result<(), VssSyncError> {
        let cmd = VssCmd::Stop();
        self.send_command(cmd).await
    }

    /// Send visas to the node.
    pub async fn push_visas(&self, visas: Vec<Visa>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::PushVisas(visas, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Revoke visas installed on the node by their IDs.
    #[allow(dead_code)]
    pub async fn revoke_visas(&self, ids: Vec<u64>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeVisasById(ids, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Revoke authorizations present on the node for the given zpr addresses.
    pub async fn revoke_auths(&self, addrs: Vec<IpAddr>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Ask the node to start re-authentication for the given zpr addresses
    /// (contract K1, zipline#123). The node's own address means
    /// "re-authenticate yourself to the VS". Returns the number of addresses
    /// the node accepted the request for; outcomes are judged by `zpr.vinst`.
    pub async fn request_auths(&self, addrs: Vec<IpAddr>) -> Result<usize, VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RequestAuthsByZprAddr(addrs, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Tell the node about authentication services connected to the ZPRnet.
    pub async fn set_services(&self, services: Vec<ServiceDescriptor>) -> Result<(), VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::SetServices(services, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }

    /// Send a `setTopology` message to the node, built from `psnap` (see
    /// `vss_worker::proposed_links`).
    pub async fn set_topology(&self, psnap: PolicySnapshot) -> Result<(), VssSyncError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::SetTopology(psnap, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VssSyncError::ConnClosed)?
    }
}

// This rather convoluted pattern for starting a vss worker is here because the capn proto
// rpc system must run in a tokio local task.
//
// See https://docs.rs/tokio/latest/tokio/task/struct.LocalSet.html#use-inside-tokiospawn
//
// There is only ever one "job" implementation -- the job that starts a VSS worker.
//
// This is called in a new thread.
async fn run_vss_job(job: Job) {
    match job {
        Job::StartVssWorker {
            asm,
            node_addr,
            vss_addr,
            delay,
            cmd_rx,
        } => {
            debug!(target: VSS, "starting VSS worker for node {} at {}", node_addr, vss_addr);
            tokio::time::sleep(delay).await;
            vss_worker::vss_worker_loop(asm.clone(), vss_addr, cmd_rx).await;
            // When we exit the worker loop, we are done but the handle is still sitting in
            // the manager. So we clean it out here:
            asm.vss_mgr.clear_handle(&node_addr);
            info!(target: VSS, "VSS worker for node {} has exited", node_addr);
            // TODO: Do we need to track somewhere that we are no longer in communication with this node?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> IpAddr {
        "fd5a:5052::50".parse().unwrap()
    }

    #[test]
    fn has_live_worker_false_without_entry() {
        let mgr = VssMgr::new();
        assert!(!mgr.has_live_worker(&node()));
    }

    #[test]
    fn has_live_worker_true_with_open_channel() {
        let mgr = VssMgr::new();
        let (cmd_tx, _cmd_rx) = mpsc::channel::<VssCmd>(1);
        mgr.insert_test_handle(node(), cmd_tx);
        assert!(mgr.has_live_worker(&node()));
    }

    #[test]
    fn has_live_worker_false_after_worker_exit() {
        let mgr = VssMgr::new();
        let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(1);
        mgr.insert_test_handle(node(), cmd_tx);
        // The worker exits: its receiver drops before clear_handle runs.
        drop(cmd_rx);
        assert!(
            !mgr.has_live_worker(&node()),
            "a closed channel is not a live worker, even before clear_handle"
        );
        mgr.clear_handle(&node());
        assert!(
            mgr.get_handle(&node()).is_none(),
            "clear_handle drops the entry"
        );
        assert!(!mgr.has_live_worker(&node()));
    }

    /// The `restart_vss_worker` map effect: the old handle is overwritten by
    /// the new one, then the old worker exits and runs `clear_handle`. The
    /// replacement stays live (no false `false` across a restart).
    #[test]
    fn has_live_worker_true_across_restart() {
        let mgr = VssMgr::new();
        let (old_tx, old_rx) = mpsc::channel::<VssCmd>(1);
        mgr.insert_test_handle(node(), old_tx);
        let (new_tx, _new_rx) = mpsc::channel::<VssCmd>(1);
        mgr.insert_test_handle(node(), new_tx);
        drop(old_rx);
        mgr.clear_handle(&node());
        assert!(mgr.has_live_worker(&node()));
    }
}
