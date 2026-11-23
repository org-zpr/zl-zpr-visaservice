//! Durable visa-revocation obligations and the barrier that orders them
//! against the reconciler (zl-zipline#289).
//!
//! # The invariant
//!
//! A state write that can make live visas unacceptable -- a policy install, an
//! actor losing attributes (logout, a session replacement, a lossy renewal), a
//! trusted-service change, a disconnect removing an actor (zl-zipline#290) --
//! records a revocation obligation durably ([RevocationLedger::begin]) BEFORE it
//! writes. A policy obligation names the vinst it installs, and the reconciler
//! completes it only once that vinst is published. One reconciler
//! (`event_mgr::reconcile_obligations`, on the event worker) satisfies the
//! obligations: it runs the sweep and deletes them only when the sweep
//! completed with no failure. The auth-expiry sweeper's loop re-kicks it
//! every `MIN_VISA_LIFETIME` until then, and startup kicks it, so a
//! cancelled RPC, a failed sweep or a VS crash never loses the revocation.
//! No RPC handler sweeps by itself.
//!
//! # The barrier
//!
//! A writer holds the barrier's read side ([ObligationGuard]) from recording
//! its obligation until its write has committed (or failed). A reconciler
//! pass takes the write side only to list the pending obligations and bump
//! the [generation](RevocationLedger::generation) ([RevocationLedger::start_pass]),
//! then releases it before it sweeps. So every obligation a pass lists has
//! its write already committed or abandoned: a pass never deletes an
//! obligation whose write lands after the pass read the state.
//!
//! # The generation
//!
//! The generation is a sequence lock over passes (zl-zipline#248): a pass that
//! lists obligations bumps it at its start, making it odd, and again when it
//! ends ([Pass] drops), making it even. A visa request reads it before it reads
//! anything its decision rests on, and commits its visa only if no pass
//! overlapped it ([RevocationLedger::no_pass_overlapped]): the generation was
//! even then and is unchanged after the store.
//!
//! # Lock rule
//!
//! The guard is always the innermost of the visa service's coordination
//! locks. Take it after the topology operation lock ([crate::topology_mgr::TopoOps])
//! and the node commit lock (`PolicyMgr::node_commit_lock`); while holding
//! it, take no other coordination lock, await no bounded queue and never
//! take a second guard. tokio's `RwLock` is fair: once a pass waits for the
//! write side, new readers queue behind it, so a guard holder waiting on a
//! lock whose holder is itself waiting in [RevocationLedger::begin] would
//! deadlock with the pass.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{RwLock, RwLockReadGuard};

use crate::db::{DbConnection, Obligation, RevocationRepo};
use crate::error::StoreError;

/// The durable obligation store plus the barrier and generation that order
/// writers against reconciler passes. Lives in the `Assembly` as
/// `revocations`.
pub struct RevocationLedger {
    repo: RevocationRepo,
    barrier: RwLock<()>,
    generation: AtomicU64,
}

/// A reconciler pass in progress ([RevocationLedger::start_pass]): derefs to the
/// obligations it listed. Dropping it ends the pass -- on every exit, a panic
/// included -- by bumping the generation back to even, if the pass bumped it at
/// its start. Drop it only once the pass has recorded every revocation.
pub struct Pass<'ledger> {
    pending: Vec<(u64, Obligation)>,
    ledger: &'ledger RevocationLedger,
}

impl std::ops::Deref for Pass<'_> {
    type Target = Vec<(u64, Obligation)>;

    fn deref(&self) -> &Self::Target {
        &self.pending
    }
}

impl Drop for Pass<'_> {
    fn drop(&mut self) {
        // start_pass bumped only for a non-empty list.
        if !self.pending.is_empty() {
            self.ledger.generation.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Held by a writer from the moment its obligation is recorded until its
/// state write is done. Drop it right after the write, whatever the outcome
/// (success, error or cancellation all drop it).
pub struct ObligationGuard<'ledger> {
    _read: RwLockReadGuard<'ledger, ()>,
}

impl RevocationLedger {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        RevocationLedger {
            repo: RevocationRepo::new(db),
            barrier: RwLock::new(()),
            generation: AtomicU64::new(0),
        }
    }

    /// Record `obligation` and return the guard the caller holds across its state
    /// write. A failed record is returned as an error: the caller must then not
    /// write (fail closed), because nothing would revoke what the write
    /// invalidates. The one exception is a disconnect, which tears down anyway
    /// (`ConnectionControl::teardown_actor`).
    pub async fn begin(&self, obligation: Obligation) -> Result<ObligationGuard<'_>, StoreError> {
        let read = self.barrier.read().await;
        self.repo.add(&obligation).await?;
        Ok(ObligationGuard { _read: read })
    }

    /// Start a reconciler pass: wait until no writer holds a guard, list the
    /// pending obligations and, if there are any, bump the generation (to odd),
    /// then release the barrier. Every listed obligation's write has committed or
    /// been abandoned by the time this returns. The pass ends when the returned
    /// [Pass] is dropped.
    pub async fn start_pass(&self) -> Result<Pass<'_>, StoreError> {
        let _write = self.barrier.write().await;
        let pending = self.repo.list().await?;
        if !pending.is_empty() {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        Ok(Pass {
            pending,
            ledger: self,
        })
    }

    /// Delete the obligations `seqs` once a pass has satisfied them.
    pub async fn complete(&self, seqs: &[u64]) -> Result<(), StoreError> {
        for seq in seqs {
            self.repo.remove(*seq).await?;
        }
        Ok(())
    }

    /// The revocation generation (SeqCst): bumped to odd under the exclusive
    /// barrier at the start of every reconciler pass that lists at least one
    /// obligation -- after every write whose obligation it lists has committed,
    /// and before the pass reads any state -- and back to even when that pass
    /// ends. Odd means a pass is in progress. A visa request reads it before it
    /// reads its actors and policy (zl-zipline#248, see
    /// [RevocationLedger::no_pass_overlapped]).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Whether no reconciler pass overlapped a visa request that read
    /// [RevocationLedger::generation] `start` before it read anything its decision
    /// rests on, called after its visa is stored: no pass was in progress then
    /// (`start` even) and none started since (unchanged). Then every pass for a
    /// write the request did not see starts after the store, and lists the visa.
    /// Otherwise a pass may have read the state, or listed the visas, before the
    /// visa was stored, and the request must not commit it (`VisaMgr::create_visa`).
    pub fn no_pass_overlapped(&self, start: u64) -> bool {
        start.is_multiple_of(2) && self.generation() == start
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FakeDb;
    use std::time::Duration;

    /// The barrier: while a writer holds its guard a pass cannot start; once
    /// the guard is dropped the pass lists the obligation, and the generation
    /// is odd while the pass runs and even again once it ended. A request that
    /// read the generation before the pass sees it overlapped.
    #[tokio::test]
    async fn test_pass_waits_for_the_guard_and_bumps_the_generation() {
        let ledger = Arc::new(RevocationLedger::new(Arc::new(FakeDb::new())));
        let guard = ledger.begin(Obligation::attributes(vec![])).await.unwrap();
        let before = ledger.generation();
        assert!(ledger.no_pass_overlapped(before));

        let pass = tokio::spawn({
            let ledger = ledger.clone();
            async move {
                let pass = ledger.start_pass().await.unwrap();
                let during = ledger.generation();
                (pass.to_vec(), during)
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !pass.is_finished(),
            "a pass must wait for the writer's guard"
        );
        assert_eq!(ledger.generation(), before);

        drop(guard);
        let (listed, during) = pass.await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(during, before + 1, "odd while the pass runs");
        assert!(
            !ledger.no_pass_overlapped(during),
            "a request starting meanwhile"
        );
        assert_eq!(ledger.generation(), before + 2, "even once it ended");
        assert!(!ledger.no_pass_overlapped(before), "a request spanning it");

        // Completing deletes it; the next pass lists nothing.
        ledger.complete(&[listed[0].0]).await.unwrap();
        assert!(ledger.start_pass().await.unwrap().is_empty());
    }

    /// A pass with nothing pending does not bump the generation.
    #[tokio::test]
    async fn test_empty_pass_keeps_the_generation() {
        let ledger = RevocationLedger::new(Arc::new(FakeDb::new()));
        assert!(ledger.start_pass().await.unwrap().is_empty());
        assert_eq!(ledger.generation(), 0);
    }
}
