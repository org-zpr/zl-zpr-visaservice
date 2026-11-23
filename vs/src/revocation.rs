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
    /// pending obligations and, if there are any, bump the generation, then
    /// release the barrier. Every listed obligation's write has committed or
    /// been abandoned by the time this returns.
    pub async fn start_pass(&self) -> Result<Vec<(u64, Obligation)>, StoreError> {
        let _write = self.barrier.write().await;
        let pending = self.repo.list().await?;
        if !pending.is_empty() {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        Ok(pending)
    }

    /// Delete the obligations `seqs` once a pass has satisfied them.
    pub async fn complete(&self, seqs: &[u64]) -> Result<(), StoreError> {
        for seq in seqs {
            self.repo.remove(*seq).await?;
        }
        Ok(())
    }

    /// The revocation generation: bumped (SeqCst) under the exclusive barrier
    /// at the start of every reconciler pass that lists at least one
    /// obligation -- after every write whose obligation it lists has
    /// committed, and before the pass reads any visa. A visa request that
    /// reads it before reading its actors and policy and again after storing
    /// its visa knows, if it moved, that a revocation may have missed the visa
    /// (zl-zipline#248, `VisaMgr::check_commit_generation`).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FakeDb;
    use std::time::Duration;

    /// The barrier: while a writer holds its guard a pass cannot start; once
    /// the guard is dropped the pass lists the obligation and the generation
    /// has moved.
    #[tokio::test]
    async fn test_pass_waits_for_the_guard_and_bumps_the_generation() {
        let ledger = Arc::new(RevocationLedger::new(Arc::new(FakeDb::new())));
        let guard = ledger.begin(Obligation::attributes(vec![])).await.unwrap();
        let before = ledger.generation();

        let pass = tokio::spawn({
            let ledger = ledger.clone();
            async move { ledger.start_pass().await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !pass.is_finished(),
            "a pass must wait for the writer's guard"
        );
        assert_eq!(ledger.generation(), before);

        drop(guard);
        let listed = pass.await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(ledger.generation(), before + 1);

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
