//! Redis/ValKey operations for pending re-authentication obligations
//! (zipline#123).
//!
//! A policy install records the obligation `(V, T)`: every connected actor
//! must re-authenticate under policy generation `V` (its `zpr.vinst` must
//! reach `V`) by deadline `T` or be revoked. The obligations persist in the
//! same state DB as the rest of VS state so a VS restart does not forget
//! them:
//!
//! - `reauth:pending` is a hash mapping the vinst (decimal string) to the
//!   deadline as unix seconds (decimal string).
//!
//! Entries are pruned when satisfied or enforced (see `auth_sweep`).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::db::DbConnection;
use crate::error::StoreError;

const KEY_REAUTH_PENDING: &str = "reauth:pending";

/// A pending re-authentication obligation: actors whose `zpr.vinst` is below
/// `vinst` must re-authenticate by `deadline` or be revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReauthObligation {
    pub vinst: u64,
    pub deadline: SystemTime,
}

pub struct ReauthRepo {
    db: Arc<dyn DbConnection>,
}

impl ReauthRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        ReauthRepo { db }
    }

    /// Record the obligation `(vinst, deadline)`. An existing entry for the
    /// same vinst is kept: the first deadline for a generation wins, so a
    /// reconciler pass that runs again for the same install (its revocation
    /// obligation is retried, zl-zipline#289) cannot postpone enforcement. The
    /// read-then-write is not atomic; it needs no lock because the only writer
    /// is the policy pass, which runs on the event worker, one pass at a time.
    pub async fn add_obligation(&self, ob: &ReauthObligation) -> Result<(), StoreError> {
        let deadline_secs = ob
            .deadline
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::InvalidData("reauth deadline predates the epoch".into()))?
            .as_secs();
        let field = ob.vinst.to_string();
        if self.db.hget(KEY_REAUTH_PENDING, &field).await?.is_some() {
            return Ok(());
        }
        self.db
            .hset(KEY_REAUTH_PENDING, &field, &deadline_secs.to_string())
            .await?;
        Ok(())
    }

    /// All pending obligations, unordered. Unparseable entries are dropped
    /// with an error rather than wedging every sweep pass on one bad record.
    pub async fn list_obligations(&self) -> Result<Vec<ReauthObligation>, StoreError> {
        let map = self.db.hgetall(KEY_REAUTH_PENDING.to_string()).await?;
        let mut obligations = Vec::with_capacity(map.len());
        for (vinst_str, deadline_str) in map {
            let (Ok(vinst), Ok(deadline_secs)) =
                (vinst_str.parse::<u64>(), deadline_str.parse::<u64>())
            else {
                tracing::error!(
                    "dropping unparseable reauth obligation: vinst={vinst_str} deadline={deadline_str}"
                );
                self.db.hdel(KEY_REAUTH_PENDING, &vinst_str).await?;
                continue;
            };
            obligations.push(ReauthObligation {
                vinst,
                deadline: UNIX_EPOCH + Duration::from_secs(deadline_secs),
            });
        }
        Ok(obligations)
    }

    /// Remove the obligation for `vinst` (satisfied or enforced). Removing an
    /// absent entry is a no-op.
    pub async fn remove_obligation(&self, vinst: u64) -> Result<(), StoreError> {
        self.db.hdel(KEY_REAUTH_PENDING, &vinst.to_string()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FakeDb;

    fn t(secs_from_epoch: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs_from_epoch)
    }

    /// The first deadline recorded for a generation wins (VS#79 Copilot r2): a
    /// reconciler pass that runs again for the same install (its revocation
    /// obligation could not be deleted, or a later step failed) must not push the
    /// re-authentication deadline out on every retry.
    #[tokio::test]
    async fn test_first_deadline_wins() {
        let repo = ReauthRepo::new(Arc::new(FakeDb::new()));
        repo.add_obligation(&ReauthObligation {
            vinst: 7,
            deadline: t(1_000),
        })
        .await
        .unwrap();
        repo.add_obligation(&ReauthObligation {
            vinst: 7,
            deadline: t(2_000),
        })
        .await
        .unwrap();
        let listed = repo.list_obligations().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].deadline,
            t(1_000),
            "the retry must keep the first deadline"
        );
    }

    /// Obligations round-trip through the store: what was added is listed
    /// back with second precision, and removal prunes exactly one entry.
    #[tokio::test]
    async fn test_obligations_roundtrip_and_remove() {
        let repo = ReauthRepo::new(Arc::new(FakeDb::new()));
        assert!(repo.list_obligations().await.unwrap().is_empty());

        let ob1 = ReauthObligation {
            vinst: 2,
            deadline: t(1_000_000),
        };
        let ob2 = ReauthObligation {
            vinst: 3,
            deadline: t(1_000_300),
        };
        repo.add_obligation(&ob1).await.unwrap();
        repo.add_obligation(&ob2).await.unwrap();

        let mut got = repo.list_obligations().await.unwrap();
        got.sort_by_key(|o| o.vinst);
        assert_eq!(got, vec![ob1, ob2]);

        repo.remove_obligation(2).await.unwrap();
        let got = repo.list_obligations().await.unwrap();
        assert_eq!(got, vec![ob2]);

        // Removing an absent entry is a no-op.
        repo.remove_obligation(99).await.unwrap();
        assert_eq!(repo.list_obligations().await.unwrap(), vec![ob2]);
    }
}
