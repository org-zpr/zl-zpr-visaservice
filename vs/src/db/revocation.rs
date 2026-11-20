//! Redis/ValKey operations for pending visa-revocation obligations
//! (zl-zipline#289).
//!
//! A state write that can make live visas unacceptable (a policy install, an
//! actor losing attributes, a trusted-service change) first records an
//! obligation here; the reconciler (`event_mgr::reconcile_obligations`)
//! deletes it only once a visa sweep under the new state has completed. The
//! obligations live in the same state DB as the rest of VS state, so a VS
//! restart does not forget them. See `crate::revocation` for the protocol.
//!
//! - `revoke:seq` is a counter; each obligation takes the next value.
//! - `revoke:pending` is a hash from that sequence number (decimal string) to
//!   the JSON [Obligation].
//!
//! A record is never rewritten once added, so the reconciler deletes exactly
//! the entries it listed with no compare-and-delete: one added after the
//! listing has a new sequence number and stays.

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::db::DbConnection;
use crate::error::StoreError;

const KEY_REVOKE_SEQ: &str = "revoke:seq";
const KEY_REVOKE_PENDING: &str = "revoke:pending";

/// What changed, and so what the reconciler has to run before the visas are
/// re-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObligationKind {
    /// A policy install: the policy pass (node revalidation, links,
    /// re-authentication obligation) runs before the visa sweep.
    Policy,
    /// Actor attributes changed: the visa sweep alone.
    Attributes,
}

/// A pending revocation obligation: sweep the live visas because of `kind`,
/// and revoke every visa of each actor in `actors` that no longer exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub kind: ObligationKind,
    /// ZPR addresses of the actors whose attributes the write changed. Empty
    /// when the write is not about particular actors (a policy install, a
    /// trusted-service change).
    pub actors: Vec<IpAddr>,
}

pub struct RevocationRepo {
    db: Arc<dyn DbConnection>,
}

impl RevocationRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        RevocationRepo { db }
    }

    /// Record `ob` under a fresh sequence number, which is returned. Sequence
    /// numbers only go up, so no record is ever overwritten.
    pub async fn add(&self, ob: &Obligation) -> Result<u64, StoreError> {
        let json = serde_json::to_string(ob)
            .map_err(|e| StoreError::InvalidData(format!("revocation obligation: {e}")))?;
        let seq = self.db.incr(KEY_REVOKE_SEQ, 1).await?;
        // Set-if-absent: a record is never overwritten, and the counter never
        // hands out a number twice, so a taken field means the store is corrupt.
        if !self
            .db
            .hset_nx(KEY_REVOKE_PENDING, &seq.to_string(), &json)
            .await?
        {
            return Err(StoreError::InvalidData(format!(
                "revocation obligation {seq} already exists"
            )));
        }
        Ok(seq)
    }

    /// All pending obligations with their sequence numbers, in sequence
    /// order. An unparseable entry is logged and deleted rather than wedging
    /// every reconciler pass on one bad record.
    pub async fn list(&self) -> Result<Vec<(u64, Obligation)>, StoreError> {
        let map = self.db.hgetall(KEY_REVOKE_PENDING.to_string()).await?;
        let mut obligations = Vec::with_capacity(map.len());
        for (seq_str, json) in map {
            let (Ok(seq), Ok(ob)) = (
                seq_str.parse::<u64>(),
                serde_json::from_str::<Obligation>(&json),
            ) else {
                tracing::error!(
                    "dropping unparseable revocation obligation: seq={seq_str} value={json}"
                );
                self.db.hdel(KEY_REVOKE_PENDING, &seq_str).await?;
                continue;
            };
            obligations.push((seq, ob));
        }
        obligations.sort_by_key(|(seq, _)| *seq);
        Ok(obligations)
    }

    /// Delete the obligation `seq` (satisfied). Deleting an absent entry is a
    /// no-op.
    pub async fn remove(&self, seq: u64) -> Result<(), StoreError> {
        self.db.hdel(KEY_REVOKE_PENDING, &seq.to_string()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FakeDb;

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Obligations round-trip through the store in sequence order, sequence
    /// numbers only go up, and removal deletes exactly one entry.
    #[tokio::test]
    async fn test_obligations_roundtrip_and_remove() {
        let repo = RevocationRepo::new(Arc::new(FakeDb::new()));
        assert!(repo.list().await.unwrap().is_empty());

        let policy = Obligation {
            kind: ObligationKind::Policy,
            actors: vec![],
        };
        let attrs = Obligation {
            kind: ObligationKind::Attributes,
            actors: vec![addr("fd5a:5052:3000::1")],
        };
        let s1 = repo.add(&policy).await.unwrap();
        let s2 = repo.add(&attrs).await.unwrap();
        assert!(s2 > s1);
        assert_eq!(
            repo.list().await.unwrap(),
            vec![(s1, policy.clone()), (s2, attrs.clone())]
        );

        repo.remove(s1).await.unwrap();
        assert_eq!(repo.list().await.unwrap(), vec![(s2, attrs.clone())]);

        // Removing an absent entry is a no-op, and a removed number is never
        // handed out again.
        repo.remove(s1).await.unwrap();
        let s3 = repo.add(&policy).await.unwrap();
        assert!(s3 > s2);
    }

    /// An unparseable record is dropped from the store, not returned.
    #[tokio::test]
    async fn test_unparseable_obligation_is_dropped() {
        let db = Arc::new(FakeDb::new());
        let repo = RevocationRepo::new(db.clone());
        db.hset(KEY_REVOKE_PENDING, "7", "not json").await.unwrap();
        db.hset(KEY_REVOKE_PENDING, "x", r#"{"kind":"policy","actors":[]}"#)
            .await
            .unwrap();
        assert!(repo.list().await.unwrap().is_empty());
        assert!(
            db.hgetall(KEY_REVOKE_PENDING.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
