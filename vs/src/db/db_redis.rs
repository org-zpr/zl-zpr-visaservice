use redis::AsyncCommands;
use redis::Script;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use crate::db::{DbConnection, DbOp, DbResult, LockDescriptor};

pub struct RedisDb {
    mgr: redis::aio::ConnectionManager,
    locks: Mutex<HashSet<LockDescriptor>>,
}

impl RedisDb {
    pub fn new(mgr: redis::aio::ConnectionManager) -> Self {
        RedisDb {
            mgr,
            locks: Mutex::new(HashSet::new()),
        }
    }

    /// Clear a lock from redis.
    /// Returns TRUE if we were able to release a lock specified by the descriptor, or if no lock exists.
    /// Returns FALSE only if the lock exists and is not "ours".
    async fn release_lock_in_redis(&self, desc: &LockDescriptor) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let script = Script::new(
            r"
                local current = redis.call('GET', KEYS[1])
                if current == false then
                    return 2
                elseif current == ARGV[1] then
                    return redis.call('DEL', KEYS[1])
                else
                    return 0
                end
        ",
        );
        // Script returns:
        //   0 if lock exists but is not ours
        //   1 if lock existed, was ours and was deleted
        //   2 if lock didn't exist to begin with

        let res: i64 = script
            .key(&desc.key)
            .arg(&desc.ident)
            .invoke_async(&mut conn)
            .await?;
        Ok(res >= 1)
    }
}

#[async_trait::async_trait]
impl DbConnection for RedisDb {
    async fn exists(&self, key: &str) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let foo: bool = conn.exists(key).await?;
        Ok(foo)
    }

    async fn set(&self, key: &str, value: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set(key, value).await?;
        Ok(())
    }

    async fn set_ex(&self, key: &str, value: &str, seconds: u64) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set_ex(key, value, seconds).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> DbResult<Option<String>> {
        let mut conn = self.mgr.clone();
        let res: Option<String> = conn.get(key).await?;
        Ok(res)
    }

    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set(key, value).await?;
        Ok(())
    }

    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set_ex(key, value, seconds).await?;
        Ok(())
    }

    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>> {
        let mut conn = self.mgr.clone();
        let res: Vec<u8> = conn.get(key).await?;
        Ok(res)
    }

    async fn del(&self, key: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }

    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>> {
        let mut conn = self.mgr.clone();
        let res: HashSet<String> = conn.smembers(key).await?;
        Ok(res)
    }

    async fn sismember(&self, key: &str, member: &str) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let res: bool = conn.sismember(key, member).await?;
        Ok(res)
    }

    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>> {
        let mut conn = self.mgr.clone();
        let res: Option<String> = conn.hget(key, field).await?;
        Ok(res)
    }

    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>> {
        let mut conn = self.mgr.clone();
        let res: HashMap<String, String> = conn.hgetall(key).await?;
        Ok(res)
    }

    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hset(key, field, value).await?;
        Ok(())
    }

    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        // Redis HSETNX returns 1 when the field was set by this call, 0 when it
        // already existed; surface that as the claim result.
        let set: bool = conn.hset_nx(key, field, value).await?;
        Ok(set)
    }

    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hset_multiple(key, field_values).await?;
        Ok(())
    }

    async fn hdel(&self, key: &str, field: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hdel(key, field).await?;
        Ok(())
    }

    async fn sadd(&self, key: &str, member: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.sadd(key, member).await?;
        Ok(())
    }

    async fn incr(&self, key: &str, by: u64) -> DbResult<u64> {
        let mut conn = self.mgr.clone();
        let res: u64 = conn.incr(key, by).await?;
        Ok(res)
    }

    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.expire(key, seconds).await?;
        Ok(())
    }

    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = pipeline_of(ops).query_async(&mut conn).await?;
        Ok(())
    }

    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>> {
        let mut conn = self.mgr.clone();
        let mut results = Vec::new();

        // Redis SCAN_MATCH can return duplicate keys so we de-dupe before returning.
        let mut seen = HashSet::new();

        let mut iter: redis::AsyncIter<String> = conn.scan_match(pattern).await?;
        while let Some(key_res) = iter.next_item().await {
            let key = key_res?;
            if seen.insert(key.clone()) {
                results.push(key);
            }
        }

        Ok(results)
    }

    async fn clear_state(&self) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.flushdb().await?;
        Ok(())
    }

    async fn shutdown_cleanup(&self) -> DbResult<()> {
        // Note that this holds the lock across the redis I/O calls.
        for ldesc in self.locks.lock().await.drain() {
            // Best effort... this call produce an error.
            let _ = self.release_lock_in_redis(&ldesc).await;
        }
        Ok(())
    }

    async fn acquire_or_renew_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        // Note that this holds the lock across the redis I/O call.
        let mut locks_guard = self.locks.lock().await;
        let mut conn = self.mgr.clone();
        let script = Script::new(
            r"
                local current = redis.call('GET', KEYS[1])
                if current == false then
                    -- Key doesn't exist, acquire it
                    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
                    return 1
                elseif current == ARGV[1] then
                    -- We hold the lock, reset the TTL
                    redis.call('PEXPIRE', KEYS[1], ARGV[2])
                    return 1
                else
                    -- Someone else holds it
                    return 0
                end
            ",
        );

        let res: i64 = script
            .key(&desc.key)
            .arg(&desc.ident)
            .arg(desc.timeout.as_millis() as u64)
            .invoke_async(&mut conn)
            .await?;

        // Note: it is possible for the LUA to run, but to then lose the return message from redis.
        // Since we are running REDIS on localhost this is unlikely. If that were to happen we would
        // end up with the lock in redis but not in our local set.

        if res == 1 {
            locks_guard.insert(desc.clone());
        }
        Ok(res == 1)
    }

    async fn release_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        // Note that this holds the lock across the redis I/O call.
        let mut locks_guard = self.locks.lock().await;
        let released = self.release_lock_in_redis(desc).await?;

        // May as well remove from our memory since it definately isn't in the DB.
        locks_guard.remove(desc);

        // Note: LUA script returns 2 when lock doesn't exist to begin with.
        Ok(released)
    }
}

/// The redis pipeline for [DbConnection::atomic_pipeline]: `ops` in order, as one
/// MULTI/EXEC transaction, so a dropped connection or a crash never leaves part of
/// them applied (zl-zipline#290).
fn pipeline_of(ops: &[DbOp]) -> redis::Pipeline {
    let mut piper = redis::pipe();
    piper.atomic();
    for op in ops {
        match op {
            DbOp::Del(key) => {
                piper.del(key);
            }
            DbOp::SetBin { key, value } => {
                piper.set(key, value.as_slice());
            }
            DbOp::SRem { set_key, member } => {
                piper.srem(set_key, member);
            }
            DbOp::HSet {
                hash_key,
                field,
                value,
            } => {
                piper.hset(hash_key, field, value);
            }
            DbOp::HSetMultiple {
                hash_key,
                field_values,
            } => {
                piper.hset_multiple(hash_key, field_values);
            }
            DbOp::Expire { key, seconds } => {
                piper.expire(key, *seconds);
            }
        }
    }
    piper
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zl-zipline#290 (local codex P1): `atomic_pipeline` must be atomic, as its
    /// callers rely on (e.g. a policy write's container, `phash` and `vinst`), so it
    /// is sent as one MULTI/EXEC transaction, not as separate commands.
    #[test]
    fn test_atomic_pipeline_is_a_transaction() {
        let packed = pipeline_of(&[DbOp::HSet {
            hash_key: "policy:current".into(),
            field: "vinst".into(),
            value: "2".into(),
        }])
        .get_packed_pipeline();
        let text = String::from_utf8_lossy(&packed);
        assert!(text.contains("MULTI") && text.contains("EXEC"), "{text}");
    }
}
