//! Fake database backend for testing.

use dashmap::mapref::entry::Entry as DashEntry;
use dashmap::{DashMap, DashSet};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tokio::time::Instant;

use crate::db::{DbConnection, DbOp, DbResult, LockDescriptor};

/// Fault-injection mode for a specific write op, used by write-through tests.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultMode {
    /// No fault: op behaves normally.
    #[default]
    None,
    /// Return an error without applying the mutation.
    Reject,
    /// Apply the mutation but still return an error (simulates an ambiguous
    /// commit where the reply was lost).
    ApplyThenError,
}

#[allow(dead_code)]
pub struct FakeDb {
    store: DashMap<String, Entry>,

    // All the operations take read lock except *_atomic ones which take write lock.
    lock: RwLock<()>,

    // Sticky fault injected on the corresponding op until reset. std Mutex is
    // fine: no await is held across it.
    set_ex_fault: std::sync::Mutex<FaultMode>,
    del_fault: std::sync::Mutex<FaultMode>,
    hset_fault: std::sync::Mutex<FaultMode>,
    exists_fault: std::sync::Mutex<FaultMode>,
    scan_fault: std::sync::Mutex<FaultMode>,
}

#[allow(dead_code)]
struct Entry {
    value: FakeDbValue,
    exp: Instant,
}

#[allow(dead_code)]
enum FakeDbValue {
    Str(String),
    Bin(Vec<u8>),
    Hash(DashMap<String, String>),
    Set(DashSet<String>),
}

impl FakeDb {
    #[allow(dead_code)]
    pub fn new() -> Self {
        FakeDb {
            store: DashMap::new(),
            lock: RwLock::new(()),
            set_ex_fault: std::sync::Mutex::new(FaultMode::None),
            del_fault: std::sync::Mutex::new(FaultMode::None),
            hset_fault: std::sync::Mutex::new(FaultMode::None),
            exists_fault: std::sync::Mutex::new(FaultMode::None),
            scan_fault: std::sync::Mutex::new(FaultMode::None),
        }
    }

    /// Inject a fault mode on the next (and subsequent) `set_ex` calls.
    #[allow(dead_code)]
    pub fn set_set_ex_fault(&self, mode: FaultMode) {
        *self.set_ex_fault.lock().unwrap() = mode;
    }

    /// Inject a fault mode on the next (and subsequent) `del` calls.
    #[allow(dead_code)]
    pub fn set_del_fault(&self, mode: FaultMode) {
        *self.del_fault.lock().unwrap() = mode;
    }

    /// Inject a fault on the next (and subsequent) `exists` calls: a read
    /// fault (any mode other than `None` fails the read).
    #[allow(dead_code)]
    pub fn set_exists_fault(&self, mode: FaultMode) {
        *self.exists_fault.lock().unwrap() = mode;
    }

    /// Inject a fault on the next (and subsequent) `scan_match_all` calls: a read
    /// fault (any mode other than `None` fails the read).
    #[allow(dead_code)]
    pub fn set_scan_fault(&self, mode: FaultMode) {
        *self.scan_fault.lock().unwrap() = mode;
    }

    /// Inject a fault mode on the next (and subsequent) `hset` calls.
    #[allow(dead_code)]
    pub fn set_hset_fault(&self, mode: FaultMode) {
        *self.hset_fault.lock().unwrap() = mode;
    }
}

/// A generic redis-shaped error to surface an injected fault.
fn injected_fault_err() -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::UnexpectedReturnType, "injected fault"))
}

impl Entry {
    #[allow(dead_code)]
    fn new(value: FakeDbValue) -> Self {
        Entry {
            value,
            exp: Instant::now() + std::time::Duration::from_secs(86400), // + 1 day
        }
    }

    #[allow(dead_code)]
    fn new_ex(value: FakeDbValue, seconds: u64) -> Self {
        Entry {
            value,
            exp: Instant::now() + std::time::Duration::from_secs(seconds),
        }
    }
}

#[allow(dead_code)]
impl FakeDb {
    async fn exists_with_lock(&self, key: &str) -> DbResult<bool> {
        if let Some(entry) = self.store.get(key) {
            if Instant::now() > entry.exp {
                drop(entry);
                self.store.remove(key);
                return Ok(false);
            }
            return Ok(true);
        }
        Ok(self.store.contains_key(key))
    }

    async fn del_with_lock(&self, key: &str) -> DbResult<()> {
        self.store.remove(key);
        Ok(())
    }

    /// Set a binary value without taking the outer lock (caller holds it).
    async fn set_bin_with_lock(&self, key: &str, value: &[u8]) -> DbResult<()> {
        self.store.insert(
            key.to_string(),
            Entry::new(FakeDbValue::Bin(value.to_vec())),
        );
        Ok(())
    }

    async fn hset_with_lock(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                h.insert(field.to_string(), value.to_string());
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "value is not a hash",
            ))),
        }
    }

    async fn hset_multiple_with_lock(
        &self,
        key: &str,
        field_values: &[(String, String)],
    ) -> DbResult<()> {
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                for (field, value) in field_values {
                    h.insert(field.to_string(), value.to_string());
                }
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "value is not a hash",
            ))),
        }
    }

    /// Remove a member from a set.
    async fn srem_with_lock(&self, key: &str, member: &str) -> DbResult<()> {
        if !self.exists_with_lock(key).await? {
            return Ok(());
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Set(s) => {
                    s.remove(member);
                    Ok(())
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a set",
                ))),
            }
        } else {
            Ok(())
        }
    }

    async fn expire_with_lock(&self, key: &str, seconds: i64) -> DbResult<()> {
        if !self.exists_with_lock(key).await? {
            return Ok(());
        }
        if seconds <= 0 {
            self.store.remove(key);
            return Ok(());
        }
        if let Some(mut entry) = self.store.get_mut(key) {
            entry.exp = Instant::now() + std::time::Duration::from_secs(seconds as u64);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DbConnection for FakeDb {
    async fn shutdown_cleanup(&self) -> DbResult<()> {
        Ok(())
    }

    /// True if the key exists (and not expired).  As a side effect this removes the
    /// key if it is expired before returning false.
    async fn exists(&self, key: &str) -> DbResult<bool> {
        if *self.exists_fault.lock().unwrap() != FaultMode::None {
            return Err(injected_fault_err());
        }
        let _rlock = self.lock.read().await;
        self.exists_with_lock(key).await
    }

    /// Set a string value.
    async fn set(&self, key: &str, value: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new(FakeDbValue::Str(value.to_string())),
        );
        Ok(())
    }

    /// Set a string value with expiration.
    async fn set_ex(&self, key: &str, value: &str, seconds: u64) -> DbResult<()> {
        let fault = *self.set_ex_fault.lock().unwrap();
        if fault == FaultMode::Reject {
            return Err(injected_fault_err());
        }
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new_ex(FakeDbValue::Str(value.to_string()), seconds),
        );
        if fault == FaultMode::ApplyThenError {
            return Err(injected_fault_err());
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> DbResult<Option<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(None);
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Str(s) => Ok(Some(s.clone())),
                FakeDbValue::Bin(b) => Ok(Some(String::from_utf8_lossy(b).to_string())),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not string",
                ))),
            }
        } else {
            Ok(None)
        }
    }

    /// Set a binary value.
    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.set_bin_with_lock(key, value).await
    }

    /// Set a binary value with expiration.
    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new_ex(FakeDbValue::Bin(value.to_vec()), seconds),
        );
        Ok(())
    }

    /// Get a binary value.
    /// TODO: What does rust redis return when key is not found?
    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "key not found",
            )));
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Bin(b) => Ok(b.clone()),
                FakeDbValue::Str(s) => Ok(s.as_bytes().to_vec()),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not binary",
                ))),
            }
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "key not found",
            )))
        }
    }

    /// Delete a key.
    async fn del(&self, key: &str) -> DbResult<()> {
        let fault = *self.del_fault.lock().unwrap();
        if fault == FaultMode::Reject {
            return Err(injected_fault_err());
        }
        let _rlock = self.lock.read().await;
        self.del_with_lock(key).await?;
        if fault == FaultMode::ApplyThenError {
            return Err(injected_fault_err());
        }
        Ok(())
    }

    /// Get all members of a set.  Returns empty set if key does not exist.
    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(HashSet::new());
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Set(s) => {
                    let mut result = HashSet::new();
                    for item in s.iter() {
                        result.insert(item.key().clone());
                    }
                    Ok(result)
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a set",
                ))),
            }
        } else {
            Ok(HashSet::new())
        }
    }

    async fn sismember(&self, key: &str, member: &str) -> DbResult<bool> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(false);
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Set(s) => Ok(s.contains(member)),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a set",
                ))),
            }
        } else {
            Ok(false)
        }
    }

    /// Get a field from a hash.
    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(None);
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Hash(h) => Ok(h.get(field).map(|v| v.value().clone())),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a hash",
                ))),
            }
        } else {
            Ok(None)
        }
    }

    /// Get all fields and values from a hash. Returns empty map if key does not exist.
    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(&key).await? {
            return Ok(HashMap::new());
        }
        if let Some(entry) = self.store.get(&key) {
            match &entry.value {
                FakeDbValue::Hash(h) => {
                    let mut result = HashMap::new();
                    for item in h.iter() {
                        result.insert(item.key().clone(), item.value().clone());
                    }
                    Ok(result)
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a hash",
                ))),
            }
        } else {
            Ok(HashMap::new())
        }
    }

    /// Set a field in a hash.
    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let fault = *self.hset_fault.lock().unwrap();
        if fault == FaultMode::Reject {
            return Err(injected_fault_err());
        }
        let _rlock = self.lock.read().await;
        self.hset_with_lock(key, field, value).await?;
        if fault == FaultMode::ApplyThenError {
            return Err(injected_fault_err());
        }
        Ok(())
    }

    /// Remove a field from a hash. Absent field or key is a no-op (HDEL).
    async fn hdel(&self, key: &str, field: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Hash(h) => {
                    h.remove(field);
                    Ok(())
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::UnexpectedReturnType,
                    "value is not a hash",
                ))),
            }
        } else {
            Ok(())
        }
    }

    /// Set the hash field only if the field with that name does not already exist.
    /// Returns true when this call set it (mirrors redis HSETNX).
    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<bool> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                let mut set_by_this_call = false;
                h.entry(field.to_string()).or_insert_with(|| {
                    set_by_this_call = true;
                    value.to_string()
                });
                Ok(set_by_this_call)
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "value is not a hash",
            ))),
        }
    }

    /// Set multiple hash fields at once.
    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let owned: Vec<(String, String)> = field_values
            .iter()
            .map(|(f, v)| (f.to_string(), v.to_string()))
            .collect();
        self.hset_multiple_with_lock(key, &owned).await
    }

    /// Add a member to a set, creating the set if it does not exist.
    async fn sadd(&self, key: &str, member: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Set(DashSet::new())));
        match &entry.value {
            FakeDbValue::Set(s) => {
                s.insert(member.to_string());
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "value is not a set",
            ))),
        }
    }

    /// Increment number stored at key by `by` amount. If key does not exist, it is set to 0 before incrementing.
    async fn incr(&self, key: &str, by: u64) -> DbResult<u64> {
        let _rlock = self.lock.read().await;
        let mut entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Str("0".to_string())));
        match &entry.value {
            FakeDbValue::Str(s) => {
                let mut num: u64 = s.parse().map_err(|_| {
                    redis::RedisError::from((
                        redis::ErrorKind::UnexpectedReturnType,
                        "value is not an integer",
                    ))
                })?;
                num += by;
                entry.value = FakeDbValue::Str(num.to_string());
                Ok(num)
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "value is not a string",
            ))),
        }
    }

    /// Set key expiration in seconds.
    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.expire_with_lock(key, seconds).await
    }

    /// To simulate atomic we take a lock that prevents all the other operations
    /// from running.
    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()> {
        // Models Redis MULTI/EXEC atomicity: a Reject fails the whole pipeline
        // before any op applies, so callers can test the all-or-nothing contract.
        if *self.set_ex_fault.lock().unwrap() == FaultMode::Reject {
            return Err(injected_fault_err());
        }
        let _wlock = self.lock.write().await;
        for op in ops {
            match op {
                DbOp::Del(key) => {
                    self.del_with_lock(key).await?;
                }
                DbOp::SetBin { key, value } => {
                    self.set_bin_with_lock(key, value).await?;
                }
                DbOp::SRem { set_key, member } => {
                    self.srem_with_lock(set_key, member).await?;
                }
                DbOp::HSet {
                    hash_key,
                    field,
                    value,
                } => {
                    self.hset_with_lock(hash_key, field, value).await?;
                }
                DbOp::HSetMultiple {
                    hash_key,
                    field_values,
                } => {
                    self.hset_multiple_with_lock(hash_key, field_values).await?;
                }
                DbOp::Expire { key, seconds } => {
                    self.expire_with_lock(key, *seconds).await?;
                }
            }
        }

        Ok(())
    }

    /// Return the set of keys that match the pattern.
    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>> {
        if *self.scan_fault.lock().unwrap() != FaultMode::None {
            return Err(injected_fault_err());
        }
        let _rlock = self.lock.read().await;
        let mut results = Vec::new();
        let pattern = pattern.replace("*", ".*");
        let re = Regex::new(&pattern).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "invalid pattern regex",
                e.to_string(),
            ))
        })?;
        for key in self.store.iter().map(|e| e.key().clone()) {
            if re.is_match(&key) {
                results.push(key);
            }
        }
        Ok(results)
    }

    async fn clear_state(&self) -> DbResult<()> {
        let _wlock = self.lock.write().await;
        self.store.clear();
        Ok(())
    }

    async fn acquire_or_renew_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        let _rlock = self.lock.read().await;
        match self.store.entry(desc.key.clone()) {
            DashEntry::Occupied(mut occ) => {
                let entry = occ.get_mut();
                if entry.exp < Instant::now() {
                    // Lock expired, so we can take it.
                    entry.exp = Instant::now() + desc.timeout;
                    entry.value = FakeDbValue::Str(desc.ident.clone());
                    Ok(true)
                } else {
                    // Not expired. Is it ours?
                    match &entry.value {
                        FakeDbValue::Str(s) => {
                            if s == &desc.ident {
                                // It's our lock, we can renew it.
                                entry.exp = Instant::now() + desc.timeout;
                                Ok(true)
                            } else {
                                // Not our lock and not expired, can't take it.
                                Ok(false)
                            }
                        }
                        _ => panic!("found a lock value that is not a string"),
                    }
                }
            }
            DashEntry::Vacant(vac) => {
                // Key absent: insert atomically under the shard lock.
                vac.insert(Entry::new_ex(
                    FakeDbValue::Str(desc.ident.clone()),
                    desc.timeout.as_secs(),
                ));
                Ok(true)
            }
        }
    }

    async fn release_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        let _rlock = self.lock.read().await;
        if let Some(entry) = self.store.get(&desc.key) {
            if entry.exp >= Instant::now() {
                // Not expired. Is it ours?
                match &entry.value {
                    FakeDbValue::Str(s) => {
                        if s != &desc.ident {
                            // Not our lock.
                            return Ok(false);
                        }
                    }
                    _ => panic!("found a lock value that is not a string"),
                }
            }
        } else {
            // not there
            return Ok(true);
        }
        // Either expired or ours, we can delete it.
        self.store.remove(&desc.key);
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_fake_db_set_get() {
        let db = FakeDb::new();
        db.set("key1", "value1").await.unwrap();
        let val = db.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_fake_db_set_bin_get_bin_roundtrip() {
        let db = FakeDb::new();
        let payload = b"hello\xffworld";
        db.set_bin("bin:key", payload).await.unwrap();
        let got = db.get_bin("bin:key").await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test(start_paused = true)]
    async fn test_fake_db_set_bin_expires() {
        let db = FakeDb::new();
        db.set_bin_ex("bin:exp", b"data", 1).await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        let exists = db.exists("bin:exp").await.unwrap();
        assert!(!exists);
    }

    /// Verifies a string value set with set_ex disappears after its TTL elapses.
    #[tokio::test(start_paused = true)]
    async fn test_fake_db_set_ex_expires() {
        let db = FakeDb::new();
        db.set_ex("str:exp", "data", 1).await.unwrap();
        assert_eq!(db.get("str:exp").await.unwrap(), Some("data".to_string()));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!db.exists("str:exp").await.unwrap());
    }

    #[tokio::test]
    async fn test_fake_db_hash_ops() {
        let db = FakeDb::new();
        db.hset("hash:key", "field1", "value1").await.unwrap();
        db.hset_multiple("hash:key", &[("field2", "value2"), ("field3", "value3")])
            .await
            .unwrap();
        db.hset_nx("hash:key", "field1", "newvalue").await.unwrap();

        let val1 = db.hget("hash:key", "field1").await.unwrap();
        assert_eq!(val1, Some("value1".to_string()));
        let all = db.hgetall("hash:key".to_string()).await.unwrap();
        assert_eq!(all.get("field2"), Some(&"value2".to_string()));
        assert_eq!(all.get("field3"), Some(&"value3".to_string()));
    }

    #[tokio::test]
    async fn test_fake_db_set_ops_and_smembers() {
        let db = FakeDb::new();
        db.sadd("set:key", "a").await.unwrap();
        db.sadd("set:key", "b").await.unwrap();
        let members = db.smembers("set:key").await.unwrap();
        assert!(members.contains("a"));
        assert!(members.contains("b"));
    }

    #[tokio::test]
    async fn test_fake_db_incr_and_expire() {
        let db = FakeDb::new();
        let v1 = db.incr("counter", 1).await.unwrap();
        let v2 = db.incr("counter", 3).await.unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 4);

        db.set("temp", "value").await.unwrap();
        db.expire("temp", 0).await.unwrap();
        let exists = db.exists("temp").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_fake_db_atomic_pipeline() {
        let db = FakeDb::new();
        db.set("key:del", "value").await.unwrap();
        db.sadd("set:key", "a").await.unwrap();

        let ops = vec![
            DbOp::Del("key:del".to_string()),
            DbOp::SRem {
                set_key: "set:key".to_string(),
                member: "a".to_string(),
            },
            DbOp::HSet {
                hash_key: "hash:key".to_string(),
                field: "field".to_string(),
                value: "value".to_string(),
            },
        ];

        db.atomic_pipeline(&ops).await.unwrap();

        let exists = db.exists("key:del").await.unwrap();
        assert!(!exists);
        let members = db.smembers("set:key").await.unwrap();
        assert!(!members.contains("a"));
        let field = db.hget("hash:key", "field").await.unwrap();
        assert_eq!(field, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_fake_db_scan_match_all() {
        let db = FakeDb::new();
        db.set("svc:one", "1").await.unwrap();
        db.set("svc:two", "2").await.unwrap();
        db.set("other:one", "3").await.unwrap();

        let mut results = db.scan_match_all("svc:*".to_string()).await.unwrap();
        results.sort();
        assert_eq!(results, vec!["svc:one".to_string(), "svc:two".to_string()]);
    }

    #[tokio::test]
    async fn test_fake_db_clear_state() {
        let db = FakeDb::new();
        db.set("key1", "value1").await.unwrap();
        db.sadd("set:key", "a").await.unwrap();
        db.hset("hash:key", "field", "value").await.unwrap();

        db.clear_state().await.unwrap();

        assert!(!db.exists("key1").await.unwrap());
        assert!(!db.exists("set:key").await.unwrap());
        assert!(!db.exists("hash:key").await.unwrap());
        let keys = db.scan_match_all("*".to_string()).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_sismember() {
        let db = FakeDb::new();

        // Member present.
        db.sadd("set:key", "a").await.unwrap();
        db.sadd("set:key", "b").await.unwrap();
        assert!(db.sismember("set:key", "a").await.unwrap());
        assert!(db.sismember("set:key", "b").await.unwrap());

        // Member absent.
        assert!(!db.sismember("set:key", "c").await.unwrap());

        // Key does not exist.
        assert!(!db.sismember("no:such:key", "a").await.unwrap());

        // Wrong type returns an error.
        db.set("string:key", "value").await.unwrap();
        let err = db.sismember("string:key", "a").await.unwrap_err();
        assert_eq!(err.kind(), redis::ErrorKind::UnexpectedReturnType);
    }

    #[tokio::test]
    async fn test_fake_db_type_errors() {
        let db = FakeDb::new();
        db.set("string:key", "value").await.unwrap();

        let err = db.hget("string:key", "field").await.unwrap_err();
        assert_eq!(err.kind(), redis::ErrorKind::UnexpectedReturnType);

        let err = db.smembers("string:key").await.unwrap_err();
        assert_eq!(err.kind(), redis::ErrorKind::UnexpectedReturnType);
    }

    fn make_lock(ident: &str) -> LockDescriptor {
        LockDescriptor::new(
            crate::db::LockType::VsInstance,
            ident.to_string(),
            Duration::from_secs(60),
        )
    }

    // --- acquire_or_renew_lock ---

    #[tokio::test]
    async fn test_lock_acquire_fresh() {
        let db = FakeDb::new();
        let lock = make_lock("owner-a");
        let acquired = db.acquire_or_renew_lock(&lock).await.unwrap();
        assert!(acquired);
    }

    #[tokio::test]
    async fn test_lock_renew_own_lock() {
        let db = FakeDb::new();
        let lock = make_lock("owner-a");
        db.acquire_or_renew_lock(&lock).await.unwrap();
        // Second call by the same owner should succeed (renew).
        let renewed = db.acquire_or_renew_lock(&lock).await.unwrap();
        assert!(renewed);
    }

    #[tokio::test]
    async fn test_lock_blocked_by_other_owner() {
        let db = FakeDb::new();
        let lock_a = make_lock("owner-a");
        let lock_b = make_lock("owner-b");
        db.acquire_or_renew_lock(&lock_a).await.unwrap();
        let acquired = db.acquire_or_renew_lock(&lock_b).await.unwrap();
        assert!(!acquired);
    }

    #[tokio::test(start_paused = true)]
    async fn test_lock_takeover_after_expiry() {
        let db = FakeDb::new();
        let lock_a = make_lock("owner-a");
        let lock_b = make_lock("owner-b");
        db.acquire_or_renew_lock(&lock_a).await.unwrap();
        // Advance past the 60-second TTL.
        tokio::time::advance(Duration::from_secs(61)).await;
        let acquired = db.acquire_or_renew_lock(&lock_b).await.unwrap();
        assert!(acquired);
    }

    // --- release_lock ---

    #[tokio::test]
    async fn test_lock_release_own_lock() {
        let db = FakeDb::new();
        let lock = make_lock("owner-a");
        db.acquire_or_renew_lock(&lock).await.unwrap();
        let released = db.release_lock(&lock).await.unwrap();
        assert!(released);
        // After release, another owner should be able to acquire.
        let lock_b = make_lock("owner-b");
        let acquired = db.acquire_or_renew_lock(&lock_b).await.unwrap();
        assert!(acquired);
    }

    #[tokio::test]
    async fn test_lock_release_not_owner() {
        let db = FakeDb::new();
        let lock_a = make_lock("owner-a");
        let lock_b = make_lock("owner-b");
        db.acquire_or_renew_lock(&lock_a).await.unwrap();
        let released = db.release_lock(&lock_b).await.unwrap();
        assert!(!released);
        // Lock should still be held by owner-a.
        let still_blocked = db.acquire_or_renew_lock(&lock_b).await.unwrap();
        assert!(!still_blocked);
    }

    #[tokio::test]
    async fn test_lock_release_nonexistent() {
        let db = FakeDb::new();
        let lock = make_lock("owner-a");
        // Releasing a lock that was never acquired should succeed (idempotent).
        let released = db.release_lock(&lock).await.unwrap();
        assert!(released);
    }
}
