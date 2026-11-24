//! General database functions.

mod actor;
mod db_fake;
mod db_redis;
mod denylist;
mod link;
mod node;
mod policy;
mod reauth;
mod revocation;
mod visa;

pub use actor::{ActorRepo, Role, ServiceEntry};
pub use db_redis::RedisDb;
pub use denylist::BootstrapDenylist;
pub use link::LinkRepo;
pub use node::{Node, NodeRepo};
pub use policy::PolicyRepo;
pub use reauth::{ReauthObligation, ReauthRepo};
pub use revocation::{Obligation, ObligationKind, RevocationRepo};
pub(crate) use visa::PURGE_MIN_INTERVAL;
pub use visa::{CommitState, NodeVisaState, VisaMetadata, VisaRepo};

#[cfg(test)]
pub use db_fake::{FakeDb, FaultMode};

use chrono::Utc;
use percent_encoding::CONTROLS;
use percent_encoding::{AsciiSet, percent_decode_str, utf8_percent_encode};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Duration;

// Encode '%' and ':' for KeyString type strings.
const KEY_ESCAPES: &AsciiSet = &CONTROLS.add(b'%').add(b':');

pub enum LockType {
    VsInstance,
}

pub type DbResult<T> = redis::RedisResult<T>;

// TODO: At some point remove this dead code and remove the unused functions.
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait DbConnection: Send + Sync {
    /// May be called during a clean shutdown so that DB can do any necessary cleanup (e.g. releasing locks).
    async fn shutdown_cleanup(&self) -> DbResult<()>;

    async fn exists(&self, key: &str) -> DbResult<bool>;
    async fn set(&self, key: &str, value: &str) -> DbResult<()>;
    async fn set_ex(&self, key: &str, value: &str, seconds: u64) -> DbResult<()>;
    async fn get(&self, key: &str) -> DbResult<Option<String>>;

    /// Set a binary value directly. For atomic writes alongside other ops, use
    /// `DbOp::SetBin` in an `atomic_pipeline` instead.
    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()>;
    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()>;
    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>>;
    async fn del(&self, key: &str) -> DbResult<()>;
    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>>;
    async fn sismember(&self, key: &str, member: &str) -> DbResult<bool>;
    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>>;
    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>>;
    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()>;
    /// Sets `field` only if it is absent. Returns true when this call set it —
    /// the atomic claim primitive for a uniquely-owned name.
    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<bool>;
    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()>;
    /// Remove `field` from the hash at `key`. Removing an absent field (or an
    /// absent key) is a no-op, mirroring redis HDEL.
    async fn hdel(&self, key: &str, field: &str) -> DbResult<()>;
    async fn sadd(&self, key: &str, member: &str) -> DbResult<()>;
    async fn incr(&self, key: &str, by: u64) -> DbResult<u64>;
    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()>;

    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()>;

    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>>;

    /// Remove all data from the database.
    async fn clear_state(&self) -> DbResult<()>;

    /// Returns TRUE if we were able to acquire or re-acquire a lock specified by the descriptor.
    /// Whent the lock is acquired or renewed the TTL will be extended by the timeout specified in the descriptor.
    async fn acquire_or_renew_lock(&self, desc: &LockDescriptor) -> DbResult<bool>;

    /// Returns TRUE if we were able to release a lock specified by the descriptor, or if no lock exists.
    /// Returns FALSE only if the lock exists but is not "ours".
    #[allow(dead_code)]
    async fn release_lock(&self, desc: &LockDescriptor) -> DbResult<bool>;
}

#[derive(Clone)]
pub struct LockDescriptor {
    key: String,
    ident: String,
    timeout: Duration,
}

impl LockDescriptor {
    /// Create LockDescriptor.
    ///
    /// The `ident` is a string that identifies the owner of the lock.  It can be any string,
    /// but should be unique to the owner (e.g. a UUID or hostname).
    ///
    /// The `timeout` is how long the lock should be held before it expires and can be acquired
    /// by someone else.
    pub fn new(ltype: LockType, ident: String, timeout: Duration) -> Self {
        let key = match ltype {
            LockType::VsInstance => format!("lock:vsinstance"),
        };
        LockDescriptor {
            key,
            ident,
            timeout,
        }
    }
}

impl Hash for LockDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
        self.ident.hash(state);
    }
}

impl PartialEq for LockDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.ident == other.ident
    }
}

impl Eq for LockDescriptor {}

#[allow(dead_code)]
pub enum DbOp {
    Del(String),
    /// Set a binary value at `key`. Lets binary blobs join an atomic pipeline.
    SetBin {
        key: String,
        value: Vec<u8>,
    },
    SRem {
        set_key: String,
        member: String,
    },
    HSet {
        hash_key: String,
        field: String,
        value: String,
    },
    HSetMultiple {
        hash_key: String,
        field_values: Vec<(String, String)>,
    },
    Expire {
        key: String,
        seconds: i64,
    },
}

/// In the redis, we sometimes need to use a ZPR address as part of a key.
/// In that case we use this `ZAddr` type instead.  Only thing it it does
/// is replace colons in IPv6 addresses with dashes.
struct ZAddr(String);

/// In redis if we want to use user supllied text as part of a key we
/// want to remove any colons in there so we use percent encoding.
/// All colons and '%' in the original are encoded.
struct KeyString(String);

impl From<&str> for KeyString {
    fn from(s: &str) -> Self {
        let encoded = utf8_percent_encode(s, KEY_ESCAPES).to_string();
        KeyString(encoded)
    }
}

impl TryFrom<KeyString> for String {
    type Error = std::str::Utf8Error;
    fn try_from(ks: KeyString) -> Result<Self, Self::Error> {
        let decoded = percent_decode_str(&ks.0)
            .decode_utf8()
            .map(|cow| cow.into_owned())?;
        Ok(decoded)
    }
}

impl KeyString {
    /// Create a KeyString from a raw (already encoded) string.
    /// Caller must ensure that the string is properly encoded.
    fn from_raw(s: String) -> Self {
        KeyString(s)
    }

    /// Get the string representation of this KeyString.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<IpAddr> for ZAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a4) => ZAddr(a4.to_string()),
            IpAddr::V6(a6) => {
                let ipv6str = a6.to_string();
                ZAddr(ipv6str.replace(":", "-"))
            }
        }
    }
}

impl From<&IpAddr> for ZAddr {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(a4) => ZAddr(a4.to_string()),
            IpAddr::V6(a6) => {
                let ipv6str = a6.to_string();
                ZAddr(ipv6str.replace(":", "-"))
            }
        }
    }
}

impl TryFrom<ZAddr> for IpAddr {
    type Error = std::net::AddrParseError;
    fn try_from(zaddr: ZAddr) -> Result<Self, Self::Error> {
        if zaddr.0.contains('-') {
            // IPv6
            let ipv6str = zaddr.0.replace("-", ":");
            Ok(IpAddr::V6(ipv6str.parse()?))
        } else {
            // IPv4
            Ok(IpAddr::V4(zaddr.0.parse()?))
        }
    }
}

impl std::fmt::Display for ZAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for KeyString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ZAddr {
    /// If you already have a "zaddr" encoded string, use this to create a ZAddr.
    pub fn new_from_encoded(s: &str) -> Self {
        ZAddr(s.into())
    }
}

/// All database string timestamps look like this.
pub fn gen_timestamp() -> String {
    let now = Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
