//! Visa-service-minted OIDC login nonces for a Zode's own login (zl-zipline#232).
//!
//! On the adapter connect path the docking node mints the OIDC `nonce`, and an
//! honest docking node therefore defeats a replayed `id_token`. On a Zode the
//! endpoint is its own docking node, so a node-minted nonce proves nothing: a
//! subverted Zode could replay a stolen `id_token` together with its nonce. The
//! visa service therefore mints the nonce itself (`VSHandle.getLoginNonce`) and
//! accepts a login (a `user` namespace gain through `reauthorize`) only when the
//! token's nonce is one it issued:
//!
//! - **bound** to the calling node's actor address AND its VS-API session
//!   generation (`zpr.session`), so it can never serve another actor, nor the
//!   same node after it re-authenticates;
//! - **one-use**: [LoginNonceStore::consume] removes the entry before it checks
//!   anything, so a nonce is spent even when the check or the later token
//!   validation fails;
//! - **short-lived**: usable until its expiry ([config::LOGIN_NONCE_TTL_SECS]);
//! - **bounded**: at most [config::LOGIN_NONCE_MAX_PER_ACTOR] unexpired
//!   outstanding nonces per actor session; minting past that is refused
//!   (`quotaExceeded` on the wire, per the vs.capnp contract).
//!
//! The store is in memory only. After a visa service restart no nonce survives
//! and the node simply asks for a new one. Expired and stale-session entries are
//! swept opportunistically on every mint and consume, so no background task and
//! no disconnect hook is needed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::config;

/// Number of random bytes in a nonce (encoded as unpadded base64url on the wire).
const NONCE_LEN: usize = 32;

/// Why a nonce could not be minted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MintError {
    /// The actor session already holds the maximum number of unexpired nonces.
    QuotaExceeded,
    /// The OS random source failed; no nonce was issued.
    Random(String),
    /// The calling handle's session is no longer the node's current one (set
    /// by the `getLoginNonce` handler, never by the store itself).
    StaleSession,
}

/// One outstanding nonce: whom it was issued to and until when it is usable.
struct Entry {
    /// ZPR address of the node actor the nonce was issued to.
    actor: IpAddr,
    /// VS-API session generation (`zpr.session`) of that actor at mint time.
    session: String,
    /// Last instant at which the nonce is still usable (whole seconds).
    expires: SystemTime,
}

/// The set of outstanding login nonces, keyed by the nonce text.
pub(crate) struct LoginNonceStore {
    entries: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    max_per_actor: usize,
}

impl Default for LoginNonceStore {
    /// A store with the production lifetime and per-actor limit.
    fn default() -> Self {
        Self::new(
            Duration::from_secs(config::LOGIN_NONCE_TTL_SECS),
            config::LOGIN_NONCE_MAX_PER_ACTOR,
        )
    }
}

impl LoginNonceStore {
    /// A store with an explicit lifetime and per-actor limit (tests use small values).
    pub(crate) fn new(ttl: Duration, max_per_actor: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_per_actor,
        }
    }

    /// Issue a fresh nonce to `actor` in VS-API session `session`.
    ///
    /// Returns the nonce text and its expiry. The expiry is truncated to whole
    /// seconds so the `LoginNonce.expiresAt` the caller sends (unix seconds)
    /// names exactly the instant the store enforces. Fails with
    /// [MintError::QuotaExceeded] when this actor session already holds
    /// `max_per_actor` unexpired nonces.
    pub(crate) fn mint(
        &self,
        actor: IpAddr,
        session: &str,
        now: SystemTime,
    ) -> Result<(String, SystemTime), MintError> {
        let mut entries = self.lock();
        Self::sweep(&mut entries, now);
        // Entries this actor holds under an older session can never be used
        // again (consume checks the session), so drop them rather than let
        // them count against the new session's quota.
        entries.retain(|_, e| e.actor != actor || e.session == session);

        let outstanding = entries.values().filter(|e| e.actor == actor).count();
        if outstanding >= self.max_per_actor {
            return Err(MintError::QuotaExceeded);
        }

        let mut bytes = [0u8; NONCE_LEN];
        openssl::rand::rand_bytes(&mut bytes).map_err(|e| MintError::Random(e.to_string()))?;
        let nonce = URL_SAFE_NO_PAD.encode(bytes);
        let expires = whole_seconds(now + self.ttl);
        entries.insert(
            nonce.clone(),
            Entry {
                actor,
                session: session.to_string(),
                expires,
            },
        );
        Ok((nonce, expires))
    }

    /// Spend `nonce` for a login by `actor` in VS-API session `session`.
    ///
    /// Returns true only when the nonce was issued to exactly this actor and
    /// session and is not yet expired (`now <= expires`). The entry is removed
    /// FIRST, whatever the outcome, so a nonce can never be presented twice --
    /// not even after a failed attempt, and not by a different actor that
    /// learned it.
    pub(crate) fn consume(
        &self,
        nonce: &str,
        actor: IpAddr,
        session: &str,
        now: SystemTime,
    ) -> bool {
        let mut entries = self.lock();
        let entry = entries.remove(nonce);
        Self::sweep(&mut entries, now);
        match entry {
            Some(e) => e.actor == actor && e.session == session && now <= e.expires,
            None => false,
        }
    }

    /// Drop every entry whose expiry has passed.
    fn sweep(entries: &mut HashMap<String, Entry>, now: SystemTime) {
        entries.retain(|_, e| now <= e.expires);
    }

    /// Lock the map. A poisoned lock only means another thread panicked while
    /// holding it; the map itself is always left consistent (every mutation is
    /// a single insert/remove/retain), so recover it rather than propagate.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Truncate `t` to whole seconds since the unix epoch.
fn whole_seconds(t: SystemTime) -> SystemTime {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const A: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 0x10));
    const B: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 0x11));

    /// A fixed, whole-second clock so expiry boundaries are exact.
    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn store() -> LoginNonceStore {
        LoginNonceStore::new(Duration::from_secs(300), 4)
    }

    #[test]
    fn minted_nonce_is_consumed_once() {
        let s = store();
        let (n, _) = s.mint(A, "s1", t0()).unwrap();
        assert!(s.consume(&n, A, "s1", t0()), "fresh nonce must be accepted");
        assert!(!s.consume(&n, A, "s1", t0()), "a nonce is one-use");
    }

    #[test]
    fn nonces_are_unique_and_unpadded_base64url() {
        let s = LoginNonceStore::new(Duration::from_secs(300), 100);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let (n, _) = s.mint(A, "s1", t0()).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(&n).unwrap().len(), NONCE_LEN);
            assert!(seen.insert(n), "nonces must not repeat");
        }
    }

    #[test]
    fn wrong_actor_rejected_and_spends_the_nonce() {
        let s = store();
        let (n, _) = s.mint(A, "s1", t0()).unwrap();
        assert!(
            !s.consume(&n, B, "s1", t0()),
            "nonce issued to A must not serve B"
        );
        assert!(
            !s.consume(&n, A, "s1", t0()),
            "a presented nonce is spent even on failure"
        );
    }

    #[test]
    fn wrong_session_rejected() {
        let s = store();
        let (n, _) = s.mint(A, "s1", t0()).unwrap();
        assert!(
            !s.consume(&n, A, "s2", t0()),
            "nonce is bound to the VS-API session"
        );
    }

    #[test]
    fn not_issued_rejected() {
        let s = store();
        assert!(!s.consume("node-minted-nonce", A, "s1", t0()));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let s = store();
        let (n1, exp) = s.mint(A, "s1", t0()).unwrap();
        assert_eq!(exp, t0() + Duration::from_secs(300));
        assert!(s.consume(&n1, A, "s1", exp), "usable at exactly expiresAt");
        let (n2, exp2) = s.mint(A, "s1", t0()).unwrap();
        assert!(
            !s.consume(&n2, A, "s1", exp2 + Duration::from_secs(1)),
            "unusable after expiresAt"
        );
    }

    #[test]
    fn expiry_is_whole_seconds() {
        let s = store();
        let (_, exp) = s.mint(A, "s1", t0() + Duration::from_millis(700)).unwrap();
        assert_eq!(exp, t0() + Duration::from_secs(300));
    }

    #[test]
    fn cap_refuses_mint_and_frees_on_consume_or_expiry() {
        let s = store();
        let mut minted = Vec::new();
        for _ in 0..4 {
            minted.push(s.mint(A, "s1", t0()).unwrap().0);
        }
        assert_eq!(s.mint(A, "s1", t0()), Err(MintError::QuotaExceeded));
        // Another actor has its own quota.
        assert!(s.mint(B, "s1", t0()).is_ok());
        // Consuming one frees a slot.
        assert!(s.consume(&minted[0], A, "s1", t0()));
        assert!(s.mint(A, "s1", t0()).is_ok());
        // After expiry every slot is free again.
        let later = t0() + Duration::from_secs(301);
        for _ in 0..4 {
            assert!(s.mint(A, "s1", later).is_ok());
        }
    }

    #[test]
    fn new_session_does_not_inherit_old_quota() {
        let s = store();
        for _ in 0..4 {
            s.mint(A, "s1", t0()).unwrap();
        }
        assert!(
            s.mint(A, "s2", t0()).is_ok(),
            "a re-authenticated node starts fresh"
        );
    }

    #[test]
    fn sweeps_expired_entries() {
        let s = store();
        s.mint(A, "s1", t0()).unwrap();
        s.mint(B, "s1", t0()).unwrap();
        let later = t0() + Duration::from_secs(301);
        assert!(!s.consume("nothing", A, "s1", later));
        assert!(s.lock().is_empty(), "expired entries are swept on consume");
    }
}
