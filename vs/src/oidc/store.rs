//! The `api = "oidc"` trusted service (zipline#10).
//!
//! Unlike file/network trusted services an OIDC provider cannot be *queried*
//! for an arbitrary identity: the claims arrive with the validated `id_token`.
//! The connect path (zipline#11) calls [`OidcTrustedService::admit`] after validation;
//! [`crate::trusted_services::TrustedServiceInterface::get_attributes_for_actor`]
//! then serves those cached claims, so the normal ts_mgr union/conflict/refresh
//! machinery applies unchanged.

use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use libeval::attribute::{Attribute, AttributeSource, key};
use zpr::policy_types::{OidcConfig, TrustedService};

use crate::error::ServiceError;
use crate::trusted_services::{AttrHint, AttributeMapper, TrustedServiceInterface, next_revision};

use super::jwks::KeySource;
use super::validate::{IdpParams, ValidatedToken};

/// The OIDC claim carrying the provider's stable subject identifier — the only
/// identity claim this store admits and looks up under.
const SUB_CLAIM: &str = "sub";

/// One admitted subject's cached record: the mapped attributes and when they
/// expire (the stamped authority expiry). Renewal anchors do NOT live here —
/// they are per actor session (see [`OidcTrustedService::record_session`]),
/// not per subject, so concurrent actors for the same account cannot clobber
/// each other (PR #19 review).
pub(crate) struct AdmittedEntry {
    /// The mapped attributes served to lookups.
    pub attrs: Vec<Attribute>,
    /// When this record stops being served (the stamped authority expiry).
    pub expires: SystemTime,
}

/// One live actor session's dual-clock renewal anchors (zipline#43),
/// keyed by the actor's session id (its ZPR address): `auth_time` (fixed per
/// login: the session ceiling) and `iat` (advances on refresh: the renewal
/// window), plus the admitted subject and the admission expiry the anchors
/// were recorded under.
pub(crate) struct SessionAnchors {
    /// The provider subject this session authenticated as.
    pub sub: String,
    /// The login's authentication moment (`auth_time`) — fixed per session.
    pub auth_time: SystemTime,
    /// The latest admitted token's mint moment (`iat`).
    pub iat: SystemTime,
    /// The admission expiry the anchors were recorded under.
    pub expires: SystemTime,
}

/// An `api = "oidc"` trusted service: a claim cache keyed by the provider's
/// `sub`, populated by [`OidcTrustedService::admit`] on the connect path and
/// served through [`TrustedServiceInterface`].
pub struct OidcTrustedService {
    /// Trusted-service id (e.g. `"google"`); also the source id stamped on
    /// every vended attribute, and thereby the derived `user.zpr.authority`.
    id: String,
    /// The pinned provider configuration from policy.
    cfg: OidcConfig,
    /// `returns_attributes` mapping from claim names to ZPR attribute keys.
    mapper: AttributeMapper,
    /// Cached signing keys for this provider (zipline#9).
    keys: Arc<KeySource>,
    /// Admitted claims, keyed by the provider's `sub`.
    admitted: DashMap<String, AdmittedEntry>,
    /// Live actor sessions' renewal anchors, keyed by the actor's session id
    /// (its ZPR address). Kept separate from `admitted` so two live actors
    /// authenticating as the same account cannot clobber each other's
    /// anchors (PR #19 review).
    sessions: DashMap<String, SessionAnchors>,
    /// How long admitted attributes live, from the policy record.
    expiration_seconds: u32,
    /// Snapshot revision, from the process-wide trusted-service counter so the
    /// ts_mgr staleness machinery treats this store like any other.
    revision: AtomicU64,
}

impl OidcTrustedService {
    /// Build the store from its policy record. The record must carry an
    /// `oidc` config (the factory guarantees it; a missing one is a policy
    /// error, not a panic).
    pub fn new(record: &TrustedService, keys: Arc<KeySource>) -> Result<Self, ServiceError> {
        let Some(cfg) = record.oidc.clone() else {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': api 'oidc' requires an oidc config",
                record.service_id
            )));
        };
        Ok(OidcTrustedService {
            id: record.service_id.clone(),
            cfg,
            mapper: AttributeMapper {
                mappings: record.returns_attrs.clone(),
            },
            keys,
            admitted: DashMap::new(),
            sessions: DashMap::new(),
            expiration_seconds: record.expiration_seconds,
            revision: AtomicU64::new(next_revision()),
        })
    }

    /// The validator parameters for this provider (zipline#8). `max_auth_age_seconds`
    /// of 0 means no freshness requirement.
    #[allow(dead_code)] // consumed by the zipline#11 connect path
    pub fn params(&self) -> IdpParams<'_> {
        IdpParams {
            issuer: &self.cfg.issuer,
            client_id: &self.cfg.client_id,
            allowed_domains: &self.cfg.allowed_domains,
            max_auth_age: (self.cfg.max_auth_age_seconds > 0)
                .then(|| Duration::from_secs(self.cfg.max_auth_age_seconds as u64)),
            allow_offline_access: self.cfg.allow_offline_access,
            clock_skew: IdpParams::default_clock_skew(),
        }
    }

    /// The fixed session ceiling for a login whose authentication moment is
    /// `auth_time`: `auth_time + max_auth_age_seconds + clock_skew`. `None`
    /// when the knob is 0 (no ceiling — the session may renew forever).
    /// Zipline#42.
    ///
    /// The `clock_skew` term is symmetric with acceptance (PR #18 review):
    /// zipline#8 validation accepts an `auth_time` up to `max_auth_age + clock_skew`
    /// old, so without it the skew window would admit tokens whose ceiling is
    /// already in the past — a successful connect carrying an expired
    /// `user.zpr.authority` that policy then immediately denies. The addition
    /// is checked: an unrepresentably far ceiling bounds nothing, which is
    /// exactly what `None` means (and only a nonsense `auth_time` gets there).
    #[allow(dead_code)] // consumed by the zipline#11 connect path
    pub fn session_ceiling(&self, auth_time: SystemTime) -> Option<SystemTime> {
        if self.cfg.max_auth_age_seconds == 0 {
            return None;
        }
        auth_time.checked_add(
            Duration::from_secs(self.cfg.max_auth_age_seconds as u64)
                + IdpParams::default_clock_skew(),
        )
    }

    /// This provider's cached signing keys.
    #[allow(dead_code)] // consumed by the zipline#11 connect path
    pub fn keys(&self) -> &KeySource {
        &self.keys
    }

    /// The shared handle to this provider's key source, for callers that
    /// need to hold it beyond the store borrow (the periodic refresher task,
    /// zipline#19).
    pub fn keys_arc(&self) -> Arc<KeySource> {
        self.keys.clone()
    }

    /// How long admitted attributes live (`expiration_seconds` from policy).
    #[allow(dead_code)] // consumed by the zipline#11 connect path
    pub fn lifetime(&self) -> Duration {
        Duration::from_secs(self.expiration_seconds as u64)
    }

    /// The provider's issuer URL, for [`crate::trusted_services::TrustedServicesMgr`]
    /// lookups by `iss`.
    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    /// The trusted-service id (e.g. `"google"`): the value stamped into
    /// `user.zpr.authority` by the connect path (zipline#11).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Map `token.raw_claims` through `returns_attributes`, stamp the given
    /// expiry and this source, cache the result under `sub`, and bump the
    /// revision. Returns the mapped attributes. Two claims mapping to the same
    /// ZPR key with differing values fail closed, mirroring the
    /// [`TrustedServiceInterface`] conflict contract.
    pub fn admit(
        &self,
        token: &ValidatedToken,
        expires: SystemTime,
    ) -> Result<Vec<Attribute>, ServiceError> {
        let src = AttributeSource::new(self.id.clone());
        let mut mapped: BTreeMap<String, Attribute> = BTreeMap::new();
        for (claim, value) in &token.raw_claims {
            let Some((zpr_key, hint)) = self.mapper.map_attribute(claim) else {
                continue; // unmapped claims can never become attributes
            };
            let values = claim_values(value);
            let builder = src.builder(zpr_key.clone()).expires(expires);
            let attr = match hint {
                AttrHint::SingleValued => {
                    let Some(first) = values.first() else {
                        continue;
                    };
                    builder.value(first.clone())
                }
                AttrHint::MultiValued => builder.values(values),
                // A tag is valueless: presence of the per-tag key is the tag.
                AttrHint::Tag => builder.values(Vec::<String>::new()),
            };
            if let Some(existing) = mapped.get(&zpr_key) {
                if existing.get_value() != attr.get_value() {
                    // Claim names only, never values: claims are attacker-
                    // influenced bytes and must not reach logs.
                    return Err(ServiceError::Param(format!(
                        "{}: two claims disagree on attribute '{zpr_key}'",
                        self.id
                    )));
                }
                continue;
            }
            mapped.insert(zpr_key, attr);
        }

        let attrs: Vec<Attribute> = mapped.into_values().collect();
        // Opportunistic eviction: a subject that disconnects and never returns
        // would otherwise stay cached forever (expiry is only checked on lookup
        // of that exact subject). Sweeping on every admission bounds the cache
        // to subjects admitted within one expiration window; recorded session
        // anchors are swept on the same trigger (see [Self::record_session]).
        let now = SystemTime::now();
        self.admitted.retain(|_, entry| entry.expires > now);
        self.admitted.insert(
            token.sub.clone(),
            AdmittedEntry {
                attrs: attrs.clone(),
                expires,
            },
        );
        self.revision.store(next_revision(), Ordering::SeqCst);
        Ok(attrs)
    }

    /// The ZPR key the `sub` claim maps to — the identity key admitted actors
    /// are looked up under. `None` when policy does not map `sub` at all (the
    /// store then never matches an identity). The connect path (zipline#11) uses this
    /// to push the mapped subject as the user identity anchor, so the
    /// trusted-service lookup can find the admission it just cached.
    pub(crate) fn mapped_sub_key(&self) -> Option<String> {
        self.mapper.map_attribute(SUB_CLAIM).map(|(key, _)| key)
    }

    /// Record (or advance) the dual-clock renewal anchors for one live actor
    /// session (zipline#43, scoped per session — PR #19 review). The
    /// session id is the actor's ZPR address: unique per live actor and
    /// stable across renewals, so two actors authenticated as the same
    /// provider account keep independent anchors. Expired records are swept
    /// on the same opportunistic trigger as [Self::admit].
    pub(crate) fn record_session(
        &self,
        session_id: &str,
        sub: &str,
        auth_time: SystemTime,
        iat: SystemTime,
        expires: SystemTime,
    ) {
        let now = SystemTime::now();
        self.sessions.retain(|_, s| s.expires > now);
        self.sessions.insert(
            session_id.to_string(),
            SessionAnchors {
                sub: sub.to_string(),
                auth_time,
                iat,
                expires,
            },
        );
    }

    /// Forget the anchors of one actor session. A node's logout
    /// (zl-zipline#232) drops its user namespace; without this a stale record
    /// would outlive the login it described until its expiry swept it.
    pub(crate) fn forget_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    /// The recorded dual-clock anchors of one live actor session, or `None`
    /// when this store never recorded that session (or it was swept). zipline#43
    /// (zipline#43) reads these on re-admission to bind a refreshed token to
    /// the same login session: same `sub`, unchanged `auth_time`, strictly
    /// greater `iat`. In-memory only — after a VS restart there is no
    /// recorded session and reauth fails, so the node reconnects.
    pub(crate) fn session_anchors(&self, session_id: &str) -> Option<SessionAnchors> {
        self.sessions.get(session_id).map(|s| SessionAnchors {
            sub: s.sub.clone(),
            auth_time: s.auth_time,
            iat: s.iat,
            expires: s.expires,
        })
    }
}

// `expiration_seconds` lives on the policy record, not `OidcConfig`, so the
// store keeps its own copy (see `lifetime`).

#[async_trait]
impl TrustedServiceInterface for OidcTrustedService {
    /// Serve the cached claims of every admitted `sub` among `identities`
    /// (matched under the mapped sub key). OIDC subjects are unique only
    /// within their issuer, so the lookup set must also carry a
    /// `user.zpr.authority` pair naming THIS service — the service that
    /// validated the actor's token. Without it (or with another service's
    /// authority) nothing is served: two providers mapping `sub` to the same
    /// ZPR key must never serve each other's admitted actors, even for a
    /// colliding subject string. Expired records are dropped, not served.
    /// Matching more than one admitted identity unions the results; a
    /// same-key/different-value disagreement fails closed per the trait
    /// contract.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError> {
        let Some(sub_key) = self.mapped_sub_key() else {
            return Ok(Vec::new());
        };
        // Bind cached admissions to the issuing service: only an actor this
        // service vouched for (authority == this service id) may match.
        let vouched_here = identities
            .iter()
            .any(|(k, v)| k == key::USER_AUTHORITY && *v == self.id);
        if !vouched_here {
            return Ok(Vec::new());
        }
        let now = SystemTime::now();
        let mut merged: BTreeMap<String, Attribute> = BTreeMap::new();
        for (ident_key, ident_value) in identities {
            if *ident_key != sub_key {
                continue;
            }
            let Some(entry) = self.admitted.get(ident_value) else {
                continue;
            };
            if entry.expires <= now {
                drop(entry);
                self.admitted
                    .remove_if(ident_value, |_, entry| entry.expires <= now);
                continue;
            }
            for attr in &entry.attrs {
                match merged.get(attr.get_key()) {
                    None => {
                        merged.insert(attr.get_key().to_string(), attr.clone());
                    }
                    Some(first) if first.get_value() != attr.get_value() => {
                        return Err(ServiceError::Param(format!(
                            "{}: two admitted identities disagree on attribute '{}'",
                            self.id,
                            attr.get_key()
                        )));
                    }
                    Some(_) => {} // same key, same values: one attribute
                }
            }
        }
        Ok(merged.into_values().collect())
    }

    /// Drop every admitted record and recorded session. The next lookup finds
    /// nothing until the connect path re-admits, which is the OIDC analogue
    /// of a data reload.
    async fn flush(&self) -> Result<(), ServiceError> {
        self.admitted.clear();
        self.sessions.clear();
        self.revision.store(next_revision(), Ordering::SeqCst);
        Ok(())
    }

    fn current_revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    fn get_source_id(&self) -> &str {
        &self.id
    }
}

/// A claim value as attribute value strings: a string is itself, a bool or
/// number is its display form, an array is its (scalar) elements, and null /
/// objects contribute nothing.
fn claim_values(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Bool(b) => vec![b.to_string()],
        serde_json::Value::Number(n) => vec![n.to_string()],
        serde_json::Value::Array(items) => items.iter().flat_map(claim_values).collect(),
        serde_json::Value::Null | serde_json::Value::Object(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{KeySource, ValidatedToken, static_proxy};
    use crate::test_helpers::make_test_oidc_config;
    use crate::trusted_services::TrustedServiceInterface;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use zpr::policy_types::{TrustedService, parse_attribute_mapping};

    /// The `TrustedService` policy record an `api = "oidc"` declaration carries.
    fn make_record(mappings: &[&str]) -> TrustedService {
        make_record_with_id("google", mappings)
    }

    /// As [make_record], for a service with the given id.
    fn make_record_with_id(id: &str, mappings: &[&str]) -> TrustedService {
        TrustedService {
            service_id: id.to_string(),
            expiration_seconds: 300,
            returns_attrs: mappings
                .iter()
                .map(|m| parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: vec!["sub".to_string()],
            oidc: Some(make_test_oidc_config()),
            attr_query: None,
        }
    }

    /// A store over the fixture OIDC config, seeded from policy (no network).
    async fn make_store(mappings: &[&str]) -> OidcTrustedService {
        make_store_with_id("google", mappings).await
    }

    /// As [make_store], for a service with the given id.
    async fn make_store_with_id(id: &str, mappings: &[&str]) -> OidcTrustedService {
        let record = make_record_with_id(id, mappings);
        let keys = Arc::new(
            KeySource::from_policy(record.oidc.as_ref().unwrap(), static_proxy(None))
                .await
                .unwrap(),
        );
        OidcTrustedService::new(&record, keys).unwrap()
    }

    /// A validated token for `sub`, carrying a verified email when given (an
    /// unverified email never reaches `raw_claims` — the zipline#8 validator strips it).
    fn make_token(sub: &str, email: Option<&str>) -> ValidatedToken {
        let mut raw_claims = serde_json::Map::new();
        raw_claims.insert("sub".to_string(), json!(sub));
        raw_claims.insert("hd".to_string(), json!("example.com"));
        if let Some(email) = email {
            raw_claims.insert("email".to_string(), json!(email));
        }
        ValidatedToken {
            sub: sub.to_string(),
            email: email.map(str::to_string),
            hd: Some("example.com".to_string()),
            auth_time: SystemTime::now(),
            iat: SystemTime::now(),
            raw_claims,
        }
    }

    const MAPPINGS: &[&str] = &["sub -> user.oidc-subject", "email -> user.email"];

    /// The lookup-identity set an actor authenticated by the "google" service
    /// carries: the vouching `user.zpr.authority` pair plus the mapped sub.
    fn google_identities(sub: &str) -> Vec<(String, String)> {
        vec![
            (
                libeval::attribute::key::USER_AUTHORITY.to_string(),
                "google".to_string(),
            ),
            ("user.oidc-subject".to_string(), sub.to_string()),
        ]
    }

    /// admit -> lookup round-trips: the mapped claims come back for the
    /// `(mapped sub key, sub)` identity, stamped with the given expiry and the
    /// service's source id.
    #[tokio::test]
    async fn test_admit_then_lookup_by_sub() {
        let store = make_store(MAPPINGS).await;
        assert_eq!(store.get_source_id(), "google");
        let expires = SystemTime::now() + Duration::from_secs(300);

        let admitted = store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();
        assert!(!admitted.is_empty());

        let attrs = store
            .get_attributes_for_actor(&google_identities("s-123"))
            .await
            .unwrap();
        let sub_attr = attrs
            .iter()
            .find(|a| a.get_key() == "user.oidc-subject")
            .expect("mapped sub attribute");
        assert_eq!(sub_attr.get_single_value().unwrap(), "s-123");
        assert_eq!(sub_attr.get_expires(), expires);
        assert_eq!(sub_attr.get_source(), "google");

        let email_attr = attrs
            .iter()
            .find(|a| a.get_key() == "user.email")
            .expect("mapped email attribute");
        assert_eq!(email_attr.get_single_value().unwrap(), "jane@example.com");
        assert_eq!(email_attr.get_expires(), expires);
    }

    /// A sub never admitted yields no attributes, and a matching value under a
    /// non-sub identity key never matches either.
    #[tokio::test]
    async fn test_lookup_unknown_sub_is_empty() {
        let store = make_store(MAPPINGS).await;
        let expires = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();

        let attrs = store
            .get_attributes_for_actor(&google_identities("s-999"))
            .await
            .unwrap();
        assert!(attrs.is_empty());

        // The admitted value under the wrong identity key is not an identity match.
        let attrs = store
            .get_attributes_for_actor(&[("device.zpr.adapter.cn".to_string(), "s-123".to_string())])
            .await
            .unwrap();
        assert!(attrs.is_empty());
    }

    /// A token whose email was unverified (email == None, stripped from
    /// raw_claims by the validator) must never produce a `user.email` attribute.
    #[tokio::test]
    async fn test_email_not_mapped_when_unverified() {
        let store = make_store(MAPPINGS).await;
        let expires = SystemTime::now() + Duration::from_secs(300);

        let admitted = store.admit(&make_token("s-123", None), expires).unwrap();
        assert!(admitted.iter().all(|a| a.get_key() != "user.email"));

        let attrs = store
            .get_attributes_for_actor(&google_identities("s-123"))
            .await
            .unwrap();
        assert!(attrs.iter().all(|a| a.get_key() != "user.email"));
        // The sub itself still maps.
        assert!(attrs.iter().any(|a| a.get_key() == "user.oidc-subject"));
    }

    /// flush drops every admitted record: the next lookup finds nothing.
    #[tokio::test]
    async fn test_flush_clears_admitted() {
        let store = make_store(MAPPINGS).await;
        let expires = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();

        store.flush().await.unwrap();

        let attrs = store
            .get_attributes_for_actor(&google_identities("s-123"))
            .await
            .unwrap();
        assert!(attrs.is_empty());
    }

    /// Admitting a token advances the store revision, so the ts_mgr refresh
    /// machinery sees actors as stale against the new snapshot.
    #[tokio::test]
    async fn test_admit_bumps_revision() {
        let store = make_store(MAPPINGS).await;
        let before = store.current_revision();
        store
            .admit(
                &make_token("s-123", Some("jane@example.com")),
                SystemTime::now() + Duration::from_secs(300),
            )
            .unwrap();
        assert!(store.current_revision() > before);
    }

    /// Cross-issuer subject collision (PR #5 review): OIDC subjects are unique
    /// per issuer only, so a lookup carrying an actor authority naming a
    /// DIFFERENT service must not be served this store's cached claims, even
    /// when the `(mapped sub key, sub)` pair matches an admitted record.
    #[tokio::test]
    async fn test_lookup_scoped_to_issuing_service_authority() {
        let store = make_store(MAPPINGS).await;
        let expires = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-123", Some("jane@example.com")), expires)
            .unwrap();

        // Actor authenticated by another provider that happens to have issued
        // the same subject string: no attributes from this store.
        let foreign = [
            (
                libeval::attribute::key::USER_AUTHORITY.to_string(),
                "other-idp".to_string(),
            ),
            ("user.oidc-subject".to_string(), "s-123".to_string()),
        ];
        let attrs = store.get_attributes_for_actor(&foreign).await.unwrap();
        assert!(
            attrs.is_empty(),
            "an actor vouched for by another service must not receive this store's cache"
        );

        // The actor this store admitted (authority == this service) is served.
        let own = [
            (
                libeval::attribute::key::USER_AUTHORITY.to_string(),
                "google".to_string(),
            ),
            ("user.oidc-subject".to_string(), "s-123".to_string()),
        ];
        let attrs = store.get_attributes_for_actor(&own).await.unwrap();
        assert!(attrs.iter().any(|a| a.get_key() == "user.email"));
    }

    /// Admission purges expired records (PR #5 review): a subject that
    /// disconnects and never returns must not stay cached forever — the next
    /// admission sweeps it out, bounding the cache to subjects seen within one
    /// expiration window.
    #[tokio::test]
    async fn test_admit_purges_expired_entries() {
        let store = make_store(MAPPINGS).await;
        let past = SystemTime::now() - Duration::from_secs(1);
        store
            .admit(&make_token("s-gone", Some("gone@example.com")), past)
            .unwrap();
        assert_eq!(store.admitted.len(), 1);

        let future = SystemTime::now() + Duration::from_secs(300);
        store
            .admit(&make_token("s-new", Some("new@example.com")), future)
            .unwrap();
        assert_eq!(
            store.admitted.len(),
            1,
            "admission must sweep out expired records"
        );
        assert!(store.admitted.contains_key("s-new"));
    }

    /// The admitted cache entry carries the attributes and expiry; renewal
    /// anchors live in the per-session store instead (PR #19 review), so a
    /// second admission for the same subject cannot clobber another live
    /// session's anchors.
    #[tokio::test]
    async fn test_admitted_entry_carries_attrs_and_expiry() {
        let store = make_store(MAPPINGS).await;
        let expires = SystemTime::now() + Duration::from_secs(300);
        let token = make_token("s-123", Some("jane@example.com"));
        store.admit(&token, expires).unwrap();

        let entry = store.admitted.get("s-123").expect("admitted entry");
        assert_eq!(entry.expires, expires);
        assert!(!entry.attrs.is_empty());
    }

    /// zipline#43 (per-session — PR #19 review): `session_anchors`
    /// returns what `record_session` recorded for that session id, `None`
    /// for an unknown session, and two sessions for the SAME subject keep
    /// independent anchors.
    #[tokio::test]
    async fn test_session_anchors_scoped_per_session() {
        let store = make_store(MAPPINGS).await;
        let auth_time1 = SystemTime::now() - Duration::from_secs(3600);
        let iat1 = SystemTime::now() - Duration::from_secs(60);
        let auth_time2 = SystemTime::now() - Duration::from_secs(120);
        let iat2 = SystemTime::now();
        let expires = SystemTime::now() + Duration::from_secs(300);

        store.record_session("fd5a::1", "s-123", auth_time1, iat1, expires);
        store.record_session("fd5a::2", "s-123", auth_time2, iat2, expires);

        let a1 = store
            .session_anchors("fd5a::1")
            .expect("session 1 recorded");
        assert_eq!(a1.sub, "s-123");
        assert_eq!(a1.auth_time, auth_time1);
        assert_eq!(a1.iat, iat1);
        assert_eq!(a1.expires, expires);

        let a2 = store
            .session_anchors("fd5a::2")
            .expect("session 2 recorded");
        assert_eq!((a2.auth_time, a2.iat), (auth_time2, iat2));

        assert!(
            store.session_anchors("fd5a::dead").is_none(),
            "an unknown session has no recorded anchors"
        );

        // flush drops recorded sessions too.
        store.flush().await.unwrap();
        assert!(store.session_anchors("fd5a::1").is_none());
    }

    /// T3 (zipline#42): `session_ceiling` is `auth_time + max_auth_age_seconds
    /// + clock_skew` (the skew term mirrors zipline#8 acceptance, PR #18 review) and
    /// `None` when the knob is 0 (no ceiling: the session may renew forever).
    #[tokio::test]
    async fn test_session_ceiling_from_max_auth_age() {
        // Fixture config has max_auth_age_seconds = 0: no ceiling.
        let store = make_store(MAPPINGS).await;
        let auth_time = SystemTime::now();
        assert_eq!(store.session_ceiling(auth_time), None);

        // With the knob set, the ceiling is auth_time + max_auth_age + skew.
        let mut record = make_record(MAPPINGS);
        record.oidc.as_mut().unwrap().max_auth_age_seconds = 7200;
        let keys = Arc::new(
            KeySource::from_policy(record.oidc.as_ref().unwrap(), static_proxy(None))
                .await
                .unwrap(),
        );
        let store = OidcTrustedService::new(&record, keys).unwrap();
        assert_eq!(
            store.session_ceiling(auth_time),
            Some(auth_time + Duration::from_secs(7200) + IdpParams::default_clock_skew())
        );
    }

    /// zipline#42 review (PR #18): validation accepts an `auth_time` up to
    /// `max_auth_age + clock_skew` old (zipline#8 skew leeway), so the ceiling must
    /// carry the same allowance — an accepted token must never be stamped an
    /// already-expired `user.zpr.authority`. The worst accepted case
    /// (`auth_time` exactly `max_auth_age + clock_skew` old) yields a ceiling
    /// that is not in the past.
    #[tokio::test]
    async fn test_session_ceiling_covers_accepted_skew() {
        let mut record = make_record(MAPPINGS);
        record.oidc.as_mut().unwrap().max_auth_age_seconds = 7200;
        let keys = Arc::new(
            KeySource::from_policy(record.oidc.as_ref().unwrap(), static_proxy(None))
                .await
                .unwrap(),
        );
        let store = OidcTrustedService::new(&record, keys).unwrap();
        let skew = IdpParams::default_clock_skew();

        let now = SystemTime::now();
        let auth_time = now - (Duration::from_secs(7200) + skew);
        let ceiling = store
            .session_ceiling(auth_time)
            .expect("knob set: there must be a ceiling");
        assert!(
            ceiling >= now,
            "an auth_time validation accepts must never yield an already-expired ceiling"
        );
        // Symmetric with acceptance: the ceiling is extended by the same
        // clock_skew used to accept, no more.
        assert_eq!(ceiling, auth_time + Duration::from_secs(7200) + skew);
    }

    /// zipline#42 review (PR #18): the ceiling addition must be total — an
    /// extreme but representable `auth_time` must not panic the unchecked
    /// `auth_time + max_auth_age` sum. An unrepresentably far ceiling bounds
    /// nothing, which is exactly what `None` (no ceiling) means.
    #[tokio::test]
    async fn test_session_ceiling_overflow_is_no_ceiling() {
        let mut record = make_record(MAPPINGS);
        record.oidc.as_mut().unwrap().max_auth_age_seconds = 7200;
        let keys = Arc::new(
            KeySource::from_policy(record.oidc.as_ref().unwrap(), static_proxy(None))
                .await
                .unwrap(),
        );
        let store = OidcTrustedService::new(&record, keys).unwrap();

        // The latest representable SystemTime on this platform, by descent.
        let mut far = SystemTime::UNIX_EPOCH;
        let mut step = Duration::from_secs(u64::MAX);
        while step > Duration::ZERO {
            match far.checked_add(step) {
                Some(next) => far = next,
                None => step /= 2,
            }
        }
        assert_eq!(store.session_ceiling(far), None);
    }
}
