//! Trusted-service abstractions and implementations.

use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use libeval::attribute::{Attribute, AttributeSource, key};

use crate::error::ServiceError;

pub(crate) mod attr_query_store;
mod attribute_mapper;
mod factory;
mod file_attribute_store;
mod manager;

pub(crate) use attribute_mapper::{AttrHint, AttributeMapper};

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod attr_query_reference_tests;

pub use factory::{
    TS_API_OIDC, TrustedServiceDefinition, build_services, trusted_service_definitions,
};
pub use manager::TrustedServicesMgr;

/// Shortest attribute lifetime a trusted-service declaration may configure, shared by
/// the `file` and `zpr-attr/1` stores (docs/ATTRIBUTE_SERVICE.md, *Declaring an
/// attribute service in policy*). The file store also reloads its snapshot once less
/// than this remains, so it never vends an attribute with less than this to live.
pub(crate) const MIN_ATTRIBUTE_TTL: Duration = Duration::from_secs(60);

// The refresh-ahead window must stay under MIN_ATTRIBUTE_TTL: a file store reloads only
// below MIN_ATTRIBUTE_TTL, so a refresh at or above it would re-vend the same expiry and
// gain nothing (zl-zipline#275).
const _: () =
    assert!(crate::config::ATTRIBUTE_REFRESH_AHEAD.as_secs() < MIN_ATTRIBUTE_TTL.as_secs());

/// A revision no snapshot will ever carry (the counter starts at 1). Recording it for
/// an actor keeps a source relevant-and-stale, forcing a retry on the next request.
pub const REVISION_NEVER: u64 = 0;

/// Process-wide source of snapshot revisions. Revisions and actor records both reset
/// on restart, while a missing actor record safely forces a refresh.
static REVISION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Hand out the next process-wide trusted-service snapshot revision.
pub(crate) fn next_revision() -> u64 {
    REVISION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Intersect the policy's lookup-identity keys (see `Policy::lookup_identity_keys`)
/// with a set of attributes -- authenticated claims at connect time, the actor's
/// attributes at refresh time -- producing the (key, value) pairs to send to trusted
/// services. Attributes that are not single-valued cannot name an identity and are
/// skipped.
///
/// `user.zpr.authority` is always included when the actor carries it, whether or
/// not policy names it: identities such as an OIDC `sub` are unique only within
/// the service that vouched for them, so sources need the authority pair to scope
/// per-issuer identities to the issuing service (see
/// `crate::oidc::OidcTrustedService::get_attributes_for_actor`).
pub(crate) fn lookup_identities<'a>(
    lookup_keys: &[&str],
    attrs: impl Iterator<Item = &'a Attribute>,
) -> Vec<(String, String)> {
    let mut identities = Vec::new();
    for attr in attrs {
        if lookup_keys.contains(&attr.get_key()) || attr.get_key() == key::USER_AUTHORITY {
            if let Ok(value) = attr.get_single_value() {
                identities.push((attr.get_key().to_string(), value.to_string()));
            }
        }
    }
    identities
}

/// Prefix of attribute keys in the user identity namespace.
const USER_NAMESPACE_PREFIX: &str = "user.";

/// Derive the bootstrap-era `user.zpr.authority` attribute from one trusted service's
/// results (#324 follow-up). A trusted service that vends `user.*` attributes for an
/// actor is the authority asserting that user identity, so the service's source id
/// becomes the authority value — the same shape as the RSA bootstrap path using
/// `zpr-bootstrap` as the `device.zpr.authority` value. The derived attribute expires
/// with the earliest-expiring vended user attribute, so the authority never outlives
/// the user record it vouches for, and is stamped with the service's source so the
/// refresh path prunes it together with that record.
///
/// Returns None when the service vended no `user.*` attributes (a device with no user
/// record in any trusted service must still not match a bare `allow users ...` rule —
/// the fail-closed property of #144 survives), when the service explicitly vended
/// `user.zpr.authority` itself (it is asserting the authority directly; nothing to
/// derive), and when `existing_authority` names a DIFFERENT source (zipline#25): the
/// service that verified the credential owns `user.zpr.authority`, so a service that
/// merely decorates an already-identified actor with extra attributes never displaces
/// it. The `!=` is load-bearing — when the existing authority IS this source,
/// derivation still proceeds, which is how the authenticating service re-stamps the
/// authority's expiry against its own current user record on every refresh.
pub(crate) fn derive_user_authority(
    source_id: &str,
    ts_attrs: &[Attribute],
    existing_authority: Option<&str>,
) -> Option<Attribute> {
    if let Some(existing) = existing_authority {
        if existing != source_id {
            return None;
        }
    }
    if ts_attrs.iter().any(|a| a.get_key() == key::USER_AUTHORITY) {
        return None;
    }
    let expires = ts_attrs
        .iter()
        .filter(|a| a.get_key().starts_with(USER_NAMESPACE_PREFIX))
        .map(|a| a.get_expires())
        .min()?;
    Some(
        AttributeSource::new(source_id)
            .builder(key::USER_AUTHORITY)
            .expires(expires)
            .value(source_id),
    )
}

/// Interface for trusted services that can provide attributes for actors.
#[async_trait]
pub trait TrustedServiceInterface: Send + Sync {
    /// Return attributes for the actor identified by `identities`, or an empty vector
    /// when none of the identities are known.
    ///
    /// `identities` is the actor's lookup-identity set: one (attribute key, value) pair
    /// per identity the actor authenticated under (e.g. a device CN and a user subject),
    /// so the source can tell which kind of identity each value is. A source that
    /// matches more than one identity returns the UNION of their attributes; if two
    /// matched identities supply the same ZPR attribute key with differing values the
    /// source must return `Err` (fail closed) rather than pick a winner.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError>;

    /// Drop cached attribute data so the next lookup fetches fresh data.
    async fn flush(&self) -> Result<(), ServiceError>;

    /// Return the revision of the data the service currently serves.
    fn current_revision(&self) -> u64;

    /// Return the stable source identifier stamped on this service's attributes.
    fn get_source_id(&self) -> &str;
}

#[cfg(test)]
mod derive_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    /// Build a source-stamped attribute expiring `secs` seconds from now.
    fn attr(source: &str, key: &str, value: &str, secs: u64) -> Attribute {
        AttributeSource::new(source)
            .builder(key)
            .expires(SystemTime::now() + Duration::from_secs(secs))
            .value(value)
    }

    /// A source vending `user.*` attributes yields a derived `user.zpr.authority`
    /// valued with the source id, stamped with that source, and expiring with the
    /// earliest-expiring vended user attribute.
    #[test]
    fn test_derive_user_authority_from_user_attrs() {
        let attrs = vec![
            attr("hr", "user.clearance", "classified", 600),
            attr("hr", "user.dept", "engineering", 300),
            attr("hr", "device.zpr.location", "hq", 60),
        ];
        let authority = derive_user_authority("hr", &attrs, None).expect("authority expected");
        assert_eq!(authority.get_key(), key::USER_AUTHORITY);
        assert_eq!(authority.get_value(), ["hr".to_string()]);
        assert_eq!(authority.get_source(), "hr");
        // Tracks the earliest user.* expiration (user.dept at ~300s), not the
        // device attribute's 60s and not user.clearance's 600s.
        assert_eq!(
            authority.get_expires(),
            attrs[1].get_expires(),
            "authority must expire with the earliest-expiring user attribute"
        );
    }

    /// A source vending only device attributes (or nothing) derives no user
    /// authority, preserving the fail-closed property of #144 for bare
    /// `allow users ...` rules.
    #[test]
    fn test_derive_user_authority_none_without_user_attrs() {
        let device_only = vec![attr("hr", "device.zpr.location", "hq", 600)];
        assert!(derive_user_authority("hr", &device_only, None).is_none());
        assert!(derive_user_authority("hr", &[], None).is_none());
    }

    /// Guard against the zipline#24 defect: the service that verified the
    /// credential owns `user.zpr.authority`. A source vending only decorating
    /// `user.*` attributes — here `happyfile` vending the tag `user.zpr.tag.lazy`
    /// — must NOT displace an authority already asserted by another source (the
    /// OIDC arm's `user.zpr.authority = google`): with a competing
    /// `existing_authority` the derivation returns `None` (zipline#25, plan
    /// task V2). Before that fix this test asserted the opposite — the derived
    /// value silently overwrote the authenticator's, last writer wins in
    /// `Actor::attrs` — which was the #24 characterization.
    #[test]
    fn test_derive_user_authority_displaces_competing_authority_zipline24() {
        let attrs = vec![attr("happyfile", "user.zpr.tag.lazy", "", 600)];
        assert!(
            derive_user_authority("happyfile", &attrs, Some("google")).is_none(),
            "a decorating source must not displace the authenticator's authority"
        );
    }

    /// The `!=` in the competing-authority guard is load-bearing: when the
    /// existing authority IS this source, derivation still proceeds so the
    /// authenticating service re-stamps the authority's expiry against its own
    /// current user record on every refresh (#324 — the authority must not
    /// outlive the record it vouches for). Blocking on `Some(_)` unconditionally
    /// would freeze the expiry and let the authority lapse mid-session.
    #[test]
    fn test_derive_user_authority_restamps_own_authority() {
        let attrs = vec![
            attr("google", "user.oidc-subject", "s-123", 600),
            attr("google", "user.dept", "engineering", 300),
        ];
        let authority = derive_user_authority("google", &attrs, Some("google"))
            .expect("the authenticating source must re-derive its own authority");
        assert_eq!(authority.get_key(), key::USER_AUTHORITY);
        assert_eq!(authority.get_value(), ["google".to_string()]);
        assert_eq!(authority.get_source(), "google");
        assert_eq!(
            authority.get_expires(),
            attrs[1].get_expires(),
            "expiry must be recomputed from the current ts_attrs on each pass"
        );
    }

    /// With no existing authority the derivation behaves exactly as today —
    /// the single-file-store case (#144 / #324) must not regress.
    #[test]
    fn test_derive_user_authority_without_existing_authority() {
        let attrs = vec![attr("hr", "user.dept", "engineering", 300)];
        let authority = derive_user_authority("hr", &attrs, None).expect("authority expected");
        assert_eq!(authority.get_value(), ["hr".to_string()]);
        assert_eq!(authority.get_expires(), attrs[0].get_expires());
    }

    /// A source that vends `user.zpr.authority` itself asserts the authority
    /// directly; nothing is derived on top of it.
    #[test]
    fn test_derive_user_authority_defers_to_explicit() {
        let attrs = vec![
            attr("hr", key::USER_AUTHORITY, "custom-authority", 600),
            attr("hr", "user.dept", "engineering", 300),
        ];
        assert!(derive_user_authority("hr", &attrs, None).is_none());
    }

    /// `user.zpr.authority` is always part of the lookup-identity set when the
    /// actor carries it (PR #5 review): it scopes per-issuer identities like an
    /// OIDC `sub` to the service that vouched for them, so it must reach the
    /// stores even though policy never declares it as an identity attribute.
    #[test]
    fn test_lookup_identities_includes_user_authority() {
        let attrs = vec![
            attr("google", key::USER_AUTHORITY, "google", 600),
            attr("google", "user.oidc-subject", "s-123", 600),
            attr("hr", "user.dept", "engineering", 600),
        ];
        let identities = lookup_identities(&["user.oidc-subject"], attrs.iter());
        assert!(
            identities.contains(&(key::USER_AUTHORITY.to_string(), "google".to_string())),
            "the authority pair must be in the lookup set: {identities:?}"
        );
        assert!(identities.contains(&("user.oidc-subject".to_string(), "s-123".to_string())));
        // Non-identity attributes still never leak into the lookup set.
        assert!(!identities.iter().any(|(k, _)| k == "user.dept"));

        // And it is not duplicated when policy also names it a lookup key.
        let identities =
            lookup_identities(&["user.oidc-subject", key::USER_AUTHORITY], attrs.iter());
        assert_eq!(
            identities
                .iter()
                .filter(|(k, _)| k == key::USER_AUTHORITY)
                .count(),
            1
        );
    }
}
