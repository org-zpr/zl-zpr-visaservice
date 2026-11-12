//! Coordination and revision tracking across trusted services.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::future::join_all;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use libeval::attribute::Attribute;

use crate::error::ServiceError;
use crate::oidc::OidcTrustedService;

use super::TrustedServiceInterface;

/// Coordinates concurrent access to the configured trusted-service implementations.
pub struct TrustedServicesMgr {
    services: ArcSwap<Vec<Arc<dyn TrustedServiceInterface>>>,
    /// The OIDC subset of `services`, kept typed so the connect path (C5) can
    /// reach provider-specific state (`params`, `keys`, `admit`) that the
    /// `dyn` interface deliberately does not expose. Every store in here is
    /// also in `services`; both lists are replaced together on policy install.
    oidc_services: ArcSwap<Vec<Arc<OidcTrustedService>>>,
    /// Per actor (keyed by ZPR address) and source, the revision from which attributes
    /// were last refreshed plus its invalidation generation ([RevisionRecord]). ZPR
    /// addresses are recycled from a pool, so entries MUST be
    /// purged on disconnect ([TrustedServicesMgr::forget_actor_revisions]) before the
    /// address can be reassigned.
    actor_revisions: DashMap<IpAddr, HashMap<String, RevisionRecord>>,
}

/// Per-source refresh record for one actor: the source revision the actor's
/// attributes were last refreshed from (`None` after a targeted invalidation),
/// and a monotonic invalidation generation (PR #29 review, P1). A refresh pass
/// captures the generation BEFORE it queries the source
/// ([TrustedServicesMgr::invalidation_generation]) and commits conditionally on
/// it ([TrustedServicesMgr::record_revision]), so a pass that read the
/// source's pre-notification state can never record "current" over a targeted
/// invalidation that landed while it was in flight — the bumped generation
/// drops the stale commit and the source stays stale until a
/// post-notification pass commits.
#[derive(Clone, Copy, Default)]
struct RevisionRecord {
    revision: Option<u64>,
    generation: u64,
}

impl TrustedServicesMgr {
    /// Create a manager with no configured services.
    pub fn new() -> Self {
        Self {
            services: ArcSwap::new(Arc::new(Vec::new())),
            oidc_services: ArcSwap::new(Arc::new(Vec::new())),
            actor_revisions: DashMap::new(),
        }
    }

    /// Return sources whose current revision differs from the record for the actor at
    /// `zpr_addr`. A source with no record at all is stale: the actor has never been
    /// refreshed from it (or the last attempt failed), so it must be consulted even
    /// when the actor holds no attribute from it -- otherwise a source that vended
    /// nothing on the first lookup would be skipped forever, including after a flush
    /// adds attributes for the actor.
    pub fn stale_sources_for_actor(&self, zpr_addr: &IpAddr) -> Vec<(String, u64)> {
        let services = self.services.load_full();
        let recorded = self.actor_revisions.get(zpr_addr);
        services
            .iter()
            .filter_map(|service| {
                let source_id = service.get_source_id();
                let recorded_revision = recorded
                    .as_ref()
                    .and_then(|revisions| revisions.value().get(source_id))
                    .and_then(|record| record.revision);
                let current_revision = service.current_revision();
                (recorded_revision != Some(current_revision))
                    .then(|| (source_id.to_string(), current_revision))
            })
            .collect()
    }

    /// Record the source revision used to refresh the attributes of the actor at
    /// `zpr_addr`, unconditionally. Test-only shorthand for catch-up setup where no
    /// refresh pass can be in flight; the production commit path is
    /// [Self::record_revision_at_generation], which cannot overwrite a targeted
    /// invalidation that landed mid-pass.
    #[cfg(test)]
    pub fn record_revision(&self, zpr_addr: &IpAddr, source: &str, revision: u64) {
        self.actor_revisions
            .entry(*zpr_addr)
            .or_default()
            .entry(source.to_string())
            .or_default()
            .revision = Some(revision);
    }

    /// The current invalidation generation for (actor, source); 0 when there is no
    /// record. A refresh pass captures this BEFORE querying the source and passes it
    /// to [Self::record_revision_at_generation] at commit time.
    pub fn invalidation_generation(&self, zpr_addr: &IpAddr, source: &str) -> u64 {
        self.actor_revisions
            .get(zpr_addr)
            .and_then(|revisions| revisions.get(source).map(|record| record.generation))
            .unwrap_or(0)
    }

    /// Record the source revision only if the (actor, source) invalidation generation
    /// still equals `observed_generation` (PR #29 review, P1). Returns whether the
    /// commit landed. A mismatch means a targeted change notification
    /// ([Self::forget_source_revision]) arrived after the caller captured the
    /// generation — the caller's data may predate the notification, so the record
    /// stays stale and the next refresh pass re-queries.
    pub fn record_revision_at_generation(
        &self,
        zpr_addr: &IpAddr,
        source: &str,
        revision: u64,
        observed_generation: u64,
    ) -> bool {
        let mut revisions = self.actor_revisions.entry(*zpr_addr).or_default();
        let record = revisions.entry(source.to_string()).or_default();
        if record.generation != observed_generation {
            return false;
        }
        record.revision = Some(revision);
        true
    }

    /// Drop all recorded per-source revisions for the actor at `zpr_addr`. Call before
    /// the address returns to the pool, so a recycled address cannot inherit them.
    pub fn forget_actor_revisions(&self, zpr_addr: &IpAddr) {
        self.actor_revisions.remove(zpr_addr);
    }

    /// Invalidate every recorded source revision of the actor at `zpr_addr`
    /// without resetting its invalidation generation (#63 review): each current
    /// source's record has its revision cleared (stale) and its generation
    /// bumped, created when absent. A refresh pass already in flight captured
    /// the old generation, so its commit ([Self::record_revision_at_generation])
    /// is refused and cannot mark data read before this point as current.
    /// [Self::forget_actor_revisions] instead deletes the records -- right for a
    /// disconnect (the address is recycled), wrong here, because a deleted
    /// record reads as generation 0 again.
    pub fn invalidate_actor_revisions(&self, zpr_addr: &IpAddr) {
        let services = self.services.load_full();
        let mut revisions = self.actor_revisions.entry(*zpr_addr).or_default();
        for record in revisions.values_mut() {
            record.revision = None;
            record.generation += 1;
        }
        for service in services.iter() {
            revisions
                .entry(service.get_source_id().to_string())
                .or_insert(RevisionRecord {
                    revision: None,
                    generation: 1,
                });
        }
    }

    /// Drop the recorded revision for exactly one (actor, source) pair
    /// (zipline#79): a targeted change notification names the actors whose
    /// data changed at one source, so only that record may go stale — the
    /// actor's other sources and every other actor keep their records. The
    /// cleared revision makes the source stale for the actor
    /// ([Self::stale_sources_for_actor]), forcing a re-query on the next
    /// refresh pass.
    ///
    /// Also bumps the pair's invalidation generation, and creates the record
    /// when none exists, so a refresh pass already in flight cannot commit
    /// state it read before this notification (PR #29 review, P1; see
    /// [Self::record_revision_at_generation]). Callers pass only connected
    /// actors' addresses; disconnect purges the entry
    /// ([Self::forget_actor_revisions]), so a created record cannot leak.
    pub fn forget_source_revision(&self, zpr_addr: &IpAddr, source: &str) {
        let mut revisions = self.actor_revisions.entry(*zpr_addr).or_default();
        let record = revisions.entry(source.to_string()).or_default();
        record.revision = None;
        record.generation += 1;
    }

    /// Atomically replace the entire trusted-service list. The typed OIDC list
    /// is cleared. Production code publishes via [Self::update_services_with_oidc];
    /// this shorthand serves the many tests that register plain stores.
    #[cfg(test)]
    pub fn update_services(&self, services: Vec<Arc<dyn TrustedServiceInterface>>) {
        self.update_services_with_oidc(services, Vec::new());
    }

    /// Replace the trusted-service list together with its typed OIDC subset
    /// (each OIDC store appears in both). Two swaps, not one atom: readers of
    /// one list never join it against the other, they only look services up
    /// by id or issuer, so a momentary mismatch cannot misattribute a store.
    pub fn update_services_with_oidc(
        &self,
        services: Vec<Arc<dyn TrustedServiceInterface>>,
        oidc_services: Vec<Arc<OidcTrustedService>>,
    ) {
        self.services.store(Arc::new(services));
        self.oidc_services.store(Arc::new(oidc_services));
    }

    /// The OIDC trusted service pinned to `issuer`, when the current policy
    /// declares one. The connect path (C5) resolves the provider for an
    /// incoming token by its `iss` claim through this.
    #[allow(dead_code)] // consumed by the C5 connect path
    pub fn oidc_service_for_issuer(&self, issuer: &str) -> Option<Arc<OidcTrustedService>> {
        self.oidc_services
            .load()
            .iter()
            .find(|service| service.issuer() == issuer)
            .cloned()
    }

    /// Query every given trusted service concurrently for an actor's attributes.
    ///
    /// `identities` is the actor's lookup-identity (key, value) set; see
    /// [TrustedServiceInterface::get_attributes_for_actor]. Takes an explicit
    /// store list — the connect path passes the stores captured in a
    /// [crate::policy_mgr::PolicySnapshot] rather than this manager's live
    /// list, pinning the whole authentication to one policy revision
    /// (PR #6 review).
    ///
    /// Each result is paired with the service's source id so the caller can attribute
    /// it (e.g. to derive `user.zpr.authority` from the vending source) without
    /// trusting the source string stamped on the returned attributes themselves.
    pub async fn get_attributes_for_actor_from(
        services: &[Arc<dyn TrustedServiceInterface>],
        identities: &[(String, String)],
    ) -> Vec<(String, Result<Vec<Attribute>, ServiceError>)> {
        let futures = services.iter().map(|service| {
            let service = service.clone();
            async move {
                (
                    service.get_source_id().to_string(),
                    service.get_attributes_for_actor(identities).await,
                )
            }
        });
        join_all(futures).await
    }

    /// Query one named trusted service for an actor's attributes.
    ///
    /// `identities` is the actor's lookup-identity (key, value) set; see
    /// [TrustedServiceInterface::get_attributes_for_actor].
    pub async fn get_attributes_from_source_for_actor(
        &self,
        source_ident: &str,
        identities: &[(String, String)],
    ) -> Vec<Result<Vec<Attribute>, ServiceError>> {
        let snapshot = self.services.load_full();
        if let Some(service) = snapshot
            .iter()
            .find(|service| service.get_source_id() == source_ident)
        {
            let service = service.clone();
            return vec![service.get_attributes_for_actor(identities).await];
        }

        vec![Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))]
    }

    /// Flush every trusted service without stopping after an individual failure.
    #[allow(dead_code)]
    pub async fn flush_all(&self) -> Vec<Result<(), ServiceError>> {
        let snapshot = self.services.load_full();
        let futures = snapshot.iter().map(|service| {
            let service = service.clone();
            async move { service.flush().await }
        });
        join_all(futures).await
    }

    /// Whether a trusted service with this source id is currently configured
    /// (zipline#79): the notification endpoint's existence check for bodies
    /// that do not go through [Self::flush_one].
    pub fn has_source(&self, source_ident: &str) -> bool {
        self.services
            .load()
            .iter()
            .any(|service| service.get_source_id() == source_ident)
    }

    /// Flush one named trusted service.
    pub async fn flush_one(&self, source_ident: &str) -> Result<(), ServiceError> {
        let snapshot = self.services.load_full();
        if let Some(service) = snapshot
            .iter()
            .find(|service| service.get_source_id() == source_ident)
        {
            let service = service.clone();
            return service.flush().await;
        }

        Err(ServiceError::TrustedServiceNotFound(
            source_ident.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::file_attribute_store::FileAttributeStore;
    use crate::trusted_services::test_support::{test_mapper, write_fixture};
    use std::fs;
    use std::time::Duration;

    /// Flushing all services reaches each registered implementation.
    #[tokio::test]
    async fn test_manager_flush_all_reaches_every_service() {
        let fp = write_fixture(
            "vs-fas-flush-all.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        );
        let manager = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        manager.update_services(vec![store.clone()]);

        let revision_before = store.current_revision();
        let results = manager.flush_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert!(store.current_revision() > revision_before);

        fs::remove_file(&fp).unwrap();
    }

    /// Actor revision records become stale whenever a relevant service advances.
    #[tokio::test]
    async fn test_stale_sources_for_actor_tracks_revisions() {
        let fp = write_fixture(
            "vs-fas-stale.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        );
        let manager = TrustedServicesMgr::new();
        let store = Arc::new(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp,
            )
            .unwrap(),
        );
        manager.update_services(vec![store.clone()]);

        // A configured source the actor has no record for is stale, even though the
        // actor holds no attribute from it -- otherwise a source that vended nothing on
        // the first lookup would never be consulted again.
        let addr: IpAddr = "fd5a:5052::a1".parse().unwrap();
        let stale = manager.stale_sources_for_actor(&addr);
        assert_eq!(stale, vec![("test".to_string(), store.current_revision())]);

        manager.record_revision(&addr, "test", stale[0].1);
        assert!(manager.stale_sources_for_actor(&addr).is_empty());

        store.flush().await.unwrap();
        assert_eq!(
            manager.stale_sources_for_actor(&addr),
            vec![("test".to_string(), store.current_revision())]
        );

        // Forgetting the actor's records makes the source stale again, so a recycled
        // address cannot inherit the previous actor's revision history.
        manager.record_revision(&addr, "test", store.current_revision());
        assert!(manager.stale_sources_for_actor(&addr).is_empty());
        manager.forget_actor_revisions(&addr);
        assert_eq!(
            manager.stale_sources_for_actor(&addr),
            vec![("test".to_string(), store.current_revision())]
        );

        fs::remove_file(&fp).unwrap();
    }

    /// Forgetting one (actor, source) revision record makes exactly that
    /// source stale for exactly that actor (zipline#79): the targeted
    /// change-notification path must not disturb the actor's other sources or
    /// any other actor's records.
    #[tokio::test]
    async fn test_forget_source_revision_scopes_to_one_actor_and_source() {
        let fp1 = write_fixture(
            "vs-fas-forget-s1.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        );
        let fp2 = write_fixture(
            "vs-fas-forget-s2.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"shape": ["round"]}}}"#,
        );
        let manager = TrustedServicesMgr::new();
        let s1 = Arc::new(
            FileAttributeStore::new(
                "s1".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp1,
            )
            .unwrap(),
        );
        let s2 = Arc::new(
            FileAttributeStore::new(
                "s2".to_string(),
                test_mapper(),
                Duration::from_secs(3600),
                &fp2,
            )
            .unwrap(),
        );
        manager.update_services(vec![s1.clone(), s2.clone()]);

        let actor_a: IpAddr = "fd5a:5052::a1".parse().unwrap();
        let actor_b: IpAddr = "fd5a:5052::b1".parse().unwrap();
        // Both actors fully caught up on every source.
        manager.record_revision(&actor_a, "s1", s1.current_revision());
        manager.record_revision(&actor_a, "s2", s2.current_revision());
        manager.record_revision(&actor_b, "s1", s1.current_revision());
        assert!(manager.stale_sources_for_actor(&actor_a).is_empty());

        manager.forget_source_revision(&actor_a, "s1");

        // Exactly s1 is stale for actor A...
        assert_eq!(
            manager.stale_sources_for_actor(&actor_a),
            vec![("s1".to_string(), s1.current_revision())]
        );
        // ...and actor B's s1 record is untouched (s2 was never recorded for
        // B, so only that one shows up).
        assert_eq!(
            manager.stale_sources_for_actor(&actor_b),
            vec![("s2".to_string(), s2.current_revision())]
        );

        // Forgetting for an actor with no records at all is a no-op.
        let actor_c: IpAddr = "fd5a:5052::c1".parse().unwrap();
        manager.forget_source_revision(&actor_c, "s1");

        fs::remove_file(&fp1).unwrap();
        fs::remove_file(&fp2).unwrap();
    }
}
