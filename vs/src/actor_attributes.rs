//! Trusted-attribute lifecycle for actors: refresh an actor's attributes from
//! the trusted services that vend them, persist the result, and only then
//! record the source revisions.
//!
//! This is application-service code, not part of `trusted_services`: it needs
//! both the [TrustedServicesMgr] and the [crate::actor_mgr::ActorMgr] (via
//! [Assembly]), and `trusted_services` is (for now...) deliberately kept free
//! of any knowledge of actors or the assembly. Used by the visa-request path
//! and by the reconciliation handlers in `event_mgr`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use libeval::actor::Actor;
use libeval::attribute::{Attribute, key};
use libeval::policy::Policy;

use tracing::{debug, warn};

use crate::assembly::Assembly;
use crate::error::ServiceError;
use crate::logging::targets::VREQ;
use crate::trusted_services::{
    REVISION_NEVER, TrustedServicesMgr, derive_user_authority, lookup_identities,
};

/// What a refresh pass found. Kept separate from the act of applying it so the caller
/// can persist the actor before any of it is committed -- see [refresh_and_persist_actor].
#[derive(Default)]
struct RefreshOutcome {
    /// The actor was modified and needs writing back.
    changed: bool,
    /// Source revisions to record once that write succeeds, each with the
    /// (actor, source) invalidation generation observed BEFORE the source was
    /// queried — the commit is conditional on it (PR #29 review, P1), so a
    /// targeted notification landing mid-pass wins over this pass's read.
    revisions: Vec<(String, u64, u64)>,
    /// Revision-stale sources that could not be reached. Their attributes have been
    /// stripped, so the actor's claim set is incomplete and must not be evaluated.
    indeterminate: Vec<String>,
}

impl RefreshOutcome {
    /// Direct [TrustedServicesMgr] to record the pending source revisions against the
    /// actor's ZPR address. Deliberately not done during the refresh itself: a revision
    /// must never say "current" for an actor whose refreshed attributes did not reach
    /// the database, or the next request would trust the stale copy it loads.
    ///
    /// Each commit is conditional on the invalidation generation observed when
    /// the pass started (PR #29 review, P1): a targeted change notification
    /// that arrived mid-pass bumps the generation, the commit is dropped, and
    /// the source stays stale so the queued reconcile re-queries the actor.
    fn commit_revisions(&self, ts_mgr: &TrustedServicesMgr, zpr_addr: &IpAddr) {
        for (source, revision, generation) in &self.revisions {
            if !ts_mgr.record_revision_at_generation(zpr_addr, source, *revision, *generation) {
                debug!(
                    target: VREQ,
                    "not recording revision {revision} of source '{source}' for actor {zpr_addr}: \
                     invalidated while the refresh was in flight"
                );
            }
        }
    }
}

/// Refresh the actor's attributes (see [refresh_expired_attributes]), persist it to the
/// store if anything changed, and only then record the source revisions. Used by the
/// request path and by the attribute-change reconciliation in `event_mgr`.
///
/// Returns TRUE if the actor was changed and written back.
///
/// ### Errors
/// - `StoreError` if the write back fails. No revision is recorded, so the next request
///   retries the whole refresh.
/// - `AttributesIndeterminate` if a revision-stale source could not be reached. The
///   actor has been stripped of that source's attributes and persisted in that state,
///   but callers must treat the result as a denial rather than evaluate it: absence is
///   not the same as "known to have no such attribute", and some policy conditions are
///   satisfied by a missing key.
pub(crate) async fn refresh_and_persist_actor(
    asm: &Assembly,
    actor: &mut Actor,
) -> Result<bool, ServiceError> {
    let policy = asm.policy_mgr.get_current();
    // The actor as read, before the refresh: its trusted services are queried outside
    // the topology lock, so the commit below applies only what the refresh changed.
    let read_before = actor.clone();
    let outcome =
        refresh_expired_attributes(&asm.ts_mgr, &policy.lookup_identity_keys(), actor).await;
    if outcome.changed {
        // The attributes moved, so the services they grant may have too.
        restamp_services(&policy, actor);
        if !commit_refresh(asm, &read_before, actor).await? {
            // The actor left while the refresh was in flight: nothing to write back,
            // and no revision to record against a departed actor.
            return Err(ServiceError::Internal(format!(
                "actor {:?} left during attribute refresh",
                actor.get_zpr_addr()
            )));
        }
    }

    // No ZPR address means refresh_expired_attributes did nothing at all (an actor
    // without an address has not completed a connection, so there is nothing to key
    // its revision records on).
    let Some(zpr_addr) = actor.get_zpr_addr().copied() else {
        return Ok(outcome.changed);
    };
    outcome.commit_revisions(&asm.ts_mgr, &zpr_addr);

    if !outcome.indeterminate.is_empty() {
        return Err(ServiceError::AttributesIndeterminate(format!(
            "actor {} could not be refreshed from source(s): {}",
            zpr_addr,
            outcome.indeterminate.join(", ")
        )));
    }
    Ok(outcome.changed)
}

/// Write a refreshed actor back under the topology operation lock
/// ([crate::topology_mgr::TopoOps]): re-read the actor as stored now and apply to it
/// only the attributes the refresh changed (`refreshed` against `read_before`), so a
/// session, substrate claim or anything else written meanwhile -- by a reconnect, say
/// -- is not rolled back to the copy the refresh started from. `actor` (`refreshed`)
/// becomes the merged result. Returns false, writing nothing, if the actor is no
/// longer stored (it left while the refresh was in flight).
async fn commit_refresh(
    asm: &Assembly,
    read_before: &Actor,
    refreshed: &mut Actor,
) -> Result<bool, ServiceError> {
    let Some(zpr_addr) = refreshed.get_zpr_addr().copied() else {
        return Ok(false);
    };
    let ops = asm.topo_mgr.ops().await;
    let Some(mut stored) = asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await? else {
        return Ok(false);
    };
    apply_changed_attributes(read_before, refreshed, &mut stored)?;
    asm.actor_mgr
        .update_actor(&stored, &asm.policy_service_names())
        .await?;
    drop(ops);
    *refreshed = stored;
    Ok(true)
}

/// Apply to `target` every attribute that differs between `before` and `after`:
/// changed or added ones are set, removed ones are removed. Attributes the two agree
/// on are left as `target` has them.
fn apply_changed_attributes(
    before: &Actor,
    after: &Actor,
    target: &mut Actor,
) -> Result<(), libeval::actor::AttributeError> {
    let keys: HashSet<String> = before
        .attrs_iter()
        .chain(after.attrs_iter())
        .map(|a| a.get_key().to_string())
        .collect();
    for k in keys {
        match (before.get_attribute(&k), after.get_attribute(&k)) {
            (b, a) if b == a => {}
            (_, Some(a)) => target.add_attribute(a.clone())?,
            (_, None) => {
                target.remove_attribute(&k);
            }
        }
    }
    Ok(())
}

/// Recompute the services the actor provides ([key::SERVICES]) from its current
/// attributes, from the join policies they match as at connect, so a service hosted
/// by attribute follows that attribute (zipline#181). Without this, an actor that gains
/// the hosting attribute provides nothing until it reconnects, and one that loses it
/// keeps providing the service -- and keeps its visas through the change sweep.
///
/// The actor's role is fixed at connect, so only the services connect would grant an
/// actor of that role count ([Policy::join_services_for_role]): an adapter never picks
/// up a node-only service here (Codex P1 on PR #50).
///
/// The policy-stamped keys are left out of the claims matched, as reauthorize does. An
/// attribute stripped because its source was unreachable grants nothing, so the
/// services it granted are dropped: fail-closed.
fn restamp_services(policy: &Policy, actor: &mut Actor) {
    let claims: Vec<Attribute> = actor
        .attrs_iter()
        .filter(|a| !key::POLICY_STAMPED.contains(&a.get_key()))
        .cloned()
        .collect();
    let services = policy.join_services_for_role(&claims, actor.is_node());
    let current: HashSet<String> = actor.services_iter().map(str::to_string).collect();
    if services == current {
        return;
    }
    debug!(
        target: VREQ,
        "actor {:?} services change after attribute refresh: {current:?} -> {services:?}",
        actor.get_zpr_addr()
    );
    actor.set_services(services);
}

/// Refresh the actor's attributes from the trusted service manager where
/// needed: any source with an expired attribute (TTL path), plus any source
/// whose snapshot revision differs from the actor's recorded one (revision
/// path, e.g. after an admin flush).
///
/// A successful lookup is authoritative for that source: anything the service
/// did not vend is dropped.
///
/// A failed TTL lookup changes nothing, so a service outage cannot strip
/// attributes. The leftovers stay expired, and libeval already refuses to
/// satisfy an allow condition from an expired attribute, so that path is
/// fail-closed in this failure case.
///
/// A failed lookup for a revision-stale source (ie, source reports a new
/// revision) is different: there is no expired copy to fall back on, so the
/// source's attributes are stripped and the source is reported as
/// *indeterminate*. The caller must deny rather than evaluate the remaining
/// claims -- absence is not "known to have no such attribute". REVISION_NEVER
/// is queued so the source stays stale and the next request retries.
///
/// Nothing is recorded with the trusted-service manager here; see
/// [RefreshOutcome].
async fn refresh_expired_attributes(
    ts_mgr: &TrustedServicesMgr,
    lookup_keys: &[&str],
    actor: &mut Actor,
) -> RefreshOutcome {
    let mut outcome = RefreshOutcome::default();
    // Revision records are keyed on the ZPR address; an actor without one has not
    // completed a connection and cannot be refreshed.
    let Some(zpr_addr) = actor.get_zpr_addr().copied() else {
        return outcome;
    };
    // The lookup-identity (key, value) set: the policy's lookup-identity keys
    // intersected with the actor's attributes. Every attribute on the actor is either
    // an authenticated claim or validated by a join policy, so this cannot include a
    // self-asserted identity. May legitimately be empty (e.g. an actor with no CN and
    // no policy-declared identity attribute); sources then match nothing.
    let identities = lookup_identities(lookup_keys, actor.attrs_iter());

    let mut sources = HashSet::new();
    for attr in actor.attrs_iter() {
        if attr.is_expired() {
            sources.insert(attr.get_source().to_string());
        }
    }

    // Sources whose snapshot revision the actor has not caught up with, the revision
    // to record once a refresh from them succeeds, and the invalidation generation
    // observed now — BEFORE any source is queried — so the commit can detect a
    // targeted notification that lands while the queries below are in flight
    // (PR #29 review, P1).
    let stale: HashMap<String, (u64, u64)> = ts_mgr
        .stale_sources_for_actor(&zpr_addr)
        .into_iter()
        .map(|(source, rev)| {
            let generation = ts_mgr.invalidation_generation(&zpr_addr, &source);
            (source, (rev, generation))
        })
        .collect();
    sources.extend(stale.keys().cloned());

    // The actor's authority AS OF THE START OF THE PASS gates authority derivation
    // for every source in the loop below (zipline#26, Codex P1 on PR #12): a
    // per-iteration read would observe mutations made by earlier iterations, so
    // when the authority-owning source and a decorating source refresh in the same
    // pass and the owner stops vending its user record, `sources`' hash order
    // would decide whether the decorator gets promoted to authority (owner pruned
    // first) or blocked (decorator first). Snapshotting makes the pass
    // order-independent: the decorator is blocked by the owner's starting stamp in
    // both orders, and if the owner pruned its record the authority is simply gone
    // until a later pass re-derives it against the post-prune state.
    let starting_authority: Option<String> = actor
        .get_attribute(key::USER_AUTHORITY)
        .and_then(|a| a.get_value().first().cloned());

    for source in &sources {
        let stale_rev = stale.get(source);
        for ts_result in ts_mgr
            .get_attributes_from_source_for_actor(source, &identities)
            .await
        {
            match ts_result {
                Ok(ts_attrs) => {
                    // A source vending `user.*` attributes also installs the derived
                    // `user.zpr.authority = <source id>` (#324 follow-up), so the
                    // authority tracks the user record it vouches for: re-derived while
                    // the record is vended, pruned with the record when it disappears
                    // (the derived key is stamped with this source and, when absent
                    // from `returned`, falls to the pruning below like any other
                    // attribute the source stopped vending).
                    let ts_attrs = {
                        let mut ts_attrs = ts_attrs;
                        // The pass's starting authority (snapshotted above) gates
                        // derivation (zipline#26): a decorating source never
                        // displaces the authenticator's stamp, while the
                        // authenticating source itself re-stamps expiry on its own
                        // refresh (same-source arm in [derive_user_authority]).
                        if let Some(authority) =
                            derive_user_authority(source, &ts_attrs, starting_authority.as_deref())
                        {
                            ts_attrs.push(authority);
                        }
                        ts_attrs
                    };
                    let returned: HashSet<String> =
                        ts_attrs.iter().map(|a| a.get_key().to_string()).collect();
                    for attr in ts_attrs {
                        if let Err(e) = actor.add_attribute(attr) {
                            warn!(target: VREQ, "failed to add attribute for actor {}: {}", zpr_addr, e);
                        } else {
                            outcome.changed = true;
                        }
                    }
                    if let Some(&(rev, generation)) = stale_rev {
                        // Revision refresh: the old snapshot's data is invalid, so drop
                        // everything the service did not just return. Queue the
                        // revision even when zero attributes came back — that is what
                        // detects both removed and newly added attributes.
                        outcome.changed |=
                            prune_from_source(actor, source, |a| !returned.contains(a.get_key()));
                        outcome.revisions.push((source.clone(), rev, generation));
                    } else {
                        // TTL refresh: whatever the service did not just set for this
                        // source is gone; drop the leftovers rather than carry a
                        // permanently expired copy.
                        outcome.changed |= prune_from_source(actor, source, |a| a.is_expired());
                    }
                }
                Err(e) => {
                    warn!(target: VREQ, "ts service attr lookup failed for actor {}: {}", zpr_addr, e);
                    if let Some(&(_, generation)) = stale_rev {
                        // Stale-revision attributes must never satisfy an allow policy
                        // just because their TTL has not run out, so strip them -- but
                        // the strip alone is not fail-closed, hence the indeterminate
                        // report. The sentinel keeps the source stale so the next
                        // request retries (the strip would otherwise leave nothing
                        // marking it relevant).
                        outcome.changed |= prune_from_source(actor, source, |_| true);
                        outcome
                            .revisions
                            .push((source.clone(), REVISION_NEVER, generation));
                        outcome.indeterminate.push(source.clone());
                    }
                }
            }
        }
    }
    outcome
}

/// Removes every attribute on `actor` from `source` that matches `pred`.
/// Returns TRUE if anything was removed.
fn prune_from_source(actor: &mut Actor, source: &str, pred: impl Fn(&Attribute) -> bool) -> bool {
    let stale: Vec<String> = actor
        .attrs_iter()
        .filter(|a| a.get_source() == source && pred(a))
        .map(|a| a.get_key().to_string())
        .collect();

    for key in &stale {
        debug!(target: VREQ, "dropping attribute '{key}' no longer vended by source '{source}'");
        actor.remove_attribute(key);
    }
    !stale.is_empty()
}

/// Refresh (and persist) the attributes of each actor in `zpr_addrs`. Only sources that
/// are TTL-expired or revision-stale are actually fetched.
///
/// A failure is logged and skipped rather than aborting the pass: that actor's recorded
/// revision stays mismatched, so its next visa request refreshes it again. This includes
/// an unreachable trusted service (`AttributesIndeterminate`).
///
/// Returns `(refreshed, unresolved, failed)` counts for logging.
///
/// TODO: Sequential, and unbounded in the size of the set. Fine while the only trusted
/// service is the in-memory file store; revisit once services are network calls and
/// actor/visa counts are large.
pub(crate) async fn refresh_actors(asm: &Assembly, zpr_addrs: HashSet<IpAddr>) -> (u32, u32, u32) {
    let (mut refreshed, mut unresolved, mut failed) = (0u32, 0u32, 0u32);
    // Sequential for now, join_all it if sweeps ever get slow.
    for zpr_addr in zpr_addrs {
        match asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await {
            Ok(Some(mut actor)) => match refresh_and_persist_actor(asm, &mut actor).await {
                Ok(true) => refreshed += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(target: VREQ, "attribute reconcile: failed to refresh actor {zpr_addr}: {e}");
                    failed += 1;
                }
            },
            Ok(None) => unresolved += 1,
            Err(e) => {
                warn!(target: VREQ, "attribute reconcile: failed to load actor {zpr_addr}: {e}");
                failed += 1;
            }
        }
    }
    (refreshed, unresolved, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::trusted_services::TrustedServiceInterface;
    use libeval::attribute::{AttributeSource, SOURCE_ZPR, key};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    /// A trusted service that records the lookup-identity sets it was asked about and
    /// returns one canned, freshly-expiring attribute. Its revision starts at 1 and
    /// bumps on every flush, like the real store.
    struct FakeTrustedService {
        calls: std::sync::Mutex<Vec<Vec<(String, String)>>>,
        revision: std::sync::atomic::AtomicU64,
    }

    const FAKE_SOURCE: &str = "fake";
    const FAKE_ATTR_KEY: &str = "user.dept";

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FakeTrustedService {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            self.calls.lock().unwrap().push(identities.to_vec());
            Ok(vec![
                AttributeSource::new(FAKE_SOURCE)
                    .builder(FAKE_ATTR_KEY)
                    .expires_in(Duration::from_secs(600))
                    .value("engineering"),
            ])
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            self.revision
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn current_revision(&self) -> u64 {
            self.revision.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn get_source_id(&self) -> &str {
            FAKE_SOURCE
        }
    }

    /// A manager holding one FakeTrustedService, plus a handle on the fake for assertions.
    fn ts_mgr_with_fake() -> (TrustedServicesMgr, Arc<FakeTrustedService>) {
        let fake = Arc::new(FakeTrustedService {
            calls: std::sync::Mutex::new(Vec::new()),
            revision: std::sync::atomic::AtomicU64::new(1),
        });
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![fake.clone()]);
        (mgr, fake)
    }

    /// The ZPR address every test actor carries, and the calls made with it.
    const TEST_ADDR: &str = "fd5a:5052::42";

    /// Parse the shared test ZPR address.
    fn test_addr() -> IpAddr {
        TEST_ADDR.parse().unwrap()
    }

    /// Refresh an actor (with CN as the only lookup-identity key, matching the default
    /// builtin identity) and commit the resulting revisions, as the request path does
    /// once the actor is persisted. Returns whether the actor changed.
    async fn refresh_and_commit(mgr: &TrustedServicesMgr, actor: &mut Actor) -> bool {
        let outcome = refresh_expired_attributes(mgr, &[key::CN], actor).await;
        if let Some(zpr_addr) = actor.get_zpr_addr().copied() {
            outcome.commit_revisions(mgr, &zpr_addr);
        }
        outcome.changed
    }

    /// An actor with a CN, a ZPR address, and one attribute (expired or still fresh)
    /// from the given source.
    fn actor_with_attr(cn: &str, source: &str, expired: bool) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder(key::CN)
                    .expires_in(Duration::from_secs(600))
                    .value(cn),
            )
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value(TEST_ADDR))
            .unwrap();
        let expires = if expired {
            SystemTime::now() - Duration::from_secs(1)
        } else {
            SystemTime::now() + Duration::from_secs(600)
        };
        actor
            .add_attribute(
                AttributeSource::new(source)
                    .builder(FAKE_ATTR_KEY)
                    .expires(expires)
                    .value("engineering"),
            )
            .unwrap();
        actor
    }

    /// An actor with a CN and a ZPR address, but no trusted-service attributes.
    fn actor_with_cn(cn: &str) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder(key::CN)
                    .expires_in(Duration::from_secs(600))
                    .value(cn),
            )
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value(TEST_ADDR))
            .unwrap();
        actor
    }

    /// The (key, value) lookup set expected for a CN-only test actor.
    fn cn_ident(cn: &str) -> Vec<(String, String)> {
        vec![(key::CN.to_string(), cn.to_string())]
    }

    /// An expired attribute whose source is a registered trusted service is refreshed
    /// from that service, and only that service is queried.
    #[tokio::test]
    async fn test_refresh_expired_attributes_refreshes_from_source() {
        let (mgr, fake) = ts_mgr_with_fake();
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, true);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).unwrap().is_expired());

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert!(!actor.get_attribute(FAKE_ATTR_KEY).unwrap().is_expired());
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![cn_ident("someone.zpr.org")]
        );
    }

    /// The hot path: nothing expired and every source's revision already recorded means
    /// no trusted-service round trip at all.
    #[tokio::test]
    async fn test_refresh_expired_attributes_skips_when_nothing_expired() {
        let (mgr, fake) = ts_mgr_with_fake();
        let mut actor = actor_with_cn("someone.zpr.org");
        mgr.record_revision(&test_addr(), FAKE_SOURCE, fake.current_revision());

        assert!(!refresh_and_commit(&mgr, &mut actor).await);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    /// An actor holding no attribute from a configured source (the service vended
    /// nothing at connect time) is still refreshed from it, so attributes that show up
    /// later are picked up instead of being ignored forever.
    #[tokio::test]
    async fn test_refresh_queries_source_with_no_prior_attributes() {
        let (mgr, fake) = ts_mgr_with_fake();
        let mut actor = actor_with_cn("someone.zpr.org");

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(
            actor.get_attribute(FAKE_ATTR_KEY).unwrap().get_value(),
            ["engineering".to_string()]
        );
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![cn_ident("someone.zpr.org")]
        );

        // The revision was recorded, so the next pass is a no-op.
        assert!(!refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }

    /// A targeted change notification ([TrustedServicesMgr::forget_source_revision])
    /// that lands while a refresh pass is in flight must survive that pass's
    /// commit (PR #29 review, P1): the in-flight refresh read the service's
    /// pre-notification state, so letting it record "current" would make the
    /// queued reconcile skip the actor and leave stale attributes until TTL.
    #[tokio::test]
    async fn test_targeted_invalidation_not_lost_to_inflight_refresh() {
        let (mgr, _fake) = ts_mgr_with_fake();
        let mut actor = actor_with_cn("someone.zpr.org");

        // The refresh pass has read the service state but not yet committed --
        // the window a slow trusted-service query holds open.
        let outcome = refresh_expired_attributes(&mgr, &[key::CN], &mut actor).await;

        // A targeted change notification lands inside the window.
        mgr.forget_source_revision(&test_addr(), FAKE_SOURCE);

        // The in-flight pass commits what it read before the notification.
        outcome.commit_revisions(&mgr, &test_addr());

        // The invalidation must win: the source is still stale for the actor.
        assert!(
            !mgr.stale_sources_for_actor(&test_addr()).is_empty(),
            "in-flight refresh must not overwrite a newer targeted invalidation"
        );
    }

    /// #310 regression: a user-only actor (no CN at all, identified by a policy-declared
    /// identity attribute) still gets its attributes refreshed — the old code early-
    /// returned on `get_cn() == None`, silently never refreshing such actors.
    #[tokio::test]
    async fn test_refresh_works_for_actor_without_cn() {
        let (mgr, fake) = ts_mgr_with_fake();

        const USER_KEY: &str = "user.sub";
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder(USER_KEY)
                    .expires_in(Duration::from_secs(600))
                    .value("google-sub-123"),
            )
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value(TEST_ADDR))
            .unwrap();

        // Lookup keys include the builtin CN and the policy-declared user key; only the
        // latter is present on this actor, so it alone forms the lookup set.
        let outcome = refresh_expired_attributes(&mgr, &[key::CN, USER_KEY], &mut actor).await;
        assert!(outcome.changed);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_some());
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![vec![(USER_KEY.to_string(), "google-sub-123".to_string())]]
        );

        // And the revisions commit against the address, so the refresh sticks.
        outcome.commit_revisions(&mgr, &test_addr());
        assert!(mgr.stale_sources_for_actor(&test_addr()).is_empty());
    }

    /// A trusted service that knows nothing about any actor: every lookup succeeds and
    /// returns no attributes.
    struct EmptyTrustedService;

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for EmptyTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Holds no cache, so its data never changes: a constant revision is honest.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            FAKE_SOURCE
        }
    }

    /// A successful lookup is authoritative: an expired attribute the service no longer
    /// vends is dropped from the actor rather than kept in its expired state.
    #[tokio::test]
    async fn test_refresh_expired_attributes_prunes_unvended() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(EmptyTrustedService)]);
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, true);

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_none());
        // The unexpired CN from another source is untouched.
        assert!(actor.get_attribute(key::CN).is_some());
    }

    /// An unroutable source (no registered service) and an actor with no ZPR address
    /// must both fall through quietly rather than panic.
    #[tokio::test]
    async fn test_refresh_expired_attributes_handles_unrefreshable() {
        let (mgr, fake) = ts_mgr_with_fake();

        // SOURCE_ZPR is internal -- no trusted service vends it. The fake's revision is
        // recorded up front so it is not stale, isolating the unroutable-source path.
        let mut internal = actor_with_attr("someone.zpr.org", SOURCE_ZPR, true);
        mgr.record_revision(&test_addr(), FAKE_SOURCE, fake.current_revision());
        assert!(!refresh_and_commit(&mgr, &mut internal).await);
        assert!(fake.calls.lock().unwrap().is_empty());

        // No ZPR address means no revision key, so there is nothing to refresh.
        let mut no_addr = Actor::new();
        no_addr
            .add_attribute(
                AttributeSource::new(FAKE_SOURCE)
                    .builder(FAKE_ATTR_KEY)
                    .expires(SystemTime::now() - Duration::from_secs(1))
                    .value("engineering"),
            )
            .unwrap();
        assert!(!refresh_and_commit(&mgr, &mut no_addr).await);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    /// A revision-stale source (no record yet, or bumped by a flush) is refreshed even
    /// when none of its attributes have expired, and the recorded revision stops
    /// further refreshes until the next bump.
    #[tokio::test]
    async fn test_refresh_revision_stale_refreshes_and_records() {
        let (mgr, fake) = ts_mgr_with_fake();
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);

        // No record yet: stale, so the source is queried despite nothing being expired.
        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);

        // Revision recorded: a second pass is a no-op.
        assert!(!refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);

        // A flush bumps the revision: stale again.
        fake.flush().await.unwrap();
        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(fake.calls.lock().unwrap().len(), 2);
    }

    /// A revision-triggered refresh that returns zero attributes prunes everything the
    /// source previously vended — even attributes that had not expired — and records
    /// the revision so there is no further churn.
    #[tokio::test]
    async fn test_refresh_revision_stale_zero_attrs_prunes_all() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(EmptyTrustedService)]);
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);
        assert!(!actor.get_attribute(FAKE_ATTR_KEY).unwrap().is_expired());

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_none());
        assert!(actor.get_attribute(key::CN).is_some());

        // The zero-attribute response was recorded: no further refresh churn.
        assert!(!refresh_and_commit(&mgr, &mut actor).await);
    }

    /// A trusted service whose lookups always fail, standing in for an outage.
    struct FailingTrustedService {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for FailingTrustedService {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(ServiceError::Internal("service is down".to_string()))
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests; a constant revision is enough.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            FAKE_SOURCE
        }
    }

    /// A failed lookup for a revision-stale source fails closed: the source's
    /// attributes are stripped even though unexpired, and the source stays stale so
    /// the next request retries.
    #[tokio::test]
    async fn test_refresh_revision_stale_failure_strips_source() {
        let mgr = TrustedServicesMgr::new();
        let failing = Arc::new(FailingTrustedService {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        mgr.update_services(vec![failing.clone()]);
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_none());
        assert!(actor.get_attribute(key::CN).is_some());

        // No revision was recorded on failure, so the next request retries the source
        // (nothing left to strip, so no change is reported).
        assert!(!refresh_and_commit(&mgr, &mut actor).await);
        assert_eq!(failing.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A plain TTL-refresh failure keeps today's behavior: the expired attributes are
    /// left in place (an outage cannot strip attributes on the TTL path).
    #[tokio::test]
    async fn test_refresh_ttl_failure_retains_attributes() {
        let mgr = TrustedServicesMgr::new();
        let failing = Arc::new(FailingTrustedService {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        mgr.update_services(vec![failing.clone()]);
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, true);

        // Mark the actor current for this source so only the TTL path triggers.
        mgr.record_revision(&test_addr(), FAKE_SOURCE, 1);

        let outcome = refresh_expired_attributes(&mgr, &[key::CN], &mut actor).await;
        assert!(!outcome.changed);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).unwrap().is_expired());
        assert_eq!(failing.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The retained attributes are expired, and libeval will not satisfy an allow
        // from an expired attribute, so there is nothing indeterminate to report.
        assert!(outcome.indeterminate.is_empty());
    }

    /// TS-1: a revision-stale source that cannot be reached is reported as indeterminate,
    /// so the request path denies instead of evaluating the stripped claim set. Stripping
    /// alone is not fail-closed -- a policy condition can be satisfied by a missing key.
    #[tokio::test]
    async fn test_refresh_revision_stale_failure_reports_indeterminate() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(FailingTrustedService {
            calls: std::sync::atomic::AtomicUsize::new(0),
        })]);
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);

        let outcome = refresh_expired_attributes(&mgr, &[key::CN], &mut actor).await;
        assert_eq!(outcome.indeterminate, vec![FAKE_SOURCE.to_string()]);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_none());
    }

    /// TS-2: a refresh does not record its revisions itself. The caller commits them only
    /// after the actor is persisted, so a failed write cannot leave a source marked
    /// current while the database still holds the stale attributes.
    #[tokio::test]
    async fn test_refresh_defers_revision_recording() {
        let (mgr, fake) = ts_mgr_with_fake();
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);

        let outcome = refresh_expired_attributes(&mgr, &[key::CN], &mut actor).await;
        assert_eq!(
            outcome.revisions,
            vec![(FAKE_SOURCE.to_string(), fake.current_revision(), 0)]
        );
        // Uncommitted: the source is still stale, so a dropped write costs a re-fetch
        // rather than a silently skipped one.
        assert!(!mgr.stale_sources_for_actor(&test_addr()).is_empty());

        outcome.commit_revisions(&mgr, &test_addr());
        assert!(mgr.stale_sources_for_actor(&test_addr()).is_empty());
    }

    /// #324 follow-up: the refresh path derives `user.zpr.authority` the same way the
    /// connect path does -- a source vending `user.*` attributes (the fake vends
    /// `user.dept`) installs the authority on refresh, so a user record that first
    /// appears post-connect still gets its authority.
    #[tokio::test]
    async fn test_refresh_installs_user_authority_with_user_attrs() {
        let (mgr, _fake) = ts_mgr_with_fake();
        let mut actor = actor_with_cn("someone.zpr.org");

        assert!(refresh_and_commit(&mgr, &mut actor).await);
        let authority = actor
            .get_attribute(key::USER_AUTHORITY)
            .expect("refresh should install user.zpr.authority");
        assert_eq!(authority.get_value(), [FAKE_SOURCE.to_string()]);
        assert_eq!(authority.get_source(), FAKE_SOURCE);
    }

    /// #324 follow-up: when a revision refresh stops vending the user record, the
    /// derived `user.zpr.authority` is pruned with it -- the authority tracks the
    /// attributes it vouches for.
    #[tokio::test]
    async fn test_refresh_prunes_user_authority_when_user_record_gone() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(EmptyTrustedService)]);
        // Actor connected while the source vended user attributes, so it carries both
        // the user attribute and the derived authority from that source.
        let mut actor = actor_with_attr("someone.zpr.org", FAKE_SOURCE, false);
        actor
            .add_attribute(
                AttributeSource::new(FAKE_SOURCE)
                    .builder(key::USER_AUTHORITY)
                    .expires_in(Duration::from_secs(600))
                    .value(FAKE_SOURCE),
            )
            .unwrap();

        // The (stale) source now vends nothing: user attribute AND authority go.
        assert!(refresh_and_commit(&mgr, &mut actor).await);
        assert!(actor.get_attribute(FAKE_ATTR_KEY).is_none());
        assert!(
            actor.get_attribute(key::USER_AUTHORITY).is_none(),
            "the derived authority must not outlive the user record it vouches for"
        );
    }

    // ---- user.zpr.authority displacement on the refresh path (zipline#24) ----

    /// An OIDC-shaped fake (`google`): enforces the real store's `vouched_here` gate
    /// (vs/src/oidc/store.rs) -- it vends its user record ONLY when the lookup set
    /// carries `("user.zpr.authority", "google")`; with a competing authority (or
    /// none) it answers with an empty, successful result, exactly like
    /// [crate::oidc::OidcTrustedService::get_attributes_for_actor].
    struct VouchedOidcFake;

    const GOOGLE: &str = "google";
    const USER_SUB_KEY: &str = "user.sub";
    const USER_SUB_VALUE: &str = "google-sub-12345";

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for VouchedOidcFake {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            let vouched_here = identities
                .iter()
                .any(|(k, v)| k == key::USER_AUTHORITY && v == GOOGLE);
            if !vouched_here {
                return Ok(Vec::new());
            }
            Ok(vec![
                AttributeSource::new(GOOGLE)
                    .builder(USER_SUB_KEY)
                    .expires_in(Duration::from_secs(600))
                    .value(USER_SUB_VALUE),
            ])
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            GOOGLE
        }
    }

    /// A file-store-shaped fake (`happyfile`): vends the tag `user.zpr.tag.lazy`
    /// whenever the lookup set carries the known `user.sub` value, like a
    /// [crate::trusted_services] file store whose `lazy -> #user.lazy` mapping is
    /// keyed on the mapped OIDC subject (zipline#24).
    struct HappyfileFake;

    const HAPPYFILE: &str = "happyfile";
    const LAZY_TAG_KEY: &str = "user.zpr.tag.lazy";

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for HappyfileFake {
        async fn get_attributes_for_actor(
            &self,
            identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            if identities
                .iter()
                .any(|(k, v)| k == USER_SUB_KEY && v == USER_SUB_VALUE)
            {
                return Ok(vec![
                    AttributeSource::new(HAPPYFILE)
                        .builder(LAZY_TAG_KEY)
                        .expires_in(Duration::from_secs(600))
                        .values(Vec::<String>::new()),
                ]);
            }
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            HAPPYFILE
        }
    }

    /// An actor as the connect path leaves a decorated OIDC login:
    /// `user.zpr.authority = google` and `user.sub` from the authenticator, the
    /// `user.zpr.tag.lazy` tag from the decorating file store, plus a ZPR address.
    /// `authority_value`/`authority_source` parameterize the displaced-state variant.
    fn post_connect_actor(authority_value: &str, authority_source: &str, tag_secs: i64) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value(TEST_ADDR))
            .unwrap();
        actor
            .add_attribute(
                AttributeSource::new(authority_source)
                    .builder(key::USER_AUTHORITY)
                    .expires_in(Duration::from_secs(600))
                    .value(authority_value),
            )
            .unwrap();
        actor
            .add_attribute(
                AttributeSource::new(GOOGLE)
                    .builder(USER_SUB_KEY)
                    .expires_in(Duration::from_secs(600))
                    .value(USER_SUB_VALUE),
            )
            .unwrap();
        let tag_expires = if tag_secs < 0 {
            SystemTime::now() - Duration::from_secs(tag_secs.unsigned_abs())
        } else {
            SystemTime::now() + Duration::from_secs(tag_secs as u64)
        };
        actor
            .add_attribute(
                AttributeSource::new(HAPPYFILE)
                    .builder(LAZY_TAG_KEY)
                    .expires(tag_expires)
                    .values(Vec::<String>::new()),
            )
            .unwrap();
        actor
    }

    /// zipline#24 (V1 gate, refresh path, symptom 1 of 2): a TTL refresh that touches
    /// ONLY the decorating file store must not displace the authenticator's
    /// `user.zpr.authority`. The actor starts as the connect path leaves it
    /// (authority = google, `user.sub`, the happyfile tag); only the tag is expired
    /// and only `happyfile` is registered, so exactly one source refreshes -- the
    /// order-nondeterministic multi-source case is deliberately avoided so the RED
    /// is deterministic.
    ///
    /// Today this FAILS: the re-vended tag is a `user.*` key, so
    /// [derive_user_authority] mints `user.zpr.authority = happyfile` on the refresh
    /// (vs/src/actor_attributes.rs) and `add_attribute` overwrites google's stamp.
    #[tokio::test]
    async fn test_refresh_of_decorating_store_keeps_google_authority_zipline24() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(HappyfileFake)]);
        // Authority and user.sub are fresh; only happyfile's tag has expired.
        let mut actor = post_connect_actor(GOOGLE, GOOGLE, -1);

        let outcome = refresh_expired_attributes(&mgr, &[USER_SUB_KEY], &mut actor).await;
        assert!(outcome.changed);

        // The tag was refreshed...
        assert!(
            !actor.get_attribute(LAZY_TAG_KEY).unwrap().is_expired(),
            "happyfile must re-vend the tag"
        );
        // ...and the authenticator's authority must survive it. FAILS today with
        // "happyfile" (zipline#24); fixed by zipline#25/#26.
        assert_eq!(
            actor
                .get_attribute(key::USER_AUTHORITY)
                .expect("user authority must be present")
                .get_value(),
            [GOOGLE.to_string()],
            "a decorating store's refresh must not displace the authenticator's authority"
        );
    }

    /// zipline#24 (V1 gate, refresh path, symptom 2 of 2): after the decorating
    /// store's refresh displaces the authority (symptom 1), the actor's attributes
    /// unravel across the following refreshes: the OIDC store's `vouched_here` gate
    /// answers the displaced-authority lookup with an empty result, the
    /// revision-stale refresh prunes `user.sub` as no-longer-vended, and the next
    /// file-store lookup (keyed on the now-missing `user.sub`) finds nothing, so
    /// `user.zpr.tag.lazy` disappears too -- the actor loses `lazy` mid-session.
    ///
    /// The displaced state is DERIVED here by the same single-source refresh
    /// symptom 1 uses (google's revision pre-committed, only happyfile's tag
    /// expired), and each later pass is kept single-source by re-staling one
    /// revision at a time -- a two-source pass iterates a HashSet, whose order
    /// would make the RED nondeterministic. Deriving the state, rather than
    /// starting from a pre-displaced fixture, is what lets the #25/#26 fix turn
    /// this test green: with pass 1 no longer displacing, google keeps vouching
    /// for `user.sub` in pass 2 and happyfile re-vends the tag in pass 3.
    ///
    /// Today this FAILS at the tag-loss check below: pass 1 displaces the
    /// authority to `happyfile`, pass 2 prunes `user.sub`, pass 3 prunes the tag.
    #[tokio::test]
    async fn test_refresh_after_displacement_loses_user_record_and_tag_zipline24() {
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(VouchedOidcFake), Arc::new(HappyfileFake)]);
        // As the connect path leaves it: authority = google, fresh user.sub, and
        // the happyfile tag expired so pass 1 touches only the decorating store.
        let mut actor = post_connect_actor(GOOGLE, GOOGLE, -1);

        // Pass 1 (the symptom-1 refresh): google's revision is pre-committed, so
        // only happyfile refreshes. Today its re-vended tag makes
        // [derive_user_authority] mint `user.zpr.authority = happyfile` over
        // google's stamp; under the #25/#26 fix the authority stays google.
        // Deliberately not asserted either way -- this test's claim is the
        // downstream cascade, asserted at the end.
        mgr.record_revision(&test_addr(), GOOGLE, 1);
        let outcome = refresh_expired_attributes(&mgr, &[USER_SUB_KEY], &mut actor).await;
        assert!(outcome.indeterminate.is_empty());
        outcome.commit_revisions(&mgr, &test_addr());

        // Pass 2: re-stale ONLY google (happyfile was committed above and its tag
        // is fresh). Displaced, google's vouched_here gate sees
        // authority=happyfile -> empty result -> the revision refresh prunes
        // user.sub as no-longer-vended. Fixed, the authority is still google, so
        // user.sub is re-vouched and kept.
        mgr.record_revision(&test_addr(), GOOGLE, REVISION_NEVER);
        let outcome = refresh_expired_attributes(&mgr, &[USER_SUB_KEY], &mut actor).await;
        assert!(outcome.indeterminate.is_empty());
        outcome.commit_revisions(&mgr, &test_addr());

        // Pass 3: re-stale ONLY happyfile. Displaced, its lookup is keyed on the
        // now-pruned user.sub, finds nothing, and the tag (and its derived
        // authority) are pruned as no-longer-vended.
        mgr.record_revision(&test_addr(), HAPPYFILE, REVISION_NEVER);
        let _ = refresh_expired_attributes(&mgr, &[USER_SUB_KEY], &mut actor).await;

        assert!(
            actor.get_attribute(LAZY_TAG_KEY).is_some(),
            "the file store's tag must survive refreshes (zipline#24: the displaced \
             authority fails google's vouched_here gate, user.sub is pruned, and the \
             next happyfile lookup finds nothing to key the tag)"
        );
        assert!(
            actor.get_attribute(USER_SUB_KEY).is_some(),
            "the authenticated user.sub must survive refreshes (zipline#24: pruned \
             because the displaced authority fails google's vouched_here gate)"
        );
    }

    /// The OIDC-shaped owner (`google`) after it stops vending the actor's user
    /// record: every lookup answers with an empty, successful result, like a store
    /// whose user entry was deleted between revisions.
    struct GoneOidcFake;

    #[async_trait::async_trait]
    impl crate::trusted_services::TrustedServiceInterface for GoneOidcFake {
        async fn get_attributes_for_actor(
            &self,
            _identities: &[(String, String)],
        ) -> Result<Vec<Attribute>, ServiceError> {
            Ok(Vec::new())
        }

        async fn flush(&self) -> Result<(), ServiceError> {
            Ok(())
        }

        // Never flushed in these tests.
        fn current_revision(&self) -> u64 {
            1
        }

        fn get_source_id(&self) -> &str {
            GOOGLE
        }
    }

    /// zipline#26 (Codex P1 review on PR #12): when the authority-owning source and
    /// a decorating source refresh in the SAME pass and the owner stops vending its
    /// user record, the outcome must not depend on the `sources` hash order. A
    /// per-iteration read of the actor's authority lets owner-first processing
    /// prune google's stamp and then mint `user.zpr.authority = happyfile` from the
    /// decorator's re-vended tag — promoting a non-authenticating store — while
    /// decorator-first processing (correctly) blocks that derivation and ends with
    /// no authority. Snapshotting the starting authority before the source loop
    /// makes both orders end with no authority.
    ///
    /// `sources` is a `HashSet` built inside [refresh_expired_attributes], so a
    /// single two-source pass cannot pin which order runs; instead the scenario is
    /// repeated with a fresh manager and actor each time (every `HashSet` hashes
    /// with fresh keys, so both orders occur across the runs) and the invariant is
    /// asserted on every pass.
    #[tokio::test]
    async fn test_refresh_same_pass_owner_prune_does_not_promote_decorator_zipline26() {
        for _ in 0..256 {
            let mgr = TrustedServicesMgr::new();
            // The owner has stopped vending its user record; the decorator still
            // vends its tag (keyed on the pre-loop identity snapshot's user.sub).
            mgr.update_services(vec![Arc::new(GoneOidcFake), Arc::new(HappyfileFake)]);
            // As the connect path left it: authority = google, fresh user.sub,
            // fresh happyfile tag. Nothing is TTL-expired and no revision is
            // recorded, so BOTH sources are revision-stale in a single pass.
            let mut actor = post_connect_actor(GOOGLE, GOOGLE, 600);

            let outcome = refresh_expired_attributes(&mgr, &[USER_SUB_KEY], &mut actor).await;
            assert!(outcome.indeterminate.is_empty());

            // The owner's empty result pruned its user record...
            assert!(actor.get_attribute(USER_SUB_KEY).is_none());
            // ...and whatever order the two sources ran in, the decorating store
            // must not have been promoted to authority off the back of that prune.
            let authority = actor
                .get_attribute(key::USER_AUTHORITY)
                .map(|a| a.get_value().to_vec());
            assert!(
                authority.is_none(),
                "no source may hold user.zpr.authority once the authenticator stops \
                 vending the user record, in either processing order (got {authority:?}; \
                 hash-order-dependent promotion, zipline#26 Codex P1)"
            );
        }
    }
}

/// Commit of a refresh against concurrent actor writes (round 15).
#[cfg(test)]
mod refresh_commit {
    use super::*;
    use crate::test_helpers::{
        TS_KEY, build_sweep_asm, register_ts, seed_source_attr, stored_attr,
    };

    const ACTOR: &str = "fd5a:5052:4000::a";

    /// Round 15 (Copilot): the refresh queries trusted services outside the topology
    /// lock with an actor read before them. Its commit applies only the attributes the
    /// refresh changed onto the actor as stored now, so a session a reconnect
    /// persisted meanwhile survives, and the refreshed attribute still lands.
    #[tokio::test]
    async fn test_refresh_commit_keeps_a_newer_session() {
        let (asm, _node) = build_sweep_asm(false).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, ACTOR, TS_KEY, "sales").await;
        let addr: IpAddr = ACTOR.parse().unwrap();
        let mut read_before = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();

        // A reconnect persists a new session while the refresh is in flight.
        let mut reconnected = read_before.clone();
        reconnected
            .add_attribute(Attribute::builder(key::SESSION).value("99-new"))
            .unwrap();
        asm.actor_mgr
            .update_actor(&reconnected, &asm.policy_service_names())
            .await
            .unwrap();

        assert!(
            refresh_and_persist_actor(&asm, &mut read_before)
                .await
                .unwrap()
        );

        let stored = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.get_attribute(key::SESSION).unwrap().get_value(),
            ["99-new".to_string()],
            "the newer session must survive the refresh commit"
        );
        assert_eq!(
            stored_attr(&asm, ACTOR, TS_KEY).await,
            Some("engineering".to_string())
        );
    }

    /// A refresh never writes back an actor that left while it was in flight.
    #[tokio::test]
    async fn test_refresh_commit_does_not_resurrect_a_departed_actor() {
        let (asm, _node) = build_sweep_asm(false).await;
        register_ts(&asm, &[(TS_KEY, "engineering")]);
        seed_source_attr(&asm, ACTOR, TS_KEY, "sales").await;
        let addr: IpAddr = ACTOR.parse().unwrap();
        let mut read_before = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&addr)
            .await
            .unwrap()
            .unwrap();
        asm.actor_mgr.remove_actor_by_zpr_addr(&addr).await.unwrap();

        let _ = refresh_and_persist_actor(&asm, &mut read_before).await;

        assert!(
            asm.actor_mgr
                .get_actor_by_zpr_addr(&addr)
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// Manager-path integration for the `zpr-attr/1` store (zipline#78 step 7):
/// a REAL `AttrQueryStore` over the in-process TLS mock, driven through
/// `TrustedServicesMgr` + `refresh_expired_attributes` exactly as the visa
/// request path drives it.
#[cfg(test)]
mod attr_query_integration {
    use super::*;
    use crate::trusted_services::TrustedServicesMgr;
    use crate::trusted_services::attr_query_store::AttrQueryStore;
    use crate::trusted_services::test_support::{AttrMockServer, spawn_tls_attr_server};
    use libeval::attribute::Attribute;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};
    use zpr::policy_types::{AttrQueryConfig, TrustedService, parse_attribute_mapping};

    const ADDR: &str = "fd5a:5052::7f";

    /// An actor carrying a `user.sub` identity and a ZPR address.
    fn actor_with_sub(sub: &str) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attribute(
                Attribute::builder("user.sub")
                    .expires_in(std::time::Duration::from_secs(600))
                    .value(sub),
            )
            .unwrap();
        actor
            .add_attribute(Attribute::builder(key::ZPR_ADDR).value(ADDR))
            .unwrap();
        actor
    }

    /// A store named `attrs` over the mock, its token on disk, mapped
    /// `dept -> user.dept`.
    fn make_store(server: &AttrMockServer, dir: &tempfile::TempDir) -> AttrQueryStore {
        std::fs::write(dir.path().join("attrs.token"), "tok").unwrap();
        AttrQueryStore::new(
            &TrustedService {
                service_id: "attrs".to_string(),
                expiration_seconds: 3600,
                returns_attrs: vec![parse_attribute_mapping("dept -> user.dept").unwrap()],
                identity_attrs: vec![],
                oidc: None,
                attr_query: Some(AttrQueryConfig {
                    url: server.url.clone(),
                    ca_cert_pem: Some(server.cert_pem.clone()),
                    timeout_seconds: 5,
                }),
            },
            dir.path(),
        )
        .unwrap()
    }

    /// A store `Err` on the request path makes the actor indeterminate and
    /// strips the source's attributes (fail closed), exactly as a failing
    /// file store does: the mock answers the first query 200 and every later
    /// one 500.
    #[tokio::test]
    async fn test_query_error_makes_actor_indeterminate_and_pruned() {
        let calls = Arc::new(AtomicU16::new(0));
        let calls_in_responder = calls.clone();
        let server = spawn_tls_attr_server(
            Arc::new(move |_req| {
                if calls_in_responder.fetch_add(1, Ordering::SeqCst) == 0 {
                    (
                        200,
                        r#"{"attributes": {"dept": {"values": ["eng"]}}}"#.to_string(),
                    )
                } else {
                    (500, "down".to_string())
                }
            }),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(make_store(&server, &dir))]);
        let mut actor = actor_with_sub("s-1");
        let addr: IpAddr = ADDR.parse().unwrap();

        // First refresh: the store answers, the mapped attribute lands.
        let outcome = refresh_expired_attributes(&mgr, &["user.sub"], &mut actor).await;
        assert!(outcome.indeterminate.is_empty());
        outcome.commit_revisions(&mgr, &addr);
        assert_eq!(
            actor.get_attribute("user.dept").unwrap().get_value(),
            ["eng".to_string()]
        );

        // The service goes down and the source becomes revision-stale (an
        // admin flush): the failed re-query strips the source's attributes
        // and reports it indeterminate — the caller must deny, not evaluate.
        mgr.flush_one("attrs").await.unwrap();
        let outcome = refresh_expired_attributes(&mgr, &["user.sub"], &mut actor).await;
        assert_eq!(outcome.indeterminate, vec!["attrs".to_string()]);
        assert!(actor.get_attribute("user.dept").is_none());
        // The identity attribute (another source's) is untouched.
        assert!(actor.get_attribute("user.sub").is_some());
    }

    /// A revision bump (flush / `changed` notification) re-queries the
    /// service for the actor even though nothing expired, and prunes what
    /// the service stopped vending.
    #[tokio::test]
    async fn test_revision_bump_requeries_and_prunes() {
        let calls = Arc::new(AtomicU16::new(0));
        let calls_in_responder = calls.clone();
        let server = spawn_tls_attr_server(
            Arc::new(move |_req| {
                if calls_in_responder.fetch_add(1, Ordering::SeqCst) == 0 {
                    (
                        200,
                        r#"{"attributes": {"dept": {"values": ["eng"]}}}"#.to_string(),
                    )
                } else {
                    // The record changed: dept is gone.
                    (200, r#"{"attributes": {}}"#.to_string())
                }
            }),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mgr = TrustedServicesMgr::new();
        mgr.update_services(vec![Arc::new(make_store(&server, &dir))]);
        let mut actor = actor_with_sub("s-1");
        let addr: IpAddr = ADDR.parse().unwrap();

        let outcome = refresh_expired_attributes(&mgr, &["user.sub"], &mut actor).await;
        outcome.commit_revisions(&mgr, &addr);
        assert!(actor.get_attribute("user.dept").is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Current revision recorded: another refresh does not touch the wire.
        let outcome = refresh_expired_attributes(&mgr, &["user.sub"], &mut actor).await;
        assert!(!outcome.changed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Revision bump: the source is stale for the actor, so the next
        // refresh re-queries, and the now-missing attribute is pruned (a
        // successful lookup is authoritative for its source).
        mgr.flush_one("attrs").await.unwrap();
        let outcome = refresh_expired_attributes(&mgr, &["user.sub"], &mut actor).await;
        assert!(outcome.changed);
        assert!(outcome.indeterminate.is_empty());
        outcome.commit_revisions(&mgr, &addr);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(actor.get_attribute("user.dept").is_none());
    }
}
