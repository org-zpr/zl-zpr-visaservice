//! File-backed trusted-service attribute storage.

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use libeval::attribute::{Attribute, AttributeSource};

use crate::error::ServiceError;
use crate::logging::targets::TS;

use super::attribute_mapper::{AttrHint, AttributeMapper};
use super::{MIN_ATTRIBUTE_TTL, TrustedServiceInterface, next_revision};

/// File-based attributes encoded in JSON.
#[derive(Debug)]
pub(super) struct FileAttributeStore {
    id: String,
    mapper: AttributeMapper,
    ttl: Duration,
    fp: PathBuf,
    snapshot: ArcSwap<Snapshot>,
    /// Serializes concurrent reloads; reads remain lock-free via ArcSwap.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Attribute data, expiration, and revision swapped as one consistent unit.
#[derive(Debug)]
struct Snapshot {
    attributes: ActorAttributes,
    expires_at: Instant,
    revision: u64,
}

impl Snapshot {
    /// Return this snapshot's remaining validity, saturating at zero.
    fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

type IdentityKey = String;
type IdentityValue = String;
type AttributeName = String;
type AttributeValue = String;

/// One actor entry's attribute data: service attribute name -> values.
type AttributeMap = BTreeMap<AttributeName, Vec<AttributeValue>>;

/// Actor attributes decoded from the file's JSON representation.
///
/// Entries are keyed by identity attribute key AND value:
///
/// ```json
/// { "device.zpr.adapter.cn": { "alice.zpr.org": { "color": ["red"] } },
///   "user.sub":              { "10769150350006150715113082367": { "dept": ["eng"] } } }
/// ```
///
/// Keying on the (key, value) pair rather than a flat value map means a device CN and a
/// user subject can never collide in this file, and the store can tell which kind of
/// identity each entry describes.
#[derive(Debug, Deserialize, Clone)]
struct ActorAttributes(BTreeMap<IdentityKey, BTreeMap<IdentityValue, AttributeMap>>);

/// Load and decode actor attributes from a local JSON file.
fn load_actor_attributes_from_file(fp: &Path) -> Result<ActorAttributes, ServiceError> {
    let contents = fs::read_to_string(fp)?;
    let attributes = serde_json::from_str(&contents)?;
    Ok(attributes)
}

impl FileAttributeStore {
    /// Create a file store and load its initial snapshot.
    pub(super) fn new(
        id: String,
        mapper: AttributeMapper,
        ttl: Duration,
        fp: &Path,
    ) -> Result<Self, ServiceError> {
        if ttl <= MIN_ATTRIBUTE_TTL {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}' ttl {ttl:?} must exceed minimum of {MIN_ATTRIBUTE_TTL:?}"
            )));
        }

        let attributes = load_actor_attributes_from_file(fp).map_err(|error| {
            ServiceError::TrustedServiceInit(format!(
                "TS '{id}' failed to read attribute data file {fp:?}: {error}"
            ))
        })?;

        let snapshot = Snapshot {
            attributes,
            expires_at: Instant::now() + ttl,
            revision: next_revision(),
        };
        Ok(Self {
            id,
            mapper,
            ttl,
            fp: fp.into(),
            snapshot: ArcSwap::from_pointee(snapshot),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Return a live snapshot, refreshing once when the cached data approaches expiry.
    async fn live_snapshot(&self) -> Result<Arc<Snapshot>, ServiceError> {
        let snapshot = self.snapshot.load_full();
        if snapshot.remaining() >= MIN_ATTRIBUTE_TTL {
            return Ok(snapshot);
        }

        let _guard = self.refresh_lock.lock().await;

        // Another caller may have refreshed while this caller waited.
        let snapshot = self.snapshot.load_full();
        if snapshot.remaining() >= MIN_ATTRIBUTE_TTL {
            return Ok(snapshot);
        }

        info!(target: TS, "TS {} re-loading actor attributes", self.id);
        let fresh = Arc::new(Snapshot {
            attributes: load_actor_attributes_from_file(&self.fp)?,
            expires_at: Instant::now() + self.ttl,
            revision: next_revision(),
        });
        self.snapshot.store(fresh.clone());
        Ok(fresh)
    }
}

#[async_trait]
impl TrustedServiceInterface for FileAttributeStore {
    /// Look up every identity the actor presented and return the UNION of the mapped
    /// attributes of every entry that matched. Two entries supplying the same
    /// attribute with differing values is a store misconfiguration; the lookup fails
    /// (and the caller treats that as indeterminate) rather than pick a winner, since
    /// silently choosing would make authorization depend on identity ordering.
    ///
    /// Conflicts are detected on the MAPPED (canonical ZPR) key, not the raw
    /// service-side name: two different service-side names can map to the same ZPR
    /// key (e.g. `department -> user.dept` and `dept -> user.dept`), and comparing
    /// raw names would let such a pair smuggle conflicting values past the check --
    /// the caller's `Actor::add_attribute` would then silently keep whichever came
    /// last instead of failing closed as this interface promises.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError> {
        let snapshot = self.live_snapshot().await?;

        // Union the attribute maps of every matched identity, keyed by the canonical
        // ZPR key so conflicts are detected after mapping collapses aliased
        // service-side names. Unmapped names are filtered out here; they can never
        // become attributes, so they cannot conflict. Value alongside: the values,
        // the emission hint, and (identity, raw name) provenance for the error path.
        struct Merged<'a> {
            values: &'a Vec<String>,
            hint: AttrHint,
            ident: &'a str,
            raw_name: &'a str,
        }
        let mut merged: BTreeMap<String, Merged> = BTreeMap::new();
        for (ident_key, ident_value) in identities {
            let Some(attributes) = snapshot
                .attributes
                .0
                .get(ident_key)
                .and_then(|by_value| by_value.get(ident_value))
            else {
                debug!(
                    target: TS,
                    "{}: identity {ident_key}={ident_value} not found in the attribute store",
                    self.id
                );
                continue;
            };
            for (name, values) in attributes {
                let Some((zpr_key, hint)) = self.mapper.map_attribute(name) else {
                    continue;
                };
                match merged.get(&zpr_key) {
                    None => {
                        merged.insert(
                            zpr_key,
                            Merged {
                                values,
                                hint,
                                ident: ident_value,
                                raw_name: name,
                            },
                        );
                    }
                    Some(first) if first.values != values => {
                        return Err(ServiceError::Param(format!(
                            "{}: '{}' (identity '{}') and '{name}' (identity '{ident_value}') \
                             disagree on attribute '{zpr_key}'",
                            self.id, first.raw_name, first.ident
                        )));
                    }
                    Some(_) => {} // Same ZPR key, same values: one attribute, no conflict.
                }
            }
        }

        let mut result = Vec::new();
        let src_builder = AttributeSource::new(self.id.clone());
        let remaining = snapshot.remaining();

        for (zpr_key, m) in merged {
            let builder = src_builder.builder(zpr_key).expires_in(remaining);
            let attribute = match m.hint {
                AttrHint::SingleValued => {
                    builder.value(m.values.first().cloned().unwrap_or_default())
                }
                AttrHint::MultiValued => builder.values(m.values.clone()),
                // A tag is valueless: presence of the per-tag key is the tag.
                AttrHint::Tag => builder.values(Vec::<String>::new()),
            };
            result.push(attribute);
        }
        Ok(result)
    }

    /// Reload the file and atomically install a fresh snapshot.
    async fn flush(&self) -> Result<(), ServiceError> {
        info!(target: TS, "TS {} flushing cached actor attributes", self.id);
        let _guard = self.refresh_lock.lock().await;
        let attributes = load_actor_attributes_from_file(&self.fp)?;
        self.snapshot.store(Arc::new(Snapshot {
            attributes,
            expires_at: Instant::now() + self.ttl,
            revision: next_revision(),
        }));
        Ok(())
    }

    /// Return the revision of the current file snapshot.
    fn current_revision(&self) -> u64 {
        self.snapshot.load().revision
    }

    /// Return the configured trusted-service identifier.
    fn get_source_id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::test_support::{test_mapper, write_fixture};
    use libeval::attribute::key;

    /// True when the snapshot holds an entry for `value` under the builtin CN
    /// identity key (the key the test fixtures use).
    fn has_cn_entry(snapshot: &Snapshot, value: &str) -> bool {
        snapshot
            .attributes
            .0
            .get(key::CN)
            .is_some_and(|by_value| by_value.contains_key(value))
    }

    /// Construction rejects TTLs that would force a reload on every request.
    #[test]
    fn test_new_rejects_ttl_below_floor() {
        let fp = write_fixture("vs-fas-short-ttl.json", "{}");
        let result = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            MIN_ATTRIBUTE_TTL - Duration::from_secs(1),
            &fp,
        );
        assert!(matches!(result, Err(ServiceError::Param(_))));

        let result =
            FileAttributeStore::new("test".to_string(), test_mapper(), MIN_ATTRIBUTE_TTL, &fp);
        assert!(matches!(result, Err(ServiceError::Param(_))));

        assert!(
            FileAttributeStore::new(
                "test".to_string(),
                test_mapper(),
                MIN_ATTRIBUTE_TTL + Duration::from_secs(1),
                &fp
            )
            .is_ok()
        );
        fs::remove_file(&fp).unwrap();
    }

    /// An unexpired store stays cached until an explicit flush installs new data.
    #[tokio::test]
    async fn test_flush_forces_reload_on_next_read() {
        let fp = write_fixture(
            "vs-fas-flush.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        );
        let store = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            Duration::from_secs(3600),
            &fp,
        )
        .unwrap();

        let snapshot = store.live_snapshot().await.unwrap();
        assert!(has_cn_entry(&snapshot, "alice"));

        fs::write(
            &fp,
            r#"{"device.zpr.adapter.cn": {"bob": {"color": ["blue"]}}}"#,
        )
        .unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(has_cn_entry(&snapshot, "alice"));
        assert!(!has_cn_entry(&snapshot, "bob"));

        store.flush().await.unwrap();
        let snapshot = store.live_snapshot().await.unwrap();
        assert!(has_cn_entry(&snapshot, "bob"));
        assert!(!has_cn_entry(&snapshot, "alice"));
        assert!(snapshot.remaining() >= MIN_ATTRIBUTE_TTL);

        fs::remove_file(&fp).unwrap();
    }

    /// A source matching several of the actor's identities returns the UNION of their
    /// attributes, and two matched identities disagreeing on one attribute key fail the
    /// lookup (fail closed) rather than silently picking a winner.
    #[tokio::test]
    async fn test_multi_identity_union_and_conflict() {
        // A device CN entry and two user-subject entries for the same actor.
        let fp = write_fixture(
            "vs-fas-multi-ident.json",
            r#"{
                "device.zpr.adapter.cn": {
                    "dev.zpr.org": { "color": ["red"] }
                },
                "user.sub": {
                    "sub-123": { "roles": ["a", "b"] },
                    "sub-conflict": { "color": ["blue"] }
                }
            }"#,
        );
        let store = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            Duration::from_secs(3600),
            &fp,
        )
        .unwrap();

        // Union: both matched identities contribute their (non-overlapping) attributes.
        let attrs = store
            .get_attributes_for_actor(&[
                (key::CN.to_string(), "dev.zpr.org".to_string()),
                ("user.sub".to_string(), "sub-123".to_string()),
            ])
            .await
            .unwrap();
        let keys: Vec<&str> = attrs.iter().map(|a| a.get_key()).collect();
        assert!(keys.contains(&"user.color"));
        assert!(keys.contains(&"user.role"));

        // Conflict: both identities supply `color` with different values -> Err.
        let result = store
            .get_attributes_for_actor(&[
                (key::CN.to_string(), "dev.zpr.org".to_string()),
                ("user.sub".to_string(), "sub-conflict".to_string()),
            ])
            .await;
        assert!(matches!(result, Err(ServiceError::Param(_))));

        // An unknown identity alone matches nothing: empty result, not an error.
        let attrs = store
            .get_attributes_for_actor(&[("user.sub".to_string(), "nobody".to_string())])
            .await
            .unwrap();
        assert!(attrs.is_empty());

        fs::remove_file(&fp).unwrap();
    }

    /// Conflicts are detected on the mapped ZPR key: two DIFFERENT service-side
    /// names mapping to the same ZPR key must fail the lookup when they carry
    /// different values, and collapse to one attribute when they agree.
    #[tokio::test]
    async fn test_conflict_detected_on_mapped_key() {
        use zpr::policy_types::parse_attribute_mapping;

        // `department` and `dept` are aliases for the same canonical ZPR key.
        let mapper = AttributeMapper {
            mappings: ["department -> user.dept", "dept -> user.dept"]
                .iter()
                .map(|mapping| parse_attribute_mapping(mapping).unwrap())
                .collect(),
        };
        let fp = write_fixture(
            "vs-fas-mapped-conflict.json",
            r#"{
                "device.zpr.adapter.cn": {
                    "dev.zpr.org": { "department": ["eng"] }
                },
                "user.sub": {
                    "sub-agree": { "dept": ["eng"] },
                    "sub-conflict": { "dept": ["sales"] }
                }
            }"#,
        );
        let store =
            FileAttributeStore::new("test".to_string(), mapper, Duration::from_secs(3600), &fp)
                .unwrap();

        // Different raw names, same mapped key, conflicting values -> fail closed.
        let result = store
            .get_attributes_for_actor(&[
                (key::CN.to_string(), "dev.zpr.org".to_string()),
                ("user.sub".to_string(), "sub-conflict".to_string()),
            ])
            .await;
        assert!(matches!(result, Err(ServiceError::Param(_))));

        // Different raw names, same mapped key, same values -> one attribute.
        let attrs = store
            .get_attributes_for_actor(&[
                (key::CN.to_string(), "dev.zpr.org".to_string()),
                ("user.sub".to_string(), "sub-agree".to_string()),
            ])
            .await
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].get_key(), "user.dept");

        fs::remove_file(&fp).unwrap();
    }

    /// A failed flush preserves the current snapshot and revision.
    #[tokio::test]
    async fn test_flush_failure_keeps_snapshot_and_revision() {
        let fp = write_fixture(
            "vs-fas-flush-fail.json",
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        );
        let store = FileAttributeStore::new(
            "test".to_string(),
            test_mapper(),
            Duration::from_secs(3600),
            &fp,
        )
        .unwrap();
        let revision = store.current_revision();

        fs::write(&fp, "not json").unwrap();
        assert!(store.flush().await.is_err());
        assert_eq!(store.current_revision(), revision);
        assert!(has_cn_entry(&store.snapshot.load(), "alice"));

        fs::write(
            &fp,
            r#"{"device.zpr.adapter.cn": {"bob": {"color": ["blue"]}}}"#,
        )
        .unwrap();
        store.flush().await.unwrap();
        assert!(store.current_revision() > revision);
        assert!(has_cn_entry(&store.snapshot.load(), "bob"));

        fs::remove_file(&fp).unwrap();
    }
}
