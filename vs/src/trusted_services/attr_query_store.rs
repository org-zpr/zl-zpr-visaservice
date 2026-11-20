//! The `api = "zpr-attr/1"` attribute-service store (zipline#72 / #78, V1).
//!
//! A *decorating* trusted service: it never authenticates anyone and is
//! queried by the identity attributes other services established, exactly
//! like a `file` store — except the answer comes from `POST {url}/query`
//! over pinned TLS with a per-declaration bearer token. Normative contract:
//! `docs/ATTRIBUTE_SERVICE.md` (the wire protocol, the five read-order
//! rules, and the fail-closed table).
//!
//! **Stateless**: the store holds no attribute cache. The actor's own
//! attribute expiry is the cache — `refresh_expired_attributes` re-queries a
//! source only when an attribute expired or is about to (within
//! `config::ATTRIBUTE_REFRESH_AHEAD`), or the revision moved, so a snapshot
//! cache here would just be a second TTL to reason about.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use libeval::attribute::{Attribute, AttributeSource};
use tracing::{debug, info, warn};
use zpr::policy_types::{AttrQueryConfig, TrustedService};

use crate::error::ServiceError;
use crate::http_util::read_body_capped;
use crate::logging::targets::TS;

use super::attribute_mapper::{AttrHint, AttributeMapper};
use super::{MIN_ATTRIBUTE_TTL, TrustedServiceInterface, next_revision};

/// Whole-request timeout when the policy record carries none (the compiler
/// defaults to 5 and caps at 30; a hand-built record decoding to 0 gets the
/// same default rather than no timeout at all).
const DEFAULT_QUERY_TIMEOUT_SECS: u32 = 5;

/// An `api = "zpr-attr/1"` trusted service: one HTTPS client pinned by
/// policy, one bearer token read from `<ts_secrets_dir>/<id>.token`, no
/// attribute cache.
pub(crate) struct AttrQueryStore {
    /// Trusted-service id; also the source stamped on every vended attribute.
    id: String,
    /// `returns_attributes` mapping from service-side names to ZPR keys.
    mapper: AttributeMapper,
    /// Default and maximum lifetime of returned attributes, from policy.
    expiration: Duration,
    /// `{url}/query`, precomputed from the policy base URL.
    query_url: String,
    /// `{url}/schema`, precomputed from the policy base URL.
    schema_url: String,
    /// The per-declaration bearer token. Never logged, never in errors.
    token: String,
    /// One client per store: no redirects, the policy timeout, and the
    /// policy CA pin (exclusive when set — built-in roots disabled).
    client: reqwest::Client,
    /// Snapshot revision from the process-wide counter, so the ts_mgr
    /// staleness machinery treats this store like any other.
    revision: AtomicU64,
}

/// One attribute entry of a `/query` response. Unknown JSON fields are
/// tolerated (forward compatibility); a missing `values` is a shape error.
#[derive(Debug, Deserialize)]
struct QueryAttrEntry {
    values: Vec<String>,
    expires_at: Option<String>,
}

/// The `/query` response body: an object keyed by service-side name.
#[derive(Debug, Deserialize)]
struct QueryResponse {
    attributes: BTreeMap<String, QueryAttrEntry>,
}

/// One SCIM 2.0 attribute definition from `/schema` (RFC 7643 §7). Only the
/// fields the correspondence check reads are decoded; every other SCIM
/// field (`required`, `caseExact`, `mutability`, ...) is ignored.
#[derive(Debug, Deserialize)]
struct SchemaAttrDef {
    name: String,
    #[serde(rename = "type", default = "default_scim_type")]
    scim_type: String,
    #[serde(rename = "multiValued", default)]
    multi_valued: bool,
}

/// SCIM's default attribute type.
fn default_scim_type() -> String {
    "string".to_string()
}

/// The `/schema` response envelope: our `identityKeys` plus SCIM definitions.
#[derive(Debug, Deserialize)]
struct SchemaResponse {
    #[serde(rename = "identityKeys", default)]
    identity_keys: Vec<String>,
    #[serde(default)]
    attributes: Vec<SchemaAttrDef>,
}

impl AttrQueryStore {
    /// Build the store from its policy record: read the bearer token from
    /// `<ts_secrets_dir>/<id>.token` (trimmed; missing or empty fails the
    /// install — a store that cannot authenticate cannot answer), and build
    /// the pinned HTTPS client. The record must carry an `attr_query` config.
    pub(crate) fn new(
        record: &TrustedService,
        ts_secrets_dir: &Path,
    ) -> Result<Self, ServiceError> {
        let id = record.service_id.clone();
        let Some(cfg) = &record.attr_query else {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}': api 'zpr-attr/1' requires an attr_query config \
                 in the policy record"
            )));
        };

        let expiration = Duration::from_secs(record.expiration_seconds as u64);
        if expiration <= MIN_ATTRIBUTE_TTL {
            return Err(ServiceError::Param(format!(
                "trusted service '{id}' ttl {expiration:?} must exceed minimum of \
                 {MIN_ATTRIBUTE_TTL:?}"
            )));
        }

        let token_path = ts_secrets_dir.join(format!("{id}.token"));
        let token = std::fs::read_to_string(&token_path)
            .map_err(|error| {
                ServiceError::TrustedServiceInit(format!(
                    "TS '{id}' failed to read bearer token file {token_path:?}: {error}"
                ))
            })?
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(ServiceError::TrustedServiceInit(format!(
                "TS '{id}' bearer token file {token_path:?} is empty"
            )));
        }

        let client = build_client(&id, cfg)?;
        let base = cfg.url.trim_end_matches('/');
        Ok(AttrQueryStore {
            query_url: format!("{base}/query"),
            schema_url: format!("{base}/schema"),
            id,
            mapper: AttributeMapper {
                mappings: record.returns_attrs.clone(),
            },
            expiration,
            token,
            client,
            revision: AtomicU64::new(next_revision()),
        })
    }

    /// The install-time schema check (docs/ATTRIBUTE_SERVICE.md, `GET
    /// {url}/schema`): advisory only. Warns per finding from
    /// [`Self::schema_findings`]; any failure to fetch or parse logs one
    /// `info` line — **a schema disagreement never fails a policy install**:
    /// policy is authoritative and an attribute-service outage must not
    /// block a policy fix.
    pub(super) async fn check_schema(&self, lookup_identity_keys: &[&str]) {
        let schema = match self.fetch_schema().await {
            Ok(schema) => schema,
            Err(reason) => {
                info!(
                    target: TS,
                    "TS {}: schema check skipped ({reason}); policy is authoritative",
                    self.id
                );
                return;
            }
        };
        for finding in self.schema_findings(&schema, lookup_identity_keys) {
            warn!(target: TS, "TS {}: {finding}", self.id);
        }
    }

    /// The advisory findings of one schema check, as warn-ready strings: one
    /// per mapped name the schema does not list, one per spelling/definition
    /// mismatch under the spec's correspondence table (including `complex`),
    /// and one when a non-empty `identityKeys` shares nothing with the
    /// policy's lookup-identity keys. Pure, so each warning is testable.
    fn schema_findings(
        &self,
        schema: &SchemaResponse,
        lookup_identity_keys: &[&str],
    ) -> Vec<String> {
        let mut findings = Vec::new();
        let defs: BTreeMap<&str, &SchemaAttrDef> = schema
            .attributes
            .iter()
            .map(|def| (def.name.as_str(), def))
            .collect();
        for mapping in &self.mapper.mappings {
            let name = mapping.service_attr_key.as_str();
            let Some(def) = defs.get(name) else {
                findings.push(format!(
                    "mapped attribute '{name}' is not in the service schema"
                ));
                continue;
            };
            // The correspondence table: what the policy spelling of this
            // mapping expects the SCIM definition to look like.
            let attr = &mapping.attr;
            let mismatch = if attr.is_tag() {
                // Tag: `type: boolean`, single-valued.
                def.scim_type != "boolean" || def.multi_valued
            } else if attr.is_multi_valued() {
                // Multi-valued: any type but boolean or complex, multiValued.
                def.scim_type == "boolean" || def.scim_type == "complex" || !def.multi_valued
            } else {
                // Single-valued: any type but boolean or complex, not multiValued.
                def.scim_type == "boolean" || def.scim_type == "complex" || def.multi_valued
            };
            if mismatch {
                findings.push(format!(
                    "mapped attribute '{name}' disagrees with its schema definition \
                     (type '{}', multiValued {}) under the policy spelling",
                    def.scim_type, def.multi_valued
                ));
            }
        }

        if !schema.identity_keys.is_empty()
            && !schema
                .identity_keys
                .iter()
                .any(|key| lookup_identity_keys.contains(&key.as_str()))
        {
            findings.push(format!(
                "schema identityKeys {:?} share nothing with the policy's \
                 lookup-identity keys {:?} — the service can never match an actor",
                schema.identity_keys, lookup_identity_keys
            ));
        }
        findings
    }

    /// `GET {url}/schema` with the bearer token, capped and parsed. Errors
    /// come back as a reason string for the caller's single `info` line.
    async fn fetch_schema(&self) -> Result<SchemaResponse, String> {
        let mut resp = self
            .client
            .get(&self.schema_url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("schema fetch failed: {e}"))?;
        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            return Err(format!("schema endpoint returned status {status}"));
        }
        let body = read_body_capped(&mut resp, "schema response")
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&body).map_err(|_| "schema response does not parse".to_string())
    }
}

/// Build the store's `reqwest::Client`: never follow a redirect (a redirect
/// is a way to move a request to a host the pin does not cover), apply the
/// policy timeout, and when `ca_cert_pem` is set trust ONLY those roots.
/// reqwest 0.13 spells the exclusive pin `tls_certs_only(certs)` — the
/// 0.12-era `tls_built_in_root_certs(false)` + `add_root_certificate` pair
/// in the plan — so with a pin the built-in roots are disabled and a
/// certificate for the same hostname chaining to a public CA is rejected.
/// The pin is exclusive, never additive.
fn build_client(id: &str, cfg: &AttrQueryConfig) -> Result<reqwest::Client, ServiceError> {
    let timeout_seconds = if cfg.timeout_seconds == 0 {
        DEFAULT_QUERY_TIMEOUT_SECS
    } else {
        cfg.timeout_seconds
    };
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds as u64))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = cfg
        .ca_cert_pem
        .as_deref()
        .filter(|pem| !pem.trim().is_empty())
    {
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_err(|e| {
            ServiceError::TrustedServiceInit(format!(
                "TS '{id}' ca_cert_pem does not parse as PEM certificates: {e}"
            ))
        })?;
        if certs.is_empty() {
            return Err(ServiceError::TrustedServiceInit(format!(
                "TS '{id}' ca_cert_pem holds no CERTIFICATE block"
            )));
        }
        builder = builder.tls_certs_only(certs);
    }
    builder.build().map_err(|e| {
        ServiceError::TrustedServiceInit(format!("TS '{id}' failed to build HTTP client: {e}"))
    })
}

#[async_trait]
impl TrustedServiceInterface for AttrQueryStore {
    /// One `POST {url}/query` per lookup, mapped and validated under the
    /// spec's read-order rules (docs/ATTRIBUTE_SERVICE.md):
    ///
    /// 1. anything but a well-formed `200` — bad status (a `404` means the
    ///    URL is wrong, never "unknown actor"; a `409` is the service
    ///    refusing to pick between conflicting records), transport error,
    ///    timeout, oversized body, malformed body — is an `Err`, and the
    ///    caller makes the actor indeterminate;
    /// 2. returned names are mapped through `returns_attributes`; unmapped
    ///    names are dropped silently;
    /// 3. a single-valued mapping whose `values` holds more than one element
    ///    is an `Err` for the whole response;
    /// 4. a single- or multi-valued mapping with empty `values` is absent;
    ///    a tag's presence is the tag and its `values` are ignored;
    /// 5. expiry is `min(expires_at, now + expiration_seconds)` — policy
    ///    shortens, never extends; already-past means absent — and every
    ///    attribute is stamped with this store's id.
    ///
    /// An unknown actor is `{"attributes": {}}`: a successful, empty answer.
    /// Attribute values never reach logs above `debug`.
    async fn get_attributes_for_actor(
        &self,
        identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError> {
        // The request body from the spec: the lookup-identity set as ZPR key
        // names, plus the service-side names we will keep (a hint the
        // service may ignore; the mapping filters the response regardless).
        let identities_body: serde_json::Map<String, serde_json::Value> = identities
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect();
        let attributes_hint: Vec<&str> = self
            .mapper
            .mappings
            .iter()
            .map(|m| m.service_attr_key.as_str())
            .collect();
        let body = serde_json::json!({
            "identities": identities_body,
            "attributes": attributes_hint,
        });

        let mut resp = self
            .client
            .post(&self.query_url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                // reqwest errors name the URL, never the request body.
                ServiceError::Internal(format!("TS '{}' query failed: {e}", self.id))
            })?;
        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            // Rule 1: everything but exactly 200 is a deny, logged by status
            // for the operator; a 404 is a wrong URL, never an unknown actor,
            // and other 2xx codes (201, 206 partial content) are not the
            // authoritative answer the spec requires.
            return Err(ServiceError::Internal(format!(
                "TS '{}' query returned status {status}",
                self.id
            )));
        }
        let raw = read_body_capped(&mut resp, "attribute query response").await?;
        let parsed: QueryResponse = serde_json::from_slice(&raw).map_err(|_| {
            // Never echo the body: attribute values are personal data.
            ServiceError::Internal(format!(
                "TS '{}' query response does not parse to the zpr-attr/1 shape",
                self.id
            ))
        })?;

        let now = SystemTime::now();
        let policy_ceiling = now + self.expiration;
        let src = AttributeSource::new(self.id.clone());
        let mut mapped: BTreeMap<String, Attribute> = BTreeMap::new();
        for (name, entry) in &parsed.attributes {
            // Rule 2: unmapped names were never going to become attributes.
            let Some((zpr_key, hint)) = self.mapper.map_attribute(name) else {
                debug!(target: TS, "TS {}: dropping unmapped attribute '{name}'", self.id);
                continue;
            };

            // Rule 5: policy can shorten a lifetime but never extend one,
            // and a value already in the past makes the attribute absent.
            let expires = match entry.expires_at.as_deref() {
                None => policy_ceiling,
                Some(stamp) => {
                    let parsed_at = chrono::DateTime::parse_from_rfc3339(stamp).map_err(|_| {
                        ServiceError::Internal(format!(
                            "TS '{}' attribute '{name}' carries a malformed expires_at",
                            self.id
                        ))
                    })?;
                    SystemTime::from(parsed_at).min(policy_ceiling)
                }
            };
            if expires <= now {
                continue;
            }

            let builder = src.builder(zpr_key.clone()).expires(expires);
            let attr = match hint {
                AttrHint::SingleValued => {
                    if entry.values.len() > 1 {
                        // Rule 3: the service and the policy disagree about
                        // what this attribute IS; picking the first element
                        // would tie authorization to iteration order.
                        return Err(ServiceError::Internal(format!(
                            "TS '{}' returned {} values for single-valued attribute '{name}'",
                            self.id,
                            entry.values.len()
                        )));
                    }
                    // Rule 4: empty values on a non-tag means absent.
                    let Some(value) = entry.values.first() else {
                        continue;
                    };
                    builder.value(value.clone())
                }
                AttrHint::MultiValued => {
                    if entry.values.is_empty() {
                        continue; // rule 4
                    }
                    builder.values(entry.values.clone())
                }
                // A tag is valueless: the name's presence is the tag.
                AttrHint::Tag => builder.values(Vec::<String>::new()),
            };

            // Two service-side names mapping to the same ZPR key must agree,
            // the same fail-closed conflict rule every store implements.
            // Names only in the error — values never reach logs.
            if let Some(existing) = mapped.get(&zpr_key) {
                if existing.get_value() != attr.get_value() {
                    return Err(ServiceError::Internal(format!(
                        "TS '{}': two returned attributes disagree on '{zpr_key}'",
                        self.id
                    )));
                }
                continue;
            }
            mapped.insert(zpr_key, attr);
        }
        Ok(mapped.into_values().collect())
    }

    /// Bump the revision so every actor becomes stale for this source and is
    /// re-queried. There is no cache to drop — the store is stateless.
    async fn flush(&self) -> Result<(), ServiceError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_services::test_support::{
        AttrMockServer, AttrResponder, spawn_tls_attr_server,
    };
    use std::sync::Arc;
    use zpr::policy_types::parse_attribute_mapping;

    /// The mapping set most tests use: one of each spelling.
    const MAPPINGS: &[&str] = &[
        "color -> user.color",
        "roles -> user.role{}",
        "contractor -> #user.contractor",
    ];

    /// A policy record for an `api = "zpr-attr/1"` service over `url`.
    fn make_record(id: &str, url: &str, ca_cert_pem: Option<&str>) -> TrustedService {
        make_record_with(id, url, ca_cert_pem, MAPPINGS, 3600, 5)
    }

    /// As [make_record], with the mapping set, expiration, and timeout under
    /// test control.
    fn make_record_with(
        id: &str,
        url: &str,
        ca_cert_pem: Option<&str>,
        mappings: &[&str],
        expiration_seconds: u32,
        timeout_seconds: u32,
    ) -> TrustedService {
        TrustedService {
            service_id: id.to_string(),
            expiration_seconds,
            returns_attrs: mappings
                .iter()
                .map(|m| parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: vec![],
            oidc: None,
            attr_query: Some(AttrQueryConfig {
                url: url.to_string(),
                ca_cert_pem: ca_cert_pem.map(str::to_string),
                timeout_seconds,
            }),
        }
    }

    /// A secrets dir holding `<id>.token` files with the given contents.
    fn secrets_dir(tokens: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (id, token) in tokens {
            std::fs::write(dir.path().join(format!("{id}.token")), token).unwrap();
        }
        dir
    }

    /// A store named `attrs` over the mock, pinned to its certificate.
    fn make_store(server: &AttrMockServer, dir: &tempfile::TempDir) -> AttrQueryStore {
        AttrQueryStore::new(
            &make_record("attrs", &server.url, Some(&server.cert_pem)),
            dir.path(),
        )
        .unwrap()
    }

    /// A responder that answers every request with `status` and `body`.
    fn fixed(status: u16, body: &str) -> AttrResponder {
        let body = body.to_string();
        Arc::new(move |_req| (status, body.clone()))
    }

    /// The actor identity set the tests query with.
    fn identities() -> Vec<(String, String)> {
        vec![("user.sub".to_string(), "s-123".to_string())]
    }

    /// Happy path: one attribute of each spelling comes back mapped, the
    /// multi-valued one keeps all values, the tag is valueless, an unmapped
    /// name is dropped silently, and every attribute carries this store's
    /// source id.
    #[tokio::test]
    async fn test_query_happy_path_all_three_types() {
        let server = spawn_tls_attr_server(
            fixed(
                200,
                r#"{"attributes": {
                    "color":      {"values": ["red"]},
                    "roles":      {"values": ["a", "b"]},
                    "contractor": {"values": []},
                    "unmapped":   {"values": ["zzz"]}
                }}"#,
            ),
            None,
        )
        .await;
        let dir = secrets_dir(&[("attrs", "sekrit-token")]);
        let store = make_store(&server, &dir);

        let attrs = store.get_attributes_for_actor(&identities()).await.unwrap();
        let by_key: BTreeMap<&str, &Attribute> = attrs.iter().map(|a| (a.get_key(), a)).collect();
        assert_eq!(attrs.len(), 3, "unmapped names must be dropped: {attrs:?}");
        assert_eq!(
            by_key["user.color"].get_single_value().unwrap(),
            "red".to_string()
        );
        assert_eq!(
            by_key["user.role"].get_value(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(by_key["user.zpr.tag.contractor"].get_value().is_empty());
        for attr in &attrs {
            assert_eq!(attr.get_source(), "attrs");
        }

        // The wire: POST {url}/query, bearer token, spec-shaped body.
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/query");
        assert_eq!(requests[0].bearer.as_deref(), Some("sekrit-token"));
        let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(body["identities"]["user.sub"], "s-123");
        assert!(
            body["attributes"]
                .as_array()
                .unwrap()
                .contains(&"color".into())
        );
    }

    /// Expiry clamping, both directions (spec rule 5): an `expires_at` beyond
    /// the policy ceiling is clamped down to it, one inside the ceiling is
    /// honored, and one already in the past makes the attribute absent.
    #[tokio::test]
    async fn test_expires_at_clamped_both_ways() {
        let soon = chrono::Utc::now() + chrono::Duration::seconds(120);
        let body = format!(
            r#"{{"attributes": {{
                "color": {{"values": ["red"],  "expires_at": "2199-01-01T00:00:00Z"}},
                "roles": {{"values": ["a"],    "expires_at": "{}"}},
                "contractor": {{"values": [], "expires_at": "2001-01-01T00:00:00Z"}}
            }}}}"#,
            soon.to_rfc3339()
        );
        let server = spawn_tls_attr_server(fixed(200, &body), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);

        let before = SystemTime::now();
        let attrs = store.get_attributes_for_actor(&identities()).await.unwrap();
        let ceiling = SystemTime::now() + Duration::from_secs(3600);
        let by_key: BTreeMap<&str, &Attribute> = attrs.iter().map(|a| (a.get_key(), a)).collect();

        // Far-future expires_at: policy shortens, never extends.
        let color = by_key["user.color"];
        assert!(color.get_expires() <= ceiling);
        assert!(color.get_expires() >= before + Duration::from_secs(3590));

        // In-window expires_at is honored as sent.
        let roles = by_key["user.role"];
        assert_eq!(roles.get_expires(), SystemTime::from(soon));

        // Already-past expires_at: the attribute is absent, not expired-and-present.
        assert!(!by_key.contains_key("user.zpr.tag.contractor"));
    }

    /// An unknown actor is a successful, EMPTY answer, exactly like the file
    /// store — never an error (spec: `{"attributes": {}}`).
    #[tokio::test]
    async fn test_unknown_actor_is_ok_empty() {
        let server = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        let attrs = store.get_attributes_for_actor(&identities()).await.unwrap();
        assert!(attrs.is_empty());
    }

    /// Empty `values` on a single- or multi-valued mapping means the service
    /// has no value: the attribute is absent (spec rule 4).
    #[tokio::test]
    async fn test_empty_values_on_non_tag_is_absent() {
        let server = spawn_tls_attr_server(
            fixed(
                200,
                r#"{"attributes": {"color": {"values": []}, "roles": {"values": []}}}"#,
            ),
            None,
        )
        .await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        let attrs = store.get_attributes_for_actor(&identities()).await.unwrap();
        assert!(attrs.is_empty(), "{attrs:?}");
    }

    /// Fail closed on every bad response (spec rule 1): each non-200 status —
    /// including 404, which means "wrong URL", never "unknown actor", and the
    /// other 2xx codes (a 206 is a partial body an intermediary vouched for;
    /// its plausible-looking attributes must not be taken as authoritative) —
    /// plus a malformed body and a single-valued attribute with two values.
    #[tokio::test]
    async fn test_fail_closed_statuses_and_shapes() {
        let cases: Vec<(u16, &str)> = vec![
            (404, r#"{"attributes": {}}"#),
            (409, r#"{"error": "conflict"}"#),
            (500, "oops"),
            // 2xx but not 200: spec says exactly 200, everything else denies.
            (
                201,
                r#"{"attributes": {"title": {"values": ["ceo"], "expires_at": null}}}"#,
            ),
            (
                206,
                r#"{"attributes": {"title": {"values": ["ceo"], "expires_at": null}}}"#,
            ),
            (200, "not json at all"),
            (
                200,
                r#"{"attributes": {"color": {"values": ["red", "blue"]}}}"#,
            ),
            (
                200,
                r#"{"attributes": {"color": {"values": ["red"], "expires_at": "bogus"}}}"#,
            ),
        ];
        for (status, body) in cases {
            let server = spawn_tls_attr_server(fixed(status, body), None).await;
            let dir = secrets_dir(&[("attrs", "t")]);
            let store = make_store(&server, &dir);
            let result = store.get_attributes_for_actor(&identities()).await;
            assert!(
                result.is_err(),
                "status={status} body={body} must fail closed"
            );
        }
    }

    /// Fail closed on timeout: the policy timeout bounds the whole request,
    /// so a server that stalls longer than it yields Err, not a hang.
    #[tokio::test]
    async fn test_fail_closed_on_timeout() {
        let server = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), Some(3)).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let record = make_record_with(
            "attrs",
            &server.url,
            Some(&server.cert_pem),
            MAPPINGS,
            3600,
            1,
        );
        let store = AttrQueryStore::new(&record, dir.path()).unwrap();
        let result = store.get_attributes_for_actor(&identities()).await;
        assert!(result.is_err(), "a stalled server must time out into Err");
    }

    /// Fail closed on an oversized body: the shared 1 MiB cap applies.
    #[tokio::test]
    async fn test_fail_closed_on_oversized_body() {
        let huge = format!(
            r#"{{"attributes": {{"color": {{"values": ["{}"]}}}}}}"#,
            "x".repeat(crate::http_util::MAX_RESPONSE_BYTES)
        );
        let server = spawn_tls_attr_server(fixed(200, &huge), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        let result = store.get_attributes_for_actor(&identities()).await;
        assert!(result.is_err(), "a body over the cap must fail closed");
    }

    /// Pin semantics: with `ca_cert_pem` set, a server chaining to the pinned
    /// root is accepted and a server presenting a DIFFERENT root is rejected
    /// — the pin is exclusive. With no pin the built-in system roots apply,
    /// which reject a self-signed mock.
    #[tokio::test]
    async fn test_ca_pin_is_exclusive() {
        let good = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let other = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);

        // Pinned to the server's own root: accepted.
        let store = AttrQueryStore::new(
            &make_record("attrs", &good.url, Some(&good.cert_pem)),
            dir.path(),
        )
        .unwrap();
        assert!(store.get_attributes_for_actor(&identities()).await.is_ok());

        // Pinned to a different root: the handshake is rejected even though
        // the certificate is valid for the same host string.
        let store = AttrQueryStore::new(
            &make_record("attrs", &good.url, Some(&other.cert_pem)),
            dir.path(),
        )
        .unwrap();
        assert!(
            store.get_attributes_for_actor(&identities()).await.is_err(),
            "a chain to a root other than the pinned one must be rejected"
        );

        // No pin: built-in roots apply, and they do not trust the mock's
        // self-signed certificate.
        let store =
            AttrQueryStore::new(&make_record("attrs", &good.url, None), dir.path()).unwrap();
        assert!(
            store.get_attributes_for_actor(&identities()).await.is_err(),
            "without a pin, system roots apply (and reject a self-signed mock)"
        );
    }

    /// A missing or empty token file fails construction — and thereby the
    /// policy install — with TrustedServiceInit, like a file store whose
    /// JSON is absent. A store that cannot authenticate cannot answer.
    #[tokio::test]
    async fn test_missing_or_empty_token_fails_install() {
        let server = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let empty_dir = tempfile::tempdir().unwrap();
        let record = make_record("attrs", &server.url, Some(&server.cert_pem));

        let missing = AttrQueryStore::new(&record, empty_dir.path());
        assert!(matches!(missing, Err(ServiceError::TrustedServiceInit(_))));

        let dir = secrets_dir(&[("attrs", "  \n")]);
        let empty = AttrQueryStore::new(&record, dir.path());
        assert!(matches!(empty, Err(ServiceError::TrustedServiceInit(_))));
    }

    /// The token is read trimmed of surrounding whitespace.
    #[tokio::test]
    async fn test_token_is_trimmed() {
        let server = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let dir = secrets_dir(&[("attrs", "  tok-42\n")]);
        let store = make_store(&server, &dir);
        store.get_attributes_for_actor(&identities()).await.unwrap();
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests[0].bearer.as_deref(), Some("tok-42"));
    }

    /// Delegation (spec, *Configuration*): two declarations may share one
    /// `url` under different ids with different tokens. They are two stores,
    /// two source stamps — and each request carries its own token.
    #[tokio::test]
    async fn test_two_ids_one_url_each_request_carries_its_own_token() {
        let server = spawn_tls_attr_server(
            fixed(200, r#"{"attributes": {"color": {"values": ["red"]}}}"#),
            None,
        )
        .await;
        let dir = secrets_dir(&[("parent", "parent-token"), ("delegate", "delegate-token")]);

        let parent = AttrQueryStore::new(
            &make_record("parent", &server.url, Some(&server.cert_pem)),
            dir.path(),
        )
        .unwrap();
        let delegate = AttrQueryStore::new(
            &make_record("delegate", &server.url, Some(&server.cert_pem)),
            dir.path(),
        )
        .unwrap();

        let from_parent = parent
            .get_attributes_for_actor(&identities())
            .await
            .unwrap();
        let from_delegate = delegate
            .get_attributes_for_actor(&identities())
            .await
            .unwrap();
        assert_eq!(from_parent[0].get_source(), "parent");
        assert_eq!(from_delegate[0].get_source(), "delegate");

        let requests = server.requests.lock().unwrap();
        let bearers: Vec<_> = requests.iter().map(|r| r.bearer.clone()).collect();
        assert_eq!(
            bearers,
            vec![
                Some("parent-token".to_string()),
                Some("delegate-token".to_string())
            ]
        );
    }

    /// flush is a revision bump and nothing else — the store is stateless,
    /// so the ts_mgr machinery re-queries every actor from the source.
    #[tokio::test]
    async fn test_flush_bumps_revision() {
        let server = spawn_tls_attr_server(fixed(200, r#"{"attributes": {}}"#), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        assert_eq!(store.get_source_id(), "attrs");
        let before = store.current_revision();
        store.flush().await.unwrap();
        assert!(store.current_revision() > before);
    }

    /// A record without an attr_query config is rejected (the factory also
    /// pre-rejects it; the store must fail closed on a hand-built record).
    #[tokio::test]
    async fn test_missing_attr_query_config_rejected() {
        let dir = secrets_dir(&[("attrs", "t")]);
        let mut record = make_record("attrs", "https://example.invalid", None);
        record.attr_query = None;
        assert!(matches!(
            AttrQueryStore::new(&record, dir.path()),
            Err(ServiceError::Param(_))
        ));
    }

    /// A TTL at or below the shared floor is rejected, as the file store does.
    #[tokio::test]
    async fn test_ttl_floor_enforced() {
        let dir = secrets_dir(&[("attrs", "t")]);
        let record = make_record_with("attrs", "https://example.invalid", None, MAPPINGS, 60, 5);
        assert!(matches!(
            AttrQueryStore::new(&record, dir.path()),
            Err(ServiceError::Param(_))
        ));
    }

    // --- the schema check -------------------------------------------------

    /// Decode a schema fixture the way fetch_schema would.
    fn schema(json: &str) -> SchemaResponse {
        serde_json::from_str(json).unwrap()
    }

    /// A store whose schema check findings we inspect directly (the pure
    /// core of check_schema, so each warning is testable).
    async fn findings_store() -> (AttrMockServer, tempfile::TempDir, AttrQueryStore) {
        let server = spawn_tls_attr_server(fixed(200, "{}"), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        (server, dir, store)
    }

    /// A schema matching every mapping and the lookup keys yields no finding.
    #[tokio::test]
    async fn test_schema_findings_clean() {
        let (_server, _dir, store) = findings_store().await;
        let s = schema(
            r#"{"identityKeys": ["user.sub"], "attributes": [
                {"name": "color", "type": "string"},
                {"name": "roles", "type": "string", "multiValued": true},
                {"name": "contractor", "type": "boolean",
                 "required": false, "caseExact": true}
            ]}"#,
        );
        assert!(store.schema_findings(&s, &["user.sub"]).is_empty());
    }

    /// Each advisory warning fires: a missing name, every spelling/definition
    /// mismatch in the correspondence table (including `complex`), and
    /// disjoint identityKeys.
    #[tokio::test]
    async fn test_schema_findings_each_warning_fires() {
        let (_server, _dir, store) = findings_store().await;

        // Missing name.
        let s = schema(
            r#"{"attributes": [{"name": "roles", "type": "string", "multiValued": true}, {"name": "contractor", "type": "boolean"}]}"#,
        );
        let f = store.schema_findings(&s, &["user.sub"]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("'color'") && f[0].contains("not in the service schema"));

        // Single-valued mapped to a multiValued definition.
        let s =
            schema(r#"{"attributes": [{"name": "color", "type": "string", "multiValued": true}]}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(
            f.iter()
                .any(|w| w.contains("'color'") && w.contains("disagrees")),
            "{f:?}"
        );

        // Multi-valued mapped to a single-valued definition.
        let s = schema(r#"{"attributes": [{"name": "roles", "type": "string"}]}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(
            f.iter()
                .any(|w| w.contains("'roles'") && w.contains("disagrees")),
            "{f:?}"
        );

        // Tag mapped to a non-boolean definition.
        let s = schema(r#"{"attributes": [{"name": "contractor", "type": "string"}]}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(
            f.iter()
                .any(|w| w.contains("'contractor'") && w.contains("disagrees")),
            "{f:?}"
        );

        // complex is never a match, whatever the spelling.
        let s = schema(r#"{"attributes": [{"name": "color", "type": "complex"}]}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(
            f.iter()
                .any(|w| w.contains("'color'") && w.contains("disagrees")),
            "{f:?}"
        );

        // identityKeys disjoint from the policy's lookup keys.
        let s = schema(r#"{"identityKeys": ["user.email"], "attributes": []}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(f.iter().any(|w| w.contains("identityKeys")), "{f:?}");

        // Empty identityKeys means "unspecified": no finding for it.
        let s = schema(r#"{"identityKeys": [], "attributes": []}"#);
        let f = store.schema_findings(&s, &["user.sub"]);
        assert!(!f.iter().any(|w| w.contains("identityKeys")), "{f:?}");
    }

    /// A schema endpoint that is missing (404) or garbled never fails the
    /// check path — check_schema returns normally and the install proceeds.
    #[tokio::test]
    async fn test_schema_endpoint_absent_is_advisory_only() {
        let server = spawn_tls_attr_server(fixed(404, "nope"), None).await;
        let dir = secrets_dir(&[("attrs", "t")]);
        let store = make_store(&server, &dir);
        // Must not panic or error; the single info line is the whole outcome.
        store.check_schema(&["user.sub"]).await;

        let server = spawn_tls_attr_server(fixed(200, "not json"), None).await;
        let store = make_store(&server, &dir);
        store.check_schema(&["user.sub"]).await;
    }

    /// The schema request is a GET on {url}/schema carrying the bearer token
    /// (the response is credential-scoped, RFC 19 §6).
    #[tokio::test]
    async fn test_schema_request_shape() {
        let server = spawn_tls_attr_server(
            fixed(200, r#"{"identityKeys": [], "attributes": []}"#),
            None,
        )
        .await;
        let dir = secrets_dir(&[("attrs", "schema-tok")]);
        let store = make_store(&server, &dir);
        store.check_schema(&["user.sub"]).await;
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/schema");
        assert_eq!(requests[0].bearer.as_deref(), Some("schema-tok"));
    }
}
