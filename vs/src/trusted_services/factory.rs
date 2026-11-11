//! Construction of trusted-service implementations from policy declarations.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libeval::policy::Policy;
use zpr::policy_types::{ServiceType, TrustedService};

use crate::error::ServiceError;
use crate::oidc::{KeySource, OidcTrustedService, ProxyResolver};

use super::TrustedServiceInterface;
use super::attr_query_store::AttrQueryStore;
use super::attribute_mapper::AttributeMapper;
use super::file_attribute_store::FileAttributeStore;

/// API name used by file-backed trusted services.
const TS_API_FILE: &str = "file";

/// API name used by OIDC identity-provider trusted services.
pub const TS_API_OIDC: &str = "oidc";

/// API name used by `zpr-attr/1` attribute services (zipline#72 / #78).
pub const TS_API_ATTR_QUERY: &str = "zpr-attr/1";

/// One policy-declared trusted service, reduced to the inputs that determine its store
/// instance. Comparing these across policies tells us whether the live stores are still
/// correct, so an unchanged declaration can keep its store (and its revision). The
/// embedded `record` carries the `oidc` config, so an OIDC config change (issuer,
/// client_id, keys, ...) breaks equality and rebuilds the store.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedServiceDefinition {
    id: String,
    api: String,
    record: TrustedService,
    /// The single-scope port pinned by the policy declaration of the regular
    /// service this OIDC config names as `jwks_proxy_service`; `None` for
    /// non-OIDC definitions, direct-egress providers, or a proxy declaration
    /// the resolver could never use (missing, or not exactly one single-port
    /// scope). Captured into the definition — not recomputed at build time —
    /// so it participates in equality: a policy update that changes only the
    /// proxy service's declaration breaks reuse and rebuilds the store, whose
    /// resolver pins this port (PR #7 review, P1).
    jwks_proxy_port: Option<u16>,
}

impl TrustedServiceDefinition {
    /// The declared trusted-service id (also the store's source id), the key
    /// unchanged declarations are matched under across policy installs.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The pinned `OidcConfig` for an `api = "oidc"` declaration, `None`
    /// otherwise. `PolicyMgr::build_state` reads `jwks_proxy_service` from it
    /// to build the ActorDb-backed proxy resolver (zipline#19).
    pub fn oidc_config(&self) -> Option<&zpr::policy_types::OidcConfig> {
        self.record.oidc.as_ref()
    }

    /// The proxy port captured from the policy's `jwks_proxy_service`
    /// declaration (see the field doc). `PolicyMgr::build_state` hands this
    /// to the proxy resolver so resolver and equality key can never disagree.
    pub fn jwks_proxy_port(&self) -> Option<u16> {
        self.jwks_proxy_port
    }
}

/// The port the ActorDb-backed JWKS proxy resolver would dial for
/// `service_id`: the policy must declare it with exactly one single-port
/// endpoint scope; anything else yields `None`.
fn jwks_proxy_port_from_policy(policy: &Policy, service_id: &str) -> Option<u16> {
    policy
        .list_services()
        .into_iter()
        .find(|service| service.id == service_id)
        .and_then(|service| match service.endpoints.as_slice() {
            [scope] => scope.port,
            _ => None,
        })
}

/// Validate and extract the trusted services a policy declares.
///
/// Two `api = "oidc"` declarations sharing an issuer are rejected: token
/// validation resolves the provider by its `iss` claim, so a duplicate issuer
/// would make which client configuration checks a token depend on unordered
/// service iteration. The error names both services and the issuer, mirroring
/// the compiler-side collision diagnostics.
pub fn trusted_service_definitions(
    policy: &Policy,
) -> Result<Vec<TrustedServiceDefinition>, ServiceError> {
    let mut definitions = Vec::new();
    let mut issuer_owners: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for service in policy.list_services() {
        let ServiceType::Trusted(api) = &service.kind else {
            continue;
        };
        if api != TS_API_FILE && api != TS_API_OIDC && api != TS_API_ATTR_QUERY {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': unsupported api '{api}'",
                service.id
            )));
        }
        // File stores resolve `<id>.json` on disk and attr-query stores
        // resolve `<id>.token`, so those ids must be plain filenames.
        if (api == TS_API_FILE || api == TS_API_ATTR_QUERY)
            && (service.id.contains('/') || service.id.contains(".."))
        {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': id is not a plain filename",
                service.id
            )));
        }
        let Some(trusted_service) = policy.trusted_service_by_id(&service.id) else {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': no trusted service record in policy",
                service.id
            )));
        };
        if api == TS_API_OIDC {
            let Some(cfg) = &trusted_service.oidc else {
                return Err(ServiceError::Param(format!(
                    "trusted service '{}': api 'oidc' requires an oidc config in the policy record",
                    service.id
                )));
            };
            if let Some(other) = issuer_owners.insert(cfg.issuer.clone(), service.id.clone()) {
                // Sort the pair: list_services iterates a HashMap, and the
                // diagnostic must not depend on its order.
                let (first, second) = if other <= service.id {
                    (other, service.id.clone())
                } else {
                    (service.id.clone(), other)
                };
                return Err(ServiceError::Param(format!(
                    "trusted services '{first}' and '{second}' both declare oidc issuer \
                     '{}': issuers must be unique so a token's iss claim selects exactly \
                     one provider",
                    cfg.issuer
                )));
            }
        }

        if api == TS_API_ATTR_QUERY && trusted_service.attr_query.is_none() {
            return Err(ServiceError::Param(format!(
                "trusted service '{}': api 'zpr-attr/1' requires an attr_query config \
                 in the policy record",
                service.id
            )));
        }
        // NOTE: two `zpr-attr/1` declarations may share one `url` under
        // different ids and tokens — that is the delegation shape
        // (docs/ATTRIBUTE_SERVICE.md, *Configuration*), so no duplicate-url
        // check here, unlike the OIDC duplicate-issuer rule above.

        let jwks_proxy_port = trusted_service
            .oidc
            .as_ref()
            .and_then(|cfg| cfg.jwks_proxy_service.as_deref())
            .and_then(|proxy_id| jwks_proxy_port_from_policy(policy, proxy_id));

        definitions.push(TrustedServiceDefinition {
            id: service.id.clone(),
            api: api.clone(),
            record: trusted_service.clone(),
            jwks_proxy_port,
        });
    }

    Ok(definitions)
}

/// Build one store per declaration. File stores load their initial attribute
/// snapshot from `file_ts_dir`; attr-query stores read their bearer token
/// from `<ts_secrets_dir>/<id>.token` and run the advisory schema check
/// against `lookup_identity_keys` (the policy's, see
/// `Policy::lookup_identity_keys`); OIDC stores build their JWKS key source
/// from the policy config, with `proxy_for(service_id)` supplying the
/// CONNECT-proxy resolver each refresh consults (see
/// `crate::oidc::ProxyResolver`). `jwks_bind_addr` is the local address a
/// proxied JWKS fetch binds to (`vs_addr` in production; see
/// `KeySource::with_bind_addr`, zl-zipline#240).
///
/// Returns the full `dyn` store list plus its typed OIDC subset (each OIDC
/// store appears in both), so `TrustedServicesMgr` can serve
/// `oidc_service_for_issuer` lookups for the connect path.
pub async fn build_services(
    definitions: &[TrustedServiceDefinition],
    file_ts_dir: &Path,
    ts_secrets_dir: &Path,
    lookup_identity_keys: &[&str],
    proxy_for: &(dyn Fn(&str) -> ProxyResolver + Sync),
    jwks_bind_addr: Option<IpAddr>,
) -> Result<
    (
        Vec<Arc<dyn TrustedServiceInterface>>,
        Vec<Arc<OidcTrustedService>>,
    ),
    ServiceError,
> {
    let mut services: Vec<Arc<dyn TrustedServiceInterface>> = Vec::new();
    let mut oidc_services: Vec<Arc<OidcTrustedService>> = Vec::new();
    for definition in definitions {
        match definition.api.as_str() {
            TS_API_OIDC => {
                let Some(cfg) = &definition.record.oidc else {
                    // trusted_service_definitions already rejects this; fail
                    // closed anyway rather than panic on a hand-built definition.
                    return Err(ServiceError::Param(format!(
                        "trusted service '{}': api 'oidc' requires an oidc config",
                        definition.id
                    )));
                };
                let keys = KeySource::from_policy(cfg, proxy_for(&definition.id))
                    .await
                    .map_err(|error| {
                        ServiceError::TrustedServiceInit(format!(
                            "TS '{}' failed to build JWKS key source: {error}",
                            definition.id
                        ))
                    })?;
                // Proxied fetches leave from the visa service's own address.
                let keys = keys.with_bind_addr(jwks_bind_addr);
                let store = Arc::new(OidcTrustedService::new(&definition.record, Arc::new(keys))?);
                oidc_services.push(store.clone());
                services.push(store);
            }
            TS_API_ATTR_QUERY => {
                let store = AttrQueryStore::new(&definition.record, ts_secrets_dir)?;
                // Advisory only, once per store build: a schema disagreement
                // warns and an unreachable endpoint logs one info line —
                // never a failed install (docs/ATTRIBUTE_SERVICE.md).
                store.check_schema(lookup_identity_keys).await;
                services.push(Arc::new(store));
            }
            _ => {
                let store = FileAttributeStore::new(
                    definition.id.clone(),
                    AttributeMapper {
                        mappings: definition.record.returns_attrs.clone(),
                    },
                    Duration::from_secs(definition.record.expiration_seconds as u64),
                    &file_ts_dir.join(format!("{}.json", definition.id)),
                )?;
                services.push(Arc::new(store));
            }
        }
    }
    Ok((services, oidc_services))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::policy_types::PolicyContainerBytes;

    use crate::loaded_policy::LoadedPolicy;
    use crate::oidc::static_proxy;
    use crate::test_helpers::{
        make_oidc_policy, make_test_oidc_config, make_trusted_service_policy,
    };

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &crate::config::POLICY_MIN_VERSION,
        )
        .unwrap();
        loaded.policy()
    }

    /// Validate and build in one step, as `PolicyMgr` does for a brand-new policy.
    /// Yields only the `dyn` list; the typed OIDC subset is manager plumbing.
    async fn build_from_policy(
        policy: &Policy,
        dir: &std::path::Path,
    ) -> Result<Vec<Arc<dyn TrustedServiceInterface>>, ServiceError> {
        // Tests keep attribute files and token files in the same directory,
        // and use the policy's own lookup-identity keys as PolicyMgr does.
        build_services(
            &trusted_service_definitions(policy)?,
            dir,
            dir,
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            None,
        )
        .await
        .map(|(services, _oidc)| services)
    }

    /// A valid file declaration constructs a working mapped attribute store.
    #[tokio::test]
    async fn test_build_services_from_policy_happy_path() {
        let dir = std::env::temp_dir().join("vs-bsfp-ok");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("attrfile.json"),
            r#"{"device.zpr.adapter.cn": {"alice": {"color": ["red"]}}}"#,
        )
        .unwrap();

        let policy = policy_from_container(make_trusted_service_policy(
            "attrfile",
            "file",
            Some(3600),
            &["color -> user.color"],
        ));
        let stores = build_from_policy(&policy, &dir).await.unwrap();

        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "attrfile");
        let attrs = stores[0]
            .get_attributes_for_actor(&[("device.zpr.adapter.cn".to_string(), "alice".to_string())])
            .await
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].get_key(), "user.color");
        assert!(attrs[0].value_has("red"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Invalid or unsupported declarations reject the policy atomically.
    #[tokio::test]
    async fn test_build_services_from_policy_rejects_bad_declarations() {
        let dir = std::env::temp_dir().join("vs-bsfp-bad");
        std::fs::create_dir_all(&dir).unwrap();

        let cases = [
            ("attrfile", "file", Some(3600)),
            ("attrfile", "ldap", Some(3600)),
            ("attrfile", "file", None),
            ("attrfile", "file", Some(1)),
            ("../escape", "file", Some(3600)),
        ];
        for (id, api, seconds) in cases {
            let policy = policy_from_container(make_trusted_service_policy(id, api, seconds, &[]));
            assert!(
                build_from_policy(&policy, &dir).await.is_err(),
                "expected failure for id={id} api={api} seconds={seconds:?}"
            );
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// zl-zipline#240: the bind address handed to `build_services` reaches the
    /// OIDC store's key source, so proxied JWKS fetches leave from `vs_addr`.
    #[tokio::test]
    async fn test_oidc_key_source_gets_jwks_bind_addr() {
        let dir = tempfile::tempdir().unwrap();
        let policy = policy_from_container(make_oidc_policy(
            "google",
            300,
            &["sub -> user.oidc-subject"],
            &["sub"],
            make_test_oidc_config(),
        ));
        let vs_addr: IpAddr = "fd5a:5052::1".parse().unwrap();
        let (_stores, oidc) = build_services(
            &trusted_service_definitions(&policy).unwrap(),
            dir.path(),
            dir.path(),
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            Some(vs_addr),
        )
        .await
        .unwrap();
        assert_eq!(oidc.len(), 1);
        assert_eq!(oidc[0].keys_arc().bind_addr(), Some(vs_addr));
    }

    /// An `api = "oidc"` declaration builds an OIDC trusted-service store (today the
    /// whole policy is rejected — the C4 acceptance case).
    #[tokio::test]
    async fn test_oidc_definition_builds_oidc_store() {
        let dir = std::env::temp_dir().join("vs-bsfp-oidc-ok");
        std::fs::create_dir_all(&dir).unwrap();

        let policy = policy_from_container(make_oidc_policy(
            "google",
            300,
            &["sub -> user.oidc-subject", "email -> user.email"],
            &["sub"],
            make_test_oidc_config(),
        ));
        let stores = build_from_policy(&policy, &dir).await.unwrap();

        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "google");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two oidc declarations differing only in `OidcConfig.client_id` compare unequal,
    /// so a policy install rebuilds the store (the definition carries the full record,
    /// including its oidc config).
    #[test]
    fn test_oidc_definition_change_rebuilds_store() {
        let make_defs = |client_id: &str| {
            let mut cfg = make_test_oidc_config();
            cfg.client_id = client_id.to_string();
            let policy = policy_from_container(make_oidc_policy(
                "google",
                300,
                &["sub -> user.oidc-subject"],
                &["sub"],
                cfg,
            ));
            trusted_service_definitions(&policy).unwrap()
        };

        let defs_a = make_defs("client-a.apps.googleusercontent.com");
        let defs_a_again = make_defs("client-a.apps.googleusercontent.com");
        let defs_b = make_defs("client-b.apps.googleusercontent.com");

        assert_eq!(
            defs_a, defs_a_again,
            "identical declarations must compare equal"
        );
        assert_ne!(
            defs_a, defs_b,
            "an oidc config change must break definition equality"
        );
    }

    /// Two oidc declarations for the SAME issuer are ambiguous (PR #5 review):
    /// which store validates a token would depend on unordered service
    /// iteration, so the policy is rejected with an error naming both services
    /// and the issuer — mirroring the compiler-side collision handling.
    #[test]
    fn test_duplicate_oidc_issuer_rejected() {
        use crate::test_helpers::{TrustedServiceSpec, make_trusted_services_policy};

        let spec = |id: &'static str| TrustedServiceSpec {
            id,
            api: "oidc",
            expiration_seconds: Some(300),
            mappings: &["sub -> user.oidc-subject"],
            identity: &["sub"],
            oidc: Some(make_test_oidc_config()), // same issuer both times
            attr_query: None,
        };
        let policy = policy_from_container(make_trusted_services_policy(&[
            spec("idp-a"),
            spec("idp-b"),
        ]));

        let err = match trusted_service_definitions(&policy) {
            Err(e) => e,
            Ok(_) => panic!("duplicate oidc issuers must be rejected"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("idp-a") && msg.contains("idp-b"), "{msg}");
        assert!(msg.contains("https://accounts.google.com"), "{msg}");
    }

    /// `api = "oidc"` with no oidc record in the TrustedService is a policy error.
    #[tokio::test]
    async fn test_oidc_definition_without_oidc_record_rejected() {
        let dir = std::env::temp_dir().join("vs-bsfp-oidc-norec");
        std::fs::create_dir_all(&dir).unwrap();

        // make_trusted_service_policy writes a TrustedService record with oidc: None.
        let policy = policy_from_container(make_trusted_service_policy(
            "google",
            "oidc",
            Some(300),
            &["sub -> user.oidc-subject"],
        ));
        let err = match build_from_policy(&policy, &dir).await {
            Err(e) => e,
            Ok(_) => panic!("oidc service without an oidc record must be rejected"),
        };
        assert!(matches!(err, ServiceError::Param(_)), "{err:?}");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod attr_query_tests {
    use super::*;
    use crate::test_helpers::{TrustedServiceSpec, make_trusted_services_policy};
    use crate::trusted_services::test_support::spawn_tls_attr_server;
    use zpr::policy_types::{AttrQueryConfig, PolicyContainerBytes};

    use crate::loaded_policy::LoadedPolicy;
    use crate::oidc::static_proxy;

    /// Decode a test policy container into its policy representation.
    fn policy_from_container(container_bytes: Vec<u8>) -> Arc<Policy> {
        let loaded = LoadedPolicy::from_container(
            PolicyContainerBytes::from(container_bytes),
            &crate::config::POLICY_MIN_VERSION,
        )
        .unwrap();
        loaded.policy()
    }

    /// A `zpr-attr/1` spec over `url`, with (`with_record`) or without its
    /// attr_query record.
    fn attr_spec<'a>(
        id: &'a str,
        url: &'a str,
        pem: &'a str,
        with_record: bool,
    ) -> TrustedServiceSpec<'a> {
        TrustedServiceSpec {
            id,
            api: "zpr-attr/1",
            expiration_seconds: Some(3600),
            mappings: &["color -> user.color"],
            identity: &[],
            oidc: None,
            attr_query: with_record.then(|| AttrQueryConfig {
                url: url.to_string(),
                ca_cert_pem: Some(pem.to_string()),
                timeout_seconds: 5,
            }),
        }
    }

    /// An `api = "zpr-attr/1"` declaration builds an AttrQueryStore through
    /// the factory, reading its token from ts_secrets_dir, and the built
    /// store answers a query against the mock.
    #[tokio::test]
    async fn test_attr_query_definition_builds_store() {
        let server = spawn_tls_attr_server(
            std::sync::Arc::new(|_req| {
                (
                    200,
                    r#"{"attributes": {"color": {"values": ["red"]}}}"#.to_string(),
                )
            }),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("attrs.token"), "tok").unwrap();

        let policy = policy_from_container(make_trusted_services_policy(&[attr_spec(
            "attrs",
            &server.url,
            &server.cert_pem,
            true,
        )]));
        let (stores, oidc) = build_services(
            &trusted_service_definitions(&policy).unwrap(),
            dir.path(),
            dir.path(),
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            None,
        )
        .await
        .unwrap();
        assert!(oidc.is_empty());
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].get_source_id(), "attrs");

        let attrs = stores[0]
            .get_attributes_for_actor(&[("user.sub".to_string(), "s-1".to_string())])
            .await
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].get_key(), "user.color");
    }

    /// `api = "zpr-attr/1"` without an attr_query record in the policy is
    /// rejected at definition time.
    #[test]
    fn test_attr_query_without_record_rejected() {
        let policy = policy_from_container(make_trusted_services_policy(&[attr_spec(
            "attrs",
            "https://example.invalid",
            "",
            false,
        )]));
        let err = trusted_service_definitions(&policy).unwrap_err();
        assert!(matches!(err, ServiceError::Param(_)), "{err:?}");
        assert!(format!("{err}").contains("attr_query"), "{err}");
    }

    /// The id resolves `<id>.token` on disk, so a path-shaped id is rejected.
    #[test]
    fn test_attr_query_id_must_be_plain_filename() {
        for id in ["../escape", "a/b"] {
            let policy = policy_from_container(make_trusted_services_policy(&[attr_spec(
                id,
                "https://example.invalid",
                "",
                true,
            )]));
            let err = trusted_service_definitions(&policy).unwrap_err();
            assert!(matches!(err, ServiceError::Param(_)), "id={id}: {err:?}");
        }
    }

    /// Two declarations naming the SAME url under different ids are legal —
    /// the delegation shape — so definitions must NOT reject the pair (unlike
    /// the OIDC duplicate-issuer rule), and both stores build with their own
    /// tokens.
    #[tokio::test]
    async fn test_two_ids_one_url_is_legal_delegation() {
        let server = spawn_tls_attr_server(
            std::sync::Arc::new(|_req| (200, r#"{"attributes": {}}"#.to_string())),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("parent.token"), "pt").unwrap();
        std::fs::write(dir.path().join("delegate.token"), "dt").unwrap();

        let policy = policy_from_container(make_trusted_services_policy(&[
            attr_spec("parent", &server.url, &server.cert_pem, true),
            attr_spec("delegate", &server.url, &server.cert_pem, true),
        ]));
        let definitions = trusted_service_definitions(&policy).unwrap();
        assert_eq!(definitions.len(), 2);
        let (stores, _oidc) = build_services(
            &definitions,
            dir.path(),
            dir.path(),
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            None,
        )
        .await
        .unwrap();
        assert_eq!(stores.len(), 2);
    }

    /// A missing token file fails the whole build (and thereby the install).
    #[tokio::test]
    async fn test_missing_token_fails_build() {
        let server = spawn_tls_attr_server(
            std::sync::Arc::new(|_req| (200, r#"{"attributes": {}}"#.to_string())),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap(); // no attrs.token

        let policy = policy_from_container(make_trusted_services_policy(&[attr_spec(
            "attrs",
            &server.url,
            &server.cert_pem,
            true,
        )]));
        let result = build_services(
            &trusted_service_definitions(&policy).unwrap(),
            dir.path(),
            dir.path(),
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            None,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a missing token file must fail the build"),
        };
        assert!(
            matches!(err, ServiceError::TrustedServiceInit(_)),
            "{err:?}"
        );
    }

    /// A schema endpoint that does not exist never fails the build: the
    /// check is advisory (the mock 404s /schema here, and the build - which
    /// runs the check - still succeeds).
    #[tokio::test]
    async fn test_schema_endpoint_absent_install_succeeds() {
        let server = spawn_tls_attr_server(
            std::sync::Arc::new(|req| {
                if req.path == "/schema" {
                    (404, "no schema here".to_string())
                } else {
                    (200, r#"{"attributes": {}}"#.to_string())
                }
            }),
            None,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("attrs.token"), "tok").unwrap();

        let policy = policy_from_container(make_trusted_services_policy(&[attr_spec(
            "attrs",
            &server.url,
            &server.cert_pem,
            true,
        )]));
        let (stores, _oidc) = build_services(
            &trusted_service_definitions(&policy).unwrap(),
            dir.path(),
            dir.path(),
            &policy.lookup_identity_keys(),
            &|_id| static_proxy(None),
            None,
        )
        .await
        .unwrap();
        assert_eq!(stores.len(), 1);
    }
}
