//! To make unit testing easier.

#![cfg(test)]

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, AttributeSource, ROLE_ADAPTER, ROLE_NODE, key};
use libeval::eval_result::{Direction, Hit};
use libeval::policy::Policy;
use libeval::route::{LinkId, Route};

use zpr::policy::v1 as capnp_policy;
use zpr::policy_types::{
    AttrExp, JoinPolicy, NetAddr, OidcConfig, PFlags, Peering, Scope, Service, ServiceType,
    TrustedService, parse_attribute_mapping,
};
use zpr::vsapi_types::{DockPepType, EndpointT, KeySet, PacketDesc, TcpUdpPep, Visa};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::assembly::tests::new_assembly_for_tests;
use crate::error::{ResolverError, ServiceError};
use crate::policy_mgr::DnsResolver;

const DEFAULT_EXPIRES: Duration = Duration::from_secs(3600);

/// Build an [Actor] with the provided attributes and a single expiration applied to all.
pub fn make_actor(attrs: &[(&str, &str)], expires: Duration) -> Actor {
    let mut actor = Actor::new();
    for (attr_key, attr_value) in attrs {
        actor
            .add_attribute(
                Attribute::builder(*attr_key)
                    .expires_in(expires)
                    .value(*attr_value),
            )
            .unwrap();
    }
    actor
}

/// Build an [Actor] with the provided attributes using the default expiration.
pub fn make_actor_defexp(attrs: &[(&str, &str)]) -> Actor {
    make_actor(attrs, DEFAULT_EXPIRES)
}

/// Build a node [Actor] with role, CN, ZPR addr and substrate addr.
/// Note: `substrate` must be a socket address string (e.g. `HOST:PORT` or `[IPv6]:PORT`).
pub fn make_node_actor(zpr_addr: &str, cn: &str, substrate: &str, expires: Duration) -> Actor {
    make_actor(
        &[
            (key::ROLE, ROLE_NODE),
            (key::CN, cn),
            (key::ZPR_ADDR, zpr_addr),
            (key::SUBSTRATE_ADDR, substrate),
        ],
        expires,
    )
}

/// Build a node [Actor] using the default expiration.
/// Note: `substrate` must be a socket address string (e.g. `HOST:PORT` or `[IPv6]:PORT`).
pub fn make_node_actor_defexp(zpr_addr: &str, cn: &str, substrate: &str) -> Actor {
    make_node_actor(zpr_addr, cn, substrate, DEFAULT_EXPIRES)
}

/// Build an adapter [Actor] with role, CN, and ZPR addr.
pub fn make_adapter_actor(zpr_addr: &str, cn: &str, expires: Duration) -> Actor {
    make_actor(
        &[
            (key::ROLE, ROLE_ADAPTER),
            (key::CN, cn),
            (key::ZPR_ADDR, zpr_addr),
        ],
        expires,
    )
}

/// Build an adapter [Actor] using the default expiration.
pub fn make_adapter_actor_defexp(zpr_addr: &str, cn: &str) -> Actor {
    make_adapter_actor(zpr_addr, cn, DEFAULT_EXPIRES)
}

/// Build a CN-less adapter [Actor], shaped like the real OIDC-only connect case:
/// adapter role, a ZPR address, a `user.*` identity attribute — and **no `cn`
/// attribute**. This is what a bootstrap-key-less adapter looks like after an
/// OIDC-only connect: see `test_oidc_only_connect_without_cn_claim_authorizes`
/// (vs/src/connection_control.rs), which asserts
/// `actor.get_attribute(key::CN).is_none()` for exactly this shape.
///
/// Shared fixture for the zipline#29 CN-keyed-surface work (zipline#30/#31/...).
pub fn make_oidc_only_adapter_defexp(zpr_addr: &str) -> Actor {
    let actor = make_actor(
        &[
            (key::ROLE, ROLE_ADAPTER),
            (key::ZPR_ADDR, zpr_addr),
            ("user.oidc-subject", "oidc-user@example.com"),
        ],
        DEFAULT_EXPIRES,
    );
    debug_assert!(actor.get_attribute(key::CN).is_none());
    actor
}

/// Build an [Actor] with role/CN/ZPR addr plus services and an identity attribute.
pub fn make_actor_with_services(
    role: &str,
    zpr_addr: &str,
    services: &[&str],
    cn: &str,
    expires: Duration,
) -> Actor {
    let mut actor = make_actor(
        &[(key::ROLE, role), (key::CN, cn), (key::ZPR_ADDR, zpr_addr)],
        expires,
    );
    actor
        .add_attribute(
            Attribute::builder(key::SERVICES)
                .expires_in(expires)
                .values(services.iter().copied()),
        )
        .unwrap();
    actor
        .add_attribute(
            Attribute::builder("identity.foo")
                .expires_in(expires)
                .value("id-1"),
        )
        .unwrap();
    actor.add_identity_key(usize::MAX, "identity.foo").unwrap();
    actor
}

/// Build an [Actor] with services using the default expiration.
pub fn make_actor_with_services_defexp(
    role: &str,
    zpr_addr: &str,
    services: &[&str],
    cn: &str,
) -> Actor {
    make_actor_with_services(role, zpr_addr, services, cn, DEFAULT_EXPIRES)
}

/// A DNS resolver for tests. IP-only peerings short-circuit before calling this,
/// so an empty map suffices for tests that use only IP-addressed peers.
/// Populate the map to test hostname-resolution paths.
pub struct FakeResolver {
    entries: HashMap<(String, u16), SocketAddr>,
}

impl FakeResolver {
    pub fn new(entries: HashMap<(String, u16), SocketAddr>) -> Self {
        FakeResolver { entries }
    }

    /// A resolver with no hostname entries — suitable for tests that only use IP peers.
    pub fn ip_only() -> Self {
        FakeResolver::new(HashMap::new())
    }
}

#[async_trait]
impl DnsResolver for FakeResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ResolverError> {
        self.entries
            .get(&(host.to_string(), port))
            .copied()
            .ok_or_else(|| ResolverError::NoAddresses(host.to_string()))
    }
}

/// Build a [Visa] with the provided ID and expiry offset.
pub fn make_visa(visa_id: u64, expires_in: Duration) -> Visa {
    Visa::new(
        visa_id,
        0,
        SystemTime::now() + expires_in,
        "fd5a:5052::10".parse().unwrap(),
        "fd5a:5052::20".parse().unwrap(),
        DockPepType::TCP(TcpUdpPep::new(1234, 443, EndpointT::Server)),
        KeySet::new(b"ingress", b"egress"),
        None,
    )
}

/// Build a dummy TCP [PacketDesc] for tests that need a five-tuple but don't
/// care about its contents.
pub fn make_pdesc() -> PacketDesc {
    PacketDesc::new_tcp("fd5a:5052::10", "fd5a:5052::20", 1234, 443).unwrap()
}

/// Build a policy container declaring one trusted service: a join policy providing a
/// `ServiceType::Trusted(api)` service named `id`, plus (when `expiration_seconds` is
/// `Some`) the matching `TrustedService` record carrying `mappings`.
///
/// Build a [Policy] holding a single communication policy whose client and service
/// condition lists carry the given attribute keys (values/ops are left unset -- only the
/// keys matter to callers that look up condition keys). Pass empty slices for a com policy
/// with no conditions on that side.
pub fn make_policy_with_com_conditions(client_keys: &[&str], service_keys: &[&str]) -> Policy {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        let mut coms = policy_bldr.reborrow().init_com_policies(1);
        let mut com = coms.reborrow().get(0);
        let mut client = com.reborrow().init_client_conds(client_keys.len() as u32);
        for (i, k) in client_keys.iter().enumerate() {
            client.reborrow().get(i as u32).set_key(k);
        }
        let mut service = com.reborrow().init_service_conds(service_keys.len() as u32);
        for (i, k) in service_keys.iter().enumerate() {
            service.reborrow().get(i as u32).set_key(k);
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
}

/// Pass `None` for `expiration_seconds` to get the "service declared but no record"
/// case. Each entry of `mappings` is a `"<service key> -> <attr spec>"` string.
pub fn make_trusted_service_policy(
    id: &str,
    api: &str,
    expiration_seconds: Option<u32>,
    mappings: &[&str],
) -> Vec<u8> {
    make_trusted_service_policy_with_identity(id, api, expiration_seconds, mappings, &[])
}

/// As [make_trusted_service_policy], but also declaring the given service-side
/// attribute names as identity attributes (they resolve through `mappings` to their
/// ZPR keys, feeding `Policy::identity_attr_keys` / `lookup_identity_keys`).
pub fn make_trusted_service_policy_with_identity(
    id: &str,
    api: &str,
    expiration_seconds: Option<u32>,
    mappings: &[&str],
    identity: &[&str],
) -> Vec<u8> {
    make_trusted_service_policy_full(id, api, expiration_seconds, mappings, identity, None)
}

/// An [OidcConfig] with plausible Google-shaped values, seeded with the C2/C3
/// fixture JWKS so a [crate::oidc::KeySource] built from it always has a key.
pub fn make_test_oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "https://accounts.google.com".to_string(),
        jwks_uri: String::new(),
        client_id: "test-client-id.apps.googleusercontent.com".to_string(),
        client_secret: None,
        scopes: vec!["openid".to_string(), "email".to_string()],
        allowed_domains: vec!["*".to_string()],
        max_auth_age_seconds: 0,
        allow_offline_access: false,
        seed_jwks: include_str!("../tests/data/oidc-test-jwks.json").to_string(),
        jwks_proxy_service: None,
    }
}

/// Build a policy container declaring one `api = "oidc"` trusted service: the
/// `ServiceType::Trusted("oidc")` service plus its `TrustedService` record carrying
/// `oidc`. Same builder path as [make_trusted_service_policy_with_identity].
pub fn make_oidc_policy(
    id: &str,
    expiration_seconds: u32,
    mappings: &[&str],
    identity: &[&str],
    oidc: OidcConfig,
) -> Vec<u8> {
    make_trusted_service_policy_full(
        id,
        "oidc",
        Some(expiration_seconds),
        mappings,
        identity,
        Some(oidc),
    )
}

/// As [make_oidc_policy], but with full control over the connect-path shape
/// (zipline#11 C5 tests): `bootstrap` adds policy bootstrap keys (CN, RSA
/// public key DER) so an SS blob can validate alongside the OIDC blob, and
/// `join_conditions` puts `(key, value)` match conditions on the single join
/// policy providing the trusted service — conditions the actor does not meet
/// give the "valid login, no join policy matched" case.
pub fn make_oidc_connect_policy(
    id: &str,
    expiration_seconds: u32,
    mappings: &[&str],
    identity: &[&str],
    oidc: OidcConfig,
    bootstrap: &[(&str, &[u8])],
    join_conditions: &[(&str, &str)],
) -> Vec<u8> {
    let jp = JoinPolicy {
        conditions: join_conditions
            .iter()
            .map(|(k, v)| {
                zpr::policy_types::Attribute::tuple(*k)
                    .value(*v)
                    .build()
                    .unwrap()
            })
            .collect(),
        flags: PFlags::default(),
        provides: Some(vec![Service {
            id: id.to_string(),
            endpoints: Vec::new(),
            kind: ServiceType::Trusted("oidc".to_string()),
        }]),
    };
    let record = TrustedService {
        service_id: id.to_string(),
        expiration_seconds,
        returns_attrs: mappings
            .iter()
            .map(|m| parse_attribute_mapping(m).unwrap())
            .collect(),
        identity_attrs: identity.iter().map(|s| s.to_string()).collect(),
        oidc: Some(oidc),
        attr_query: None,
    };

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        if !bootstrap.is_empty() {
            let mut keys = policy_bldr.reborrow().init_keys(bootstrap.len() as u32);
            for (i, (cn, der)) in bootstrap.iter().enumerate() {
                let mut key_bldr = keys.reborrow().get(i as u32);
                key_bldr.set_id(cn);
                key_bldr.set_key_type(capnp_policy::KeyMaterialT::RsaPub);
                key_bldr
                    .reborrow()
                    .init_key_allows(1)
                    .set(0, capnp_policy::KeyAllowance::Bootstrap);
                key_bldr.set_key_data(der);
            }
        }
        jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));
        let mut ts_bldr = policy_bldr.reborrow().init_trusted_services(1);
        record.write_to(&mut ts_bldr.reborrow().get(0));
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// The common builder behind the trusted-service policy helpers.
fn make_trusted_service_policy_full(
    id: &str,
    api: &str,
    expiration_seconds: Option<u32>,
    mappings: &[&str],
    identity: &[&str],
    oidc: Option<OidcConfig>,
) -> Vec<u8> {
    make_trusted_services_policy(&[TrustedServiceSpec {
        id,
        api,
        expiration_seconds,
        mappings,
        identity,
        oidc,
        attr_query: None,
    }])
}

/// One trusted-service declaration for [make_trusted_services_policy].
pub struct TrustedServiceSpec<'a> {
    pub id: &'a str,
    pub api: &'a str,
    /// `None` gives the "service declared but no record" case.
    pub expiration_seconds: Option<u32>,
    pub mappings: &'a [&'a str],
    pub identity: &'a [&'a str],
    pub oidc: Option<OidcConfig>,
    /// `Some` gives an `api = "zpr-attr/1"` declaration its pinned config record.
    pub attr_query: Option<zpr::policy_types::AttrQueryConfig>,
}

/// Build a policy container declaring several trusted services at once: one join
/// policy providing every `ServiceType::Trusted(api)` service, plus a
/// `TrustedService` record per spec carrying an `expiration_seconds`.
pub fn make_trusted_services_policy(specs: &[TrustedServiceSpec]) -> Vec<u8> {
    let services: Vec<Service> = specs
        .iter()
        .map(|spec| Service {
            id: spec.id.to_string(),
            endpoints: Vec::new(),
            kind: ServiceType::Trusted(spec.api.to_string()),
        })
        .collect();
    let jp = JoinPolicy {
        conditions: Vec::new(),
        flags: PFlags::default(),
        provides: Some(services),
    };

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));

        let records: Vec<TrustedService> = specs
            .iter()
            .filter_map(|spec| {
                spec.expiration_seconds.map(|secs| TrustedService {
                    service_id: spec.id.to_string(),
                    expiration_seconds: secs,
                    returns_attrs: spec
                        .mappings
                        .iter()
                        .map(|m| parse_attribute_mapping(m).unwrap())
                        .collect(),
                    identity_attrs: spec.identity.iter().map(|s| s.to_string()).collect(),
                    oidc: spec.oidc.clone(),
                    attr_query: spec.attr_query.clone(),
                })
            })
            .collect();
        if !records.is_empty() {
            let mut ts_bldr = policy_bldr
                .reborrow()
                .init_trusted_services(records.len() as u32);
            for (i, record) in records.iter().enumerate() {
                record.write_to(&mut ts_bldr.reborrow().get(i as u32));
            }
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build a policy container declaring one `api = "oidc"` trusted service whose
/// join policy also carries a jwks-proxy service: the OIDC service (endpoints
/// empty, as compiled policy has for an off-net provider) plus a
/// `ServiceType::Regular` proxy service with a single port scope — the shape
/// the ActorDb-backed proxy resolver reads its port from.
pub fn make_oidc_policy_with_proxy_service(
    id: &str,
    oidc: OidcConfig,
    proxy_service_id: &str,
    proxy_port: u16,
) -> Vec<u8> {
    let services = vec![
        Service {
            id: id.to_string(),
            endpoints: Vec::new(),
            kind: ServiceType::Trusted("oidc".to_string()),
        },
        Service {
            id: proxy_service_id.to_string(),
            endpoints: vec![Scope {
                protocol: 6, // TCP
                flag: None,
                port: Some(proxy_port),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        },
    ];
    let jp = JoinPolicy {
        conditions: Vec::new(),
        flags: PFlags::default(),
        provides: Some(services),
    };
    let record = TrustedService {
        service_id: id.to_string(),
        expiration_seconds: 300,
        returns_attrs: vec![parse_attribute_mapping("sub -> user.oidc-subject").unwrap()],
        identity_attrs: vec!["sub".to_string()],
        oidc: Some(oidc),
        attr_query: None,
    };

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));
        let mut ts_bldr = policy_bldr.reborrow().init_trusted_services(1);
        record.write_to(&mut ts_bldr.reborrow().get(0));
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build a policy container with one ALLOW communication policy for `service_id`
/// on TCP `port`, with no client/service/link conditions. The minimal policy that
/// drives the visa request pipeline to an Allow: the provider actor must carry
/// `service_id` in its [key::SERVICES] attribute, and the flow's dest port must
/// be `port` (zipline#167 regression test).
pub fn make_allow_policy_for_tcp_service(service_id: &str, port: u16) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        let mut coms = policy_bldr.reborrow().init_com_policies(1);
        let mut com = coms.reborrow().get(0);
        com.set_allow(true);
        com.set_service_id(service_id);
        let mut scopes = com.reborrow().init_scope(1);
        let mut scope = scopes.reborrow().get(0);
        scope.set_protocol(6); // TCP
        scope.init_port().set_port_num(port);
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build a policy container in which `service_id` (TCP `port`) is hosted by any
/// actor whose `host_key` attribute equals `host_value`, and anyone may access it:
/// one join policy granting the service on that condition, plus one unconditional
/// ALLOW communication policy for it. The ZPL equivalent is
/// `define <service_id> as a service with <host_key>:'<host_value>'.` followed by
/// `allow devices to access <service_id>.` (zipline#181). `flags` are the join
/// policy's flags, e.g. [PFlags::node] for a service only nodes may host.
pub fn make_attr_hosted_service_policy(
    service_id: &str,
    port: u16,
    host_key: &str,
    host_value: &str,
    flags: PFlags,
) -> Vec<u8> {
    let jp = JoinPolicy {
        conditions: vec![
            zpr::policy_types::Attribute::tuple(host_key)
                .value(host_value)
                .build()
                .unwrap(),
        ],
        flags,
        provides: Some(vec![Service {
            id: service_id.to_string(),
            endpoints: vec![Scope {
                protocol: 6, // TCP
                flag: None,
                port: Some(port),
                port_range: None,
            }],
            kind: ServiceType::Regular,
        }]),
    };

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy_bldr = msg.init_root::<capnp_policy::policy::Builder>();
        policy_bldr.set_created("2024-01-01T00:00:00Z");
        policy_bldr.set_version(1);
        policy_bldr.set_metadata("");
        jp.write_to(&mut policy_bldr.reborrow().init_join_policies(1).get(0));
        let mut coms = policy_bldr.reborrow().init_com_policies(1);
        let mut com = coms.reborrow().get(0);
        com.set_allow(true);
        com.set_service_id(service_id);
        let mut scopes = com.reborrow().init_scope(1);
        let mut scope = scopes.reborrow().get(0);
        scope.set_protocol(6); // TCP
        scope.init_port().set_port_num(port);
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build a `Peering` between two ZPR addresses, each reachable at its own address as
/// substrate so a `FakeResolver::ip_only()` resolves it. `describe_link(node_a, node_b)`
/// on the resulting policy finds this link.
pub fn make_peering(node_a: IpAddr, node_b: IpAddr, link_id: &str, attrs: Vec<AttrExp>) -> Peering {
    Peering {
        link_id: link_id.to_string(),
        node_a,
        substrate_a: Some(NetAddr::new_for_ip_or_host(&node_a.to_string(), 0)),
        node_b,
        substrate_b: Some(NetAddr::new_for_ip_or_host(&node_b.to_string(), 0)),
        attributes: attrs,
    }
}

/// Build the container bytes of a policy whose topology is the given peerings
/// (an empty slice gives a valid policy with no topology).
pub fn policy_with_peerings(peerings: &[Peering]) -> Vec<u8> {
    policy_with_peerings_and_node_cns(peerings, &[])
}

/// As [policy_with_peerings], plus one node join policy per `(zpr_addr, cn)`, in the shape
/// the compiler emits for a node: match `device.zpr.adapter.cn eq <cn>` and
/// `zpr.addr eq <zpr_addr>`, flagged `node`. This is what `Policy::node_cn_for_addr` reads.
pub fn policy_with_peerings_and_node_cns(
    peerings: &[Peering],
    node_cns: &[(IpAddr, &str)],
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy = msg.init_root::<capnp_policy::policy::Builder>();
        policy.reborrow().set_created("1970-01-01T00:00:00Z");
        if !peerings.is_empty() {
            let mut topo = policy.reborrow().init_topology(peerings.len() as u32);
            for (i, p) in peerings.iter().enumerate() {
                p.write_to(&mut topo.reborrow().get(i as u32));
            }
        }
        if !node_cns.is_empty() {
            let mut jps = policy.reborrow().init_join_policies(node_cns.len() as u32);
            for (i, (addr, cn)) in node_cns.iter().enumerate() {
                let mut jp = jps.reborrow().get(i as u32);
                {
                    let mut matches = jp.reborrow().init_match(2);
                    let mut cn_cond = matches.reborrow().get(0);
                    cn_cond.set_key(key::CN);
                    cn_cond.set_op(capnp_policy::AttrOp::Eq);
                    cn_cond.init_value(1).set(0, cn);
                    let mut addr_cond = matches.reborrow().get(1);
                    addr_cond.set_key(key::ZPR_ADDR);
                    addr_cond.set_op(capnp_policy::AttrOp::Eq);
                    addr_cond.init_value(1).set(0, addr.to_string());
                }
                jp.init_flags(1).set(0, capnp_policy::JoinFlag::Node);
            }
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    make_container_bytes(
        crate::config::POLICY_MIN_COMPILER_MAJOR,
        crate::config::POLICY_MIN_COMPILER_MINOR,
        crate::config::POLICY_MIN_COMPILER_PATCH,
        &bytes,
    )
}

/// Build the Cap'n Proto encoded bytes of a `PolicyContainer` with the given
/// compiler version and (arbitrary) policy payload, for use as test input.
pub fn make_container_bytes(maj: u32, min: u32, patch: u32, policy: &[u8]) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    {
        let mut container = msg.init_root::<capnp_policy::policy_container::Builder>();
        container.set_zplc_ver_major(maj);
        container.set_zplc_ver_minor(min);
        container.set_zplc_ver_patch(patch);
        container.set_policy(policy);
        container.set_signature(&[]);
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &msg).unwrap();
    buf
}

// ---- visa-sweep fixtures ----
// Shared by `visa_reconciler` (the sweep itself) and `event_mgr` (the handlers that
// drive it), so they live here rather than in either module's test block.

/// Build an assembly with two docked adapters (`::4000::a`/`::4000::b`) whose
/// nodes are in the topology. `with_link` controls whether a route exists.
/// The default (empty) policy denies everything (NoMatch), so with a route
/// present the eval still denies — either way the sweep sees a deny.
pub async fn build_sweep_asm(with_link: bool) -> (Arc<Assembly>, IpAddr) {
    let asm = new_assembly_for_tests(None).await;
    let node_a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
    let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
    asm.actor_mgr
        .add_node(
            &make_node_actor_defexp("fd5a:5052:3000::1", "na", "10.0.0.1:1"),
            false,
            &Default::default(),
        )
        .await
        .unwrap();
    asm.actor_mgr
        .add_node(
            &make_node_actor_defexp("fd5a:5052:3000::2", "nb", "10.0.0.2:2"),
            false,
            &Default::default(),
        )
        .await
        .unwrap();
    asm.topo_mgr.add_node(node_a).unwrap();
    asm.topo_mgr.add_node(node_b).unwrap();
    if with_link {
        asm.topo_mgr
            .add_link(node_a, node_b, LinkId("l".into()), vec![], 1)
            .unwrap();
    }
    asm.actor_mgr
        .add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052:4000::a", "src"),
            &node_a,
            &Default::default(),
        )
        .await
        .unwrap();
    asm.actor_mgr
        .add_adapter_via_node(
            &make_adapter_actor_defexp("fd5a:5052:4000::b", "dst"),
            &node_b,
            &Default::default(),
        )
        .await
        .unwrap();
    (Arc::new(asm), node_a)
}

/// Create a single-node visa held (PendingInstall) by `req` for the given
/// five-tuple, seeded at `vinst`. Returns its id. Its path is `req` alone, so a
/// sweep on the linked assembly sees the route move and revokes it; use
/// [create_routed_sweep_visa] for a visa the sweep can keep.
pub async fn create_sweep_visa(asm: &Arc<Assembly>, req: &IpAddr, vinst: u64) -> u64 {
    create_sweep_visa_on_route(asm, req, vinst, &Route::new_direct((*req).into())).await
}

/// As [create_sweep_visa], but on the best route between the two sweep nodes, which
/// is the route a re-check computes. Needs the linked assembly
/// (`build_sweep_asm(true)`).
pub async fn create_routed_sweep_visa(asm: &Arc<Assembly>, req: &IpAddr, vinst: u64) -> u64 {
    let node_a: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
    let node_b: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
    let route = asm
        .topo_mgr
        .get_best_route(&node_a, &node_b)
        .expect("sweep nodes must be linked");
    create_sweep_visa_on_route(asm, req, vinst, &route).await
}

/// Create the sweep visa (`::4000::a` -> `::4000::b`, TCP 80) held by `req` on
/// `route`, seeded at `vinst`. Returns its id.
async fn create_sweep_visa_on_route(
    asm: &Arc<Assembly>,
    req: &IpAddr,
    vinst: u64,
    route: &Route,
) -> u64 {
    let pdesc = PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 80).unwrap();
    let hit = Hit::new_no_signal(0, Direction::Forward);
    let vwmd = asm
        .visa_mgr
        .create_visa(
            asm,
            req,
            &pdesc,
            &hit,
            route,
            "",
            0,
            vinst,
            SystemTime::now() + DEFAULT_EXPIRES,
        )
        .await
        .unwrap();
    vwmd.visa.issuer_id
}

// ---- attribute-change sweep ----

pub const TS_SOURCE: &str = "hr";
pub const TS_KEY: &str = "user.dept";

/// A trusted service whose vended attributes, revision, and failure mode are all
/// settable, so a test can simulate "the external data changed" and "the service is
/// down".
pub struct MutableTrustedService {
    /// (key, value) pairs to vend; empty means the actor has no attributes here.
    pub attrs: std::sync::Mutex<Vec<(String, String)>>,
    pub fail: std::sync::atomic::AtomicBool,
    pub revision: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl crate::trusted_services::TrustedServiceInterface for MutableTrustedService {
    async fn get_attributes_for_actor(
        &self,
        _identities: &[(String, String)],
    ) -> Result<Vec<Attribute>, ServiceError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ServiceError::TrustedServiceInit("down".into()));
        }
        Ok(self
            .attrs
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                AttributeSource::new(TS_SOURCE)
                    .builder(k)
                    .expires_in(Duration::from_secs(600))
                    .value(v)
            })
            .collect())
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
        TS_SOURCE
    }
}

/// Register one [MutableTrustedService] vending `attrs` on the assembly, and return
/// it so the test can change its data or knock it over.
pub fn register_ts(asm: &Arc<Assembly>, attrs: &[(&str, &str)]) -> Arc<MutableTrustedService> {
    let svc = Arc::new(MutableTrustedService {
        attrs: std::sync::Mutex::new(
            attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ),
        fail: std::sync::atomic::AtomicBool::new(false),
        revision: std::sync::atomic::AtomicU64::new(1),
    });
    asm.ts_mgr.update_services(vec![svc.clone()]);
    svc
}

/// Give the stored actor at `zpr_addr` an attribute from [TS_SOURCE], standing in for
/// data the actor picked up from that source under the previous snapshot.
pub async fn seed_source_attr(asm: &Arc<Assembly>, zpr_addr: &str, ts_key: &str, value: &str) {
    let addr: IpAddr = zpr_addr.parse().unwrap();
    let mut actor = asm
        .actor_mgr
        .get_actor_by_zpr_addr(&addr)
        .await
        .unwrap()
        .unwrap();
    actor
        .add_attribute(
            AttributeSource::new(TS_SOURCE)
                .builder(ts_key)
                .expires_in(Duration::from_secs(600))
                .value(value),
        )
        .unwrap();
    asm.actor_mgr
        .update_actor(&actor, &Default::default())
        .await
        .unwrap();
}

/// The stored actor's attribute values for `key`, if any.
pub async fn stored_attr(asm: &Arc<Assembly>, zpr_addr: &str, attr_key: &str) -> Option<String> {
    let addr: IpAddr = zpr_addr.parse().unwrap();
    let actor = asm
        .actor_mgr
        .get_actor_by_zpr_addr(&addr)
        .await
        .unwrap()
        .unwrap();
    actor
        .attrs_iter()
        .find(|a| a.get_key() == attr_key)
        .map(|a| a.get_value_as_string())
}
