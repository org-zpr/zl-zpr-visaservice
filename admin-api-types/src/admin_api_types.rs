use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::{TimestampSeconds, serde_as};

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

/// List entry is a list with a numeric ID.
#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub id: u64,
}

/// NamedListEntry is a list with a string ID.
#[derive(Serialize, Deserialize)]
pub struct NamedListEntry {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VisaMatchDirection {
    Forward,
    Reverse,
}

#[serde_as]
#[derive(Serialize, Debug, Deserialize, Eq)]
pub struct VisaDescriptor {
    /// Policy reported version number
    pub id: u64,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub expires: SystemTime,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub created: SystemTime,
    pub policy_id: String,
    pub zpl: String,
    pub direction: VisaMatchDirection,
    pub requesting_node: String,     // ZPR address
    pub source_addr: Option<String>, // ZPR address
    pub dest_addr: Option<String>,   // ZPR address
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub proto: String,
    pub signals: Vec<String>,
    pub session_key: ApiKeySet,
}

impl PartialEq for VisaDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Ord for VisaDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for VisaDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Intentionally match the zpr::vsapi_types KeySet and KeyFormat, but
/// reproduced here to prevent coupling of the API types from the internal types
/// Note these keys are encrypted.
#[serde_as]
#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ApiKeySet {
    pub format: ApiKeyFormat,
    /// session key encrypted for ingress node to read
    #[serde_as(as = "Base64")]
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    #[serde_as(as = "Base64")]
    pub egress_key: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ApiKeyFormat {
    #[default]
    ZprKF01,
}

#[derive(Serialize, Deserialize)]
pub struct Revokes {
    pub id: String,
    pub revoked: Vec<u64>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq)]
pub struct ActorDescriptor {
    /// Display label; may be absent (e.g. an OIDC-only connect). Never an identity.
    pub cn: Option<String>,
    #[serde(rename = "created")]
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub ctime: SystemTime,
    pub ident: String,
    pub node: bool,
    /// The ZPR address: the identity of an actor on the admin API.
    pub zpr_addr: String,
    pub attrs: Vec<ApiAttribute>,
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub auth_exp: Option<SystemTime>,
    pub node_details: Option<NodeRecordBrief>,
    /// Hostname values this actor claimed that were refused because another actor
    /// or a policy service already held them. Empty in the normal case (zipline#54).
    /// Display data only; `#[serde(default)]` keeps pre-#54 payloads parseable.
    #[serde(default)]
    pub hostname_conflicts: Vec<String>,
}

// Wire-side actor identity is the ZPR address, not the CN: CNs may be shared or
// absent, so keying equality/order on them would collapse CN-less actors into one
// equivalence class.
impl PartialEq for ActorDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.zpr_addr == other.zpr_addr
    }
}

impl Ord for ActorDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.zpr_addr.cmp(&other.zpr_addr)
    }
}

impl PartialOrd for ActorDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ApiAttribute {
    pub key: String,
    pub value: Vec<String>,
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub expires_at: SystemTime,
}

/// One resolvable hostname from the `host:<NAME>` claim index (zipline#54).
/// Returned by `GET /admin/hosts/{name}`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct HostDescriptor {
    pub hostname: String,
    /// ZPR address of the actor holding the name.
    pub zpr_addr: String,
    /// Display label of the owning actor; may be empty.
    pub actor_cn: String,
}

#[derive(Serialize, Deserialize, Debug, Eq)]
pub struct ServiceDescriptor {
    pub service_name: String,
    pub actor_cn: String,
    pub zpr_addr: String,
    pub dock_zpr_addr: String,
    pub service_kind: String,
    pub service_endpoints: String,
}

impl PartialEq for ServiceDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.service_name == other.service_name
    }
}

impl Ord for ServiceDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.service_name.cmp(&other.service_name)
    }
}

impl PartialOrd for ServiceDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecordBrief {
    // Number of visas pending install on the node
    pub pending_install: u32,
    // Last time the visa service heard from the node, in either direction;
    // None if there was no contact. Updated when the node joins
    // (`ActorMgr::add_node`), on every inbound vsapi call from the node
    // (`register_vss`, `authorize_connect`, `reauthorize`, `visa_request`,
    // `ping`, `visa_ids_request`, `visa_request_by_id` in `vsapi_worker.rs`;
    // the node pings every 5 s), and on each successful outbound VSS ping
    // (`vss_worker.rs`).
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub last_contact: Option<SystemTime>,
    // Number of visa requests on the node
    pub visa_requests: u64,
    // Number of calls to authorize_connect by the node
    pub connect_requests: u64,
    // True if a live VSS worker exists for the node in the visa service
    // (`VssMgr::has_live_worker`); false once the worker has exited. A worker
    // still in its start delay (3 s) or still connecting counts as running.
    // A node with a live vsapi session gets a new worker on its next ping
    // (~5 s), so a `false` that lasts longer than that means the VS has no
    // live VSS worker and cannot push to the node's VSS (e.g. the VSS
    // listener refuses the connect, so each new worker exits at once). It
    // does not show that the node is unreachable: use `last_contact` for
    // that. Does not consider pending installs or revocations.
    pub in_sync: bool,
    // Approved visa requests
    pub approved_vreqs: u64,
    // Denied visa requests
    pub denied_vreqs: u64,
    // Time of last visa request, None if there was no request
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub last_vreq: Option<SystemTime>,
    // ZPR addresses of all adapters connected to the node
    pub adapters: Vec<String>,
    // ZPR addresses of all other nodes connected to the node
    pub links: Vec<String>,
    // IDs of all visas installed on the node
    pub visas: Vec<u64>,
    // IDs of all pending visas on the node
    pub visas_enqueued: Vec<u64>,
    // Number of visas pending revocation on the node
    pub pending_revocation: u32,
    // Port of the VSS the node registered (node DB VSS record). Kept after
    // the VSS worker exits, so it can be set while `in_sync` is false.
    pub vss_port: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRevokeDescriptor {
    pub ty: String,
    pub cn: String,
}

/// Response to `POST /admin/authrevoke/{cn}` (zipline#136): the denylist
/// entry id, the descriptor it recorded, and the ZPR addresses of the actors
/// that were revoked immediately (admitted under the revoked CN and
/// positively acked; deferred revocations complete on the sweep tick).
#[derive(Serialize, Deserialize)]
pub struct AuthRevokeResult {
    pub id: u64,
    pub ty: String,
    pub cn: String,
    pub revoked: Vec<String>,
}

/// One actor in the `GET /admin/actors` listing. The ZPR address identifies the
/// actor; the CN is a display label that may be absent.
#[derive(Serialize, Deserialize, Debug)]
pub struct ActorEntry {
    pub zpr_addr: String,
    pub cn: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkDetails {
    pub network: Vec<NodeConnection>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ConnectionType {
    /// Link is in policy and is UP.
    UP,
    /// Link is in policy but is DOWN.
    DOWN,
    /// Link is not in policy and is UP.
    INVALID,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConnection {
    pub node_a_addr: IpAddr,
    pub node_b_addr: IpAddr,
    pub ctype: ConnectionType,
    pub node_a_substrate: String, // stringified NetAddr
    pub node_b_substrate: String, // stringified NetAddr
    pub link_id: String,
    pub link_attrs: Vec<ApiAttribute>,
    pub link_cost: u32,
}

impl NodeConnection {
    /// Create builder for a link, initiallty set 'DOWN'.
    pub fn builder(a: IpAddr, b: IpAddr) -> NodeConnectionBuilder {
        NodeConnectionBuilder::new_down(a, b)
    }

    /// True if this connection joins `a` and `b`, in either direction.
    pub fn is_link_between(&self, a: &IpAddr, b: &IpAddr) -> bool {
        (&self.node_a_addr == a && &self.node_b_addr == b)
            || (&self.node_a_addr == b && &self.node_b_addr == a)
    }

    pub fn set_status(&mut self, status: ConnectionType) {
        self.ctype = status;
    }
}

pub struct NodeConnectionBuilder {
    node_a_addr: IpAddr,
    node_b_addr: IpAddr,
    ctype: ConnectionType,
    node_a_substrate: String,
    node_b_substrate: String,
    link_id: String,
    link_attrs: Vec<ApiAttribute>,
    link_cost: u32,
}

impl NodeConnectionBuilder {
    /// Creates a builder which by default returns a `DOWN` connection.
    fn new_down(a: IpAddr, b: IpAddr) -> Self {
        NodeConnectionBuilder {
            node_a_addr: a,
            node_b_addr: b,
            ctype: ConnectionType::DOWN,
            node_a_substrate: String::new(),
            node_b_substrate: String::new(),
            link_id: String::new(),
            link_attrs: Vec::new(),
            link_cost: 0,
        }
    }

    pub fn link_id(mut self, link_id: String) -> Self {
        self.link_id = link_id;
        self
    }

    /// Sets node A's stringified substrate address, ie the local end of the link.
    pub fn node_a_substrate(mut self, node_a_substrate: String) -> Self {
        self.node_a_substrate = node_a_substrate;
        self
    }

    pub fn node_b_substrate(mut self, node_b_substrate: String) -> Self {
        self.node_b_substrate = node_b_substrate;
        self
    }

    pub fn link_cost(mut self, link_cost: u32) -> Self {
        self.link_cost = link_cost;
        self
    }

    pub fn link_attrs(mut self, attrs: Vec<ApiAttribute>) -> Self {
        self.link_attrs = attrs;
        self
    }

    pub fn up(mut self) -> Self {
        self.ctype = ConnectionType::UP;
        self
    }

    pub fn invalid(mut self) -> Self {
        self.ctype = ConnectionType::INVALID;
        self
    }

    pub fn build(self) -> NodeConnection {
        NodeConnection {
            node_a_addr: self.node_a_addr,
            node_b_addr: self.node_b_addr,
            ctype: self.ctype,
            node_a_substrate: self.node_a_substrate,
            node_b_substrate: self.node_b_substrate,
            link_id: self.link_id,
            link_attrs: self.link_attrs,
            link_cost: self.link_cost,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Stats {
    pub stats: HashMap<String, String>,
}

/// One collapsed deny from the visa service's recent-denies window.
/// `last_deny_ms` is epoch **milliseconds** (not seconds like other endpoints).
///
/// Denies are collapsed on
/// (source_addr, dest_addr, protocol, dest_port, icmp_type, deny_code). The
/// TCP/UDP source port is not part of the key and is not reported.
#[derive(Serialize, Deserialize, Debug)]
pub struct DenyRecord {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    /// Raw IP protocol number.
    pub protocol: u8,
    /// Destination port for TCP/UDP; the ICMP **code** for ICMP and ICMPv6.
    pub dest_port: u16,
    /// The ICMP **type** for ICMP and ICMPv6; JSON `null` for every other
    /// protocol (and for a malformed ICMP type that does not fit in a byte).
    pub icmp_type: Option<u8>,
    pub count: u64,
    pub last_deny_ms: u64,
    pub deny_code: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn api_keyset_serializes_keys_as_base64() {
        let ks = ApiKeySet {
            format: ApiKeyFormat::ZprKF01,
            ingress_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            egress_key: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };

        let json = serde_json::to_string(&ks).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Confirm they're strings, not arrays
        assert!(v["ingress_key"].is_string());
        assert!(v["egress_key"].is_string());

        // Confirm the actual base64 values
        assert_eq!(v["ingress_key"].as_str().unwrap(), "3q2+7w==");
        assert_eq!(v["egress_key"].as_str().unwrap(), "yv66vg==");
    }

    #[test]
    fn api_keyset_roundtrips_through_json() {
        let original = ApiKeySet {
            format: ApiKeyFormat::ZprKF01,
            ingress_key: vec![0x01, 0x02, 0x03],
            egress_key: vec![0xFF, 0xFE, 0xFD],
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiKeySet = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn api_attribute_serializes_expires_at_as_seconds() {
        let attr = ApiAttribute {
            key: "test_key".to_string(),
            value: vec!["val1".to_string()],
            expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12345),
        };

        let json = serde_json::to_string(&attr).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Should be a bare integer (seconds since epoch), not an object or string
        assert_eq!(v["expires_at"].as_i64().unwrap(), 12345);
    }

    #[test]
    fn api_attribute_deserializes_expires_at_from_seconds() {
        let json = r#"{"key":"k","value":["v"],"expires_at":123}"#;
        let attr: ApiAttribute = serde_json::from_str(json).unwrap();

        let expected = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123);
        assert_eq!(attr.expires_at, expected);
    }

    #[test]
    fn api_attribute_roundtrips_through_json() {
        let original = ApiAttribute {
            key: "roundtrip".to_string(),
            value: vec!["a".to_string(), "b".to_string()],
            expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiAttribute = serde_json::from_str(&json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn visa_descriptor_serializes_timestamps_as_integer_seconds() {
        let vd = VisaDescriptor {
            id: 42,
            expires: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9000),
            created: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000),
            policy_id: "pol".to_string(),
            zpl: "zpl".to_string(),
            direction: VisaMatchDirection::Forward,
            requesting_node: "fd5a::1".to_string(),
            source_addr: Some("fd5a::2".to_string()),
            dest_addr: Some("fd5a::3".to_string()),
            source_port: Some(80),
            dest_port: Some(443),
            proto: "TCP".to_string(),
            signals: vec![],
            session_key: ApiKeySet::default(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&vd).unwrap()).unwrap();
        assert_eq!(v["expires"].as_i64().unwrap(), 9000);
        assert_eq!(v["created"].as_i64().unwrap(), 1000);
    }

    #[test]
    fn visa_descriptor_deserializes_timestamps_from_integer_seconds() {
        let json = r#"{
            "id": 1, "expires": 9000, "created": 1000,
            "policy_id": "p", "zpl": "z", "direction": "forward",
            "requesting_node": "fd5a::1", "source_addr": "fd5a::2", "dest_addr": "fd5a::3",
            "source_port": 80, "dest_port": 443, "proto": "TCP", "signals": [],
            "session_key": {"format": "ZprKF01", "ingress_key": "AAEC", "egress_key": "AAEC"}
        }"#;
        let vd: VisaDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(
            vd.expires,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9000)
        );
        assert_eq!(
            vd.created,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000)
        );
    }

    #[test]
    fn actor_descriptor_serializes_timestamps_as_integer_seconds() {
        let ad = ActorDescriptor {
            cn: Some("test.cn".to_string()),
            ctime: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5000),
            ident: "ident".to_string(),
            node: false,
            zpr_addr: "fd5a::1".to_string(),
            attrs: vec![],
            auth_exp: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7000)),
            node_details: None,
            hostname_conflicts: vec![],
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ad).unwrap()).unwrap();
        assert_eq!(v["created"].as_i64().unwrap(), 5000);
        assert_eq!(v["auth_exp"].as_i64().unwrap(), 7000);
    }

    /// zipline#54: a pre-#54 payload without `hostname_conflicts` still parses
    /// (the field is `#[serde(default)]`), and it defaults to empty.
    #[test]
    fn actor_descriptor_parses_payload_without_hostname_conflicts() {
        let json = r#"{
            "cn": "test.cn", "created": 5000, "ident": "id", "node": false,
            "zpr_addr": "fd5a::1", "attrs": [], "auth_exp": null, "node_details": null
        }"#;
        let ad: ActorDescriptor = serde_json::from_str(json).unwrap();
        assert!(ad.hostname_conflicts.is_empty());
    }

    /// zipline#54: `hostname_conflicts` round-trips through JSON.
    #[test]
    fn actor_descriptor_hostname_conflicts_roundtrips() {
        let ad = ActorDescriptor {
            cn: Some("test.cn".to_string()),
            ctime: SystemTime::UNIX_EPOCH,
            ident: "ident".to_string(),
            node: false,
            zpr_addr: "fd5a::1".to_string(),
            attrs: vec![],
            auth_exp: None,
            node_details: None,
            hostname_conflicts: vec!["taken-name".to_string()],
        };
        let json = serde_json::to_string(&ad).unwrap();
        let decoded: ActorDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hostname_conflicts, vec!["taken-name".to_string()]);
    }

    /// zipline#54: `HostDescriptor` round-trips through JSON.
    #[test]
    fn host_descriptor_roundtrips_through_json() {
        let hd = HostDescriptor {
            hostname: "somename".to_string(),
            zpr_addr: "fd5a:5052::c1".to_string(),
            actor_cn: "".to_string(),
        };
        let json = serde_json::to_string(&hd).unwrap();
        let decoded: HostDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hostname, "somename");
        assert_eq!(decoded.zpr_addr, "fd5a:5052::c1");
        assert_eq!(decoded.actor_cn, "");
    }

    #[test]
    fn actor_descriptor_none_auth_exp_serializes_as_null() {
        let ad = ActorDescriptor {
            cn: Some("test.cn".to_string()),
            ctime: SystemTime::UNIX_EPOCH,
            ident: "ident".to_string(),
            node: false,
            zpr_addr: "fd5a::1".to_string(),
            attrs: vec![],
            auth_exp: None,
            node_details: None,
            hostname_conflicts: vec![],
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ad).unwrap()).unwrap();
        assert!(v["auth_exp"].is_null());
    }

    fn make_node_record_brief(
        last_contact: Option<SystemTime>,
        last_vreq: Option<SystemTime>,
    ) -> NodeRecordBrief {
        NodeRecordBrief {
            pending_install: 0,
            last_contact,
            visa_requests: 0,
            connect_requests: 0,
            in_sync: false,
            approved_vreqs: 0,
            denied_vreqs: 0,
            last_vreq,
            adapters: vec![],
            links: vec![],
            visas: vec![],
            visas_enqueued: vec![],
            pending_revocation: 0,
            vss_port: None,
        }
    }

    #[test]
    fn node_record_brief_serializes_timestamps_as_integer_seconds() {
        let nb = make_node_record_brief(
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000)),
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3000)),
        );
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&nb).unwrap()).unwrap();
        assert_eq!(v["last_contact"].as_i64().unwrap(), 2000);
        assert_eq!(v["last_vreq"].as_i64().unwrap(), 3000);
    }

    #[test]
    fn node_record_brief_none_timestamps_serialize_as_null() {
        let nb = make_node_record_brief(None, None);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&nb).unwrap()).unwrap();
        assert!(v["last_contact"].is_null());
        assert!(v["last_vreq"].is_null());
    }

    #[test]
    fn node_record_brief_roundtrips_through_json() {
        let original = make_node_record_brief(
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890)),
            None,
        );
        let json = serde_json::to_string(&original).unwrap();
        let decoded: NodeRecordBrief = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
