use std::collections::{HashMap, HashSet};
use std::io::Error as IoError;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use openssl::pkey::{PKey, Public};
use thiserror::Error;

use crate::attribute::{Attribute, key};
use crate::joinpolicy::{JFlag, JPolicy};
use crate::logging::targets::EVAL;
use tracing::warn;

use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::{
    AttrExp, NetAddr, Peering, PolicyTypeError, Service, ServiceType, TrustedService,
};

/// The default and the minimum.
pub const DEFAULT_LINK_COST: u32 = 1;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("i/o error: {0}")]
    Io(#[from] IoError),

    #[error("cap'n proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("cap'n proto not-in-shchema error: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("invalid policy format: {0}")]
    InvalidFormat(String),

    #[error("UTF8 encoding error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("openssl error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("policy file error: {0}")]
    PolicyFileError(String),

    #[error("policy version error: {0}")]
    PolicyVersionError(String),

    #[error("policy type error: {0}")]
    PolicyTypeError(#[from] PolicyTypeError),

    #[error("link not found: {0}")]
    LinkNotFound(String),
}

#[derive(Default)]
pub struct Policy {
    /// Buffer containing the encoded policy, if present
    policy_rdr: Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>>,
    vinst: u64,
    bootstrap_keys: HashMap<String, PKey<Public>>,
    join_policies: Vec<JPolicy>,
    services: HashMap<String, Service>,
    /// Trusted service records, keyed by `service_id`. Pairs with the `services` entry
    /// whose `kind` is [`ServiceType::Trusted`].
    trusted_services: HashMap<String, TrustedService>,
    /// ZPR attribute keys that policy declares as identity attributes, resolved out of the
    /// trusted services' `identity_attrs`. Precomputed at load: the per-connection path must
    /// not depend on `trusted_services` HashMap iteration order.
    identity_attr_keys: Vec<String>,
    cpol_sources: Vec<String>,
    serialized: Bytes,
    peer_table: Option<HashMap<IpAddr, Vec<Peer>>>, // zpr_addr -> peers
    link_attrs: Option<HashMap<String, Vec<AttrExp>>>, // link_id -> attributes
}

/// A "Peer" is a one-way view of a link from the perspective of one endpoint.
/// See [Policy::get_peers_for_node].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Each link has an identifier set in compiler. Used for debugging, and in policy here this is
    /// used to get the link attributes.
    ///
    /// See [Policy::get_link_attrs].
    pub link_id: String,

    /// ZPR address of the remote peer on this link.
    pub remote_zpr_addr: IpAddr,

    /// Substrate (physical/underlay) address used to reach the remote peer. `None` when
    /// policy gives no address for that end: the node reports its own when it
    /// authenticates (zpr-core#1381, zl-zipline#225); zl-zipline#227 fills it in.
    pub remote_substrate: Option<NetAddr>,

    /// Substrate (physical/underlay) address of *this* node (the node this peer list is
    /// keyed under) on this link. `None` as for `remote_substrate`.
    pub local_substrate: Option<NetAddr>,
}

#[derive(Debug, Clone)]
pub struct LinkDescription {
    pub link_id: String,
    pub attrs: Vec<Attribute>,
    pub cost: u32,
}

impl Policy {
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(encoded_policy_bytes: Bytes) -> Result<Self, PolicyError> {
        // Keep a copy of the bytes so we can make it avaialbe for storage.
        // TODO: Do we actually want the whole container?
        let serialized = encoded_policy_bytes.clone();

        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            encoded_policy_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )?;

        let policy = policy_reader.get_root::<policy_capnp::policy::Reader>()?;

        let bootstrap_keys = load_bootstrap_keys(&policy)?;
        let join_policies = load_join_policies(&policy)?;
        let services = load_services(&policy)?;
        let trusted_services = load_trusted_services(&policy)?;
        let identity_attr_keys = resolve_identity_attr_keys(&trusted_services);
        let cpol_sources = load_cpol_sources(&policy)?;
        let peerings = load_peerings(&policy)?;
        let peer_table = if let Some(ref peerings) = peerings {
            load_peer_table(peerings)
        } else {
            None
        };
        let link_attrs = if let Some(ref peerings) = peerings {
            let mut table: HashMap<String, Vec<AttrExp>> = HashMap::new();
            for p in peerings {
                table.insert(p.link_id.clone(), p.attributes.clone());
            }
            Some(table)
        } else {
            None
        };

        Ok(Policy {
            policy_rdr: Some(Arc::new(policy_reader)),
            bootstrap_keys,
            join_policies,
            services,
            trusted_services,
            identity_attr_keys,
            cpol_sources,
            serialized,
            peer_table,
            link_attrs,
            ..Default::default()
        })
    }

    pub fn get_policy_reader(
        &self,
    ) -> Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>> {
        self.policy_rdr.clone()
    }

    /// Returns the serialized Cap'n Proto `Policy` struct that created this [Policy].
    pub fn get_serialized(&self) -> &Bytes {
        &self.serialized
    }

    pub fn vinst(&self) -> u64 {
        self.vinst
    }

    /// Set the "installed version". This is here to support the visa service which
    /// increments the vinst each time a new policy is installed. This should not
    /// be called by other users of policy.
    pub fn set_vinst(&mut self, vinst: u64) {
        self.vinst = vinst;
    }

    /// The vinst (version instance) is incremented each time the policy is changed.
    pub fn get_vinst(&self) -> u64 {
        self.vinst
    }

    /// Return all join policies that match the given attributes.
    pub fn match_join_policies(&self, attrs: &[Attribute]) -> Vec<&JPolicy> {
        let mut matched_policies: Vec<&JPolicy> = Vec::new();

        for jp in &self.join_policies {
            if jp.matches(attrs) {
                matched_policies.push(jp);
            }
        }
        matched_policies
    }

    /// The services granted to an actor with the given attributes: the union of the
    /// services of every join policy they match. Connect stamps this into
    /// [key::SERVICES], and an attribute refresh recomputes it, so what an actor
    /// provides follows its attributes (zipline#181). An expired attribute matches
    /// no join policy (see [JPolicy::matches]), so it grants nothing.
    pub fn join_services(&self, attrs: &[Attribute]) -> HashSet<String> {
        self.match_join_policies(attrs)
            .into_iter()
            .filter_map(|jp| jp.services.as_ref())
            .flatten()
            .cloned()
            .collect()
    }

    /// The services to restamp onto an already-connected actor whose role is fixed
    /// (`is_node`), when its attributes change: what connect would grant an actor of
    /// that role, so a refresh can never contradict the role connect assigned.
    ///
    /// - An adapter skips join policies flagged [JFlag::IsNode]. Matching one would have
    ///   made it a node at connect, and a refresh cannot change the role, so a
    ///   node-only service must not reach an actor that stays an adapter.
    /// - A node gets the union of everything it matches, as at connect, but only while
    ///   it still matches a node join policy. Without one it no longer qualifies as a
    ///   node at all (`approve_connected` rejects it), so it gets nothing: fail-closed.
    pub fn join_services_for_role(&self, attrs: &[Attribute], is_node: bool) -> HashSet<String> {
        let matching = self.match_join_policies(attrs);
        let is_node_policy = |jp: &&JPolicy| jp.flags.contains(JFlag::IsNode);
        if is_node && !matching.iter().any(is_node_policy) {
            return HashSet::new();
        }
        matching
            .into_iter()
            .filter(|jp| is_node || !is_node_policy(jp))
            .filter_map(|jp| jp.services.as_ref())
            .flatten()
            .cloned()
            .collect()
    }

    /// Test-only: append a join policy directly, bypassing the compiled policy
    /// bytes. Lets eval tests exercise join-policy matching cases that no
    /// checked-in fixture compiles to — e.g. a policy that matches on CN alone
    /// with no `zpr.addr` pin (zipline#97).
    #[cfg(test)]
    pub(crate) fn push_join_policy(&mut self, jp: JPolicy) {
        self.join_policies.push(jp);
    }

    pub fn get_bootstrap_key_by_cn(&self, cn: &str) -> Option<PKey<Public>> {
        self.bootstrap_keys.get(cn).cloned()
    }

    /// Get the created timestamp string from the policy, if present.
    pub fn get_created(&self) -> Option<&str> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                if let Ok(created) = policy.get_created() {
                    return created.to_str().ok();
                }
            }
        }
        None
    }

    /// Get the version number from the policy, if present.
    pub fn get_version(&self) -> Option<u64> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                return Some(policy.get_version());
            }
        }
        None
    }

    /// Get the metadata string from the policy, if present.
    pub fn get_metadata(&self) -> Option<&str> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                if let Ok(metadata) = policy.get_metadata() {
                    match metadata.to_str() {
                        Ok(s) => return Some(s),
                        Err(_) => return None,
                    }
                }
            }
        }
        None
    }

    /// List all services defined in this policy.
    pub fn list_services(&self) -> Vec<&Service> {
        self.services.values().collect()
    }

    /// List all services defined in this policy that have the indicated `kind`.
    pub fn list_services_by_kind(&self, kind: ServiceType) -> Vec<&Service> {
        self.services
            .values()
            .filter(|svc| svc.kind == kind)
            .collect()
    }

    pub fn service_by_id(&self, id: &str) -> Option<&Service> {
        self.services.get(id)
    }

    /// The trusted service record declared for `id`, if this policy has one.
    pub fn trusted_service_by_id(&self, id: &str) -> Option<&TrustedService> {
        self.trusted_services.get(id)
    }

    /// The ZPR attribute keys this policy declares as identity attributes.
    ///
    /// `identity_attributes` names attributes the way the *service* names them (the LHS of a
    /// `returns_attributes` mapping), so each entry is resolved through that mapping into the
    /// ZPR key the attribute actually lands on the actor under. That is the same resolution
    /// `vs/src/trusted_services/attribute_mapper.rs` performs when ingesting a service reply,
    /// so these keys match the keys that appear on the actor.
    ///
    /// Ordering is stable for a given policy: trusted services in `service_id` order, and
    /// within a service the declared order. Cross-service duplicates collapse to the first.
    ///
    /// This is NOT the complete identity key set — libeval also treats [key::CN] as an
    /// identity key on its own. See [crate::eval::EvalContext::approve_connection].
    pub fn identity_attr_keys(&self) -> &[String] {
        &self.identity_attr_keys
    }

    /// Attribute keys that may be used as external attribute-store lookup keys: the
    /// builtin CN plus every policy-declared identity attribute, in that order.
    ///
    /// This is the same UNION [crate::eval::EvalContext::approve_connection] applies when
    /// assigning identity keys to an actor (and that code is written in terms of this
    /// accessor, so the two definitions cannot drift): libeval treats [key::CN] as an
    /// identity key on its own — mirroring zplc's builtin `default` trusted service,
    /// which emits no `TrustedService` record — while [Policy::identity_attr_keys]
    /// excludes CN by construction.
    ///
    /// Because it is an allow-list, caller-layered identity keys (the Visa Service's
    /// bootstrap JWT and the namespaced authorities `device.zpr.authority` /
    /// `user.zpr.authority`) and internal keys (`zpr.addr`,
    /// `zpr.actor_hash`) are excluded without a deny-list to maintain. Callers
    /// intersect this set with the authenticated claims (or actor attributes) in hand
    /// and send (key, value) pairs to attribute stores — never bare values.
    pub fn lookup_identity_keys(&self) -> Vec<&str> {
        let mut keys = vec![key::CN];
        for ikey in &self.identity_attr_keys {
            // Policy can name CN again via a returns_attributes mapping; dedupe it.
            if ikey != key::CN {
                keys.push(ikey.as_str());
            }
        }
        keys
    }

    /// Get the ZPL source for the communication policy by policy index.
    pub fn get_cpol_source(&self, idx: usize) -> Option<&str> {
        self.cpol_sources.get(idx).map(|s| s.as_str())
    }

    /// Get the attribute keys for the `client` and `service` conditions of the
    /// communication policy at index `idx`.
    ///
    /// Returns tuple of (CLIENT_KEYS, SERVICE_KEYS). Both are None when there is no
    /// communication policy at `idx`; an empty vec means that side has no conditions.
    ///
    /// It is up to caller to make sure the ComPolicy index passed here is valid for
    /// this policy.
    ///
    /// All parsing errors, etc are ignored here and most end up returning (None, None).
    pub fn get_condition_keys_for_com_policy(
        &self,
        idx: usize,
    ) -> (Option<Vec<String>>, Option<Vec<String>>) {
        // Helper to pull the `key` field out of every attribute expression in a condition list.
        fn keys(conds: capnp::struct_list::Reader<policy_capnp::attr_expr::Owned>) -> Vec<String> {
            conds
                .iter()
                .filter_map(|c| c.get_key().ok()?.to_string().ok())
                .collect()
        }

        let Some(rdr) = self.policy_rdr.as_ref() else {
            return (None, None);
        };
        let Ok(proot) = rdr.get_root::<policy_capnp::policy::Reader>() else {
            return (None, None);
        };
        let Ok(coms) = proot.get_com_policies() else {
            return (None, None);
        };
        // struct_list::get panics when out of bounds, so bounds-check first.
        if idx >= coms.len() as usize {
            return (None, None);
        }
        let com = coms.get(idx as u32);
        (
            com.get_client_conds().ok().map(keys),
            com.get_service_conds().ok().map(keys),
        )
    }

    /// Pass the node ZPR address to get the list of peers (if any).
    pub fn get_peers_for_node(&self, node_zpr_addr: &IpAddr) -> Option<&[Peer]> {
        self.peer_table
            .as_ref()?
            .get(node_zpr_addr)
            .map(|v| v.as_slice())
    }

    /// Returns an iterator over node addresses that have peers (empty if none).
    pub fn all_peered_nodes(&self) -> impl Iterator<Item = &IpAddr> + '_ {
        self.peer_table.iter().flat_map(|table| table.keys())
    }

    /// A link may have attributes on it, this returns them.
    pub fn get_link_attrs(&self, link_id: &str) -> Option<&[AttrExp]> {
        self.link_attrs.as_ref()?.get(link_id).map(|v| v.as_slice())
    }

    /// Describe the link between `node_a` and `node_b` against the captured policy.
    /// Both arguments are ZPR addresses.
    ///
    /// ## Errors
    /// - `PolicyError::LinkNotFound` if there is no link between `node_a` and `node_b`
    ///   in the captured policy.
    pub fn describe_link(
        &self,
        node_a: &IpAddr,
        node_b: &IpAddr,
    ) -> Result<LinkDescription, PolicyError> {
        if let Some(peers) = self.get_peers_for_node(node_a) {
            for peer in peers {
                if &peer.remote_zpr_addr == node_b {
                    let attrs = get_attributes_for_link(self, &peer.link_id);
                    let cost = if !attrs.is_empty() {
                        get_link_cost(&attrs, DEFAULT_LINK_COST)
                    } else {
                        DEFAULT_LINK_COST
                    };
                    return Ok(LinkDescription {
                        link_id: peer.link_id.clone(),
                        attrs,
                        cost,
                    });
                }
            }
        }
        Err(PolicyError::LinkNotFound(format!("{node_a} <-> {node_b}")))
    }
}

fn load_peer_table(peerings: &[Peering]) -> Option<HashMap<IpAddr, Vec<Peer>>> {
    // We have links defined in policy. Organize into useful lookup table for visa service.
    let mut table: HashMap<IpAddr, Vec<Peer>> = HashMap::new();
    for p in peerings {
        // Each "Peering" is an edge with two endpoints. We create entries in our peer table
        // for each endpoint.
        //
        // From node_a's perspective: remote is node_b, reachable at substrate_b.
        let peer_a_to_b = Peer {
            link_id: p.link_id.clone(),
            remote_zpr_addr: p.node_b,
            remote_substrate: p.substrate_b.clone(),
            local_substrate: p.substrate_a.clone(),
        };
        table
            .entry(p.node_a)
            .or_insert_with(Vec::new)
            .push(peer_a_to_b);

        // From node_b's perspective: remote is node_a, reachable at substrate_a.
        let peer_b_to_a = Peer {
            link_id: p.link_id.clone(),
            remote_zpr_addr: p.node_a,
            remote_substrate: p.substrate_a.clone(),
            local_substrate: p.substrate_b.clone(),
        };
        table
            .entry(p.node_b)
            .or_insert_with(Vec::new)
            .push(peer_b_to_a);
    }
    Some(table)
}

/// Given policy and a link_id, return the libeval-style Attributes for that link.
/// If there are no attributes, return an empty vec.
fn get_attributes_for_link(policy: &Policy, link_id: &str) -> Vec<Attribute> {
    if let Some(attr_exps) = policy.get_link_attrs(link_id) {
        attr_exps
            .iter()
            .map(|ae| Attribute::builder(ae.key.clone()).values(ae.value.clone()))
            .collect()
    } else {
        Vec::new()
    }
}

/// Use the special 'zpr.link.cost' attribute to obtain a numeric cost.
/// Return `default_cost` if there is no cost attribute or if we cannot cooerce it into a number.
///
/// TODO: Better to do this in the compiler and then just have an integer cost value as part of the
/// bin2 representation.
fn get_link_cost(attrs: &[Attribute], default_cost: u32) -> u32 {
    for attr in attrs {
        if attr.get_key() == key::LINK_COST {
            let value = attr
                .get_single_value()
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(default_cost as i32);
            return if value > 0 {
                value as u32
            } else {
                default_cost
            };
        }
    }
    // Default cost if not specified or if parsing fails.
    default_cost
}

fn load_bootstrap_keys(
    policy: &policy_capnp::policy::Reader,
) -> Result<HashMap<String, PKey<Public>>, PolicyError> {
    let mut bootstrap_keys: HashMap<String, PKey<Public>> = HashMap::new();
    if policy.has_keys() {
        for key in policy.get_keys()?.iter() {
            // Only take the key if it is for bootstrap.
            let allows = key.get_key_allows()?;
            for allowance in allows.iter() {
                if let Ok(aw) = allowance {
                    if aw == policy_capnp::KeyAllowance::Bootstrap {
                        let cn = key.get_id()?.to_string()?;
                        if key.get_key_type()? != policy_capnp::KeyMaterialT::RsaPub {
                            return Err(PolicyError::InvalidFormat(format!(
                                "Unsupported key type in bootstrap key for cn '{cn}': {:?}",
                                key.get_key_type()?
                            )));
                        }
                        let key_der = key.get_key_data()?;
                        let pkey = PKey::public_key_from_der(&key_der)?;
                        bootstrap_keys.insert(cn.to_string(), pkey);
                    }
                }
            }
        }
    }
    Ok(bootstrap_keys)
}

// Load (cache) the set of join policies found in the binary policy object.
fn load_join_policies(policy: &policy_capnp::policy::Reader) -> Result<Vec<JPolicy>, PolicyError> {
    let mut join_policies: Vec<JPolicy> = Vec::new();
    if policy.has_join_policies() {
        for jp_rdr in policy.get_join_policies()?.iter() {
            let jp = JPolicy::try_from(jp_rdr)?;
            join_policies.push(jp);
        }
    }
    Ok(join_policies)
}

fn load_cpol_sources(policy: &policy_capnp::policy::Reader) -> Result<Vec<String>, PolicyError> {
    let mut cpol_sources = Vec::new();
    if policy.has_com_policies() {
        for cp_rdr in policy.get_com_policies()?.iter() {
            let zpl = cp_rdr.get_zpl()?.to_string()?;
            cpol_sources.push(zpl);
        }
    }
    Ok(cpol_sources)
}

// Load (cache) the set of services found in the binary policy object. The services are
// stored in binary policy as part of the join policies but our join-policy loader doesn't
// fully load them since it doesn't need to.
fn load_services(
    policy: &policy_capnp::policy::Reader,
) -> Result<HashMap<String, Service>, PolicyError> {
    let mut services = HashMap::new();
    if policy.has_join_policies() {
        for jp_rdr in policy.get_join_policies()?.iter() {
            if jp_rdr.has_provides() {
                for svc_rdr in jp_rdr.get_provides()?.iter() {
                    let svc = Service::try_from(svc_rdr)?;
                    if let Some(previous) = services.insert(svc.id.clone(), svc) {
                        return Err(PolicyError::InvalidFormat(format!(
                            "duplicate service id in policy: {}",
                            previous.id
                        )));
                    }
                }
            }
        }
    }
    Ok(services)
}

// Load (cache) the trusted service records found in the binary policy object. Each pairs
// with a service whose kind is ServiceType::Trusted; see [Policy::trusted_service_by_id].
fn load_trusted_services(
    policy: &policy_capnp::policy::Reader,
) -> Result<HashMap<String, TrustedService>, PolicyError> {
    let mut trusted_services = HashMap::new();
    if policy.has_trusted_services() {
        for ts_rdr in policy.get_trusted_services()?.iter() {
            let ts = TrustedService::try_from(ts_rdr).map_err(PolicyTypeError::from)?;
            if let Some(previous) = trusted_services.insert(ts.service_id.clone(), ts) {
                return Err(PolicyError::InvalidFormat(format!(
                    "duplicate trusted service id in policy: {}",
                    previous.service_id
                )));
            }
        }
    }
    Ok(trusted_services)
}

// Resolve each trusted service's `identity_attrs` (service-side names) into the ZPR attribute
// keys those attributes land on the actor under. Services are visited in `service_id` order
// because HashMap iteration order is random and the resulting key order is user visible.
//
// An entry that cannot serve as an identity is dropped with a warning rather than failing the
// whole policy load:
//   - no matching `returns_attributes` mapping: nothing would ever set that attribute.
//   - a tag spec (`#user.gov`): tags are valueless, so there is no identity value to read.
//   - a multi-valued spec (`user.roles{}`): which value is "the" identity is undefined.
// zplc forbids `identity_attributes` on api="file" services but screens for none of the above.
fn resolve_identity_attr_keys(trusted_services: &HashMap<String, TrustedService>) -> Vec<String> {
    let mut service_ids: Vec<&String> = trusted_services.keys().collect();
    service_ids.sort();

    let mut keys: Vec<String> = Vec::new();
    for sid in service_ids {
        let ts = &trusted_services[sid];
        for entry in &ts.identity_attrs {
            let Some(mapping) = ts
                .returns_attrs
                .iter()
                .find(|m| &m.service_attr_key == entry)
            else {
                warn!(target: EVAL, "trusted service '{sid}': identity attribute '{entry}' has no returns_attributes mapping; ignoring");
                continue;
            };
            if mapping.attr.is_tag() || mapping.attr.is_multi_valued() {
                warn!(target: EVAL, "trusted service '{sid}': identity attribute '{entry}' maps to '{}', which cannot carry an identity value; ignoring", mapping.zpr_attr_spec);
                continue;
            }
            // Linear scan: an identity list is a handful of entries at most.
            let key = mapping.attr.zpl_key();
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// Build policy bytes carrying the given trusted service records (ids may repeat, so
/// the duplicate-id path can be exercised). Test helper shared with `eval.rs`.
#[cfg(test)]
pub(crate) fn policy_bytes_with_trusted_services(records: &[TrustedService]) -> Bytes {
    use zpr::write_to::WriteTo;

    let mut msg = capnp::message::Builder::new_default();
    {
        let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
        let mut list = policy
            .reborrow()
            .init_trusted_services(records.len() as u32);
        for (i, ts) in records.iter().enumerate() {
            ts.write_to(&mut list.reborrow().get(i as u32));
        }
    }
    let mut bytes = Vec::new();
    capnp::serialize::write_message(&mut bytes, &msg).unwrap();
    Bytes::from(bytes)
}

fn load_peerings(
    policy: &policy_capnp::policy::Reader,
) -> Result<Option<Vec<Peering>>, PolicyError> {
    if policy.has_topology() {
        let mut peerings = Vec::new();
        for peer_rdr in policy.get_topology()?.iter() {
            let peering = Peering::try_from(peer_rdr)?;
            peerings.push(peering);
        }
        Ok(Some(peerings))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pio::{Version, load_policy};
    use std::env;
    use std::path::PathBuf;

    use bytes::Bytes;
    use zpr::policy::v1 as policy_capnp;
    use zpr::policy_types::{AttrExp, AttrOp, NetAddr, Peering, parse_attribute_mapping};
    use zpr::write_to::WriteTo;

    const MIN_COMPILER_VERSION: Version = Version(0, 13, 0);

    fn read_policy_from_test_file(filename: &str) -> Policy {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let fpath = PathBuf::from(manifest_dir).join("test-data").join(filename);
        load_policy(&fpath, &MIN_COMPILER_VERSION).unwrap()
    }

    /// Build a Policy from a list of ZPL source strings by constructing a capnp
    /// policy message in memory, without needing a compiled policy file.
    fn policy_with_cpol_sources(zpls: &[&str]) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            let mut coms = policy.reborrow().init_com_policies(zpls.len() as u32);
            for (i, zpl) in zpls.iter().enumerate() {
                coms.reborrow().get(i as u32).set_zpl(zpl);
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
    }

    #[test]
    fn test_get_boostrap_key_by_cn_not_there() {
        let policy = Policy::new_empty();
        let key = policy.get_bootstrap_key_by_cn("nonexistent");
        assert!(key.is_none());
    }

    #[test]
    fn test_get_bootstrap_key() {
        let policy = read_policy_from_test_file("test-keys.bin2");

        // not there:
        let key = policy.get_bootstrap_key_by_cn("nonexistant");
        assert!(key.is_none());

        let cns = vec!["node.zpr.org", "foo.fee", "haha.very.funny"];
        for cn in cns {
            let key = policy.get_bootstrap_key_by_cn(cn);
            assert!(
                key.is_some(),
                "expected to find bootstrap key for cn '{cn}'"
            );
        }
    }

    #[test]
    /// get_cpol_source returns the expected ZPL string for known indices when the
    /// policy contains communication policies.
    fn test_get_cpol_source_returns_zpl_for_known_index() {
        let zpls = ["allow all traffic.", "deny all traffic."];
        let policy = policy_with_cpol_sources(&zpls);

        assert_eq!(policy.get_cpol_source(0), Some("allow all traffic."));
        assert_eq!(policy.get_cpol_source(1), Some("deny all traffic."));
    }

    #[test]
    /// get_cpol_source returns None when the requested index is out of bounds.
    fn test_get_cpol_source_out_of_bounds_returns_none() {
        let zpls = ["allow all traffic."];
        let policy = policy_with_cpol_sources(&zpls);

        assert!(policy.get_cpol_source(1).is_none());
        assert!(policy.get_cpol_source(99).is_none());
    }

    #[test]
    /// get_cpol_source returns None for any index on an empty policy that has no
    /// communication policies.
    fn test_get_cpol_source_empty_policy_returns_none() {
        let policy = Policy::new_empty();

        assert!(policy.get_cpol_source(0).is_none());
    }

    #[test]
    /// get_condition_keys_for_com_policy returns the client/service condition keys for a
    /// valid index, an empty vec for a side with no conditions, and (None, None) when the
    /// index is out of bounds (which must not panic).
    fn test_get_condition_keys_for_com_policy() {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            let mut coms = policy.reborrow().init_com_policies(1);
            let mut com = coms.reborrow().get(0);
            let mut client = com.reborrow().init_client_conds(2);
            client.reborrow().get(0).set_key("user.role");
            client.reborrow().get(1).set_key("user.dept");
            com.reborrow().init_service_conds(0);
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        let policy = Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap();

        let (client, service) = policy.get_condition_keys_for_com_policy(0);
        assert_eq!(client.unwrap(), vec!["user.role", "user.dept"]);
        assert_eq!(service.unwrap(), Vec::<String>::new());

        assert_eq!(
            policy.get_condition_keys_for_com_policy(9),
            (None, None),
            "out-of-range index must return (None, None)"
        );
        assert_eq!(
            Policy::new_empty().get_condition_keys_for_com_policy(0),
            (None, None)
        );
    }

    /// A trusted service record and its attribute mappings survive the capnp round trip
    /// and are reachable by id.
    #[test]
    fn test_trusted_service_by_id_round_trip() {
        let ts = TrustedService {
            service_id: "attrfile".to_string(),
            expiration_seconds: 3600,
            returns_attrs: vec![parse_attribute_mapping("color -> user.color").unwrap()],
            identity_attrs: vec![],
            oidc: None,
            attr_query: None,
        };
        let policy =
            Policy::new_from_policy_bytes(policy_bytes_with_trusted_services(&[ts])).unwrap();

        let found = policy.trusted_service_by_id("attrfile").unwrap();
        assert_eq!(found.expiration_seconds, 3600);
        assert_eq!(found.returns_attrs[0].service_attr_key, "color");
        assert_eq!(found.returns_attrs[0].attr.zpl_key(), "user.color");
        assert!(policy.trusted_service_by_id("nope").is_none());
    }

    /// Two trusted service records sharing an id are ambiguous, so the whole policy is
    /// rejected rather than silently keeping one of them.
    #[test]
    fn test_duplicate_trusted_service_id_errors() {
        let ts = TrustedService {
            service_id: "attrfile".to_string(),
            expiration_seconds: 3600,
            returns_attrs: vec![],
            identity_attrs: vec![],
            oidc: None,
            attr_query: None,
        };
        let result =
            Policy::new_from_policy_bytes(policy_bytes_with_trusted_services(&[ts.clone(), ts]));
        assert!(matches!(result, Err(PolicyError::InvalidFormat(_))));
    }

    /// Build a TrustedService test record from attribute-mapping strings and the
    /// service-side names of its identity attributes.
    fn ts(id: &str, mappings: &[&str], identity: &[&str]) -> TrustedService {
        TrustedService {
            service_id: id.to_string(),
            expiration_seconds: 3600,
            returns_attrs: mappings
                .iter()
                .map(|m| parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: identity.iter().map(|s| s.to_string()).collect(),
            oidc: None,
            attr_query: None,
        }
    }

    /// Build a Policy from trusted service records and return its resolved identity keys.
    fn keys_for(records: &[TrustedService]) -> Vec<String> {
        let policy =
            Policy::new_from_policy_bytes(policy_bytes_with_trusted_services(records)).unwrap();
        policy.identity_attr_keys().to_vec()
    }

    /// A service-side identity name resolves through returns_attributes to the ZPR key,
    /// and mappings not named as identity are excluded.
    #[test]
    fn test_identity_attr_keys_resolves_service_side_name() {
        let record = ts(
            "hr",
            &["tint -> device.tint", "employee_id -> user.employee_id"],
            &["employee_id"],
        );
        assert_eq!(keys_for(&[record]), vec!["user.employee_id"]);
    }

    /// No identity declarations means no identity keys, on both a built and an empty policy.
    #[test]
    fn test_identity_attr_keys_empty_when_none_declared() {
        let record = ts("attrfile", &["color -> user.color"], &[]);
        assert!(keys_for(&[record]).is_empty());
        assert!(Policy::new_empty().identity_attr_keys().is_empty());
    }

    /// An identity entry with no matching returns_attributes mapping is dropped without
    /// failing the policy load.
    #[test]
    fn test_identity_attr_keys_unresolvable_entry_ignored() {
        let record = ts("hr", &["employee_id -> user.employee_id"], &["nope"]);
        assert!(keys_for(&[record]).is_empty());
    }

    /// Tag and multi-valued mappings cannot carry an identity value and are dropped;
    /// the single-valued entry survives.
    #[test]
    fn test_identity_attr_keys_skips_tag_and_multi_valued() {
        let record = ts(
            "hr",
            &[
                "gov -> #user.government",
                "roles -> user.role{}",
                "id -> user.id",
            ],
            &["gov", "roles", "id"],
        );
        assert_eq!(keys_for(&[record]), vec!["user.id"]);
    }

    /// Within one service, keys keep the declared identity order, not alphabetical order.
    #[test]
    fn test_identity_attr_keys_preserves_declared_order() {
        let record = ts("hr", &["a -> user.a", "b -> user.b"], &["b", "a"]);
        assert_eq!(keys_for(&[record]), vec!["user.b", "user.a"]);
    }

    /// lookup_identity_keys is the builtin CN followed by the policy-declared identity
    /// keys in policy order, and a policy that names CN again via a returns_attributes
    /// mapping does not produce a duplicate.
    #[test]
    fn test_lookup_identity_keys_is_cn_union_policy_keys() {
        // Empty policy: CN alone (identity_attr_keys excludes it by construction).
        assert_eq!(Policy::new_empty().lookup_identity_keys(), vec![key::CN]);

        // Declared keys follow CN in policy order.
        let record = ts("hr", &["a -> user.a", "b -> user.b"], &["b", "a"]);
        let policy =
            Policy::new_from_policy_bytes(policy_bytes_with_trusted_services(&[record])).unwrap();
        assert_eq!(
            policy.lookup_identity_keys(),
            vec![key::CN, "user.b", "user.a"]
        );

        // A mapping re-declaring CN as identity is deduped, not repeated.
        let record = ts(
            "hr",
            &[&format!("cn -> {}", key::CN), "id -> user.id"],
            &["cn", "id"],
        );
        let policy =
            Policy::new_from_policy_bytes(policy_bytes_with_trusted_services(&[record])).unwrap();
        assert_eq!(policy.lookup_identity_keys(), vec![key::CN, "user.id"]);
    }

    /// Across services the order is service_id-sorted and duplicates collapse to the
    /// first occurrence; repeated parses agree (guards against HashMap-order flakiness).
    #[test]
    fn test_identity_attr_keys_is_deterministic_across_services() {
        let records = [
            ts(
                "zeta",
                &["shared -> user.shared", "z -> user.z"],
                &["shared", "z"],
            ),
            ts(
                "alpha",
                &["a -> user.a", "shared -> user.shared"],
                &["a", "shared"],
            ),
        ];
        let bytes = policy_bytes_with_trusted_services(&records);
        for _ in 0..20 {
            let policy = Policy::new_from_policy_bytes(bytes.clone()).unwrap();
            assert_eq!(
                policy.identity_attr_keys(),
                &["user.a", "user.shared", "user.z"]
            );
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a Policy containing the given peerings via an in-memory capnp message.
    fn policy_with_peerings(peerings: &[Peering]) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            policy.reborrow().set_created("1970-01-01T00:00:00Z");
            if !peerings.is_empty() {
                let mut topo = policy.reborrow().init_topology(peerings.len() as u32);
                for (i, p) in peerings.iter().enumerate() {
                    p.write_to(&mut topo.reborrow().get(i as u32));
                }
            }
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
    }

    /// Build a Peering between two ZPR nodes with explicit substrate addresses.
    fn make_peering_full(
        node_a: IpAddr,
        sub_a: &str,
        node_b: IpAddr,
        sub_b: &str,
        link_id: &str,
        attrs: Vec<AttrExp>,
    ) -> Peering {
        Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: Some(NetAddr::new_for_ip_or_host(sub_a, 5000)),
            node_b,
            substrate_b: Some(NetAddr::new_for_ip_or_host(sub_b, 5001)),
            attributes: attrs,
        }
    }

    #[test]
    /// A peering end with no substrate address in policy (the node reports its own,
    /// zl-zipline#225) survives the policy round trip as `None` on both peer entries
    /// that refer to it, and building the peer table does not panic.
    fn test_get_peers_for_node_unset_substrate_is_none() {
        let mut peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "unused",
            "link-reported",
            vec![],
        );
        peering.substrate_b = None;
        let policy = policy_with_peerings(&[peering]);

        // node_a reaches node_b at an address node_b will report: remote is None.
        let peers_a = policy.get_peers_for_node(&ip("fd5a:5052::1")).unwrap();
        assert_eq!(peers_a[0].remote_substrate, None);
        assert_eq!(
            peers_a[0].local_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.1", 5000))
        );

        // node_b's own end is the unset one: local is None, remote is node_a's address.
        let peers_b = policy.get_peers_for_node(&ip("fd5a:5052::2")).unwrap();
        assert_eq!(peers_b[0].local_substrate, None);
        assert_eq!(
            peers_b[0].remote_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.1", 5000))
        );
    }

    // --- get_peers_for_node ---

    #[test]
    /// get_peers_for_node returns None when the policy has no topology (new_empty).
    fn test_get_peers_for_node_no_topology() {
        let policy = Policy::new_empty();
        assert!(policy.get_peers_for_node(&ip("fd5a:5052::1")).is_none());
    }

    #[test]
    /// get_peers_for_node returns None for a node that is not in any peering.
    fn test_get_peers_for_node_unknown_node() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        assert!(policy.get_peers_for_node(&ip("fd5a:5052::99")).is_none());
    }

    #[test]
    /// get_peers_for_node returns a Peer for node_a with the correct remote ZPR address
    /// and the remote's substrate (substrate_b), not node_a's own substrate.
    fn test_get_peers_for_node_a_sees_correct_remote() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-abc",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        let peers = policy.get_peers_for_node(&ip("fd5a:5052::1")).unwrap();
        assert_eq!(peers.len(), 1);
        let p = &peers[0];
        assert_eq!(p.link_id, "link-abc");
        assert_eq!(p.remote_zpr_addr, ip("fd5a:5052::2"));
        assert_eq!(
            p.remote_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.2", 5001))
        );
        assert_eq!(
            p.local_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.1", 5000))
        );
    }

    #[test]
    /// A single peering creates entries for both endpoints; querying node_b yields node_a as the
    /// remote, with substrate_a as the reachable address.
    fn test_get_peers_for_node_bidirectional() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-x",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);

        // node_b's peer entry should point back at node_a via substrate_a
        let peers_b = policy.get_peers_for_node(&ip("fd5a:5052::2")).unwrap();
        assert_eq!(peers_b.len(), 1);
        let p = &peers_b[0];
        assert_eq!(p.link_id, "link-x");
        assert_eq!(p.remote_zpr_addr, ip("fd5a:5052::1"));
        assert_eq!(
            p.remote_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.1", 5000))
        );
        assert_eq!(
            p.local_substrate,
            Some(NetAddr::new_for_ip_or_host("10.0.0.2", 5001))
        );
    }

    #[test]
    /// A node that appears in two peerings has two entries in its peer list.
    fn test_get_peers_for_node_multiple_peers() {
        let p1 = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![],
        );
        let p2 = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::3"),
            "10.0.0.3",
            "link-2",
            vec![],
        );
        let policy = policy_with_peerings(&[p1, p2]);
        let peers = policy.get_peers_for_node(&ip("fd5a:5052::1")).unwrap();
        assert_eq!(peers.len(), 2);
        let ids: Vec<&str> = peers.iter().map(|p| p.link_id.as_str()).collect();
        assert!(ids.contains(&"link-1"));
        assert!(ids.contains(&"link-2"));
    }

    // --- get_link_attrs ---

    #[test]
    /// get_link_attrs returns None when the policy has no topology (new_empty).
    fn test_get_link_attrs_no_topology() {
        let policy = Policy::new_empty();
        assert!(policy.get_link_attrs("link-1").is_none());
    }

    #[test]
    /// get_link_attrs returns None for an unknown link_id when topology is present.
    fn test_get_link_attrs_unknown_link() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["trusted".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[peering]);
        assert!(policy.get_link_attrs("no-such-link").is_none());
    }

    #[test]
    /// get_link_attrs returns Some(&[]) for a known link that has no attributes, distinguishing
    /// it from an unknown link ID which returns None.
    fn test_get_link_attrs_link_with_no_attrs_returns_empty_slice() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-bare",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        assert_eq!(policy.get_link_attrs("link-bare"), Some(&[] as &[AttrExp]));
        assert!(policy.get_link_attrs("no-such-link").is_none());
    }

    #[test]
    /// get_link_attrs returns the correct attribute list for a link with attributes.
    fn test_get_link_attrs_known_link() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-rich",
            vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["trusted".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[peering]);
        let attrs = policy.get_link_attrs("link-rich").unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].key, "link.class");
        assert_eq!(attrs[0].value, vec!["trusted"]);
    }

    #[test]
    /// get_link_attrs for two distinct links returns independent attribute lists keyed by link_id.
    fn test_get_link_attrs_multiple_links_independent() {
        let p1 = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-alpha",
            vec![AttrExp {
                key: "link.zpr.cost".to_string(),
                op: AttrOp::Eq,
                value: vec!["3".to_string()],
            }],
        );
        let p2 = make_peering_full(
            ip("fd5a:5052::2"),
            "10.0.0.2",
            ip("fd5a:5052::3"),
            "10.0.0.3",
            "link-beta",
            vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["untrusted".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[p1, p2]);
        let alpha = policy.get_link_attrs("link-alpha").unwrap();
        assert_eq!(alpha[0].key, "link.zpr.cost");
        let beta = policy.get_link_attrs("link-beta").unwrap();
        assert_eq!(beta[0].key, "link.class");
    }

    // --- describe_link ---

    #[test]
    /// describe_link returns LinkNotFound when the policy has no topology.
    fn test_describe_link_no_topology() {
        let policy = policy_with_peerings(&[]);
        let result = policy.describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"));
        assert!(matches!(result, Err(PolicyError::LinkNotFound(_))));
    }

    #[test]
    /// describe_link returns LinkNotFound when node_a has no peers in the topology.
    fn test_describe_link_node_a_not_in_topology() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy.describe_link(&ip("fd5a:5052::99"), &ip("fd5a:5052::2"));
        assert!(matches!(result, Err(PolicyError::LinkNotFound(_))));
    }

    #[test]
    /// describe_link returns LinkNotFound when node_a is found but no peer's ZPR address
    /// matches node_b.
    fn test_describe_link_node_b_not_matched() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy.describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::99"));
        assert!(matches!(result, Err(PolicyError::LinkNotFound(_))));
    }

    #[test]
    /// describe_link returns the correct link_id when a matching peer is found via IP.
    fn test_describe_link_found_by_ip() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-abc",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.link_id, "link-abc");
    }

    #[test]
    /// describe_link returns DEFAULT_LINK_COST and an empty attrs vec when the link has no
    /// attributes.
    fn test_describe_link_default_cost_no_attrs() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, DEFAULT_LINK_COST);
        assert!(result.attrs.is_empty());
    }

    #[test]
    /// describe_link reads the numeric cost from the link.zpr.cost attribute.
    fn test_describe_link_cost_from_attr() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![AttrExp {
                key: key::LINK_COST.to_string(),
                op: AttrOp::Eq,
                value: vec!["5".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, 5);
    }

    #[test]
    /// describe_link falls back to DEFAULT_LINK_COST when the cost attribute cannot be parsed.
    fn test_describe_link_cost_unparseable_uses_default() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![AttrExp {
                key: key::LINK_COST.to_string(),
                op: AttrOp::Eq,
                value: vec!["not-a-number".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.cost, DEFAULT_LINK_COST);
    }

    #[test]
    /// describe_link includes non-cost attributes in the returned LinkDescription.
    fn test_describe_link_returns_non_cost_attrs() {
        let peering = make_peering_full(
            ip("fd5a:5052::1"),
            "10.0.0.1",
            ip("fd5a:5052::2"),
            "10.0.0.2",
            "link-1",
            vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["trusted".to_string()],
            }],
        );
        let policy = policy_with_peerings(&[peering]);
        let result = policy
            .describe_link(&ip("fd5a:5052::1"), &ip("fd5a:5052::2"))
            .unwrap();
        assert_eq!(result.attrs.len(), 1);
        assert_eq!(result.attrs[0].get_key(), "link.class");
    }
}
