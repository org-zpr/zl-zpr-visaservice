use crate::actor::Actor;
use crate::attribute::{Attribute, NEVER_EXPIRES, ROLE_ADAPTER, ROLE_NODE, key};
use crate::error::EvalError;
use crate::eval_result::{Direction, FinalDeny, Hit, PartialEvalResult, Signal};
use crate::joinpolicy::JFlag;
use crate::logging::targets::EVAL;
use crate::policy::Policy;
use crate::visa::VisaProps;

use zpr::vsapi_types::PacketDesc;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use enumset::EnumSet;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use tracing::{debug, warn};

use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::{AttrExp, AttrOp};

/// True if this join-policy match expression PINS zpr.addr: key `zpr.addr`
/// with exact-equality (`Eq`) semantics and at least one concrete, non-empty
/// value. Only such an expression admits exactly the pinned value(s), so only
/// it can validate a peer-requested address in `approve_connection`. `Ne`,
/// valueless `Has` and `Excludes` match whole families of peer-selected
/// addresses; a valued `Has` is subset semantics rather than exact equality.
/// None of those pin, so none of them commit the request.
fn pins_zpr_addr(exp: &AttrExp) -> bool {
    exp.key == key::ZPR_ADDR
        && exp.op == AttrOp::Eq
        && !exp.value.is_empty()
        && exp.value.iter().all(|v| !v.is_empty())
}

// TODO: Not yet sure if this is useful. Maybe the context can build up
// some cache or something to make future eval calls faster?
pub struct EvalContext {
    policy: Arc<Policy>,
}

#[derive(Debug, PartialEq, Eq)]
enum ScopeMatchType {
    Forward,
    Reverse,
}

enum PAttrValue {
    Atom(String),
    Set(Vec<String>),
}

impl PAttrValue {
    fn is_empty(&self) -> bool {
        match self {
            PAttrValue::Atom(s) => s.is_empty(),
            PAttrValue::Set(vs) => vs.is_empty(),
        }
    }

    fn as_slice(&self) -> &[String] {
        match self {
            PAttrValue::Atom(s) => std::slice::from_ref(s),
            PAttrValue::Set(vs) => vs.as_slice(),
        }
    }
}

impl EvalContext {
    pub fn new(policy: Arc<Policy>) -> Self {
        EvalContext { policy }
    }

    /// Check if policy permits the described actor communication.
    ///
    /// Caller must ensure that the two actors passed here are the ones
    /// involved in the communication described by `request`.
    pub fn eval_request(
        &self,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
    ) -> Result<PartialEvalResult, EvalError> {
        if !matches!(
            request.protocol(),
            ip_proto::TCP | ip_proto::UDP | ip_proto::IPV6_ICMP
        ) {
            return Ok(PartialEvalResult::Deny(FinalDeny::NoMatch(
                "only TCP/UDP/ICMPv6 protocols supported".into(),
            )));
        }
        let rdr = match self.policy.get_policy_reader() {
            Some(r) => r,
            None => {
                return Ok(PartialEvalResult::deny_no_match(
                    "no policy available".into(),
                ));
            }
        };
        let policy = rdr.get_root::<policy_capnp::policy::Reader>()?;
        if !policy.has_com_policies() {
            return Ok(PartialEvalResult::deny_no_match(
                "no communication policies defined".into(),
            ));
        }

        // We will make two passes, once looking for denies, and then looking for allows (if needed).
        let deny_hits = self.match_policies(false, src_actor, dst_actor, request, &policy)?;
        if !deny_hits.is_empty() {
            return Ok(PartialEvalResult::deny_hits(deny_hits));
        }

        let allow_hits = self.match_policies(true, src_actor, dst_actor, request, &policy)?;
        // Different hits will have different constraints etc. We'll leave the picking of the
        // policy to apply to the caller.
        if !allow_hits.is_empty() {
            return Ok(PartialEvalResult::allow_hits(allow_hits));
        }
        Ok(PartialEvalResult::deny_no_match(
            "no matching policy".into(),
        ))
    }

    pub fn visa_info_for_hit(
        &self,
        hit: &Hit,
        request: &PacketDesc,
    ) -> Result<VisaProps, EvalError> {
        let rdr = match self.policy.get_policy_reader() {
            Some(r) => r,
            None => {
                return Err(EvalError::EmptyPolicy);
            }
        };
        let policy = rdr.get_root::<policy_capnp::policy::Reader>()?;

        let matched_pol = policy.get_com_policies().unwrap().get(hit.match_idx as u32);

        if !matched_pol.get_allow() {
            return Err(EvalError::InvalidRequest(
                "visa_info_for_hit called on a deny".into(),
            ));
        }

        let match_source_port;
        let match_dest_port;

        match request.protocol() {
            // For TCP/UDP if request was using a high numberd "client" port, grant the visa for
            // any client port.
            //
            // THIS IS NOT REQUIRED BY ZDP AND MAY NOT BE WHAT WE WANT.
            //
            //    This is an example of a "handler" related to the protocol.
            //    We should amend or remove if we don't want this behavior.
            //    Here only because this was in the prototype.
            //
            ip_proto::TCP | ip_proto::UDP => match hit.direction {
                Direction::Forward => {
                    if request.source_port() > 1023 {
                        match_source_port = 0;
                    } else {
                        match_source_port = request.source_port();
                    }
                    match_dest_port = request.dest_port();
                }
                Direction::Reverse => {
                    if request.dest_port() > 1023 {
                        match_dest_port = 0;
                    } else {
                        match_dest_port = request.dest_port();
                    }
                    match_source_port = request.source_port();
                }
            },
            ip_proto::IPV6_ICMP => {
                // For ICMPv6 the source port is the ICMP type.
                // The dest port is the ICMP code.
                // TODO: We do not yet encode ICMP codes into the binary policy format.
                match_source_port = request.source_port();
                match_dest_port = request.dest_port();
            }
            _ => {
                return Err(EvalError::UnsupportedProtocol(format!(
                    "unsupported protocol {}",
                    request.protocol()
                )));
            }
        }

        Ok(VisaProps {
            source_addr: request.source_addr().clone(),
            dest_addr: request.dest_addr().clone(),
            protocol: request.protocol(),
            source_port: match_source_port,
            dest_port: match_dest_port,
            constraints: None, // TODO
            comm_opts: None,   // TODO
            zpl: matched_pol.get_zpl().unwrap().to_string().unwrap(),
        })
    }

    /// Consult policy and determine if connection is allowed from the actor with
    /// the indicated authenticated and unauthenticated claims.
    ///
    /// On success returns an actor object that will include additional attributes set from
    /// policy (eg, ROLE).
    ///
    /// A requested ZPR address is a check, never a grant. If the peer requests a
    /// specific address, `zpr.addr:<addr>` should be included in the
    /// `unauthenticated_claims`; it is used for join-policy matching, but it is
    /// committed to the returned actor only when at least one MATCHED join policy
    /// pins `zpr.addr` — carries a `zpr.addr` condition with exact-equality
    /// (`Eq`) semantics and a concrete value in its match expressions.
    /// Non-pinning expressions on the key (`Ne`, valueless `Has`, `Excludes`,
    /// or `Has` with a value) match families of addresses and do not commit.
    /// A policy that matches on other keys alone does not validate the request:
    /// the address is scrubbed and the caller allocates one from the pool. A
    /// request that conflicts with a policy's pinned address simply fails to
    /// match that policy.
    ///
    /// An actor that matches no join policy is still approved -- with its
    /// unauthenticated claims scrubbed -- because a join policy grants a role and
    /// services, and an endpoint that gets neither can reach nothing anyway (#227).
    /// Authentication admits the endpoint; communication policy decides what it may
    /// do. This holds however the actor authenticated: it was briefly not true for
    /// OIDC user logins (zipline#11), which is now reverted.
    pub fn approve_connection(
        &self,
        authenticated_claims: Option<&[Attribute]>,
        unauthenticated_claims: Option<&[Attribute]>,
    ) -> Result<Actor, EvalError> {
        if authenticated_claims.is_none() {
            return Err(EvalError::AttributeMissing(
                "no authenticated claims provided".into(),
            ));
        }
        let authenticated_claims = authenticated_claims.unwrap();

        let mut query_claims = Vec::new();
        query_claims.extend_from_slice(authenticated_claims);

        // Collect any requested zpr.addr from the unauth claims. These are used
        // for join-policy matching, but only committed to the final actor if a
        // join policy actually matches (and thereby validates them).
        let mut unauth_claims = Vec::new();
        if let Some(uc) = unauthenticated_claims {
            for ua_attr in uc {
                if ua_attr.get_key() == key::ZPR_ADDR {
                    unauth_claims.push(ua_attr.clone());
                }
            }
        }
        query_claims.extend_from_slice(&unauth_claims);

        // Query to see if the claims match any join policies.
        let matching_jps = self.policy.match_join_policies(&query_claims);
        // A matched join policy alone does not validate the requested address:
        // the request is committed only when at least one MATCHED policy PINS
        // zpr.addr — an exact-equality expression (`zpr.addr Eq <addr>`) with
        // a concrete, non-empty value. Only Eq admits exactly the pinned
        // value(s); `Ne`, valueless `Has` and `Excludes` match whole families
        // of peer-selected addresses and validate nothing, and even a valued
        // `Has` is subset semantics rather than exact equality, so it is
        // conservatively rejected too. A policy that matched on other keys
        // says nothing about the address, and an unvalidated claim must be
        // scrubbed: otherwise a bootstrap-authenticated peer could claim an
        // arbitrary or already-used ZPR address and overwrite/disconnect that
        // actor.
        let matched_addr_pin = matching_jps
            .iter()
            .any(|jp| jp.matches.iter().any(pins_zpr_addr));
        debug!(
            target: EVAL,
            "found {} matching join policies",
            matching_jps.len()
        );

        // Each policy may have flags and services. Services go through
        // Policy::join_services, the same computation an attribute refresh uses.
        let mut flags: EnumSet<JFlag> = EnumSet::new();
        for jp in matching_jps {
            flags |= jp.flags;
        }
        let services = self.policy.join_services(&query_claims);

        let mut actor = Actor::new();

        // Always commit the authenticated claims. Commit the unauth claims
        // only if a matched join policy pins zpr.addr; otherwise scrub them.
        let final_claims: &[Attribute] = if matched_addr_pin {
            &query_claims
        } else {
            if !unauth_claims.is_empty() {
                warn!(
                    target: EVAL,
                    "scrubbing {} unauthenticated claim(s) from actor: no matched join policy pins zpr.addr",
                    unauth_claims.len()
                );
            }
            authenticated_claims
        };

        for attr in final_claims {
            if let Err(e) = actor.add_attribute(attr.clone()) {
                warn!(target: EVAL, "dropping invalid claim attribute: {}", e);
            }
        }

        let role_attr = if flags.contains(JFlag::IsNode) {
            Attribute::builder(key::ROLE)
                .expires_in(NEVER_EXPIRES)
                .value(ROLE_NODE)
        } else {
            Attribute::builder(key::ROLE)
                .expires_in(NEVER_EXPIRES)
                .value(ROLE_ADAPTER)
        };
        actor.add_attribute(role_attr).unwrap();

        if !services.is_empty() {
            debug!(target: EVAL, "actor provides services: {:?}", services);
        }
        actor.set_services(services);

        actor
            .add_attribute(
                Attribute::builder(key::VINST)
                    .expires_in(NEVER_EXPIRES)
                    .value(self.policy.get_vinst().to_string()),
            )
            .unwrap();

        // Policy tells us which attributes are tied to identity, and there is one identity
        // attribute libeval knows on its own: the adapter CN, established by the builtin RSA
        // authentication. Policy::lookup_identity_keys() carries that UNION (builtin CN
        // first, then the policy-declared keys in policy order, CN deduped), and is also
        // what the Visa Service intersects with claims when querying trusted services --
        // sharing the accessor keeps the two definitions from drifting.
        //
        // Everything is appended (usize::MAX) so CN stays first and the policy-declared keys keep
        // policy order. Callers layer their own keys around this set -- the Visa Service prepends
        // its JWT at order 0 and appends the namespaced authorities at the end -- so this must not reorder.
        //
        // Presence on the actor is a sufficient test: every attribute committed above is either an
        // authenticated claim or a zpr.addr validated by a matching join policy, so a peer cannot
        // self-assert an identity attribute into this set.
        for ikey in self.policy.lookup_identity_keys() {
            if actor.has_attribute_named(ikey) {
                // Only fails when the attribute is absent, which was just checked.
                actor.add_identity_key(usize::MAX, ikey).unwrap();
            }
        }

        // Last resort. An actor with no identity key at all reads as "never authenticated":
        // get_authentication_expiration returns None, and the Visa Service *skips* its
        // expiry check when it is None. So this set must never be left empty.
        if actor.identity_keys_iter().next().is_none() {
            if actor.has_attribute_named(key::ZPR_ADDR) {
                actor.add_identity_key(usize::MAX, key::ZPR_ADDR).unwrap();
            } else {
                let mut s = DefaultHasher::new();
                actor.hash(&mut s);
                let hash_str = format!("hash:{:x}", s.finish());
                actor
                    .add_attribute(Attribute::builder(key::ACTOR_HASH).value(hash_str))
                    .unwrap();
                actor.add_identity_key(usize::MAX, key::ACTOR_HASH).unwrap();
            }
        }

        Ok(actor)
    }

    /// Similar to [EvalContext::approve_connection] except this assumes that the passed actor
    /// is already connected and this just checks to see if the actor is compatible with the
    /// current policy.
    pub fn approve_connected(&self, connected_actor: &Actor) -> Result<bool, EvalError> {
        // All the AttrExpr's in the Join Policy must be present as Attributes on the actor and
        // have the same values.  It's ok for the actor to have more attributes than indicated in
        // a Join Policy.
        //
        // If join policy indicates (via flags) that the actor is a node, then the actor must return
        // true for `is_node()`. If there is no node flag then `is_node()` must return false.
        //
        // Any services offered by the actor must be allowed by policy.
        // The policy may have more services for the actor. For a node the visa
        // service's policy pass recalculates its services before calling this
        // (zl-zipline#273); otherwise they are picked up on re-auth. Identity keys are in the same bucket: a policy update does
        // not retroactively re-key a connected actor; new identity attributes are picked
        // up on re-auth via approve_connection.

        // Re-run join-policy matching against the actor's current attributes.
        let claims: Vec<Attribute> = connected_actor.attrs_iter().cloned().collect();
        let matching = self.policy.match_join_policies(&claims);
        if matching.is_empty() {
            // A node must be covered by a join policy; a non-node may remain
            // connected without one (see #227).
            return Ok(!connected_actor.is_node());
        }

        // Union the flags and services from all matching policies, mirroring
        // how `approve_connection` builds the actor.
        let mut flags: EnumSet<JFlag> = EnumSet::new();
        let mut services = HashSet::new();
        for jp in matching {
            flags |= jp.flags;
            if let Some(svcs) = &jp.services {
                services.extend(svcs.iter().cloned());
            }
        }

        // Node role must agree with policy in both directions.
        if flags.contains(JFlag::IsNode) != connected_actor.is_node() {
            return Ok(false);
        }

        // Every service offered by the actor must be allowed by policy. Policy
        // may allow more services than the actor offers; those are picked up by
        // the visa service's policy pass (for a node) or on re-auth, not here.
        if !connected_actor
            .services_iter()
            .all(|s| services.contains(s))
        {
            return Ok(false);
        }

        Ok(true)
    }

    fn match_policies(
        &self,
        allows: bool,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
        policy: &policy_capnp::policy::Reader,
    ) -> Result<Vec<Hit>, EvalError> {
        let mut hits = Vec::new();
        for (i, com_policy) in policy.get_com_policies().unwrap().iter().enumerate() {
            if allows != com_policy.get_allow() {
                continue;
            }
            if allows {
                debug!(target: EVAL, "trying to match allow policy #{i}");
            } else {
                debug!(target: EVAL, "trying to match deny policy #{i}");
            }
            let service_id = com_policy.get_service_id().unwrap().to_str().unwrap();
            // Work out which way the packet flows relative to this policy's
            // service. Forward (a request): the destination port is in one of the
            // policy's scopes and the destination actor provides the service.
            // Reverse (a reply): the same for the source side. Forward is checked
            // against every scope before reverse is tried, so a client port that
            // happens to fall in one scope cannot hide a service port in another.
            let maybe_direction =
                if self.policy_scope_matches(request, &com_policy, ScopeMatchType::Forward)
                    && actor_provides_service(i, "FWD", dst_actor, service_id)
                {
                    debug!(target: EVAL, "policy #{i} matches FWD scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(src_actor, dst_actor, &com_policy, allows) {
                        Some(Direction::Forward)
                    } else {
                        None
                    }
                } else if self.policy_scope_matches(request, &com_policy, ScopeMatchType::Reverse)
                    && actor_provides_service(i, "REV", src_actor, service_id)
                {
                    debug!(target: EVAL, "policy #{i} matches REV scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(dst_actor, src_actor, &com_policy, allows) {
                        Some(Direction::Reverse)
                    } else {
                        None
                    }
                } else {
                    None
                };
            if let Some(direction) = maybe_direction {
                if com_policy.has_signal() {
                    let signal_rdr = com_policy.get_signal().unwrap();
                    let signal = Signal {
                        message: signal_rdr.get_msg().unwrap().to_string().unwrap(),
                        service: signal_rdr.get_svc().unwrap().to_string().unwrap(),
                    };
                    debug!(target: EVAL, "policy #{i} hits {direction} with signal: {:?}", signal);
                    hits.push(Hit::new_with_signal(i, direction, signal));
                } else {
                    debug!(target: EVAL, "policy #{i} hits {direction} no signal");
                    hits.push(Hit::new_no_signal(i, direction));
                }
            }
        }
        debug!(target: EVAL, "matched {} policies", hits.len());
        Ok(hits)
    }

    /// Check that all conditions on the passed `com_policy` are satisfied by
    /// the `client_actor` and `service_actor`.  The policies "client
    /// conditions" are checked against the client_actor, and the "service
    /// conditions" are checked against the service_actor.
    ///
    /// To get an "allow/match", ALL conditions must be satisfied.
    fn match_policy_conditions(
        &self,
        client_actor: &Actor,
        server_actor: &Actor,
        com_policy: &policy_capnp::c_policy::Reader,
        for_allow: bool,
    ) -> bool {
        // All conditions must match for the policy to match. Expired attributes must
        // not help satisfy an allow policy; denies are matched against all attributes,
        // expired or not, so they stay fail-closed.
        if com_policy.has_client_conds() {
            for cond in com_policy.get_client_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, client_actor, for_allow) {
                    debug!(target: EVAL, "-- client condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        if com_policy.has_service_conds() {
            for cond in com_policy.get_service_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, server_actor, for_allow) {
                    debug!(target: EVAL, "-- service condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        true
    }

    /// Returns TRUE if the policy condition is satisfied by the actor. `for_allow`
    /// marks this as part of the allow pass, where expired attributes cannot match.
    fn match_condition_to_actor(
        &self,
        cond: &policy_capnp::attr_expr::Reader,
        actor: &Actor,
        for_allow: bool,
    ) -> bool {
        let value = if !cond.has_value() {
            None
        } else {
            let val_list = cond.get_value().unwrap();
            if val_list.len() == 0 {
                None
            } else if val_list.len() == 1 {
                Some(PAttrValue::Atom(
                    val_list.get(0).unwrap().to_str().unwrap().into(),
                ))
            } else {
                Some(PAttrValue::Set(
                    val_list
                        .iter()
                        .map(|v| v.unwrap().to_str().unwrap().into())
                        .collect(),
                ))
            }
        };
        let key = cond.get_key().unwrap().to_str().unwrap();

        // An expired attribute is indeterminate: we can neither confirm nor rule out
        // its value, so it can never satisfy an allow condition. Note this is not the
        // same as treating it as absent -- absent would make NE and EXCLUDES *pass*,
        // which would let expiry grant access. A key that was never set is unaffected.
        if for_allow && actor.get_attribute(key).is_some_and(|a| a.is_expired()) {
            debug!(target: EVAL, "-- condition key '{}' is expired, cannot match allow", key);
            return false;
        }

        match cond.get_op().unwrap() {
            policy_capnp::AttrOp::Eq => {
                match value {
                    None => {
                        // TODO: This is not valid and should be rejected at policy install.
                        warn!(target: EVAL, "INVALID ZPL: condition key '{}' has EQ op but no value", key);
                        return !for_allow;
                    }
                    Some(PAttrValue::Set(_)) => {
                        // EQ with a set is not supported for now, so this condition is
                        // indeterminate: it cannot satisfy an allow, and a deny keyed on
                        // it must still fire rather than silently disappear.
                        return !for_allow;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if !actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Ne => {
                match value {
                    None => {
                        // TODO: This is not valid and should be rejected at policy install.
                        warn!(target: EVAL, "INVALID ZPL: condition key '{}' has NE op but no value", key);
                        return !for_allow;
                    }
                    Some(PAttrValue::Set(_)) => {
                        // NE with a set is not supported for now, so this condition is
                        // indeterminate: it cannot satisfy an allow, and a deny keyed on
                        // it must still fire rather than silently disappear.
                        return !for_allow;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Has => {
                let blank = match value {
                    None => true,
                    Some(ref v) => v.is_empty(),
                };
                if blank {
                    // This means we match if the actor has the attribute key present.
                    if !actor.has_attribute_named(key) {
                        return false;
                    }
                } else {
                    // HAS means the actor must have all the values set here.
                    if !actor.has_attribute_values(key, value.as_ref().unwrap().as_slice()) {
                        return false;
                    }
                }
            }
            policy_capnp::AttrOp::Excludes => {
                // Any values in here must not be present in the actor.
                // TODO: The compiler does not produce EXCLUDES or NE, so maybe we should remove them.
                let Some(ref values) = value else {
                    // Valueless EXCLUDES is indeterminate rather than a panic: it cannot
                    // satisfy an allow, and a deny keyed on it must still fire.
                    warn!(target: EVAL, "INVALID ZPL: condition key '{}' has EXCLUDES op but no value", key);
                    return !for_allow;
                };
                if actor.has_any_attribute_values(key, values.as_slice()) {
                    return false;
                }
            }
        };
        true
    }

    /// True if any scope of `com_policy` matches `request` in direction `want`.
    fn policy_scope_matches(
        &self,
        request: &PacketDesc,
        com_policy: &policy_capnp::c_policy::Reader,
        want: ScopeMatchType,
    ) -> bool {
        com_policy
            .get_scope()
            .unwrap()
            .iter()
            .any(|scope| scope_matches(request, &scope, &want))
    }
}

/// True if `actor` provides `service_id`, the service named by policy #`idx`.
/// `dir` ("FWD" or "REV") only labels the debug message when it does not.
fn actor_provides_service(idx: usize, dir: &str, actor: &Actor, service_id: &str) -> bool {
    if actor.provides(service_id) {
        return true;
    }
    debug!(
        target: EVAL,
        "policy #{idx} matches {dir} on ports but actor does not provide service {service_id}"
    );
    false
}

/// True if a single policy `scope` matches `request` in direction `want`.
///
/// For TCP/UDP, a forward match means the destination port is the scope's port
/// (or inside its range): a request to the service. A reverse match means the
/// source port is: a reply from the service. A UDP scope flagged one-way never
/// matches in reverse.
///
/// For ICMP the "port" fields carry ICMP types. A single-type scope only matches
/// forward, on that type. A two-type scope (stored as a range) matches forward on
/// its low (request) type and reverse on its high (response) type.
fn scope_matches(
    request: &PacketDesc,
    scope: &policy_capnp::scope::Reader,
    want: &ScopeMatchType,
) -> bool {
    if scope.get_protocol() != request.protocol() {
        return false;
    }
    let is_icmp = request.protocol() == ip_proto::IPV6_ICMP;
    let port_matches = match scope.which() {
        Ok(policy_capnp::scope::Port(pnum)) => {
            let allowed = pnum.get_port_num();
            match (is_icmp, want) {
                (true, ScopeMatchType::Forward) => request.source_port() == allowed,
                (true, ScopeMatchType::Reverse) => false,
                (false, ScopeMatchType::Forward) => request.dest_port() == allowed,
                (false, ScopeMatchType::Reverse) => request.source_port() == allowed,
            }
        }
        Ok(policy_capnp::scope::PortRange(pr)) => {
            let (low, high) = (pr.get_low(), pr.get_high());
            match (is_icmp, want) {
                // ICMP: forward is SRC->DST using the REQUEST type, reverse the RESPONSE type.
                (true, ScopeMatchType::Forward) => request.source_port() == low,
                (true, ScopeMatchType::Reverse) => request.source_port() == high,
                (false, ScopeMatchType::Forward) => (low..=high).contains(&request.dest_port()),
                (false, ScopeMatchType::Reverse) => (low..=high).contains(&request.source_port()),
            }
        }
        Err(::capnp::NotInSchema(_)) => false,
    };
    if !port_matches {
        return false;
    }

    // If we are UDP and the UDP-one-way flag is set, then reverse match is not permitted.
    let one_way_reply = request.protocol() == ip_proto::UDP
        && *want == ScopeMatchType::Reverse
        && matches!(scope.get_flag(), Ok(policy_capnp::ScopeFlag::UdpOneWay));
    !one_way_reply
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attribute::key;
    use crate::joinpolicy::JPolicy;
    use bytes::{Buf, Bytes};
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};
    use std::{path::Path, sync::Once};
    use tracing::Level;
    use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};
    use zpr::policy_types::{AttrExp, AttrOp};

    static TRACING_INIT: Once = Once::new();

    /// init logging
    fn setup() {
        TRACING_INIT.call_once(|| {
            tracing_subscriber::registry()
                .with(fmt::layer().with_thread_ids(true))
                .with(LevelFilter::from_level(Level::DEBUG))
                .init();
        });
    }

    /// Load a binary policy by name from the tests/zpl directory.
    fn load_policy(pname: &str) -> Policy {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let pname = Path::new(manifest_dir)
            .join("tests")
            .join("zpl")
            .join(pname);
        let encoded = std::fs::read(pname).unwrap();
        let encoded_container_bytes = Bytes::from(encoded);
        let container_reader = capnp::serialize::read_message(
            encoded_container_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        let container = container_reader
            .get_root::<policy_capnp::policy_container::Reader>()
            .unwrap();
        if !container.has_policy() {
            panic!("policy container missing 'policy' field");
        }
        let policy_bytes = container.get_policy().unwrap();
        Policy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes)).unwrap()
    }

    /// A user actor as the visa service would hold it after a trusted service
    /// vended its user record: compilers >= 0.16 guard every user rule with
    /// `has user.zpr.authority` (#144), so a fixture user needs the authority
    /// (here the fixtures' `hr` trusted service) to match any user rule.
    fn new_user_actor() -> Actor {
        let mut user = Actor::new();
        user.add_attr_from_parts(key::USER_AUTHORITY, "hr", Duration::from_secs(60))
            .unwrap();
        user
    }

    #[test]
    fn test_basic_eval() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users access content:red databases.
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 2);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }

        // Should deny access to green tagged users.
        let mut green_user = Actor::new();
        green_user
            .add_attr_from_parts("user.zpr.tag.green", "", Duration::from_secs(60))
            .unwrap();
        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 1);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    /// A service configured with several ports (`port = "443, 4343, 8000-8010"`
    /// in multiport.zplc) compiles to one policy line with several scopes. Every
    /// scope must be honoured: a request to any listed port or to a port inside
    /// the range matches forward, a reply from any of them matches reverse, and
    /// a port outside them all matches nothing.
    ///
    /// The client's own (source) port must not decide the direction: a client
    /// whose port happens to fall in one scope, talking to a service port in
    /// another, is still a forward request (and its reply a reverse one).
    #[test]
    fn test_multi_port_scope() {
        setup();
        let pol = load_policy("multiport.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();
        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "web", Duration::from_secs(60))
            .unwrap();

        let client_addr = "fd5a:5052:3000::1";
        let service_addr = "fd5a:5052:3000::2";

        // Single ports from the list, plus both ends and the middle of the range.
        let service_ports = [443, 4343, 8000, 8005, 8010];
        // A client port outside every scope, plus client ports that collide with
        // an earlier or later scope than the service port.
        let client_ports = [12345, 443, 4343, 8005];

        for port in service_ports {
            for client_port in client_ports {
                let ctx_msg = format!("client port {client_port}, service port {port}");

                let request =
                    PacketDesc::new_tcp(client_addr, service_addr, client_port, port).unwrap();
                match ctx.eval_request(&user, &service, &request).unwrap() {
                    PartialEvalResult::AllowWithoutRoute(hits) => {
                        assert_eq!(hits.len(), 1, "{ctx_msg}");
                        assert!(hits[0].direction == Direction::Forward, "{ctx_msg}");
                    }
                    other => panic!("{ctx_msg}: expected forward allow, not {:?}", other),
                }

                let reply =
                    PacketDesc::new_tcp(service_addr, client_addr, port, client_port).unwrap();
                match ctx.eval_request(&service, &user, &reply).unwrap() {
                    PartialEvalResult::AllowWithoutRoute(hits) => {
                        assert_eq!(hits.len(), 1, "{ctx_msg}");
                        assert!(hits[0].direction == Direction::Reverse, "{ctx_msg}");
                    }
                    other => panic!("{ctx_msg}: expected reverse allow, not {:?}", other),
                }
            }
        }

        // Ports outside every scope, including either side of the range.
        for port in [80, 4344, 7999, 8011] {
            let request = PacketDesc::new_tcp(client_addr, service_addr, 12345, port).unwrap();
            match ctx.eval_request(&user, &service, &request).unwrap() {
                PartialEvalResult::Deny(FinalDeny::NoMatch(_)) => {}
                other => panic!("port {port}: expected NoMatch deny, not {:?}", other),
            }
        }
    }

    #[test]
    fn test_visa_info() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users access content:red databases.
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(
                    vinfo.zpl,
                    "(line 2) allow red users to access content:red services"
                );
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0); // high port becomes 0
                assert_eq!(vinfo.dest_port, 80);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    // Ran into an issue where libeval was not checking that the policy ID was applicable.
    // And this simple eval was failing.
    #[test]
    fn test_eval_with_never() {
        setup();
        let pol = load_policy("test-signal.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // User with employee_id and color:red should be able to access database service.
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();
        user.add_attr_from_parts("user.employee_id", "1000", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.employee_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 3);
                assert!(hits[0].direction == Direction::Forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_signal() {
        setup();
        let pol = load_policy("test-signal.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // Set user with color:green so it does not match color:red since in that
        // case we would match two policies.
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.color", "green", Duration::from_secs(60))
            .unwrap();
        user.add_attr_from_parts("user.employee_id", "1000", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.employee_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 3);
                assert!(hits[0].direction == Direction::Forward);
                assert!(hits[0].signal.is_some());
                let signal = hits[0].signal.as_ref().unwrap();
                assert_eq!(signal.message, "employee");
                assert_eq!(signal.service, "signalService");
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_request() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "pingdb", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.employee_id", "1233", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 0x80, 0).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(vinfo.zpl, "(line 5) allow red users to access pingdb");
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0x80);
                assert_eq!(vinfo.dest_port, 0x0);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_reply() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb
        let mut user = new_user_actor();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "pingdb", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.employee_id", "1233", Duration::from_secs(60))
            .unwrap();

        // We picked up an echo reply packet.
        // According to policy this should match.
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::2", "fd5a:5052:3000::1", 0x81, 0).unwrap();

        let decision = ctx.eval_request(&service, &user, &packet).unwrap();
        match decision {
            PartialEvalResult::AllowWithoutRoute(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(vinfo.zpl, "(line 5) allow red users to access pingdb");
                assert_eq!(vinfo.source_addr, packet.five_tuple.source_addr);
                assert_eq!(vinfo.dest_addr, packet.five_tuple.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol());
                assert_eq!(vinfo.source_port, 0x81);
                assert_eq!(vinfo.dest_port, 0x0);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_ping_echo_reply_not_permitted() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // should let red users ping pingdb -- should not let randos send echo-reply to red users.
        let mut user = Actor::new();
        user.add_attr_from_parts("user.zpr.tag.red", "", Duration::from_secs(60))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "foo", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("user.employee_id", "1000", Duration::from_secs(60))
            .unwrap();

        // Echo reply to a red user
        let packet =
            PacketDesc::new_icmp("fd5a:5052:3000::2", "fd5a:5052:3000::1", 0x81, 0).unwrap();
        let decision = ctx.eval_request(&service, &user, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(s)) => {
                assert_eq!(s, "no matching policy");
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_node_can_connect() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut authenticated_claims = Vec::new();
        let mut unauthenticated_claims = Vec::new();

        authenticated_claims.push(Attribute::builder(key::CN).value("node.zpr.org"));

        unauthenticated_claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"));

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        assert!(actor.is_node());

        // And address is set
        assert!(actor.get_zpr_addr().is_some());
        let ipaddr = actor.get_zpr_addr().unwrap().clone();
        assert_eq!(ipaddr, "fd5a:5052:90de::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_connect_allowed_even_with_no_allows() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut authenticated_claims = Vec::new();
        let mut unauthenticated_claims = Vec::new();

        authenticated_claims.push(Attribute::builder(key::CN).value("nobody.zpr.org"));

        unauthenticated_claims.push(Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"));

        match ctx.approve_connection(
            Some(authenticated_claims.as_slice()),
            Some(unauthenticated_claims.as_slice()),
        ) {
            Err(e) => panic!("expected connection approval to succeed, got {:?}", e),
            Ok(actor) => {
                assert!(!actor.is_node());
                assert!(actor.has_attribute_value(key::ROLE, ROLE_ADAPTER));
                // No join policy matched, so the requested (unauthenticated)
                // zpr.addr must have been scrubbed from the actor.
                assert!(actor.get_zpr_addr().is_none());
            }
        };
    }

    // Even when a join policy matches, only zpr.addr is taken from the
    // unauthenticated claims: a self-asserted identity-shaped claim (e.g.
    // `user.sub`) must never reach the actor, or the refresh path would send
    // it to trusted services as a lookup identity and leak another identity's
    // attributes to the claimant.
    #[test]
    fn test_join_match_does_not_commit_non_addr_unauth_claims() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // node.zpr.org matches a join policy in basic.bin2 (see
        // test_node_can_connect), so the zpr.addr claim IS validated and kept.
        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims = vec![
            Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"),
            Attribute::builder("user.sub").value("someone-else"),
        ];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        // The join policy matched: the requested address was committed...
        assert!(actor.is_node());
        assert!(actor.get_zpr_addr().is_some());
        // ...but the self-asserted user.sub claim was not.
        assert!(!actor.has_attribute_named("user.sub"));
    }

    // ---- zipline#97: a requested zpr.addr is a check, never a grant. ----
    // approve_connection commits the peer's requested address only when at
    // least one MATCHED join policy PINS zpr.addr — an exact-equality (Eq)
    // condition with a concrete value in its `matches`. A policy that matches
    // on other keys alone, or carries a non-pinning zpr.addr expression
    // (NE / valueless HAS / EXCLUDES / valued HAS), does not validate
    // the request: the address is scrubbed and the caller pool-allocates.

    /// Single-expression join policy matching CN eq `cn`, with no zpr.addr pin.
    fn jp_cn_eq(cn: &str) -> JPolicy {
        JPolicy {
            matches: vec![AttrExp {
                key: key::CN.to_string(),
                op: AttrOp::Eq,
                value: vec![cn.to_string()],
            }],
            flags: EnumSet::new(),
            services: None,
        }
    }

    /// Join policy matching CN eq `cn` that also pins zpr.addr eq `addr`.
    fn jp_cn_eq_with_addr_pin(cn: &str, addr: &str) -> JPolicy {
        JPolicy {
            matches: vec![
                AttrExp {
                    key: key::CN.to_string(),
                    op: AttrOp::Eq,
                    value: vec![cn.to_string()],
                },
                AttrExp {
                    key: key::ZPR_ADDR.to_string(),
                    op: AttrOp::Eq,
                    value: vec![addr.to_string()],
                },
            ],
            flags: EnumSet::new(),
            services: None,
        }
    }

    /// Join policy matching CN eq `cn` plus an arbitrary zpr.addr expression.
    fn jp_cn_eq_with_addr_exp(cn: &str, op: AttrOp, values: &[&str]) -> JPolicy {
        JPolicy {
            matches: vec![
                AttrExp {
                    key: key::CN.to_string(),
                    op: AttrOp::Eq,
                    value: vec![cn.to_string()],
                },
                AttrExp {
                    key: key::ZPR_ADDR.to_string(),
                    op,
                    value: values.iter().map(|v| v.to_string()).collect(),
                },
            ],
            flags: EnumSet::new(),
            services: None,
        }
    }

    // ---- zipline#181: the services an actor provides follow its attributes. ----

    /// Join policy granting `service` to actors whose `device.tags` has `tag`.
    fn jp_tag_grants_service(tag: &str, service: &str) -> JPolicy {
        JPolicy {
            matches: vec![AttrExp {
                key: "device.tags".to_string(),
                op: AttrOp::Has,
                value: vec![tag.to_string()],
            }],
            flags: EnumSet::new(),
            services: Some(vec![service.to_string()]),
        }
    }

    /// `join_services` is the union of the services of every matching join policy,
    /// and empty when none match.
    #[test]
    fn test_join_services_follow_attributes() {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_tag_grants_service("server", "ssh"));
        pol.push_join_policy(jp_tag_grants_service("media", "plex"));
        pol.push_join_policy(jp_cn_eq("box.zpr.org"));

        let cn = Attribute::builder(key::CN).value("box.zpr.org");
        let tags = |values: &[&str]| Attribute::builder("device.tags").values(values);

        let both = pol.join_services(&[cn.clone(), tags(&["server", "media"])]);
        assert_eq!(both, HashSet::from(["ssh".to_string(), "plex".to_string()]));

        let one = pol.join_services(&[cn.clone(), tags(&["server"])]);
        assert_eq!(one, HashSet::from(["ssh".to_string()]));

        // A matching join policy without services contributes nothing.
        assert!(pol.join_services(&[cn]).is_empty());
    }

    /// An expired hosting attribute grants no service: expiry is indeterminate,
    /// so a refresh that could not reach the source must not keep the service.
    #[test]
    fn test_join_services_ignore_expired_attribute() {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_tag_grants_service("server", "ssh"));

        let expired = Attribute::builder("device.tags")
            .expires_in(Duration::ZERO)
            .value("server");
        std::thread::sleep(Duration::from_millis(5));
        assert!(pol.join_services(&[expired]).is_empty());
    }

    /// As [jp_tag_grants_service], but the join policy also marks the actor a node.
    fn jp_tag_grants_node_service(tag: &str, service: &str) -> JPolicy {
        let mut jp = jp_tag_grants_service(tag, service);
        jp.flags = JFlag::IsNode.into();
        jp
    }

    /// Recomputing for an adapter skips node join policies: an attribute that would
    /// make it match one must not hand a node-only service to an actor that stays an
    /// adapter (connect would have made it a node instead). Codex P1 on PR #50.
    #[test]
    fn test_join_services_for_adapter_skip_node_policies() {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_tag_grants_service("server", "ssh"));
        pol.push_join_policy(jp_tag_grants_node_service("relay", "vss"));

        let tags = Attribute::builder("device.tags").values(["server", "relay"]);
        assert_eq!(
            pol.join_services_for_role(&[tags], false),
            HashSet::from(["ssh".to_string()])
        );
    }

    /// Recomputing for a node grants the union, as connect does, only while it still
    /// matches a node join policy; otherwise it gets nothing (fail-closed, the same
    /// verdict `approve_connected` reaches).
    #[test]
    fn test_join_services_for_node_require_node_policy() {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_tag_grants_service("server", "ssh"));
        pol.push_join_policy(jp_tag_grants_node_service("relay", "vss"));

        let both = Attribute::builder("device.tags").values(["server", "relay"]);
        assert_eq!(
            pol.join_services_for_role(&[both], true),
            HashSet::from(["ssh".to_string(), "vss".to_string()])
        );

        let no_node_match = Attribute::builder("device.tags").value("server");
        assert!(
            pol.join_services_for_role(&[no_node_match], true)
                .is_empty()
        );
    }

    /// Connect stamps exactly what `join_services` computes for the claims.
    #[test]
    fn test_approve_connection_stamps_join_services() {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_tag_grants_service("server", "ssh"));
        let ctx = EvalContext::new(Arc::new(pol));

        let claims = vec![
            Attribute::builder(key::CN).value("box.zpr.org"),
            Attribute::builder("device.tags").value("server"),
        ];
        let actor = ctx
            .approve_connection(Some(claims.as_slice()), None)
            .unwrap();
        assert!(actor.provides("ssh"));
    }

    /// Approve a connection for `cn` requesting zpr.addr `addr` against a
    /// single-join-policy Policy, returning the actor.
    fn approve_with_policy(jp: JPolicy, cn: &str, addr: &str) -> Actor {
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp);
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value(cn)];
        let unauthenticated_claims = vec![Attribute::builder(key::ZPR_ADDR).value(addr)];

        ctx.approve_connection(
            Some(authenticated_claims.as_slice()),
            Some(unauthenticated_claims.as_slice()),
        )
        .unwrap()
    }

    // 1. A join policy that matches on CN alone (no zpr.addr condition) does
    //    not validate a requested address: the actor is approved but the
    //    address is scrubbed.
    #[test]
    fn test_addr_scrubbed_when_matched_policy_has_no_pin() {
        setup();
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_cn_eq("cn-only.zpr.org"));
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("cn-only.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::99")];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        // The join policy matched on CN, so the actor is approved...
        assert!(actor.has_attribute_named(key::CN));
        // ...but no matched policy pins zpr.addr, so the requested address is
        // unvalidated and must be scrubbed; the caller pool-allocates.
        assert!(actor.get_zpr_addr().is_none());
    }

    // 2. A matched policy that pins zpr.addr eq X commits a request for X.
    //    (Pins the existing test_node_can_connect behaviour to the new rule:
    //    basic.bin2's node join policy carries the zpr.addr condition.)
    #[test]
    fn test_addr_committed_when_matched_policy_pins_it() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1")];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        assert!(actor.is_node());
        assert_eq!(
            actor.get_zpr_addr(),
            Some(&"fd5a:5052:90de::1".parse::<IpAddr>().unwrap())
        );
    }

    // 3. A pin of X with a request of Y: the pinning policy does not match at
    //    all (existing matcher semantics), so nothing validates the request
    //    and it is scrubbed.
    #[test]
    fn test_addr_mismatching_pin_scrubbed() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::2")];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        // The node join policy pins fd5a:5052:90de::1, so with a request of
        // ::2 it does not match: no node role, and the address is scrubbed.
        assert!(!actor.is_node());
        assert!(actor.get_zpr_addr().is_none());
    }

    // 4. Two policies match and only one carries the zpr.addr pin: one
    //    matched pin is enough to commit the request.
    #[test]
    fn test_addr_committed_when_any_matched_policy_pins() {
        setup();
        let mut pol = Policy::new_empty();
        pol.push_join_policy(jp_cn_eq("two.zpr.org"));
        pol.push_join_policy(jp_cn_eq_with_addr_pin("two.zpr.org", "fd5a:5052:90de::7"));
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("two.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::7")];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        assert_eq!(
            actor.get_zpr_addr(),
            Some(&"fd5a:5052:90de::7".parse::<IpAddr>().unwrap())
        );
    }

    // 4b. zipline#97 review P1 (PR #32): only an exact Eq expression pins.
    //     A matched policy whose zpr.addr expression is NE cannot commit the
    //     request: `zpr.addr NE X` matches (and thereby "validates") every
    //     address except X, so the peer would be choosing its own address.
    #[test]
    fn test_addr_ne_expression_does_not_pin() {
        setup();
        let actor = approve_with_policy(
            jp_cn_eq_with_addr_exp("ne.zpr.org", AttrOp::Ne, &["fd5a:5052:90de::1"]),
            "ne.zpr.org",
            "fd5a:5052:90de::2",
        );
        // The policy matched (::2 != ::1), so the actor is approved...
        assert!(actor.has_attribute_named(key::CN));
        // ...but NE does not pin an address: the request must be scrubbed.
        assert!(actor.get_zpr_addr().is_none());
    }

    // 4c. A valueless HAS (`zpr.addr HAS ""`) only tests key presence: it
    //     matches any requested address, so it must not count as a pin.
    #[test]
    fn test_addr_valueless_has_does_not_pin() {
        setup();
        let actor = approve_with_policy(
            jp_cn_eq_with_addr_exp("has.zpr.org", AttrOp::Has, &[]),
            "has.zpr.org",
            "fd5a:5052:90de::3",
        );
        assert!(actor.has_attribute_named(key::CN));
        assert!(actor.get_zpr_addr().is_none());
    }

    // 4d. A non-empty EXCLUDES matches every address outside the excluded
    //     set, so it must not count as a pin either.
    #[test]
    fn test_addr_excludes_expression_does_not_pin() {
        setup();
        let actor = approve_with_policy(
            jp_cn_eq_with_addr_exp("excl.zpr.org", AttrOp::Excludes, &["fd5a:5052:90de::1"]),
            "excl.zpr.org",
            "fd5a:5052:90de::4",
        );
        assert!(actor.has_attribute_named(key::CN));
        assert!(actor.get_zpr_addr().is_none());
    }

    // 4e. Even HAS with a concrete value is conservative-rejected: for the
    //     single-valued zpr.addr it behaves like Eq today, but HAS is subset
    //     semantics, not exact equality — only Eq with a non-empty value pins.
    #[test]
    fn test_addr_has_with_value_does_not_pin() {
        setup();
        let actor = approve_with_policy(
            jp_cn_eq_with_addr_exp("hasv.zpr.org", AttrOp::Has, &["fd5a:5052:90de::5"]),
            "hasv.zpr.org",
            "fd5a:5052:90de::5",
        );
        assert!(actor.has_attribute_named(key::CN));
        assert!(actor.get_zpr_addr().is_none());
    }

    // 5. An unauthenticated `device.zpr_addr` claim never reaches the actor,
    //    even when a matched policy pins zpr.addr and the request commits.
    //    Extends the guarantee of
    //    test_join_match_does_not_commit_non_addr_unauth_claims: A3 reads
    //    device.zpr_addr from the actor, so pin it explicitly.
    #[test]
    fn test_unauth_device_zpr_addr_never_reaches_actor() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims = vec![
            Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1"),
            Attribute::builder("device.zpr_addr").value("fd5a:5052:90de::bad"),
        ];

        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        // The matched pin commits the requested zpr.addr...
        assert!(actor.get_zpr_addr().is_some());
        // ...but the self-asserted device.zpr_addr claim must not.
        assert!(!actor.has_attribute_named("device.zpr_addr"));
    }

    // A node approved under the current policy should still pass re-check.
    #[test]
    fn test_approve_connected_node_still_valid() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1")];
        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();
        assert!(actor.is_node());

        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // A non-node actor that matches no join policy may stay connected (#227).
    #[test]
    fn test_approve_connected_non_node_no_policy_ok() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("nobody.zpr.org")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();
        assert!(!actor.is_node());

        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // A node whose attributes match no join policy must be rejected.
    #[test]
    fn test_approve_connected_node_not_in_policy() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(key::CN, "rando.zpr.org", Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attr_from_parts(key::ROLE, ROLE_NODE, Duration::from_secs(1000))
            .unwrap();
        assert!(actor.is_node());

        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    // Build the node actor from join policy 4 (node.zpr.org) with the given services.
    fn node_actor_with_services(services: &[&str]) -> Actor {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(
                key::ZPR_ADDR,
                "fd5a:5052:90de::1",
                Duration::from_secs(1000),
            )
            .unwrap();
        actor
            .add_attr_from_parts(key::CN, "node.zpr.org", Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attr_from_parts(key::ROLE, ROLE_NODE, Duration::from_secs(1000))
            .unwrap();
        actor
            .add_attribute(
                Attribute::builder(key::SERVICES)
                    .expires_in(Duration::from_secs(1000))
                    .values(services.iter().copied()),
            )
            .unwrap();
        actor
    }

    // An actor offering only a subset of the services its policy allows is still
    // approved; the policy having extra services does not reject the connection.
    #[test]
    fn test_approve_connected_policy_has_extra_services_ok() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // Join policy 4 allows both "zpr/n0/vss" and "/zpr/n0"; offer just one.
        let actor = node_actor_with_services(&["zpr/n0/vss"]);
        assert!(ctx.approve_connected(&actor).unwrap());
    }

    // An actor offering a service its policy does not allow must be rejected.
    #[test]
    fn test_approve_connected_actor_service_not_in_policy() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // "not-allowed" is not among join policy 4's permitted services.
        let actor = node_actor_with_services(&["zpr/n0/vss", "not-allowed"]);
        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    /// Build an attribute that is already expired.
    fn expired(key: &str, value: &str) -> Attribute {
        Attribute::builder(key)
            .expires(SystemTime::now() - Duration::from_secs(1))
            .value(value)
    }

    /// A user whose tag has expired cannot satisfy the allow policy that keys on it.
    #[test]
    fn test_expired_attr_cannot_match_allow() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut user = Actor::new();
        user.add_attribute(expired("user.zpr.tag.red", "")).unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(_)) => {}
            _ => panic!("expected NoMatch deny, not {:?}", decision),
        }
    }

    /// Expiry must never *grant* access: the deny pass ignores expiry, so an expired
    /// green tag still hits the deny policy rather than falling through to NoMatch.
    #[test]
    fn test_expired_attr_does_not_flip_deny() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut green_user = Actor::new();
        green_user
            .add_attribute(expired("user.zpr.tag.green", ""))
            .unwrap();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::Deny(hits)) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 1);
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    /// A key the actor never sets at all behaves exactly as before: the new guard is
    /// keyed on present-but-expired, not on absence.
    #[test]
    fn test_absent_attr_unaffected_by_expiry_guard() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        // No user.zpr.tag at all -- neither the deny nor the allow policy can match.
        let user = Actor::new();

        let mut service = Actor::new();
        service
            .add_attr_from_parts(key::SERVICES, "database", Duration::from_secs(60))
            .unwrap();
        service
            .add_attr_from_parts("service.content", "red", Duration::from_secs(60))
            .unwrap();
        let packet =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            PartialEvalResult::Deny(FinalDeny::NoMatch(_)) => {}
            _ => panic!("expected NoMatch deny, not {:?}", decision),
        }
    }

    /// A connected node whose join-policy key (CN) has expired matches no join policy
    /// and must be disconnected rather than silently re-approved. Role is a cached
    /// snapshot and NEVER_EXPIRES, so `is_node()` still reports true.
    #[test]
    fn test_approve_connected_expired_join_key_rejects_node() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let mut actor = node_actor_with_services(&["zpr/n0/vss"]);
        // Overwrite the CN join policy 4 keys on with an expired copy.
        actor
            .add_attribute(expired(key::CN, "node.zpr.org"))
            .unwrap();
        assert!(actor.is_node());

        assert!(!ctx.approve_connected(&actor).unwrap());
    }

    /// Build a standalone `AttrExpr` message so a single condition can be evaluated
    /// without compiling a whole policy.
    fn cond_message(
        key: &str,
        op: policy_capnp::AttrOp,
        values: &[&str],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut expr = msg.init_root::<policy_capnp::attr_expr::Builder>();
            expr.set_key(key);
            expr.set_op(op);
            let mut vlist = expr.init_value(values.len() as u32);
            for (i, v) in values.iter().enumerate() {
                vlist.set(i as u32, *v);
            }
        }
        msg
    }

    /// An actor that authenticates with a CN gets exactly the CN as its identity key,
    /// even when it also carries a zpr.addr (guard test for the identity-key cascade).
    #[test]
    fn test_identity_keys_default_to_cn() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder(key::CN).value("node.zpr.org")];
        let unauthenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::1")];
        let actor = ctx
            .approve_connection(
                Some(authenticated_claims.as_slice()),
                Some(unauthenticated_claims.as_slice()),
            )
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
        assert_eq!(actor.get_identity(), Some(vec!["node.zpr.org".to_string()]));
    }

    /// Without a CN, an actor carrying a zpr.addr uses that address as its identity key.
    #[test]
    fn test_identity_keys_fall_back_to_zpr_addr_without_cn() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims =
            vec![Attribute::builder(key::ZPR_ADDR).value("fd5a:5052:90de::2")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ZPR_ADDR]);
    }

    /// With neither CN nor zpr.addr, a synthesized zpr.actor_hash attribute becomes the
    /// identity key, so the identity-key set is never empty.
    #[test]
    fn test_identity_keys_fall_back_to_actor_hash() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(Arc::new(pol));

        let authenticated_claims = vec![Attribute::builder("user.color").value("red")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ACTOR_HASH]);
        let hash_attr = actor.get_attribute(key::ACTOR_HASH).unwrap();
        assert!(hash_attr.get_value().first().unwrap().starts_with("hash:"));
    }

    /// Build a TrustedService test record from attribute-mapping strings and the
    /// service-side names of its identity attributes.
    fn ts(id: &str, mappings: &[&str], identity: &[&str]) -> zpr::policy_types::TrustedService {
        zpr::policy_types::TrustedService {
            service_id: id.to_string(),
            expiration_seconds: 3600,
            returns_attrs: mappings
                .iter()
                .map(|m| zpr::policy_types::parse_attribute_mapping(m).unwrap())
                .collect(),
            identity_attrs: identity.iter().map(|s| s.to_string()).collect(),
            oidc: None,
            attr_query: None,
        }
    }

    /// Build an EvalContext over an in-memory policy carrying the given trusted services.
    fn ctx_with_trusted_services(records: &[zpr::policy_types::TrustedService]) -> EvalContext {
        let bytes = crate::policy::policy_bytes_with_trusted_services(records);
        EvalContext::new(Arc::new(Policy::new_from_policy_bytes(bytes).unwrap()))
    }

    /// A policy-declared identity attribute joins the builtin CN identity key: the two
    /// are a union, not a fallback. The core behavior of issue #201.
    #[test]
    fn test_policy_identity_attr_unions_with_cn() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts(
            "hr",
            &["employee_id -> user.employee_id"],
            &["employee_id"],
        )]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.employee_id").value("1233"),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN, "user.employee_id"]);
        assert_eq!(
            actor.get_identity(),
            Some(vec!["a.zpr".to_string(), "1233".to_string()])
        );
    }

    /// An actor identified by a policy-declared attribute alone gets that key and no
    /// synthesized actor hash.
    #[test]
    fn test_policy_identity_attr_without_cn_is_not_hashed() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts(
            "hr",
            &["employee_id -> user.employee_id"],
            &["employee_id"],
        )]);

        let authenticated_claims = vec![Attribute::builder("user.employee_id").value("1233")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec!["user.employee_id"]);
        assert!(actor.get_attribute(key::ACTOR_HASH).is_none());
    }

    /// A declared identity attribute the actor does not carry changes nothing: the CN
    /// stays the sole identity key (the no-regression case every current caller hits).
    #[test]
    fn test_policy_identity_attr_absent_from_actor_leaves_cn() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts(
            "hr",
            &["employee_id -> user.employee_id"],
            &["employee_id"],
        )]);

        let authenticated_claims = vec![Attribute::builder(key::CN).value("a.zpr")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// Declaring an identity attribute must not suppress the last-resort hash for an
    /// actor that carries neither the CN nor the declared attribute.
    #[test]
    fn test_no_identity_attr_present_still_hashes() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts(
            "hr",
            &["employee_id -> user.employee_id"],
            &["employee_id"],
        )]);

        let authenticated_claims = vec![Attribute::builder("user.color").value("red")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::ACTOR_HASH]);
    }

    /// Policy-declared keys keep policy order after the CN; fails if the loop inserts
    /// at order 0 (which would reverse them).
    #[test]
    fn test_policy_identity_keys_follow_policy_order() {
        setup();
        let ctx =
            ctx_with_trusted_services(&[ts("hr", &["a -> user.a", "z -> user.z"], &["z", "a"])]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.a").value("va"),
            Attribute::builder("user.z").value("vz"),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN, "user.z", "user.a"]);
    }

    /// A policy that names the CN itself as an identity attribute must not duplicate it:
    /// add_identity_key does not dedupe, so the union loop has to.
    #[test]
    fn test_policy_identity_cn_is_not_duplicated() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("hr", &["cn -> device.zpr.adapter.cn"], &["cn"])]);

        let authenticated_claims = vec![Attribute::builder(key::CN).value("a.zpr")];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// A tag mapping declared as identity resolves to nothing: tags are valueless, so
    /// carrying the tag attribute never adds an identity key.
    #[test]
    fn test_policy_identity_tag_spec_is_not_an_identity_key() {
        setup();
        let ctx = ctx_with_trusted_services(&[ts("hr", &["gov -> #user.government"], &["gov"])]);

        let authenticated_claims = vec![
            Attribute::builder(key::CN).value("a.zpr"),
            Attribute::builder("user.zpr.tag.government").value(""),
        ];
        let actor = ctx
            .approve_connection(Some(authenticated_claims.as_slice()), None)
            .unwrap();

        let keys: Vec<&String> = actor.identity_keys_iter().collect();
        assert_eq!(keys, vec![key::CN]);
    }

    /// Conditions libeval cannot evaluate -- valueless EQ/NE/EXCLUDES, and set-valued
    /// EQ/NE -- are indeterminate: they must never satisfy an allow, and must never let
    /// a deny silently stop matching. Valueless EXCLUDES also used to panic here.
    #[test]
    fn test_indeterminate_conditions_fail_safe() {
        setup();
        let ctx = EvalContext::new(Arc::new(load_policy("basic.bin2")));
        let actor = Actor::new();

        let cases: [(policy_capnp::AttrOp, &[&str]); 5] = [
            (policy_capnp::AttrOp::Eq, &[]),
            (policy_capnp::AttrOp::Ne, &[]),
            (policy_capnp::AttrOp::Excludes, &[]),
            (policy_capnp::AttrOp::Eq, &["a", "b"]),
            (policy_capnp::AttrOp::Ne, &["a", "b"]),
        ];
        for (op, values) in cases {
            let msg = cond_message("user.zpr.tag", op, values);
            let cond = msg
                .get_root_as_reader::<policy_capnp::attr_expr::Reader>()
                .unwrap();
            assert!(
                !ctx.match_condition_to_actor(&cond, &actor, true),
                "{op:?} with {values:?} must not satisfy an allow"
            );
            assert!(
                ctx.match_condition_to_actor(&cond, &actor, false),
                "{op:?} with {values:?} must keep a deny matching"
            );
        }
    }
}
