//! Visa request worker work on matching packets to policy in order to create visas.
//! The beating heart of the visa service.
//!
//! Each worker gets a single visa request and tries to run it through the policy.
//! There are several outcomes:
//! - One or both actors may be missing (disconnected)
//! - There may not be a route between the actors, so request fails.
//! - One or both actors may need to be refreshed from attribute services.
//! - One or both actors may have expired authentication.
//! - A visa may already exist and policy has not changed, in which case we can use existing visa.
//! - The visa may be denied by policy.
//! - The visa may be allowed, but not over any available route, so that is a deny.
//! - If at the end of all this a visa is permitted, then
//! - If policy has not been updated in the meanwhile, we issue a visa, else we fail it and hope caller tries again.
//!
//! Once a visa is issued we need to pick the path and figure out which nodes need to be informed.
//! There may be path constraints that make the visa invalid.
//!
//! Once we have a path, the visa is queued up for install on all the impacted nodes and
//! returned to the caller.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use futures::future::{FutureExt, join_all};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_ADAPTER, key};
use libeval::eval_result::Hit;
use libeval::policy::Policy;
use libeval::route::Route;

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, warn};
use zpr::vsapi_types::{DenyCode, PacketDesc, Visa};

use crate::actor_attributes::refresh_and_persist_actor;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::error::ServiceError;
use crate::logging::targets::VREQ;
use crate::packet::describe_five_tuple;
use crate::visa_bootstrap;
use crate::visa_mgr::VisaWithMetadata;
use crate::visa_policy::{
    PolicyOutcome, evaluate_against_policy, resolve_docking_node, route_for_allow,
};
use crate::{config, net_mgr};

pub enum VisaDecision {
    Allow(Visa, Route),
    Deny(DenyCode),
}

/// The result is either a [Visa], or a regular denial, or there was an unexpected failure
/// and you get a [ServiceError].
pub type VisaRequestResult = Result<VisaDecision, ServiceError>;

/// TODO: add a job ID for tracing/logging.
pub struct VisaRequestJob {
    pub requesting_node: IpAddr,
    pub packet_desc: PacketDesc,
    // A channel to send the result back to the requester.
    response_chan: oneshot::Sender<VisaRequestResult>,
}

// Visa requests come into the arena where they are processed by workers.
pub async fn launch_arena(
    asm: Arc<Assembly>,
    incoming: mpsc::Receiver<VisaRequestJob>,
    max_concurrent: usize,
) {
    let stream = ReceiverStream::new(incoming);

    // TODO: This looks slick but we may want to know when we are under pressure.
    stream
        .for_each_concurrent(max_concurrent, |job| {
            tokio::spawn(process_visa_request_job(asm.clone(), job)).map(|r| r.unwrap())
        })
        .await;
}

/// Helper function to submit a visa request job and wait for the decision.
/// All visa request jobs should run through this so that visa request related counters
/// are properly updated.
///
/// ### Errors
/// - [ServiceError::Timeout] if the request times out.
/// - [ServiceError::InternalError] if there is an internal error enqueuing the request or receiving the response.
pub async fn request_visa_wait_response(
    asm: &Assembly,
    requesting_node: &IpAddr,
    pkt_data: PacketDesc,
    timeout: Duration,
) -> Result<VisaDecision, ServiceError> {
    let deadline = tokio::time::Instant::now() + timeout;
    // Copied out before the job takes ownership of pkt_data; needed for the deny log below.
    let five_tuple = pkt_data.five_tuple;
    let (job, response_rx) = VisaRequestJob::new(requesting_node.clone(), pkt_data);

    asm.counters.incr(CounterType::VisaRequests);
    asm.counters
        .incr_node(CounterType::VisaRequests, requesting_node);
    asm.counters.update_request_time(requesting_node);

    match tokio::time::timeout_at(deadline, asm.vreq_chan.reserve()).await {
        Ok(Ok(permit)) => {
            permit.send(job);
            Ok(())
        }

        Ok(Err(_closed)) => {
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(
                "internal error enqueuing visa request".to_string(),
            ))
        }

        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestQueueFull);
            Err(ServiceError::Timeout(
                "timeout enqueuing visa request".into(),
            ))
        }
    }?;

    // Now wait for a response with the remaining timeout.
    match tokio::time::timeout_at(deadline, response_rx).await {
        // Increment the appropriate counters before returning.
        Ok(Ok(vr_result)) => match vr_result {
            Ok(VisaDecision::Allow(_, _)) => {
                asm.counters.incr(CounterType::VisaRequestsApproved);
                asm.counters
                    .incr_node(CounterType::VisaRequestsApproved, requesting_node);

                vr_result
            }
            Ok(VisaDecision::Deny(ref code)) => {
                asm.counters.incr(CounterType::VisaRequestsDenied);
                asm.counters
                    .incr_node(CounterType::VisaRequestsDenied, requesting_node);
                asm.deny_log.record(&five_tuple, code);
                vr_result
            }
            Err(_) => {
                asm.counters.incr(CounterType::VisaRequestFailed);
                vr_result
            }
        },
        Ok(Err(e)) => {
            // Queue read error -- probably closed?
            asm.counters.incr(CounterType::VisaRequestQueueError);
            Err(ServiceError::Internal(format!(
                "queue error receiving visa request response: {}",
                e
            )))
        }
        Err(_timedout) => {
            asm.counters.incr(CounterType::VisaRequestTimeout);
            Err(ServiceError::Timeout(format!(
                "timeout waiting for visa request response after {:?}",
                timeout
            )))
        }
    }
}

impl VisaRequestJob {
    pub fn new(
        requesting_node: IpAddr,
        packet_desc: PacketDesc,
    ) -> (Self, oneshot::Receiver<VisaRequestResult>) {
        let (tx, rx) = oneshot::channel();
        (
            VisaRequestJob {
                requesting_node,
                packet_desc,
                response_chan: tx,
            },
            rx,
        )
    }

    /// Complete this job by sending a result to the requester.
    /// Logs a warning if the requester has dropped the receiver.
    ///
    pub fn complete(self, result: VisaRequestResult) {
        if let Err(_) = self.response_chan.send(result) {
            // Means the requester has dropped the receiver.
            warn!(target: VREQ,
                "failed to enqueue visa request result for {:?}",
                self.requesting_node
            );
        }
    }
}

/// Main processing function for processing a visa request.
///
/// This is just a rough sketch for now.
async fn process_visa_request_job(asm: Arc<Assembly>, job: VisaRequestJob) {
    // Run the job, send the result back over the job response channel.
    let vrr = process_visa_request(asm.clone(), &job).await;
    job.complete(vrr);
}

/// Run visa request.
async fn process_visa_request(asm: Arc<Assembly>, job: &VisaRequestJob) -> VisaRequestResult {
    let (source_actor, dest_actor) = get_actors(&asm, job).await?;

    // An endpoint with no actor may be a peer that has not connected yet, on either end of a
    // VSAPI flow: the peer's own SYN, or the reply direction of it. Policy cannot answer
    // either; the pre-minted bootstrap visa can.
    if source_actor.is_none() || dest_actor.is_none() {
        if let Some(decision) =
            visa_bootstrap::visa_for_future_peer_request(&asm, job, &source_actor, &dest_actor)
                .await
        {
            return Ok(decision);
        }
    }

    let (mut source_actor, mut dest_actor) =
        match resolve_actors_or_deny(&asm, job, source_actor, dest_actor).await {
            Ok(actors) => actors,
            Err(decision) => return Ok(decision),
        };

    // Both actors must have addresses. Extract them here or return a fail.
    let source_zpr_addr = match source_actor.get_zpr_addr() {
        Some(addr) => *addr,
        None => {
            debug!(target: VREQ,
                "visa request from {:?} denied: source actor {:?} has no ZPR address",
                job.requesting_node, source_actor
            );
            return Ok(VisaDecision::Deny(DenyCode::SourceNotFound));
        }
    };
    let dest_zpr_addr = match dest_actor.get_zpr_addr() {
        Some(addr) => *addr,
        None => {
            debug!(target: VREQ,
                "visa request from {:?} denied: dest actor {:?} has no ZPR address",
                job.requesting_node, dest_actor
            );
            return Ok(VisaDecision::Deny(DenyCode::DestNotFound));
        }
    };

    // Bind the request to the requesting node (zipline#183): refuse it unless that
    // node docks the source or the destination actor. VISA_SERVICE.md requires the
    // requester to have a directly connected ingress or egress adapter; without
    // this check a subverted node could probe policy for flows between other
    // actors ("allowed" leaked as an internal error, distinguishable from a deny)
    // and push unrequested visas onto other nodes' paths. The deny is deliberately
    // DenyCode::NoMatch -- byte-for-byte the response an ordinary policy no-match
    // produces -- so the refusal reveals nothing about what policy would have
    // said; the log below is the only record (server-side) of the real reason.
    // Fabricated AAA actors resolve through the AAA table, which the request side
    // registered to `job.requesting_node` moments ago, so AAA passes by
    // construction. The bootstrap path returned above, before this check.
    //
    // This early check is not the binding guarantee -- it rejects off-path probes
    // before the refresh awaits below spend anything on them. The authoritative
    // check re-runs on the Allow arm against the docking state evaluation itself
    // resolved (PR #52 review, Codex P1): docking can move while those awaits are
    // suspended, and a snapshot taken here can authorize a requester that no
    // longer docks either endpoint by the time policy evaluates.
    let src_dock = resolve_docking_node(&asm, &source_actor, &source_zpr_addr);
    let dst_dock = resolve_docking_node(&asm, &dest_actor, &dest_zpr_addr);
    if src_dock != Some(job.requesting_node) && dst_dock != Some(job.requesting_node) {
        warn!(target: VREQ,
            "visa request from node {} denied: flow {} is between actors not docked at \
             the requesting node (source docks at {:?}, dest docks at {:?})",
            job.requesting_node,
            describe_five_tuple(&job.packet_desc),
            src_dock,
            dst_dock
        );
        return Ok(VisaDecision::Deny(DenyCode::NoMatch));
    }

    // If necessary, refresh any expired attributes
    if let Err(e) = refresh_and_persist_actor(&asm, &mut source_actor).await {
        error!(target: VREQ, "failed to update source actor after refreshing attributes: {}", e);
        return Ok(VisaDecision::Deny(DenyCode::NoReason));
    }
    if let Err(e) = refresh_and_persist_actor(&asm, &mut dest_actor).await {
        error!(target: VREQ, "failed to update dest actor after refreshing attributes: {}", e);
        return Ok(VisaDecision::Deny(DenyCode::NoReason));
    }

    // Test seam (zipline#183 review): the two refresh awaits above are suspension
    // points where docking state can move. A gated test parks the request here and
    // mutates the connection table, standing in for a disconnect/reconnect that
    // lands mid-await -- deterministic, no timing games. Compiled out of release.
    #[cfg(test)]
    race_gate::pause_if_gated(&job.requesting_node).await;

    // Docking-node resolution, routing, and policy eval all live in the shared
    // core (used by the Phase 2 sweep too). Actor resolution above stays
    // per-caller — the request path fabricates AAA and denies on missing.
    let policy = asm.policy_mgr.get_current();
    let outcome = evaluate_against_policy(
        &asm,
        &source_actor,
        &dest_actor,
        &source_zpr_addr,
        &dest_zpr_addr,
        &job.packet_desc,
        &policy,
    )
    .await?;

    match outcome {
        PolicyOutcome::Allow {
            hits,
            default_route,
            src_dock,
            dst_dock,
        } => {
            // Re-run the requester-binding check against the docking state the
            // evaluation itself resolved (zipline#183, PR #52 review, Codex P1).
            // The early check above ran before the refresh awaits; if the
            // requester's endpoint undocked and re-docked elsewhere while they
            // were suspended, the allow would otherwise reach visa_from_allow,
            // which stores the visa and starts path distribution before
            // actualization fails for the now-off-path requester -- restoring
            // exactly the oracle and unrequested pushes the early check exists
            // to prevent. Same deliberate Deny(NoMatch) + server-side warn.
            if src_dock != job.requesting_node && dst_dock != job.requesting_node {
                warn!(target: VREQ,
                    "visa request from node {} denied: docking moved during the request; \
                     flow {} is no longer between actors docked at the requesting node \
                     (source docks at {:?}, dest docks at {:?})",
                    job.requesting_node,
                    describe_five_tuple(&job.packet_desc),
                    src_dock,
                    dst_dock
                );
                return Ok(VisaDecision::Deny(DenyCode::NoMatch));
            }
            visa_from_allow(
                asm.clone(),
                job,
                &hits,
                &policy,
                default_route,
                &source_actor,
                &dest_actor,
            )
            .await
        }
        PolicyOutcome::Deny(code) => Ok(VisaDecision::Deny(code)),
    }
}

/// Run one visa request end to end, for tests in other modules. A [VisaRequestJob]'s response
/// channel is private, so they cannot drive [process_visa_request] themselves.
#[cfg(test)]
pub(crate) async fn process_visa_request_for_test(
    asm: Arc<Assembly>,
    requesting_node: IpAddr,
    pkt: PacketDesc,
) -> VisaDecision {
    let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
    process_visa_request(asm, &job).await.unwrap()
}

/// Fabricate an AAA actor for an anonymous endpoint at the given address.
fn fabricate_aaa_actor(anon_addr: &IpAddr, expiration: SystemTime) -> Actor {
    let mut anon_actor = Actor::new();
    let _ =
        anon_actor.add_attribute(Attribute::builder(key::ZPR_ADDR).value(anon_addr.to_string()));
    let _ = anon_actor
        .add_attribute(Attribute::builder(key::DEVICE_AUTHORITY).value("vs_hack_anon_to_auth"));
    let _ = anon_actor.add_attribute(Attribute::builder(key::ROLE).value(ROLE_ADAPTER));
    let _ = anon_actor.add_attribute(
        Attribute::builder(key::CN)
            .expires(expiration)
            .value(format!("hack.{}.zpr", anon_addr)),
    );
    let _ = anon_actor.add_identity_key(0, key::CN);
    anon_actor
}

/// Given that we have an ALLOW decision, pass the hist list in here and we will pick the first
/// hit and create a visa based on it.
///
/// If the hit has a route, we use that, otherwise we use the default route passed in. If there
/// is no default route and no route in the hit the create fails.
///
/// `hits` - Positive hits from the evaluator. We choose the first one.
/// `default_route` - A default route for the visa, only used if there is no route on the first hit.
/// Creates and returns the visa for the requesting node, then spawns a background task to
/// push actualized copies to any other nodes on the multihop path.
///
/// Note that an ALLOW decision can still come back as a [VisaDecision::Deny]: if the
/// authentication or attribute expirations leave less than [config::MIN_VISA_LIFETIME] to
/// work with, the visa would lapse before the nodes could install and use it, so we deny
/// rather than issue it.
async fn visa_from_allow(
    asm: Arc<Assembly>,
    job: &VisaRequestJob,
    hits: &[Hit],
    policy: &Policy,
    default_route: Option<Route>,
    src_actor: &Actor,
    dst_actor: &Actor,
) -> Result<VisaDecision, ServiceError> {
    debug_assert!(!hits.is_empty(), "allow decision with no hits"); // should never happen.
    let policy_version = policy.get_version().unwrap_or(0);
    let vinst = policy.vinst();
    // TODO: For now we pick the first hit.
    let zpl = policy
        .get_cpol_source(hits[0].match_idx)
        .unwrap_or("")
        .to_string();

    let allowed_route: Route = route_for_allow(hits, default_route)?;

    let expiration = compute_expiration(src_actor, dst_actor, policy, &hits[0])?;

    // Too little time left to be usable. Deny rather than issue a visa that cannot be
    // installed before it lapses -- and that the store would silently discard.
    if expiration < SystemTime::now() + config::MIN_VISA_LIFETIME {
        debug!(target: VREQ,
            "visa request from {:?} denied: computed expiration {:?} leaves less than {:?}",
            job.requesting_node, expiration, config::MIN_VISA_LIFETIME
        );
        return Ok(VisaDecision::Deny(DenyCode::NoReason));
    }

    let visawmd = asm
        .visa_mgr
        .create_visa(
            &asm,
            &job.requesting_node,
            &job.packet_desc,
            &hits[0],
            &allowed_route,
            zpl,
            policy_version,
            vinst,
            expiration,
        )
        .await?;

    // Clone the visa for the requesting node before moving visawmd into the background task.
    let visa_for_requester = visawmd.visa.clone();
    let req_node = job.requesting_node;
    let asm_bg = asm.clone();
    tokio::spawn(async move {
        distribute_visa_on_path(asm_bg, visawmd, req_node).await;
    });

    let visa = asm
        .visa_mgr
        .actualize_visa_for_target_node(visa_for_requester, &job.requesting_node)
        .await?;
    Ok(VisaDecision::Allow(visa, allowed_route))
}

/// Compute a visa expiration value. The expiration is set to the soonest of:
/// - source actor authentication expiration.
/// - dest actor authentication expiration.
/// - soonest attribute expiration used in the policy conditions for the hit.
/// - the [key::SERVICES] attribute on the providing actor, which selected the policy.
/// - the maximum visa lifetime [config::MAX_VISA_LIFETIME].
///
/// Note/(TODO?) that [key::SERVICES] holds every service id in a single attribute, so there is one
/// expiration for the whole set: a provider whose service ids come from sources with
/// different TTLs is bounded by the soonest of them.
///
/// TODO: In future we may want to specify a max lifetime in the matched communication policy.
/// TODO: We may want max lifetime to be a policy setting, not compile time setting.
///
/// ### Errors
/// - [ServiceError::Internal] if the hit does not name a communication policy in `policy`.
///   An allow hit always does, so this means policy state is inconsistent. We refuse to
///   guess an expiration rather than silently issue a visa with no attribute constraint.
fn compute_expiration(
    src_actor: &Actor,
    dst_actor: &Actor,
    policy: &Policy,
    hit: &Hit,
) -> Result<SystemTime, ServiceError> {
    // Both sides come back Some for a valid index -- an empty vec means that side has no
    // conditions -- so a None here is only ever a failed lookup or an undecodable list.
    let (Some(client_keys), Some(service_keys)) =
        policy.get_condition_keys_for_com_policy(hit.match_idx)
    else {
        return Err(ServiceError::Internal(format!(
            "no communication policy at index {} for allow hit",
            hit.match_idx
        )));
    };

    let (client_actor, service_actor) = if hit.direction == libeval::eval_result::Direction::Forward
    {
        (src_actor, dst_actor)
    } else {
        (dst_actor, src_actor)
    };

    // zpr.services on the providing actor is what selected this policy -- eval only matches
    // when the service side satisfies provides(service_id) -- so it bounds the visa as much
    // as any condition attribute does.
    let mut service_keys = service_keys;
    service_keys.push(key::SERVICES.to_string());

    // Sampled once so the clamp below compares and assigns against the same instant.
    let now = SystemTime::now();
    let mut soonest_expiration = now + libeval::attribute::NEVER_EXPIRES;
    let mut expiration_gate = String::from("(none)"); // for debugging

    for (keys, actor) in [(&client_keys, client_actor), (&service_keys, service_actor)] {
        for key in keys {
            if let Some(attr) = actor.get_attribute(key) {
                if attr.get_expires() < soonest_expiration {
                    soonest_expiration = attr.get_expires();
                    expiration_gate = key.clone();
                }
            }
        }
    }

    if let Some(exp) = src_actor.get_authentication_expiration() {
        if exp < soonest_expiration {
            soonest_expiration = exp;
            expiration_gate = String::from("source_actor_auth");
        }
    }
    if let Some(exp) = dst_actor.get_authentication_expiration() {
        if exp < soonest_expiration {
            soonest_expiration = exp;
            expiration_gate = String::from("destination_actor_auth");
        }
    }

    if soonest_expiration > now + config::MAX_VISA_LIFETIME {
        soonest_expiration = now + config::MAX_VISA_LIFETIME;
        expiration_gate = String::from("max_visa_lifetime");
    }

    debug!(target: VREQ,
        "visa request computed expiration {:?} (gate: {})",
        soonest_expiration, expiration_gate
    );
    Ok(soonest_expiration)
}

/// Pushes actualized copies of a visa to all non-requesting nodes on the path.
/// Runs all pushes concurrently. Intended to be called as a background task after the
/// requesting node has already received its visa.
///
/// Note that if these fail the visas should have already been marked as pending-install
/// for the target nodes before calling this, so the vss worker will pick up on that
/// during housekeeping.
async fn distribute_visa_on_path(
    asm: Arc<Assembly>,
    visa_with_metadata: VisaWithMetadata,
    requesting_node: IpAddr,
) {
    let issuer_id = visa_with_metadata.visa.issuer_id;

    let Some(ref path) = visa_with_metadata.metadata.path else {
        return;
    };

    // Build one future per non-requesting path node and drive them all concurrently.
    // Each node has its own VssHandle (independent channel), so there is no contention.
    let push_futures: Vec<_> = path
        .iter()
        .filter(|node_addr| **node_addr != requesting_node)
        .map(|node_addr| {
            let asm = asm.clone();
            let onpath_visa = visa_with_metadata.visa.clone();
            let node_addr = *node_addr;
            async move {
                match asm
                    .visa_mgr
                    .actualize_visa_for_target_node(onpath_visa, &node_addr)
                    .await
                {
                    Ok(onpath_visa) => {
                        if let Some(vss_handle) = asm.vss_mgr.get_handle(&node_addr) {
                            match vss_handle.push_visas(vec![onpath_visa]).await {
                                Ok(1) => {
                                    if let Err(e) =
                                        asm.visa_mgr.visa_installed(issuer_id, &node_addr).await
                                    {
                                        warn!(target: VREQ,
                                            "error marking visa {issuer_id} as installed for node {node_addr}: {e}"
                                        );
                                    }
                                }
                                Ok(_) => {
                                    warn!(target: VREQ,
                                        "failed to push visa {issuer_id} to node {node_addr}"
                                    );
                                }
                                Err(e) => {
                                    debug!(target: VREQ,
                                        "error pushing visa {issuer_id} for node {node_addr} in VSS: {e}"
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => {
                        warn!(target: VREQ,
                            "error actualizing visa {issuer_id} for node {node_addr}"
                        );
                    }
                }
            }
        })
        .collect();

    join_all(push_futures).await;
}

/// Resolves a pair of optional actors into concrete actors. One side may be missing because
/// it is an unauthenticated actor reaching an auth service over an AAA address, in which case
/// we fabricate it; anything else missing is a deny.
///
/// Returns `Ok((source, dest))` when both actors are resolved, or `Err(decision)` for an
/// early deny that should be returned directly to the caller.
async fn resolve_actors_or_deny(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
    mut source_actor: Option<Actor>,
    mut dest_actor: Option<Actor>,
) -> Result<(Actor, Actor), VisaDecision> {
    if source_actor.is_some() && dest_actor.is_some() {
        return Ok((source_actor.unwrap(), dest_actor.unwrap()));
    }
    if source_actor.is_none() && dest_actor.is_none() {
        return Err(VisaDecision::Deny(DenyCode::SourceNotFound));
    }

    // Exactly one side is missing from here on.
    let missing_source = source_actor.is_none();

    // "candidate" => the known actor's address, "anon_addr" => the missing actor's address.
    let (candidate_addr, anon_addr) = if missing_source {
        (job.packet_desc.dest_addr(), job.packet_desc.source_addr())
    } else {
        (job.packet_desc.source_addr(), job.packet_desc.dest_addr())
    };

    let expiration = SystemTime::now() + config::DEFAULT_ANON_AUTH_EXPIRATION;

    // The missing side names its own deny code.
    let deny = if missing_source {
        DenyCode::SourceNotFound
    } else {
        DenyCode::DestNotFound
    };

    let actor = match try_aaa_actor(
        asm,
        job,
        anon_addr,
        candidate_addr,
        missing_source,
        expiration,
    )
    .await
    .map_err(VisaDecision::Deny)?
    {
        Some(actor) => actor,
        None => {
            // Names the requesting node and the flow: without them a denial for an
            // unconnected peer is indistinguishable from a genuine AAA miss.
            warn!(target: VREQ,
                "visa denied ({deny:?}) for node {}: {anon_addr} has no actor and is not a registered AAA address (peer {candidate_addr}, flow {})",
                job.requesting_node, describe_five_tuple(&job.packet_desc)
            );
            return Err(VisaDecision::Deny(deny));
        }
    };

    if missing_source {
        source_actor = Some(actor);
    } else {
        dest_actor = Some(actor);
    }

    Ok((source_actor.unwrap(), dest_actor.unwrap()))
}

/// Tries to resolve `anon_addr` as an unauthenticated actor using an AAA address to reach an
/// authentication service.
///
/// `Ok(None)` means this is not an AAA case at all, so the caller should deny with the
/// missing side's code. `Err(code)` means it is an AAA case but a denied one, and the code
/// names whichever endpoint is actually at fault.
async fn try_aaa_actor(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
    anon_addr: &IpAddr,
    candidate_addr: &IpAddr,
    missing_source: bool,
    expiration: SystemTime,
) -> Result<Option<Actor>, DenyCode> {
    if missing_source {
        // Request side: the anonymous actor must be in the requesting node's AAA subnet,
        // and the destination must actually be a registered auth service.
        if !net_mgr::aaa_network_for_node(&job.requesting_node).contains(anon_addr) {
            return Ok(None);
        }

        match asm
            .actor_mgr
            .has_auth_services(asm.clone(), candidate_addr)
            .await
        {
            Ok(true) => (),
            Ok(false) => {
                warn!(target: VREQ, "visa denied: actor using AAA addr attempting to contact non-authentication service at {candidate_addr}");
                // Names the candidate rather than the missing side: the dest is the problem.
                return Err(DenyCode::DestNotFound);
            }
            Err(e) => {
                debug!(target: VREQ, "visa denied: error checking authentication services for actor at {candidate_addr}: {e}");
                return Err(DenyCode::DestNotFound);
            }
        }

        // Record the docking node so the response side can resolve it correctly,
        // even when the response arrives via a different requesting node.
        asm.actor_mgr
            .register_aaa(*anon_addr, job.requesting_node, expiration);
    } else {
        // Response side: the AAA address must already be in the table, put there by the
        // request side. Whether the peer is really an auth service is left to policy eval.
        if asm.actor_mgr.get_docking_node_for_aaa(anon_addr).is_none() {
            return Ok(None);
        }
    }

    debug!(target: VREQ, "fabricated AAA actor for anonymous endpoint {anon_addr} (peer {candidate_addr})");
    Ok(Some(fabricate_aaa_actor(anon_addr, expiration)))
}

// Lookup source and destination actors in the DB based on ZPR address.
async fn get_actors(
    asm: &Arc<Assembly>,
    job: &VisaRequestJob,
) -> Result<(Option<Actor>, Option<Actor>), ServiceError> {
    // TODO: The source or destination could be from an unauthenticated adapter
    // using an AAA address to talk to an authentication service.

    // See prototype code in vsinst-core.go (around line 128). In there we create
    // a fake actor to use for granting the visa.  But we need to establish that
    // the AAA address is correct for the node the adapter is connected to.

    let source_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.source_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VREQ,
                "error retrieving source actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal(
                "error retrieving source actor".into(),
            ));
        }
    };

    let dest_actor = match asm
        .actor_mgr
        .get_actor_by_zpr_addr(&job.packet_desc.dest_addr())
        .await
    {
        Ok(maybe_actor) => maybe_actor,
        Err(e) => {
            debug!(target: VREQ,
                "error retrieving dest actor for visa request from {:?}: {e}",
                job.requesting_node
            );
            return Err(ServiceError::Internal("error retrieving dest actor".into()));
        }
    };
    Ok((source_actor, dest_actor))
}

/// Test-only rendezvous for racing docking-state changes against an in-flight
/// request (zipline#183 review, Codex P1). A test arms a gate for its (unique)
/// requesting-node address; `process_visa_request` parks at the gate after the
/// attribute-refresh awaits, the test mutates docking state, then resumes it.
/// Keyed by requesting node so concurrently-running tests never trip each
/// other's gates. Compiled only into test builds.
#[cfg(test)]
pub(crate) mod race_gate {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex, OnceLock};

    use tokio::sync::Notify;

    struct Gate {
        parked: Arc<Notify>,
        resume: Arc<Notify>,
    }

    fn gates() -> &'static Mutex<HashMap<IpAddr, Gate>> {
        static GATES: OnceLock<Mutex<HashMap<IpAddr, Gate>>> = OnceLock::new();
        GATES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Arm a gate for requests from `node`. Returns `(parked, resume)`: await
    /// `parked.notified()` to learn the request has reached the gate, then
    /// `resume.notify_one()` to let it continue. Single-permit `Notify`
    /// semantics make both directions race-free regardless of arrival order.
    pub(crate) fn arm(node: IpAddr) -> (Arc<Notify>, Arc<Notify>) {
        let parked = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        gates().lock().unwrap().insert(
            node,
            Gate {
                parked: parked.clone(),
                resume: resume.clone(),
            },
        );
        (parked, resume)
    }

    /// Disarm the gate so later requests from `node` run through unimpeded.
    pub(crate) fn disarm(node: &IpAddr) {
        gates().lock().unwrap().remove(node);
    }

    /// Called from `process_visa_request`: if a gate is armed for this
    /// requesting node, signal the test and wait to be resumed. No-op (and
    /// lock-only cost) for every other request.
    pub(crate) async fn pause_if_gated(node: &IpAddr) {
        let armed = {
            let map = gates().lock().unwrap();
            map.get(node).map(|g| (g.parked.clone(), g.resume.clone()))
        };
        if let Some((parked, resume)) = armed {
            parked.notify_one();
            resume.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assembly::Assembly;
    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::{
        make_actor, make_actor_with_services_defexp, make_adapter_actor_defexp,
        make_container_bytes, make_node_actor_defexp, make_policy_with_com_conditions,
    };
    use libeval::attribute::ROLE_ADAPTER;
    use libeval::eval_result::Direction;
    use libeval::policy::Policy;
    use libeval::route::LinkId;
    use std::time::{Duration, SystemTime};
    use zpr::policy_types::{JoinPolicy, PFlags, Scope, Service, ServiceType};
    use zpr::write_to::WriteTo;

    /// Builds a Policy that declares one Authentication service with the given id.
    fn make_policy_with_auth_service(service_id: &str) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<zpr::policy::v1::policy::Builder>();
            policy_bldr.set_created("2024-01-01T00:00:00Z");
            policy_bldr.set_version(2);
            policy_bldr.set_metadata("");

            let mut jp_list = policy_bldr.reborrow().init_join_policies(1);
            let mut jp_bldr = jp_list.reborrow().get(0);
            let jp = JoinPolicy {
                conditions: Vec::new(),
                flags: PFlags::default(),
                provides: Some(vec![Service {
                    id: service_id.to_string(),
                    endpoints: vec![Scope {
                        protocol: 0,
                        flag: None,
                        port: Some(4000),
                        port_range: None,
                    }],
                    kind: ServiceType::Authentication,
                }]),
            };
            jp.write_to(&mut jp_bldr);
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        make_container_bytes(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
            &bytes,
        )
    }

    // This test just runs a request through the pipeline. There is no real policy here
    // so it will fail.  But it should be a visa-deny not some other error.
    #[tokio::test]
    async fn request_visa_wait_response_denies_when_policy_has_no_match() {
        let (vreq_tx, vreq_rx) = mpsc::channel(8);
        let asm_inner = new_assembly_for_tests(Some(vreq_tx)).await;
        let src_zpr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let dst_zpr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        asm_inner.topo_mgr.add_node(src_zpr).unwrap();
        asm_inner.topo_mgr.add_node(dst_zpr).unwrap();
        asm_inner
            .topo_mgr
            .add_link(src_zpr, dst_zpr, LinkId("test-link".into()), vec![], 1)
            .unwrap();
        let asm = Arc::new(asm_inner);

        let source_actor =
            make_node_actor_defexp("fd5a:5052:3000::1", "source-node", "10.0.0.1:10001");
        let dest_actor = make_node_actor_defexp("fd5a:5052:3000::2", "dest-node", "10.0.0.2:10002");
        asm.actor_mgr
            .add_node(&source_actor, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&dest_actor, false, &Default::default())
            .await
            .unwrap();

        let arena = tokio::spawn(launch_arena(asm.clone(), vreq_rx, 1));

        let requestor_ip: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();

        let result =
            request_visa_wait_response(&asm, &requestor_ip, pkt_data, Duration::from_secs(1))
                .await
                .unwrap();

        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));

        // The deny funnel must have logged this exact 5-tuple in the deny log.
        let denies = asm.deny_log.recent(None, None);
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].source_addr, src_zpr);
        assert_eq!(denies[0].dest_addr, dst_zpr);
        assert_eq!(denies[0].protocol, zpr::vsapi_types::vsapi_ip_number::TCP);
        assert_eq!(denies[0].dest_port, 80);
        assert_eq!(denies[0].deny_code, "NoMatch");
        assert_eq!(denies[0].count, 1);

        arena.abort();
    }

    // Verifies that visa_from_allow issues a visa and returns Allow when given a valid hit and route,
    // and that the stored metadata records the installed policy vinst as both created/checked_vinst.
    #[tokio::test]
    async fn visa_from_allow_issues_visa_on_allow() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt_data);

        let hits = vec![Hit::new_no_signal(0, Direction::Forward)];
        let mut policy = make_policy_with_com_conditions(&[], &[]);
        policy.set_vinst(7);
        let route = Route::new_direct(requesting_node.into());

        let src_actor = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let dst_actor = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");

        let result = visa_from_allow(
            asm.clone(),
            &job,
            &hits,
            &policy,
            Some(route),
            &src_actor,
            &dst_actor,
        )
        .await;
        let visa = match result {
            Ok(VisaDecision::Allow(visa, _)) => visa,
            _ => panic!("expected Allow"),
        };

        let md = asm
            .visa_mgr
            .get_visa_metadata_by_id(visa.issuer_id)
            .await
            .unwrap()
            .expect("metadata should be stored");
        assert_eq!(md.created_vinst, 7);
        assert_eq!(md.checked_vinst, 7);
    }

    // An actor whose authentication expires almost immediately leaves less than
    // MIN_VISA_LIFETIME to work with, so an ALLOW must come back as a deny and no visa may
    // be stored. Issuing here would half-succeed: the store drops a sub-second TTL silently
    // but create_visa still returns Ok, so the caller would fail on actualize.
    #[tokio::test]
    async fn visa_from_allow_denies_when_expiration_below_min_lifetime() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt_data =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt_data);

        let hits = vec![Hit::new_no_signal(0, Direction::Forward)];
        let policy = make_policy_with_com_conditions(&[], &[]);
        let route = Route::new_direct(requesting_node.into());

        // DEVICE_AUTHORITY drives get_authentication_expiration; one second is well under the floor.
        let mut src_actor = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        src_actor
            .add_attribute(
                Attribute::builder(key::DEVICE_AUTHORITY)
                    .expires_in(Duration::from_secs(1))
                    .value("about-to-expire"),
            )
            .unwrap();
        let dst_actor = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");

        let result = visa_from_allow(
            asm.clone(),
            &job,
            &hits,
            &policy,
            Some(route),
            &src_actor,
            &dst_actor,
        )
        .await;

        assert!(
            matches!(result, Ok(VisaDecision::Deny(DenyCode::NoReason))),
            "expected deny when expiration is under MIN_VISA_LIFETIME"
        );
        assert!(
            asm.visa_mgr.list_all_visa_ids().await.unwrap().is_empty(),
            "no visa may be stored when the request is denied"
        );
    }

    // The attribute named by a policy condition expires before MAX_VISA_LIFETIME, so it
    // sets the visa expiration.
    #[test]
    fn compute_expiration_uses_soonest_condition_attribute() {
        let policy = make_policy_with_com_conditions(&["user.role"], &[]);
        let src = make_actor(&[("user.role", "admin")], Duration::from_secs(600));
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let hit = Hit::new_no_signal(0, Direction::Forward);

        let expected = src.get_attribute("user.role").unwrap().get_expires();
        let exp = compute_expiration(&src, &dst, &policy, &hit).unwrap();
        assert_eq!(exp, expected);
    }

    // Client conditions apply to the source on a Forward hit and to the dest on a Reverse
    // hit, so the same policy must pick up a different actor's attribute per direction.
    #[test]
    fn compute_expiration_swaps_client_and_service_by_direction() {
        let policy = make_policy_with_com_conditions(&["user.role"], &[]);
        let src = make_actor(&[("user.role", "admin")], Duration::from_secs(600));
        let dst = make_actor(&[("user.role", "admin")], Duration::from_secs(1200));

        let fwd = compute_expiration(
            &src,
            &dst,
            &policy,
            &Hit::new_no_signal(0, Direction::Forward),
        )
        .unwrap();
        let rev = compute_expiration(
            &src,
            &dst,
            &policy,
            &Hit::new_no_signal(0, Direction::Reverse),
        )
        .unwrap();

        assert_eq!(fwd, src.get_attribute("user.role").unwrap().get_expires());
        assert_eq!(rev, dst.get_attribute("user.role").unwrap().get_expires());
    }

    // The zpr.services attribute selected the policy, so its expiration bounds the visa even
    // though it is not named by any policy condition. It lives on the providing actor, which
    // is the dest on a Forward hit and the source on a Reverse one.
    #[test]
    fn compute_expiration_uses_services_attribute_of_provider() {
        let policy = make_policy_with_com_conditions(&[], &[]);
        let provider = make_actor(&[(key::SERVICES, "svc:x")], Duration::from_secs(600));
        let client = make_node_actor_defexp("fd5a:5052:3000::1", "client", "10.0.0.1:1001");
        let expected = provider.get_attribute(key::SERVICES).unwrap().get_expires();

        // Forward: the dest provides the service.
        let fwd = compute_expiration(
            &client,
            &provider,
            &policy,
            &Hit::new_no_signal(0, Direction::Forward),
        )
        .unwrap();
        assert_eq!(fwd, expected);

        // Reverse: the source provides the service.
        let rev = compute_expiration(
            &provider,
            &client,
            &policy,
            &Hit::new_no_signal(0, Direction::Reverse),
        )
        .unwrap();
        assert_eq!(rev, expected);
    }

    // With no condition attributes and no authentication expiration, the expiration falls
    // back to the MAX_VISA_LIFETIME clamp.
    #[test]
    fn compute_expiration_clamps_to_max_visa_lifetime() {
        let policy = make_policy_with_com_conditions(&[], &[]);
        let src = make_actor(&[("some.attr", "x")], libeval::attribute::NEVER_EXPIRES);
        let dst = make_actor(&[("some.attr", "y")], libeval::attribute::NEVER_EXPIRES);
        let hit = Hit::new_no_signal(0, Direction::Forward);

        let before = SystemTime::now();
        let exp = compute_expiration(&src, &dst, &policy, &hit).unwrap();
        assert!(exp >= before + config::MAX_VISA_LIFETIME);
        assert!(exp <= SystemTime::now() + config::MAX_VISA_LIFETIME);
    }

    // A hit whose match_idx names no communication policy is a broken invariant, not a
    // visa with no attribute constraints: fail rather than issue a full-lifetime visa.
    #[test]
    fn compute_expiration_errors_when_hit_names_no_com_policy() {
        let policy = make_policy_with_com_conditions(&[], &[]);
        let src = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");

        // Index 9 is past the single com policy in the test policy.
        let hit = Hit::new_no_signal(9, Direction::Forward);
        assert!(matches!(
            compute_expiration(&src, &dst, &policy, &hit),
            Err(ServiceError::Internal(_))
        ));

        // Same for a policy with no com policies at all.
        let hit = Hit::new_no_signal(0, Direction::Forward);
        assert!(matches!(
            compute_expiration(&src, &dst, &Policy::new_empty(), &hit),
            Err(ServiceError::Internal(_))
        ));
    }

    // When both actors are None the request cannot proceed: deny the source immediately.
    #[tokio::test]
    async fn resolve_actors_or_deny_both_missing_denies_source() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt = PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let result = resolve_actors_or_deny(&asm, &job, None, None).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::SourceNotFound))
        ));
    }

    // When both actors are known they pass through unchanged.
    #[tokio::test]
    async fn resolve_actors_or_deny_both_present_passes_through() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let pkt = PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let src_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let dst_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();

        let (ra, rb) = resolve_actors_or_deny(&asm, &job, Some(src), Some(dst))
            .await
            .ok()
            .expect("expected Ok");
        assert_eq!(ra.get_zpr_addr(), Some(&src_addr));
        assert_eq!(rb.get_zpr_addr(), Some(&dst_addr));
    }

    // Missing source whose address is a plain ZPR address (not in the node's AAA subnet) is denied.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_not_in_aaa_network_denies_source() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // source addr is a normal ZPR address, outside any node AAA subnet
        let pkt =
            PacketDesc::new_tcp("fd5a:5052:3000::99", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let result = resolve_actors_or_deny(&asm, &job, None, Some(dst)).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::SourceNotFound))
        ));
    }

    // Missing source in the AAA subnet but the destination has no auth service registered:
    // deny because it would be a non-authenticated actor talking to a non-auth endpoint.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_in_aaa_net_dest_not_auth_service_denies() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // AAA subnet for node ::ff is fd5a:5052:0:aaa:0:ff00::/88; pick an address inside it.
        let aaa_src = "fd5a:5052:0:aaa:0:ff00::1";
        let pkt = PacketDesc::new_tcp(aaa_src, "fd5a:5052:3000::2", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        // No actor with auth services in the DB at the dest addr.
        let dst = make_node_actor_defexp("fd5a:5052:3000::2", "dst", "10.0.0.2:1002");
        let result = resolve_actors_or_deny(&asm, &job, None, Some(dst)).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::DestNotFound))
        ));
    }

    // Missing source in the AAA subnet, destination is a registered auth service:
    // fabricate an AAA actor for the anonymous source and register it in the AAA table.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_source_in_aaa_net_with_auth_service_fabricates_aaa_actor()
     {
        let asm_inner = new_assembly_for_tests(None).await;

        let dest_zpr = "fd5a:5052:3000::2";
        let auth_actor =
            make_actor_with_services_defexp(ROLE_ADAPTER, dest_zpr, &["svc:auth"], "auth-svc");
        asm_inner
            .actor_mgr
            .hack_add_adapter_no_node(&auth_actor, &Default::default())
            .await
            .unwrap();
        asm_inner
            .policy_mgr
            .update_policy_from_container_bytes(make_policy_with_auth_service("svc:auth"))
            .await
            .unwrap();

        let asm = Arc::new(asm_inner);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let aaa_src = "fd5a:5052:0:aaa:0:ff00::1";
        let pkt = PacketDesc::new_tcp(aaa_src, dest_zpr, 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let dst = make_node_actor_defexp(dest_zpr, "dst", "10.0.0.2:1002");
        let (aaa_src_actor, resolved_dst) = resolve_actors_or_deny(&asm, &job, None, Some(dst))
            .await
            .ok()
            .expect("expected Ok");

        let expected_aaa: IpAddr = aaa_src.parse().unwrap();
        let expected_dst: IpAddr = dest_zpr.parse().unwrap();
        assert_eq!(aaa_src_actor.get_zpr_addr(), Some(&expected_aaa));
        assert_eq!(resolved_dst.get_zpr_addr(), Some(&expected_dst));

        // Confirm the AAA table was populated by the request-side registration.
        assert_eq!(
            asm.actor_mgr.get_docking_node_for_aaa(&expected_aaa),
            Some(requesting_node),
            "aaa_table must record the requesting node as docking node"
        );
    }

    // Missing destination whose address is a plain ZPR address (not in the node's AAA subnet) is denied.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_dest_not_in_aaa_network_denies_dest() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        // dest addr is a normal ZPR address, outside any node AAA subnet
        let pkt =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::99", 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp("fd5a:5052:3000::1", "src", "10.0.0.1:1001");
        let result = resolve_actors_or_deny(&asm, &job, Some(src), None).await;
        assert!(matches!(
            result,
            Err(VisaDecision::Deny(DenyCode::DestNotFound))
        ));
    }

    // Missing destination with the AAA address pre-registered in the table (simulating a prior
    // forward request): fabricate an AAA actor for the anonymous destination.
    #[tokio::test]
    async fn resolve_actors_or_deny_missing_dest_in_aaa_table_fabricates_aaa_actor() {
        let asm_inner = new_assembly_for_tests(None).await;

        let src_zpr = "fd5a:5052:3000::1";
        let auth_actor =
            make_actor_with_services_defexp(ROLE_ADAPTER, src_zpr, &["svc:auth"], "auth-svc");
        asm_inner
            .actor_mgr
            .hack_add_adapter_no_node(&auth_actor, &Default::default())
            .await
            .unwrap();
        asm_inner
            .policy_mgr
            .update_policy_from_container_bytes(make_policy_with_auth_service("svc:auth"))
            .await
            .unwrap();

        let asm = Arc::new(asm_inner);
        let requesting_node: IpAddr = "fd5a:5052:3000::ff".parse().unwrap();
        let aaa_dst = "fd5a:5052:0:aaa:0:ff00::1";
        let aaa_dst_addr: IpAddr = aaa_dst.parse().unwrap();

        // Pre-register as the request side would have done.
        asm.actor_mgr.register_aaa(
            aaa_dst_addr,
            requesting_node,
            SystemTime::now() + Duration::from_secs(300),
        );

        let pkt = PacketDesc::new_tcp(src_zpr, aaa_dst, 12345, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);

        let src = make_node_actor_defexp(src_zpr, "src", "10.0.0.1:1001");
        let (resolved_src, aaa_dst_actor) = resolve_actors_or_deny(&asm, &job, Some(src), None)
            .await
            .ok()
            .expect("expected Ok");

        let expected_src: IpAddr = src_zpr.parse().unwrap();
        assert_eq!(resolved_src.get_zpr_addr(), Some(&expected_src));
        assert_eq!(aaa_dst_actor.get_zpr_addr(), Some(&aaa_dst_addr));
    }

    // --- AAA actor full pipeline tests ---

    // Shared setup for AAA pipeline tests:
    //   node A (fd5a:5052:3000::1) = requesting node and AAA actor docking node
    //   node B (fd5a:5052:3000::2) = auth service docking node
    //   auth adapter (fd5a:5052:3000::30) docked to node B, service "svc:auth"
    //   AAA subnet for node A: fd5a:5052:0:aaa:0:100::/88
    async fn build_aaa_test_asm(with_link: bool) -> Arc<Assembly> {
        let asm = new_assembly_for_tests(None).await;

        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();

        let node_a = make_node_actor_defexp("fd5a:5052:3000::1", "node-a", "10.0.0.1:1001");
        let node_b = make_node_actor_defexp("fd5a:5052:3000::2", "node-b", "10.0.0.2:1002");
        asm.actor_mgr
            .add_node(&node_a, false, &Default::default())
            .await
            .unwrap();
        asm.actor_mgr
            .add_node(&node_b, false, &Default::default())
            .await
            .unwrap();
        asm.topo_mgr.add_node(node_a_addr).unwrap();
        asm.topo_mgr.add_node(node_b_addr).unwrap();

        if with_link {
            asm.topo_mgr
                .add_link(
                    node_a_addr,
                    node_b_addr,
                    LinkId("link-ab".into()),
                    vec![],
                    1,
                )
                .unwrap();
        }

        let auth_adapter = make_actor_with_services_defexp(
            ROLE_ADAPTER,
            "fd5a:5052:3000::30",
            &["svc:auth"],
            "auth-svc",
        );
        asm.actor_mgr
            .add_adapter_via_node(&auth_adapter, &node_b_addr, &Default::default())
            .await
            .unwrap();

        asm.policy_mgr
            .update_policy_from_container_bytes(make_policy_with_auth_service("svc:auth"))
            .await
            .unwrap();

        Arc::new(asm)
    }

    // An AAA source actor passes the docking-node check and reaches policy evaluation.
    // Deny(NoMatch) confirms the actor was resolved and routing succeeded.
    #[tokio::test]
    async fn process_visa_request_aaa_source_reaches_policy_eval() {
        let asm = build_aaa_test_asm(true).await;
        let requesting_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        // node_id for ::1 = 0x000001; segments[5] = 0x0001<<8 = 0x0100 → subnet fd5a:5052:0:aaa:0:100::/88
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));
    }

    // An AAA source with no route between the docking node and the auth service docking node
    // is denied NoRoute (not SourceNotFound), confirming the docking check passed.
    #[tokio::test]
    async fn process_visa_request_aaa_source_no_route_denied() {
        let asm = build_aaa_test_asm(false).await;
        let requesting_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoRoute)));
    }

    /// zl-zipline#227 acceptance: the direct link between the two docks is down, and
    /// the only other way is through C, which policy does not mark transit-capable.
    /// The visa request is denied `NoRoute`; it is not routed through C.
    #[tokio::test]
    async fn process_visa_request_denied_no_route_through_a_non_transit_node() {
        use crate::test_helpers::{
            build_transit_asm, take_transit_asm_direct_link_down, transit_policy,
        };
        let (asm, _a, _b, _c) = build_transit_asm().await;
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[]))
            .await
            .unwrap();
        asm.topo_mgr.apply_transit_nodes(
            &asm.topo_mgr.ops().await,
            &asm.policy_mgr.get_current_snapshot(),
        );
        take_transit_asm_direct_link_down(&asm);

        let requesting_node: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let pkt = PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(
            matches!(result, VisaDecision::Deny(DenyCode::NoRoute)),
            "expected NoRoute"
        );
    }

    /// The same, with C in `Policy.transitNodes`: the request is routed through C (and
    /// then denied `NoMatch` by the empty communication policy, which shows routing
    /// succeeded).
    #[tokio::test]
    async fn process_visa_request_routes_through_a_transit_node() {
        use crate::test_helpers::{
            build_transit_asm, take_transit_asm_direct_link_down, transit_policy,
        };
        use libeval::route::LinkId;
        let (asm, a, b, c) = build_transit_asm().await;
        asm.policy_mgr
            .update_policy_from_container_bytes(transit_policy(&[c]))
            .await
            .unwrap();
        asm.topo_mgr.apply_transit_nodes(
            &asm.topo_mgr.ops().await,
            &asm.policy_mgr.get_current_snapshot(),
        );
        take_transit_asm_direct_link_down(&asm);
        assert_eq!(
            asm.topo_mgr.get_best_route(&a, &b).unwrap().links,
            vec![LinkId("ac".into()), LinkId("cb".into())]
        );

        let pkt = PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 1234, 80).unwrap();
        let (job, _rx) = VisaRequestJob::new(a, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(
            matches!(result, VisaDecision::Deny(DenyCode::NoMatch)),
            "expected routing to succeed (NoMatch from the empty policy)"
        );
    }

    // An AAA destination actor with the AAA table pre-populated reaches policy evaluation.
    // Deny(NoMatch) confirms the actor was resolved and routing succeeded.
    #[tokio::test]
    async fn process_visa_request_aaa_dest_reaches_policy_eval() {
        let asm = build_aaa_test_asm(true).await;
        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let aaa_addr: IpAddr = "fd5a:5052:0:aaa:0:100::1".parse().unwrap();

        // Pre-register as the request side would have done.
        asm.actor_mgr.register_aaa(
            aaa_addr,
            node_a_addr,
            SystemTime::now() + Duration::from_secs(300),
        );

        let requesting_node = node_a_addr;
        let pkt = PacketDesc::new_tcp(
            "fd5a:5052:3000::30",
            "fd5a:5052:0:aaa:0:100::1",
            4000,
            12345,
        )
        .unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        let result = process_visa_request(asm, &job).await.unwrap();
        assert!(matches!(result, VisaDecision::Deny(DenyCode::NoMatch)));
    }

    // Multi-node test: node A is the AAA docking node, node B hosts the auth service.
    // A forward request (requesting_node=A) registers the AAA address.
    // A return visa (requesting_node=B) must resolve the AAA dest to node A via the table.
    #[tokio::test]
    async fn process_visa_request_aaa_dest_multi_node_resolves_to_correct_docking_node() {
        let asm = build_aaa_test_asm(true).await;

        let node_a_addr: IpAddr = "fd5a:5052:3000::1".parse().unwrap();
        let node_b_addr: IpAddr = "fd5a:5052:3000::2".parse().unwrap();
        let aaa_addr: IpAddr = "fd5a:5052:0:aaa:0:100::1".parse().unwrap();

        // Step 1: forward request from node A registers the AAA address in the table.
        let fwd_pkt = PacketDesc::new_tcp(
            "fd5a:5052:0:aaa:0:100::1",
            "fd5a:5052:3000::30",
            12345,
            4000,
        )
        .unwrap();
        let (fwd_job, _rx) = VisaRequestJob::new(node_a_addr, fwd_pkt);
        let _ = process_visa_request(asm.clone(), &fwd_job).await.unwrap();

        // Confirm the AAA table now maps the address to node A.
        assert_eq!(
            asm.actor_mgr.get_docking_node_for_aaa(&aaa_addr),
            Some(node_a_addr),
            "aaa_table must map aaa_addr to node A after forward request"
        );

        // Step 2: return visa arrives via node B (the auth service's node).
        // Without the fix, requesting_node=B would cause the subnet check to fail.
        // With the fix, the table lookup finds node A as the correct docking node.
        let ret_pkt = PacketDesc::new_tcp(
            "fd5a:5052:3000::30",
            "fd5a:5052:0:aaa:0:100::1",
            4000,
            12345,
        )
        .unwrap();
        let (ret_job, _rx) = VisaRequestJob::new(node_b_addr, ret_pkt);
        let result = process_visa_request(asm, &ret_job).await.unwrap();

        // Deny(NoMatch) means routing resolved correctly; the request reached policy eval.
        // Deny(DestNotFound) would mean the table lookup failed (the old bug).
        assert!(
            matches!(result, VisaDecision::Deny(DenyCode::NoMatch)),
            "expected NoMatch (policy eval reached)"
        );
    }

    // --- requesting-node binding tests (zipline#183) ---

    // Shared setup for the binding tests:
    //   node N1 (fd5a:5052:3000::1) docks client adapter A (fd5a:5052:4000::a)
    //   node N2 (fd5a:5052:3000::2) docks provider adapter B (fd5a:5052:4000::b, svc:web)
    //   node N3 (fd5a:5052:3000::3) docks neither actor (the off-path requester)
    //   links N1<->N2 (the flow's route) and N1<->N3, N2<->N3 (N3 is connected,
    //   just not docking either endpoint)
    //   policy: unconditional ALLOW for svc:web on TCP 8080
    async fn build_binding_test_asm() -> Arc<Assembly> {
        build_binding_test_asm_in("fd5a:5052:3000", "fd5a:5052:4000").await
    }

    /// As [build_binding_test_asm], with the node and adapter subnets supplied.
    /// The race-gate test needs addresses no other concurrently-running test
    /// requests from: the gate is keyed by requesting-node address, and the AAA
    /// tests above also request from `fd5a:5052:3000::*`.
    async fn build_binding_test_asm_in(node_net: &str, adapter_net: &str) -> Arc<Assembly> {
        let asm = new_assembly_for_tests(None).await;

        let n1: IpAddr = format!("{node_net}::1").parse().unwrap();
        let n2: IpAddr = format!("{node_net}::2").parse().unwrap();
        let n3: IpAddr = format!("{node_net}::3").parse().unwrap();

        for (addr, cn, sub) in [
            (format!("{node_net}::1"), "node-1", "10.0.0.1:1001"),
            (format!("{node_net}::2"), "node-2", "10.0.0.2:1002"),
            (format!("{node_net}::3"), "node-3", "10.0.0.3:1003"),
        ] {
            asm.actor_mgr
                .add_node(
                    &make_node_actor_defexp(&addr, cn, sub),
                    false,
                    &Default::default(),
                )
                .await
                .unwrap();
        }
        asm.topo_mgr.add_node(n1).unwrap();
        asm.topo_mgr.add_node(n2).unwrap();
        asm.topo_mgr.add_node(n3).unwrap();
        asm.topo_mgr
            .add_link(n1, n2, LinkId("link-12".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(n1, n3, LinkId("link-13".into()), vec![], 1)
            .unwrap();
        asm.topo_mgr
            .add_link(n2, n3, LinkId("link-23".into()), vec![], 1)
            .unwrap();

        // Client adapter A docked at N1; provider adapter B (svc:web) docked at N2.
        asm.actor_mgr
            .add_adapter_via_node(
                &make_adapter_actor_defexp(&format!("{adapter_net}::a"), "client-a"),
                &n1,
                &Default::default(),
            )
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(
                &make_actor_with_services_defexp(
                    ROLE_ADAPTER,
                    &format!("{adapter_net}::b"),
                    &["svc:web"],
                    "web-svc",
                ),
                &n2,
                &Default::default(),
            )
            .await
            .unwrap();

        // Unconditional ALLOW for svc:web on TCP 8080: A -> B dport 8080 is allowed
        // by policy, any other dport has no match.
        asm.policy_mgr
            .update_policy_from_container_bytes(
                crate::test_helpers::make_allow_policy_for_tcp_service("svc:web", 8080),
            )
            .await
            .unwrap();

        Arc::new(asm)
    }

    /// A -> B on the allowed port (8080), i.e. a flow policy WOULD allow.
    fn binding_allowed_pkt() -> PacketDesc {
        PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 12345, 8080).unwrap()
    }

    /// A -> B on a port no com policy covers, i.e. a flow policy denies (NoMatch).
    fn binding_unmatched_pkt() -> PacketDesc {
        PacketDesc::new_tcp("fd5a:5052:4000::a", "fd5a:5052:4000::b", 12345, 9999).unwrap()
    }

    /// Flatten a request's outcome for comparison: deny code, allow marker, or error
    /// marker. The oracle test compares these byte-for-byte between the allowed and
    /// denied flows, so an internal error must NOT collapse into a deny.
    async fn binding_request_outcome(
        asm: Arc<Assembly>,
        requester: &str,
        pkt: PacketDesc,
    ) -> String {
        let requesting_node: IpAddr = requester.parse().unwrap();
        let (job, _rx) = VisaRequestJob::new(requesting_node, pkt);
        match process_visa_request(asm, &job).await {
            Ok(VisaDecision::Deny(code)) => format!("Deny({code:?})"),
            Ok(VisaDecision::Allow(..)) => "Allow".to_string(),
            Err(e) => format!("Err({e:?})"),
        }
    }

    // zipline#183: a request from a node that docks neither actor must be refused with
    // a plain Deny(NoMatch) before policy runs, creating no visa and pushing nothing
    // to other nodes -- even when policy would allow the flow.
    #[tokio::test]
    async fn visa_request_from_node_docking_neither_actor_is_denied() {
        let asm = build_binding_test_asm().await;

        let outcome =
            binding_request_outcome(asm.clone(), "fd5a:5052:3000::3", binding_allowed_pkt()).await;
        assert_eq!(
            outcome, "Deny(NoMatch)",
            "off-path requester must get a plain policy-shaped deny, not {outcome}"
        );

        // Nothing may be created or distributed for the refused request.
        assert!(
            asm.visa_mgr.list_all_visa_ids().await.unwrap().is_empty(),
            "no visa may be stored for an off-path request"
        );
        for node in ["fd5a:5052:3000::1", "fd5a:5052:3000::2"] {
            let node_addr: IpAddr = node.parse().unwrap();
            assert!(
                asm.visa_mgr
                    .get_pending_visa_ids_for_node(&node_addr)
                    .await
                    .unwrap()
                    .is_empty(),
                "nothing may be queued for {node} by an off-path request"
            );
        }
    }

    // zipline#183 (the policy oracle): for an off-path requester, the response to a
    // policy-allowed flow must be byte-for-byte the same as to a policy-denied flow.
    // Before the fix the allowed case surfaced as an internal error ("allowed" leaks
    // through the error) while the denied case was Deny(NoMatch).
    #[tokio::test]
    async fn off_path_deny_is_indistinguishable_from_policy_no_match() {
        let asm = build_binding_test_asm().await;

        let allowed_flow_outcome =
            binding_request_outcome(asm.clone(), "fd5a:5052:3000::3", binding_allowed_pkt()).await;
        let denied_flow_outcome =
            binding_request_outcome(asm.clone(), "fd5a:5052:3000::3", binding_unmatched_pkt())
                .await;

        assert_eq!(
            allowed_flow_outcome, denied_flow_outcome,
            "an off-path requester must not be able to distinguish an allowed flow \
             from a denied one"
        );
    }

    // zipline#183 regression: a request from the SOURCE actor's docking node (N1)
    // still succeeds end-to-end for an allowed flow.
    #[tokio::test]
    async fn visa_request_from_source_docking_node_still_allowed() {
        let asm = build_binding_test_asm().await;
        let outcome =
            binding_request_outcome(asm, "fd5a:5052:3000::1", binding_allowed_pkt()).await;
        assert_eq!(
            outcome, "Allow",
            "the source's docking node must still get its visa, got {outcome}"
        );
    }

    // zipline#183 regression: a request from the DESTINATION actor's docking node
    // (N2) -- the reverse-direction / return-visa case -- still succeeds.
    #[tokio::test]
    async fn visa_request_from_dest_docking_node_still_allowed() {
        let asm = build_binding_test_asm().await;
        let outcome =
            binding_request_outcome(asm, "fd5a:5052:3000::2", binding_allowed_pkt()).await;
        assert_eq!(
            outcome, "Allow",
            "the destination's docking node must still get its visa, got {outcome}"
        );
    }

    // zipline#183 review (Codex P1, PR #52): the requester-binding check must hold
    // against the docking state policy evaluation resolves, not a snapshot taken
    // before the attribute-refresh awaits. Here the source adapter A undocks from
    // the requesting node N1 and re-docks at N3 while the request is parked at the
    // refresh seam: by evaluation time N1 docks neither actor, so the request must
    // get the same plain Deny(NoMatch) as any other off-path request, and nothing
    // may be created or distributed. Before the fix the stale pre-refresh snapshot
    // authorizes N1, policy allows A(N3)->B(N2), and a visa is stored and pushed.
    #[tokio::test]
    async fn visa_request_is_denied_when_requester_undocks_during_refresh() {
        // Subnets unique to this test: the race gate is keyed by requesting-node
        // address and other tests also request from fd5a:5052:3000::*.
        let asm = build_binding_test_asm_in("fd5a:5052:3100", "fd5a:5052:4100").await;

        let n1: IpAddr = "fd5a:5052:3100::1".parse().unwrap();
        let n3: IpAddr = "fd5a:5052:3100::3".parse().unwrap();
        let a_addr: IpAddr = "fd5a:5052:4100::a".parse().unwrap();
        let pkt =
            PacketDesc::new_tcp("fd5a:5052:4100::a", "fd5a:5052:4100::b", 12345, 8080).unwrap();

        let (parked, resume) = race_gate::arm(n1);

        // Request from N1, which docks source A at submission time, for a
        // policy-allowed flow.
        let asm_task = asm.clone();
        let request = tokio::spawn(async move {
            let (job, _rx) = VisaRequestJob::new(n1, pkt);
            process_visa_request(asm_task, &job).await
        });

        // Wait for the request to pass the early binding check and park at the
        // refresh seam, then move A: disconnect from N1, reconnect through N3.
        parked.notified().await;
        let actor_a = asm
            .actor_mgr
            .get_actor_by_zpr_addr(&a_addr)
            .await
            .unwrap()
            .expect("adapter A must exist");
        asm.actor_mgr
            .remove_actor_by_zpr_addr(&a_addr)
            .await
            .unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&actor_a, &n3, &Default::default())
            .await
            .unwrap();
        resume.notify_one();

        let outcome = match request.await.unwrap() {
            Ok(VisaDecision::Deny(code)) => format!("Deny({code:?})"),
            Ok(VisaDecision::Allow(..)) => "Allow".to_string(),
            Err(e) => format!("Err({e:?})"),
        };
        race_gate::disarm(&n1);

        assert_eq!(
            outcome, "Deny(NoMatch)",
            "a requester that undocked mid-request must get the plain off-path deny, \
             got {outcome}"
        );
        assert!(
            asm.visa_mgr.list_all_visa_ids().await.unwrap().is_empty(),
            "no visa may be stored when the requester undocked mid-request"
        );
        for node in ["fd5a:5052:3100::2", "fd5a:5052:3100::3"] {
            let node_addr: IpAddr = node.parse().unwrap();
            assert!(
                asm.visa_mgr
                    .get_pending_visa_ids_for_node(&node_addr)
                    .await
                    .unwrap()
                    .is_empty(),
                "nothing may be queued for {node} by a request whose requester undocked"
            );
        }
    }
}
