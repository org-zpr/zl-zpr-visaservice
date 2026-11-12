//! Shared VSS related types.

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::oneshot;

use libeval::policy::Policy;
use zpr::vsapi_types::{Param, ServiceDescriptor, Visa};

use crate::error::VssSyncError;
use crate::policy_mgr::ResolvedPeer;

pub type VssPushResponse = Result<usize, VssSyncError>; // usize is number items pushed.
pub type VssRevokeAuthResponse = Result<usize, VssSyncError>; // usize is number of items revoked.
pub type VssRequestAuthResponse = Result<usize, VssSyncError>; // usize is number of re-auth requests accepted.
pub type VssSetServicesResponse = Result<(), VssSyncError>;
pub type VssConfigureResponse = Result<(), VssSyncError>;
pub type VssSetTopologyResponse = Result<(), VssSyncError>;

// Each API call is expressed as a message using this enum.
#[allow(dead_code)]
pub enum VssCmd {
    Stop(),
    PushVisas(Vec<Visa>, oneshot::Sender<VssPushResponse>),
    RevokeVisasById(Vec<u64>, oneshot::Sender<VssPushResponse>),
    RevokeAuthsByZprAddr(Vec<IpAddr>, oneshot::Sender<VssRevokeAuthResponse>),
    /// Ask the node to start re-authentication for the listed actors (its own
    /// address means "re-authenticate yourself to the VS"). Contract K1
    /// (zipline#123): the ack reports that re-auth was *started* for each
    /// accepted address, not its outcome — outcomes arrive as
    /// `authenticate`/`reauthorize` calls and are judged by `zpr.vinst`.
    RequestAuthsByZprAddr(Vec<IpAddr>, oneshot::Sender<VssRequestAuthResponse>),
    SetServices(
        Vec<ServiceDescriptor>,
        oneshot::Sender<VssSetServicesResponse>,
    ), // (version, services-descriptor-list, channel)
    Configure(Vec<Param>, oneshot::Sender<VssConfigureResponse>),
    /// The resolved peers plus the policy snapshot they were computed from. The snapshot
    /// rides along so the worker can build the wire-level `Link` structs (including
    /// bootstrap-visa minting) against the same view that produced the peers.
    SetTopology(
        Vec<ResolvedPeer>,
        Arc<Policy>,
        oneshot::Sender<VssSetTopologyResponse>,
    ),
}
