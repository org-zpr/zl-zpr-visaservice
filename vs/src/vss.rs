//! Shared VSS related types.

use std::net::IpAddr;
use tokio::sync::oneshot;

use zpr::vsapi_types::{Param, ServiceDescriptor, Visa};

use crate::error::VssSyncError;
use crate::policy_mgr::PolicySnapshot;

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
    /// The policy snapshot to build the node's topology from. The worker builds the
    /// wire-level `Link` structs from this one snapshot (peers, CNs and policy
    /// addresses), so they never mix two policies (see `vss_worker::proposed_links`).
    SetTopology(PolicySnapshot, oneshot::Sender<VssSetTopologyResponse>),
}
