//! Topology manager - maintains the graph of nodes and links, and provides pathfinding and route selection.
//! Note that this is topology as it exists. For toplogy as it is intended to be, you need to look at policy.
//!
//! The in-memory graph lives in [Router]. This manager owns a [LinkRepo] and is the
//! write-through point that persists the node-link adjacency to state so the graph can
//! be rebuilt on restart (see [TopologyMgr::restore_from_state]). Nodes themselves are
//! persisted by `ActorMgr`/`NodeRepo`; only the edges (links) are persisted here.
//!
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::actor_mgr::ActorMgr;
use crate::db::LinkRepo;
use crate::error::{ServiceError, TopologyError};
use crate::link_state::LinkStateTable;
use crate::logging::targets::TOPO;
use crate::policy_mgr::PolicySnapshot;
use crate::router::{LinkSpec, Router};

use libeval::actor::Actor;
use libeval::attribute::{AttrMatch, Attribute, attributes_equivalent};
use libeval::eval_route::{RouteHint, TopologyQueryApi};
use libeval::policy::LinkDescription;
use libeval::route::{LinkId, NodeId, Route};
use zpr::vsapi_types::LinkStateReport;

pub struct TopologyMgr {
    router: Router,
    link_repo: LinkRepo,
    /// Latest link-state snapshot per reporting node (zl-zipline#224). Decides each
    /// router link's up/down flag together with policy CNs; see [Self::refresh_link].
    /// In memory only; a std mutex because no critical section awaits.
    link_state: Mutex<LinkStateTable>,
}

/// The fate of a persisted/live edge when validated against the current policy.
enum EdgeDecision {
    /// Policy still describes this link; install/refresh it with this description.
    Install(LinkDescription),
    /// Policy no longer describes this link (or an endpoint is gone); garbage-collect it.
    Gc,
}

/// Summary of what [TopologyMgr::revalidate_against_policy] changed, for logging by the caller.
#[derive(Debug, Default)]
pub struct RevalidationReport {
    /// Links removed because policy no longer describes them.
    pub links_removed: usize,
    /// Links whose id/attrs/cost were refreshed to match policy.
    pub links_updated: usize,
    /// Links re-installed/re-persisted to repair router/persistence drift.
    pub links_repaired: usize,
    /// Known nodes left with no remaining links. Detected and reported only.
    pub orphaned_nodes: Vec<IpAddr>,
    /// Links this reconciliation took from up to down -- a rebuilt link whose
    /// link-state reports no longer agree under the new policy -- or removed while
    /// up. The caller revokes the visas that cross them (zl-zipline#224): a visa
    /// committed under the new policy before this ran is not re-checked by the
    /// policy sweep, whose generation gate considers it current.
    pub links_down: Vec<(IpAddr, IpAddr)>,
}

/// Special error returned by [TopologyMgr::add_linked_node] that records
/// whether the failing call created the node. Callers (e.g.
/// `authorize_connect`) use this to decide whether to release the actor's
/// freshly allocated address: a pre-existing node's address is still live and
/// must not be released.
#[derive(Debug, thiserror::Error)]
pub enum AddLinkedNodeError {
    /// Failure while creating/persisting a brand-new node. The freshly allocated
    /// address is owned by this attempt and the caller should release it.
    #[error("new node failed: {0}")]
    NewNodeFailed(ServiceError),
    /// Failure while updating/repairing state for a node that already existed. The
    /// node and its address remain live; the caller must NOT release the address.
    #[error("existing node failed: {0}")]
    ExistingNodeFailed(ServiceError),
}

impl AddLinkedNodeError {
    /// Creates correct enum based on `preexisting` flag.
    pub fn new(preexisting: bool, e: ServiceError) -> Self {
        if preexisting {
            AddLinkedNodeError::ExistingNodeFailed(e)
        } else {
            AddLinkedNodeError::NewNodeFailed(e)
        }
    }
}

impl TopologyMgr {
    pub fn new(link_repo: LinkRepo) -> Self {
        Self {
            router: Router::new(),
            link_repo,
            link_state: Mutex::new(LinkStateTable::new()),
        }
    }

    /// The node-address -> CN lookup that link-state evaluation uses, backed by policy
    /// (`Policy::node_cn_for_addr`).
    pub fn policy_cn_lookup(snapshot: &PolicySnapshot) -> impl Fn(&IpAddr) -> Option<String> + '_ {
        move |addr: &IpAddr| snapshot.policy().node_cn_for_addr(addr).map(str::to_string)
    }

    /// Store `reporter`'s link-state snapshot (already validated, see
    /// `link_state::validate_snapshot`) and re-evaluate every router link incident to it.
    ///
    /// `current_policy` returns the policy snapshot current at the time of the call. It
    /// is called once, inside the link-state table lock, and every CN of the evaluation
    /// comes from that one snapshot: CNs come from policy, and mixing two policies'
    /// CNs in one edge could enable a link neither policy would. Revalidation holds the
    /// same lock with the new policy, so whichever applies second sees it.
    ///
    /// Returns the links that went from up to down, as `(reporter, peer)`, so the caller
    /// can revoke the visas that use them. A link coming up is not returned: it affects
    /// new visas only (Zodes plan §5.8).
    pub fn record_link_states(
        &self,
        reporter: &IpAddr,
        entries: Vec<LinkStateReport>,
        current_policy: &dyn Fn() -> PolicySnapshot,
    ) -> Vec<(IpAddr, IpAddr)> {
        let mut table = self.link_state.lock().unwrap();
        let snapshot = current_policy();
        self.record_locked(
            &mut table,
            reporter,
            entries,
            &Self::policy_cn_lookup(&snapshot),
        )
    }

    /// As [Self::record_link_states], with a fixed node-address -> CN lookup instead of a
    /// policy. For tests, which have no compiled policy naming CNs.
    #[cfg(test)]
    pub fn record_link_states_with_cns(
        &self,
        reporter: &IpAddr,
        entries: Vec<LinkStateReport>,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Vec<(IpAddr, IpAddr)> {
        let mut table = self.link_state.lock().unwrap();
        self.record_locked(&mut table, reporter, entries, cn_of)
    }

    /// Body of [Self::record_link_states], with the table locked by the caller: one
    /// critical section from storing the snapshot through the last router update, so
    /// two overlapping reports cannot interleave and leave an older evaluation's flag
    /// on the router (table, then router: the same order as installs).
    fn record_locked(
        &self,
        table: &mut LinkStateTable,
        reporter: &IpAddr,
        entries: Vec<LinkStateReport>,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Vec<(IpAddr, IpAddr)> {
        // A report from a node that is no longer in the router -- a stale handle whose
        // node was disconnected meanwhile -- is dropped: storing it would let a
        // pre-disconnect snapshot govern the link after the node reconnects.
        // `remove_node` clears the snapshot and the router node under this same lock.
        if !self.router.has_node(reporter) {
            debug!(target: TOPO, "link-state report from {reporter}: node is no longer connected; dropped");
            return Vec::new();
        }
        table.set_snapshot(*reporter, entries);
        self.refresh_links_locked(table, reporter, cn_of)
    }

    /// Re-evaluate every router link incident to `node`. Returns the links that went from
    /// up to down, as `(node, peer)`. Production code re-evaluates through
    /// [Self::record_link_states] and the install paths; tests use this directly.
    #[cfg(test)]
    pub fn refresh_links_for_node(
        &self,
        node: &IpAddr,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Vec<(IpAddr, IpAddr)> {
        let table = self.link_state.lock().unwrap();
        self.refresh_links_locked(&table, node, cn_of)
    }

    /// As [Self::refresh_links_for_node], with the table already locked by the caller.
    fn refresh_links_locked(
        &self,
        table: &LinkStateTable,
        node: &IpAddr,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Vec<(IpAddr, IpAddr)> {
        self.router
            .get_peers(node)
            .into_iter()
            .filter(|peer| self.refresh_link(table, node, peer, cn_of))
            .map(|peer| (*node, peer))
            .collect()
    }

    /// Whether the link between `a` and `b` may carry routes according to the current
    /// link-state reports (`LinkStateTable::edge_usable`).
    fn usable_now(
        &self,
        a: &IpAddr,
        b: &IpAddr,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> bool {
        Self::usable_in(&self.link_state.lock().unwrap(), a, b, cn_of)
    }

    /// As [Self::usable_now], against a table the caller already holds locked.
    fn usable_in(
        table: &LinkStateTable,
        a: &IpAddr,
        b: &IpAddr,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> bool {
        let (a_cn, b_cn) = (cn_of(a), cn_of(b));
        table.edge_usable(a, a_cn.as_deref(), b, b_cn.as_deref())
    }

    /// True if a link connects `a` and `b` and it is up.
    pub fn link_up(&self, a: &IpAddr, b: &IpAddr) -> bool {
        self.router.link_between(a, b).is_some_and(|l| l.up)
    }

    /// True if a stored visa's route is still valid: with its recorded node `path`,
    /// every link exists, is up and joins the matching hop ([Router::route_matches]);
    /// without one (a route that stays on one node, or no recorded path), every link
    /// exists and is up ([Router::links_up]).
    pub fn route_still_valid(&self, links: &[LinkId], path: Option<&[IpAddr]>) -> bool {
        match path {
            Some(p) => self.router.route_matches(links, p),
            None => self.router.links_up(links),
        }
    }

    /// The one place that decides a router link's up/down flag: usable only while both
    /// ends agree it is up (`LinkStateTable::edge_usable`). The caller holds the table
    /// locked through the router update, so the flag set is the one the latest
    /// snapshots call for. Returns true if the link went from up to down. A missing
    /// link is a no-op.
    fn refresh_link(
        &self,
        table: &LinkStateTable,
        a: &IpAddr,
        b: &IpAddr,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> bool {
        let Some(link) = self.router.link_between(a, b) else {
            return false;
        };
        let usable = Self::usable_in(table, a, b, cn_of);
        let changed = self.router.set_link_up(&link.id, usable);
        if changed {
            info!(target: TOPO, "link {} between {} and {} is now {}", link.id.0, a, b, if usable { "up" } else { "down" });
        }
        changed && !usable
    }

    /// Install a link into the in-memory router from a [LinkDescription], without
    /// persisting it. Used by both `add_linked_node` (which persists separately) and
    /// `restore_from_state` (which must not re-persist). The router error is returned
    /// unchanged so callers can decide how to treat [TopologyError::LinkExists].
    ///
    /// The link is installed with the up/down flag its link-state reports call for,
    /// atomically, so a link one end already vetoes is never usable in between.
    fn install_router_link(
        &self,
        a: &IpAddr,
        b: &IpAddr,
        link_desc: LinkDescription,
        cn_of: &dyn Fn(&IpAddr) -> Option<String>,
    ) -> Result<(), TopologyError> {
        // Hold the link-state table from reading the flag until the link is in the
        // router. A concurrent report stores its snapshot under this lock and then
        // refreshes the links it can see: it either runs before (and this read sees
        // its snapshot) or after (and its refresh sees this link). Lock order is
        // table, then router; no path takes them the other way round.
        let table = self.link_state.lock().unwrap();
        let up = Self::usable_in(&table, a, b, cn_of);
        self.router.add_link_with_state(
            a.clone(),
            b.clone(),
            link_desc.link_id.into(),
            link_desc.attrs,
            link_desc.cost,
            up,
        )
    }

    /// Persist an edge to state. Called only from public write-through mutation paths.
    async fn persist_edge(&self, a: &IpAddr, b: &IpAddr) -> Result<(), ServiceError> {
        self.link_repo.add_edge(a, b).await?;
        Ok(())
    }

    /// Roll back a node a call had just created. Used by the undo
    /// paths. Failures are logged rather than propagated so they do not mask the original
    /// error that triggered the rollback.
    async fn rollback_created_node(&self, actor_mgr: &ActorMgr, addr: &IpAddr) {
        // Removing the router node also drops its incident links.
        self.router.remove_node(addr);
        if let Err(re) = actor_mgr.remove_node(addr).await {
            warn!(target: TOPO, "rollback: failed to remove node {} state from actor_mgr: {}", addr, re);
        }
        if let Err(re) = actor_mgr.remove_actor_by_zpr_addr(addr).await {
            warn!(target: TOPO, "rollback: failed to remove actor record for {} from actor_mgr: {}", addr, re);
        }
    }

    /// Add a linked node to the graph.
    /// Also adds the node via the actor_manager if it is not already in the graph.
    ///
    /// On success the node-link edge is persisted to state. If persistence fails the
    /// partial in-memory/actor state created here is rolled back before returning the
    /// error, so we never report failure while leaving a router edge behind.
    pub async fn add_linked_node(
        &self,
        snapshot: &PolicySnapshot,
        actor_mgr: &ActorMgr,
        actor: &Actor,
        connect_via: &IpAddr,
        new_node_addr: &IpAddr,
    ) -> Result<(), AddLinkedNodeError> {
        let peer_node_addrs = self.router.get_peers(new_node_addr);
        let preexisting_node = self.router.has_node(new_node_addr);

        let link_desc = match snapshot.describe_link(connect_via, new_node_addr) {
            Ok(d) => d,
            Err(e) => return Err(AddLinkedNodeError::new(preexisting_node, e)),
        };
        // Kept for rollback: install_router_link consumes link_desc.
        let link_id_for_rollback = link_desc.link_id.clone();

        // If the new node has peers and one is the 'connect_via' .... uh, that's odd.  Error out?
        // If the new node has peers and none are the 'connect_via', then we already know about
        //    this node, but it is just forming a new link.
        // If the new node has no peers then it is not yet in our system.

        if !preexisting_node {
            // Brand new node. Add to router, add to actor_mgr.
            if let Err(e) = self.router.add_node(new_node_addr.clone()) {
                return Err(AddLinkedNodeError::NewNodeFailed(e.into()));
            }
            let policy_service_names: std::collections::HashSet<String> = snapshot
                .policy_arc()
                .list_services()
                .iter()
                .map(|svc| svc.id.clone())
                .collect();
            if let Err(e) = actor_mgr
                .add_node(actor, false, &policy_service_names)
                .await
            {
                warn!(target: TOPO, "failed to add node to actor_mgr: {}", e);
                self.router.remove_node(new_node_addr);
                return Err(AddLinkedNodeError::NewNodeFailed(e.into()));
            };
        } else if peer_node_addrs.contains(connect_via) {
            // Already connected over this same link (e.g. a reconnect or re-auth).
            // Persist the edge before returning, to repair the case where the router
            // has the edge but Redis missed it.
            debug!(target: TOPO, "try_add_node but node at addr {} is already connected to us via {}: FINE!", new_node_addr, connect_via);
            if let Err(e) = self.persist_edge(connect_via, new_node_addr).await {
                warn!(target: TOPO, "failed to persist already-connected edge {} <-> {}: {}", connect_via, new_node_addr, e);
                // Pre-existing node: its address is still live, so this is not a
                // new-node failure.
                return Err(AddLinkedNodeError::ExistingNodeFailed(e));
            }
            return Ok(()); // Assume everything is just fine!
        }

        // Add the link to the router. LinkExists is tolerated (repair / re-auth): in
        // that case we did NOT add a link, so the rollback below must not remove it.
        let mut added_new_link = false;
        match self.install_router_link(
            connect_via,
            new_node_addr,
            link_desc,
            &Self::policy_cn_lookup(snapshot),
        ) {
            Ok(()) => added_new_link = true,
            Err(TopologyError::LinkExists(_)) => {}
            Err(e) => {
                error!(target: TOPO, "failed to add link from {} to {}: {}", connect_via, new_node_addr, e);
                if !preexisting_node {
                    self.rollback_created_node(actor_mgr, new_node_addr).await;
                }
                return Err(AddLinkedNodeError::new(preexisting_node, e.into()));
            }
        }

        // Write-through: persist the edge. On failure, clean up the partial state we
        // created here, but return the ORIGINAL persistence error — the rollback calls
        // log their own failures.
        if let Err(e) = self.persist_edge(connect_via, new_node_addr).await {
            error!(target: TOPO, "failed to persist edge {} <-> {}: {}", connect_via, new_node_addr, e);
            if !preexisting_node {
                // We created the node; rolling it back also drops the incident link.
                self.rollback_created_node(actor_mgr, new_node_addr).await;
            } else if added_new_link {
                // Node pre-existed; remove only the link we just added.
                self.router.remove_link(&link_id_for_rollback.into());
            }
            return Err(AddLinkedNodeError::new(preexisting_node, e));
        }

        Ok(())
    }

    /// Rebuild the router graph from persisted state. Nodes come from `node_addrs`
    /// (the surviving node set after actor-state refresh); edges come from the
    /// [LinkRepo]. Edge attributes/cost are re-derived from the current policy.
    ///
    /// Stale-edge safety: an edge is only recreated when both endpoints survived the
    /// node-state refresh AND the current policy still describes that exact link.
    /// Otherwise the persisted edge is garbage-collected. Even if an address is reused,
    /// this never resurrects an edge the policy no longer describes.
    ///
    /// "Load state completely or fail": any error other than the precise
    /// link-not-found-in-policy case is propagated, so a transient policy/DB problem at
    /// startup fails the service rather than silently deleting valid persisted edges.
    pub async fn restore_from_state(
        &self,
        snapshot: &PolicySnapshot,
        node_addrs: &[IpAddr],
    ) -> Result<(), ServiceError> {
        // In this code path there should be no cases for errors from add_node.
        for addr in node_addrs {
            self.router.add_node(addr.clone())?;
        }

        let known: HashSet<IpAddr> = node_addrs.iter().copied().collect();

        for (a, b) in self.link_repo.list_edges().await? {
            // Decide the edge's fate against the current policy + known-node set. Any
            // error other than the precise not-described case is propagated, so a
            // transient policy/DB problem fails startup rather than deleting valid edges.
            match Self::decide_edge(snapshot, &known, &a, &b)? {
                EdgeDecision::Install(link_desc) => {
                    match self.install_router_link(
                        &a,
                        &b,
                        link_desc,
                        &Self::policy_cn_lookup(snapshot),
                    ) {
                        Ok(()) | Err(TopologyError::LinkExists(_)) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                EdgeDecision::Gc => {
                    info!(target: TOPO, "restore: GC stale edge {} <-> {}", a, b);
                    if let Err(e) = self.link_repo.remove_edge(&a, &b).await {
                        warn!(target: TOPO, "restore: failed to GC stale edge {} <-> {}: {}", a, b, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Decide whether an edge should be installed (policy still describes it) or
    /// garbage-collected (an endpoint is no longer a known node, or policy no longer
    /// describes the link in either direction).
    ///
    /// Preserves the "load completely or fail" rule: only the precise
    /// `LinkNotFound`-in-policy case yields `Gc`; any other error propagates so a
    /// transient policy/DB failure never silently deletes a valid edge.
    fn decide_edge(
        snapshot: &PolicySnapshot,
        known: &HashSet<IpAddr>,
        a: &IpAddr,
        b: &IpAddr,
    ) -> Result<EdgeDecision, ServiceError> {
        if !known.contains(a) || !known.contains(b) {
            return Ok(EdgeDecision::Gc);
        }
        // Edges are stored undirected, so try describing the link in either direction
        // before concluding the policy no longer describes it.
        match Self::describe_policy_link_either(snapshot, a, b) {
            Ok(desc) => Ok(EdgeDecision::Install(desc)),
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_))) => Ok(EdgeDecision::Gc),
            Err(e) => Err(e),
        }
    }

    /// Revalidate the live topology against the current policy after a policy
    /// update.
    ///
    /// Unlike [TopologyMgr::restore_from_state], which rebuilds an empty router
    /// at startup, this reconciles the live router plus the persisted edge set.
    /// Per edge we either prune it (policy no longer describes it), refresh its
    /// attrs/cost (policy changed), or repair router/persistence drift. Nodes
    /// left with no links are detected and reported but not torn down — node
    /// membership is governed by the passed in `node_addrs` (the authoritative
    /// known-node set), not by edge count.
    ///
    /// Validation always runs against the current policy. The pass is
    /// idempotent, so a policy update racing mid-pass simply produces another
    /// pass.
    pub async fn revalidate_against_policy(
        &self,
        snapshot: &PolicySnapshot,
        node_addrs: &[IpAddr],
    ) -> Result<RevalidationReport, ServiceError> {
        let mut report = RevalidationReport::default();
        let known: HashSet<IpAddr> = node_addrs.iter().copied().collect();

        // Actor/node state is the authoritative live-node set; make sure each such node
        // exists in the router before repairing its links.
        for addr in node_addrs {
            self.add_node_if_not_exists(*addr);
        }

        // Reconcile the union of persisted and live-router edges: either store may hold
        // an edge the other is missing.
        let persisted_edges = self.link_repo.list_edges().await?;
        let router_links = self.router.link_snapshot();
        let persisted_set: HashSet<(IpAddr, IpAddr)> = persisted_edges
            .iter()
            .map(|(a, b)| Self::canonical_pair(*a, *b))
            .collect();
        let mut work_edges: HashSet<(IpAddr, IpAddr)> = persisted_set.clone();
        for link in &router_links {
            work_edges.insert(Self::canonical_pair(link.a, link.b));
        }

        // Reconcile in two phases: decide every edge first, then mutate. A policy update
        // can move a link id from one edge to another; doing the work edge-by-edge would
        // let an install collide with the id's prior holder when `work_edges` (a HashSet)
        // happens to visit the new edge first, aborting the whole pass nondeterministically.
        // Deciding first lets us free every reassigned id before installing any, and lets
        // us reject a genuinely invalid policy (two surviving edges claiming one id)
        // up front so the live topology is left untouched rather than half-rewritten.

        /// How a surviving edge's router link must change to match policy.
        enum Action {
            /// Router already matches policy; nothing to install.
            Keep,
            /// Router missing the link (drift) — install fresh.
            Fresh,
            /// Router link differs (id/cost/attrs changed) — vacate this old id, then reinstall.
            Replace(LinkId),
        }
        struct Surviving {
            a: IpAddr,
            b: IpAddr,
            persisted: bool,
            desc: LinkDescription,
            action: Action,
            /// Whether the router link was up before this reconciliation.
            was_up: bool,
        }
        struct Removal {
            a: IpAddr,
            b: IpAddr,
            persisted: bool,
            old_id: Option<LinkId>,
            /// Whether the router link was up before this reconciliation.
            was_up: bool,
        }

        let cn_of = Self::policy_cn_lookup(snapshot);
        let mut surviving: Vec<Surviving> = Vec::new();
        let mut removals: Vec<Removal> = Vec::new();
        for (a, b) in work_edges {
            let persisted = persisted_set.contains(&(a, b));
            let router_link = self.router.link_between(&a, &b);
            match Self::decide_edge(snapshot, &known, &a, &b)? {
                EdgeDecision::Gc => removals.push(Removal {
                    a,
                    b,
                    persisted,
                    was_up: router_link.as_ref().is_some_and(|rl| rl.up),
                    old_id: router_link.map(|rl| rl.id),
                }),
                EdgeDecision::Install(desc) => {
                    let action = match &router_link {
                        None => Action::Fresh,
                        Some(rl) => {
                            // The up/down flag is part of the comparison: the
                            // node-to-CN index comes from policy, so a new policy can
                            // change which link-state reports match a link whose id,
                            // cost and attributes did not change.
                            let changed = rl.id.0 != desc.link_id
                                || rl.cost != desc.cost
                                || !attributes_equivalent(&rl.attributes, &desc.attrs)
                                || rl.up != self.usable_now(&a, &b, &cn_of);
                            if changed {
                                Action::Replace(rl.id.clone())
                            } else {
                                Action::Keep
                            }
                        }
                    };
                    surviving.push(Surviving {
                        a,
                        b,
                        persisted,
                        desc,
                        action,
                        was_up: router_link.as_ref().is_some_and(|rl| rl.up),
                    });
                }
            }
        }

        // Reject genuine id collisions (two surviving edges want the same id) before any
        // mutation. A surviving edge's final id is always its policy `link_id`.
        let mut claimed: HashSet<&str> = HashSet::new();
        for e in &surviving {
            if !claimed.insert(e.desc.link_id.as_str()) {
                return Err(TopologyError::LinkExists(e.desc.link_id.clone()).into());
            }
        }

        // Do all fallible async persistence before touching the router, so a persistence
        // failure returns with the live graph untouched rather than half-rewritten.
        // Repair persistence drift: router knows the link but Redis missed it.
        for e in &surviving {
            if !e.persisted {
                self.persist_edge(&e.a, &e.b).await?;
                report.links_repaired += 1;
            }
        }
        for r in &removals {
            if r.persisted {
                // Best-effort, same as restore: a surviving stale edge is
                // re-validated on the next pass / restart.
                if let Err(e) = self.link_repo.remove_edge(&r.a, &r.b).await {
                    warn!(target: TOPO, "revalidate: failed to GC edge {} <-> {}: {}", r.a, r.b, e);
                }
            }
            if r.old_id.is_some() || r.persisted {
                info!(target: TOPO, "revalidate: removed edge {} <-> {} (policy no longer describes link)", r.a, r.b);
                report.links_removed += 1;
            }
        }

        // Collect every router mutation and apply it as one atomic batch: no concurrent
        // visa route can observe a half-rewritten graph, and a rejected install rolls back
        // instead of leaving moved ids vacated. Removals (GC'd edges plus the old id of
        // every changed edge) are listed first so each reassigned id is free before reuse.
        let mut removal_ids: Vec<LinkId> =
            removals.iter().filter_map(|r| r.old_id.clone()).collect();
        report.links_down = removals
            .iter()
            .filter(|r| r.was_up)
            .map(|r| (r.a, r.b))
            .collect();
        let mut additions: Vec<LinkSpec> = Vec::new();
        // Link state comes from link-state reports, not policy: every installed or
        // rebuilt link gets the flag its reports call for, inside the atomic batch.
        // The table stays locked until the batch is applied, for the same reason as
        // in install_router_link: a concurrent report cannot slip in between.
        let table = self.link_state.lock().unwrap();
        for e in surviving {
            let spec = LinkSpec {
                a: e.a,
                b: e.b,
                id: e.desc.link_id.into(),
                attributes: e.desc.attrs,
                cost: e.desc.cost,
                up: Self::usable_in(&table, &e.a, &e.b, &cn_of),
            };
            if e.was_up && !spec.up {
                report.links_down.push((e.a, e.b));
            }
            match e.action {
                Action::Keep => {}
                Action::Fresh => {
                    additions.push(spec);
                    report.links_repaired += 1;
                }
                Action::Replace(old) => {
                    removal_ids.push(old);
                    additions.push(spec);
                    report.links_updated += 1;
                }
            }
        }
        self.router.apply_link_batch(&removal_ids, additions)?;
        drop(table);

        // Detect + report orphans. An orphan node is a legitimate state and stays in the
        // topology so long as it remains a known node; removing it belongs to the
        // node-leave / re-auth path, not here.
        for addr in node_addrs {
            if self.router.get_peers(addr).is_empty() {
                warn!(target: TOPO, "revalidate: node {} has no remaining valid links (orphaned)", addr);
                report.orphaned_nodes.push(*addr);
            }
        }

        Ok(report)
    }

    /// Return an ordered undirected key so router and LinkRepo edges compare the same way.
    fn canonical_pair(a: IpAddr, b: IpAddr) -> (IpAddr, IpAddr) {
        if a <= b { (a, b) } else { (b, a) }
    }

    /// Describe a link defined in policy in either direction. Edges are stored undirected, so a stored
    /// `(a, b)` may correspond to a policy peering recorded as `b -> a`. Returns
    /// `LinkNotFound` only when neither direction matches; any other error from the
    /// first lookup is returned as-is.
    fn describe_policy_link_either(
        snapshot: &PolicySnapshot,
        a: &IpAddr,
        b: &IpAddr,
    ) -> Result<LinkDescription, ServiceError> {
        match snapshot.describe_link(a, b) {
            Err(ServiceError::Topology(TopologyError::LinkNotFound(_))) => {
                snapshot.describe_link(b, a)
            }
            other => other,
        }
    }

    /// Add a node to the router without disturbing links or persisted edges.
    /// This calls [Router::add_node].
    ///
    /// Retruns an error if the node already exists.
    #[allow(dead_code)]
    pub fn add_node(&self, addr: IpAddr) -> Result<(), TopologyError> {
        self.router.add_node(addr)
    }

    /// Add a node to the router without disturbing links or persisted edges.
    /// This calls [Router::add_node].
    ///
    /// Returns true if node was added. If node already exists, you get `false` back instead.
    pub fn add_node_if_not_exists(&self, addr: IpAddr) -> bool {
        match self.router.add_node(addr) {
            Ok(()) => true,
            Err(TopologyError::NodeExists(_)) => false,
            Err(e) => unreachable!("unexpected error adding node to router: {}", e),
        }
    }

    #[allow(dead_code)]
    pub fn add_link(
        &self,
        zpr_addr_a: IpAddr,
        zpr_addr_b: IpAddr,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        self.router
            .add_link(zpr_addr_a, zpr_addr_b, id, attributes, cost)
    }

    /// Remove a node and all its incident links from the router, and best-effort
    /// delete the corresponding persisted edges.
    ///
    /// Persisted-edge removal is read-then-delete: incident peers are read *before*
    /// the router removal so we know which edges to delete. Failures are logged but do
    /// not abort the removal — this is a deliberate eventual-cleanup model: a stale
    /// persisted edge may survive a DB failure, but `restore_from_state` validates
    /// every persisted edge against the surviving node set and current policy before
    /// recreating anything, so stale edges never resurrect a real link.
    pub async fn remove_node(&self, addr: &IpAddr) {
        let peers = self.router.get_peers(addr);
        for peer in &peers {
            if let Err(e) = self.link_repo.remove_edge(addr, peer).await {
                warn!(target: TOPO, "failed to remove persisted edge {} <-> {} on node removal: {}", addr, peer, e);
            }
        }
        // Under the table lock, so a concurrent report either lands before (and is
        // cleared here) or after (and finds the node gone; see record_link_states).
        let mut table = self.link_state.lock().unwrap();
        table.remove_node(addr);
        self.router.remove_node(addr)
    }

    /// Find optimal route between the nodes.
    /// Note that `a` and `b` must be node addresses.
    pub fn get_best_route(&self, a: &IpAddr, b: &IpAddr) -> Option<Route> {
        self.router.get_best_route(a, b)
    }

    /// Find all routes between the nodes.
    /// Note that `a` and `b` must be node addresses.
    pub fn get_routes(&self, a: &IpAddr, b: &IpAddr, hint: Option<&RouteHint>) -> Vec<Route> {
        self.router.get_routes(a, b, hint)
    }

    pub fn route_to_path(
        &self,
        route: &Route,
        starting: &NodeId,
    ) -> Result<Vec<NodeId>, TopologyError> {
        self.router.route_to_path(route, starting)
    }

    pub fn get_peers(&self, zpr_addr: &IpAddr) -> Vec<IpAddr> {
        self.router.get_peers(zpr_addr)
    }
}

impl TopologyQueryApi for TopologyMgr {
    /// TODO: We do not yet support policy on link attributes and [AttrMatch] is not yet defined. This alwayes returns false.
    fn link_has_attr(&self, _link_id: &LinkId, _attr: &AttrMatch) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::trusted_services::TrustedServicesMgr;

    use zpr::policy::v1 as policy_capnp;
    use zpr::policy_types::{AttrExp, AttrOp, NetAddr, Peering};
    use zpr::write_to::WriteTo;

    use crate::config;
    use crate::counters::Counters;
    use crate::db::{ActorRepo, DbConnection, FakeDb, LinkRepo, NodeRepo, PolicyRepo};
    use crate::policy_mgr::PolicyMgr;
    use crate::test_helpers::{FakeResolver, make_container_bytes, make_node_actor_defexp};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Build a single peering between `node_a` and `node_b` carrying the given link
    /// attributes. Substrate addresses use the node IPs with port 0 so the IP-only
    /// resolver works.
    fn peering(node_a: IpAddr, node_b: IpAddr, link_id: &str, attributes: Vec<AttrExp>) -> Peering {
        Peering {
            link_id: link_id.to_string(),
            node_a,
            substrate_a: Some(NetAddr::new_for_ip_or_host(&node_a.to_string(), 0)),
            node_b,
            substrate_b: Some(NetAddr::new_for_ip_or_host(&node_b.to_string(), 0)),
            attributes,
        }
    }

    /// A `link.zpr.cost` attribute carrying the given cost, for exercising the cost path.
    fn cost_attr(cost: u32) -> AttrExp {
        AttrExp {
            key: "link.zpr.cost".to_string(),
            op: AttrOp::Eq,
            value: vec![cost.to_string()],
        }
    }

    /// Serialize a policy whose topology is exactly the given peerings.
    fn policy_bytes_from_peerings(peerings: &[Peering]) -> Vec<u8> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            policy.reborrow().set_created("1970-01-01T00:00:00Z");
            let mut topo = policy.reborrow().init_topology(peerings.len() as u32);
            for (i, p) in peerings.iter().enumerate() {
                p.write_to(&mut topo.reborrow().get(i as u32));
            }
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        bytes
    }

    /// Build a Policy containing a single attribute-free peering between `node_a` and `node_b`.
    fn policy_with_link(node_a: IpAddr, node_b: IpAddr, link_id: &str) -> Vec<u8> {
        policy_bytes_from_peerings(&[peering(node_a, node_b, link_id, vec![])])
    }

    /// Create a PolicyMgr over the given db preloaded with the given policy bytes.
    async fn make_policy_mgr_from_bytes(db: Arc<FakeDb>, pol_bytes: Vec<u8>) -> PolicyMgr {
        let repo = PolicyRepo::new(db.clone());
        PolicyMgr::new_with_initial_policy(
            make_container_bytes(
                config::POLICY_MIN_COMPILER_MAJOR,
                config::POLICY_MIN_COMPILER_MINOR,
                config::POLICY_MIN_COMPILER_PATCH,
                &pol_bytes,
            ),
            repo,
            Arc::new(FakeResolver::ip_only()),
            Arc::new(TrustedServicesMgr::new()),
            PathBuf::from("."),
            PathBuf::from("."),
            Arc::new(crate::db::ActorRepo::new(db)),
            None,
            crate::config::VSConfig::default().get_vs_addr(),
        )
        .await
        .unwrap()
    }

    /// Create a PolicyMgr over the given db preloaded with a single-link policy.
    async fn make_policy_mgr(db: Arc<FakeDb>, a: IpAddr, b: IpAddr, link_id: &str) -> PolicyMgr {
        make_policy_mgr_from_bytes(db, policy_with_link(a, b, link_id)).await
    }

    /// Build an ActorMgr over the given db.
    fn make_actor_mgr(db: Arc<FakeDb>) -> ActorMgr {
        ActorMgr::new(
            ActorRepo::new(db.clone()),
            NodeRepo::new(db),
            Arc::new(Counters::default()),
        )
    }

    /// add_linked_node persists the node-link edge to state.
    #[tokio::test]
    async fn test_add_linked_node_persists_edge() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // connect_via node `a` must already exist in the router.
        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");

        topo.add_linked_node(
            &policy_mgr.get_current_snapshot(),
            &actor_mgr,
            &actor_b,
            &a,
            &b,
        )
        .await
        .unwrap();

        let edges = LinkRepo::new(db).list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
        let (ea, eb) = edges[0];
        assert!((ea == a && eb == b) || (ea == b && eb == a));
    }

    /// The already-connected (existing router link) path repairs a missing persisted edge.
    #[tokio::test]
    async fn test_add_linked_node_repairs_missing_persisted_edge() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Pre-create both nodes and the router link directly, WITHOUT persisting an edge.
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        assert!(
            LinkRepo::new(db.clone())
                .list_edges()
                .await
                .unwrap()
                .is_empty()
        );

        // Re-adding the same link hits the already-connected path and repairs Redis.
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        topo.add_linked_node(
            &policy_mgr.get_current_snapshot(),
            &actor_mgr,
            &actor_b,
            &a,
            &b,
        )
        .await
        .unwrap();

        let edges = LinkRepo::new(db).list_edges().await.unwrap();
        assert_eq!(edges.len(), 1);
    }

    /// A persistence failure compensates the partial router/actor state and returns Err.
    #[tokio::test]
    async fn test_add_linked_node_compensates_on_persist_failure() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");

        // Poison the edges key so sadd (and thus add_edge) fails with a type error.
        db.set("topology:edges", "junk").await.unwrap();

        let result = topo
            .add_linked_node(
                &policy_mgr.get_current_snapshot(),
                &actor_mgr,
                &actor_b,
                &a,
                &b,
            )
            .await;
        // A brand-new node's failure must be reported as a new-node failure so the
        // caller releases the freshly allocated address.
        assert!(
            matches!(result, Err(AddLinkedNodeError::NewNodeFailed(_))),
            "new-node persist failure must be a NewNodeFailed error, got {:?}",
            result
        );

        // Compensation removed node `b` from the router (it can be re-added cleanly)...
        assert!(
            topo.add_node(b).is_ok(),
            "node b should have been removed from the router by compensation"
        );
        // ...and from the actor manager.
        assert!(
            actor_mgr.get_actor_by_zpr_addr(&b).await.unwrap().is_none(),
            "node b should have been removed from the actor manager by compensation"
        );
    }

    /// A persist failure while repairing a PRE-EXISTING node's edge is reported as an
    /// existing-node failure and leaves the live node in place.
    #[tokio::test]
    async fn test_add_linked_node_preexisting_failure_is_existing_node_error() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Pre-create both nodes and the router link so `b` is already connected over `a`
        // (the already-connected edge-repair path).
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();

        // Poison the edges key so the repair persist fails.
        db.set("topology:edges", "junk").await.unwrap();

        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        let result = topo
            .add_linked_node(
                &policy_mgr.get_current_snapshot(),
                &actor_mgr,
                &actor_b,
                &a,
                &b,
            )
            .await;

        assert!(
            matches!(result, Err(AddLinkedNodeError::ExistingNodeFailed(_))),
            "pre-existing node persist failure must be an ExistingNodeFailed error, got {:?}",
            result
        );
        // The live node must not have been removed by the failed call.
        assert!(
            topo.add_node(b).is_err(),
            "pre-existing node b must remain in the router after an existing-node failure"
        );
    }

    /// remove_node deletes the persisted incident edges.
    #[tokio::test]
    async fn test_remove_node_deletes_incident_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.add_node(a).unwrap();
        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        topo.add_linked_node(
            &policy_mgr.get_current_snapshot(),
            &actor_mgr,
            &actor_b,
            &a,
            &b,
        )
        .await
        .unwrap();
        assert_eq!(
            LinkRepo::new(db.clone()).list_edges().await.unwrap().len(),
            1
        );

        topo.remove_node(&b).await;

        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "incident edge should be removed from state"
        );
    }

    /// restore_from_state rebuilds the router graph from persisted edges + policy.
    #[tokio::test]
    async fn test_restore_rebuilds_graph_from_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;

        // Persist an edge directly, then restore into a fresh (empty) topology.
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        // The link is back: a and b are peers and a route exists.
        assert_eq!(topo.get_peers(&a), vec![b]);
        assert!(topo.get_best_route(&a, &b).is_some());
    }

    /// add_node_if_not_exists preserves restored in-memory links and persisted edges on reconnect.
    #[tokio::test]
    async fn test_add_node_if_not_exists_preserves_restored_links_on_reconnect() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;

        // Persist an edge directly, then restore into a fresh topology to simulate restart.
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.restore_from_state(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();
        assert_eq!(topo.get_peers(&a), vec![b], "precondition: link restored");

        let added = topo.add_node_if_not_exists(b);

        assert!(!added, "node was already present from restore");
        assert_eq!(
            topo.get_peers(&a),
            vec![b],
            "restored in-memory link must survive reconnect"
        );
        assert_eq!(
            LinkRepo::new(db).list_edges().await.unwrap().len(),
            1,
            "persisted edge must survive reconnect"
        );
    }

    /// A persisted edge the current policy no longer describes is skipped and GC'd.
    #[tokio::test]
    async fn test_restore_gcs_stale_edge_not_in_policy() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        // Policy only describes a<->b; the persisted edge a<->c is stale.
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &c).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr.get_current_snapshot(), &[a, c])
            .await
            .unwrap();

        assert!(
            topo.get_peers(&a).is_empty(),
            "stale edge must not be installed"
        );
        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "stale edge must be garbage-collected"
        );
    }

    /// A persisted edge whose endpoint is no longer a known node is GC'd on restore.
    #[tokio::test]
    async fn test_restore_gcs_edge_with_unknown_endpoint() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // Only `a` survived node-state refresh; `b` is gone.
        topo.restore_from_state(&policy_mgr.get_current_snapshot(), &[a])
            .await
            .unwrap();

        assert!(topo.get_peers(&a).is_empty());
        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "edge with a missing endpoint must be garbage-collected"
        );
    }

    /// Restoring from an empty surviving-node set intentionally GCs every persisted edge.
    /// With no known nodes, no persisted topology links or routes can remain valid.
    #[tokio::test]
    async fn test_restore_with_empty_node_set_gcs_all_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        topo.restore_from_state(&policy_mgr.get_current_snapshot(), &[])
            .await
            .unwrap();

        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "with no surviving nodes every edge is GC'd"
        );
    }

    // --- revalidate_against_policy tests ---

    /// A live + persisted link the new policy no longer describes is removed from both
    /// the router and persisted state.
    #[tokio::test]
    async fn test_revalidate_removes_link_not_in_policy() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        // New policy only describes a<->b; the live a<->c link is now stale.
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();
        topo.add_node(c).unwrap();
        topo.add_link(a, c, LinkId("link-ac".into()), vec![], 1)
            .unwrap();
        LinkRepo::new(db.clone()).add_edge(&a, &c).await.unwrap();

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, c])
            .await
            .unwrap();

        assert_eq!(report.links_removed, 1);
        assert!(topo.get_peers(&a).is_empty(), "stale router link removed");
        assert!(
            LinkRepo::new(db).list_edges().await.unwrap().is_empty(),
            "stale persisted edge GC'd"
        );
    }

    /// A still-valid link whose policy cost changed is updated in the router.
    #[tokio::test]
    async fn test_revalidate_updates_changed_cost() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        // New policy describes a<->b with cost 9.
        let policy_mgr = make_policy_mgr_from_bytes(
            db.clone(),
            policy_bytes_from_peerings(&[peering(a, b, "link-ab", vec![cost_attr(9)])]),
        )
        .await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        // Live router link still has the old cost of 1.
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        assert_eq!(report.links_updated, 1);
        assert_eq!(report.links_removed, 0);
        assert_eq!(
            topo.get_best_route(&a, &b).unwrap().cost,
            9,
            "router link cost refreshed from policy"
        );
    }

    /// A persisted edge missing from the live router is re-installed (repair).
    #[tokio::test]
    async fn test_revalidate_repairs_missing_router_link() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        // Edge persisted but router is empty (drift).
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        assert_eq!(report.links_repaired, 1);
        assert_eq!(topo.get_peers(&a), vec![b], "router link re-installed");
    }

    /// A live router link missing from persisted state, still described by policy, has its
    /// persisted edge repaired.
    #[tokio::test]
    async fn test_revalidate_repairs_missing_persisted_edge() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        // Router link present at the policy's default cost; nothing persisted.
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        assert!(
            LinkRepo::new(db.clone())
                .list_edges()
                .await
                .unwrap()
                .is_empty()
        );

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        assert_eq!(report.links_repaired, 1);
        assert_eq!(report.links_updated, 0, "matching link must not be updated");
        assert_eq!(
            LinkRepo::new(db).list_edges().await.unwrap().len(),
            1,
            "missing persisted edge repaired"
        );
    }

    /// A live router link missing from persisted state that policy no longer describes is
    /// removed from the router.
    #[tokio::test]
    async fn test_revalidate_removes_unpersisted_router_link_not_in_policy() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        // Policy describes a<->b only; the live (unpersisted) a<->c link is stale.
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();
        topo.add_node(c).unwrap();
        topo.add_link(a, c, LinkId("link-ac".into()), vec![], 1)
            .unwrap();

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, c])
            .await
            .unwrap();

        assert_eq!(report.links_removed, 1);
        assert!(topo.get_peers(&a).is_empty());
    }

    /// A valid unchanged link is left intact and its edge preserved (idempotent pass).
    #[tokio::test]
    async fn test_revalidate_leaves_unchanged_link_intact() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        // First pass installs the link from policy.
        topo.revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        // Second pass must be a no-op.
        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        assert_eq!(report.links_removed, 0);
        assert_eq!(report.links_updated, 0);
        assert_eq!(report.links_repaired, 0);
        assert_eq!(topo.get_peers(&a), vec![b]);
        assert_eq!(LinkRepo::new(db).list_edges().await.unwrap().len(), 1);
    }

    /// A valid unchanged link with non-empty attributes must not be falsely updated:
    /// policy rebuilds attrs with a fresh `expires_at`, but stable-content comparison
    /// must treat them as equivalent.
    #[tokio::test]
    async fn test_revalidate_nonempty_attrs_not_falsely_updated() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr_from_bytes(
            db.clone(),
            policy_bytes_from_peerings(&[peering(a, b, "link-ab", vec![cost_attr(5)])]),
        )
        .await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        // First pass installs the attribute-bearing link.
        topo.revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        // Second pass must not report a spurious update from rebuilt attrs.
        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();

        assert_eq!(report.links_updated, 0, "rebuilt attrs must compare equal");
        assert_eq!(report.links_repaired, 0);
        assert_eq!(topo.get_best_route(&a, &b).unwrap().cost, 5);
    }

    /// A policy whose link id collides with another live router link's id makes the
    /// replacement fail; the error propagates and the old link is left intact.
    #[tokio::test]
    async fn test_revalidate_id_collision_errors_and_preserves_link() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        let d = ip("fd5a:5052::4");
        // Policy describes a<->b and c<->d both under link id "shared".
        let policy_mgr = make_policy_mgr_from_bytes(
            db.clone(),
            policy_bytes_from_peerings(&[
                peering(a, b, "shared", vec![]),
                peering(c, d, "shared", vec![]),
            ]),
        )
        .await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_node(c).unwrap();
        topo.add_node(d).unwrap();
        // a<->b currently has a different id; c<->d already holds "shared".
        topo.add_link(a, b, LinkId("old-ab".into()), vec![], 1)
            .unwrap();
        topo.add_link(c, d, LinkId("shared".into()), vec![], 1)
            .unwrap();

        let result = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b, c, d])
            .await;

        assert!(result.is_err(), "id collision must surface as an error");
        // The old a<->b link must survive the rejected replacement.
        assert!(
            topo.get_best_route(&a, &b).is_some(),
            "old link must be left intact after a failed replacement"
        );
    }

    /// A policy update that reassigns link ids between two still-valid edges must
    /// reconcile successfully. Here a<->b and c<->d swap ids: each id stays unique in
    /// the new policy, but during the single reconciliation pass the target id is still
    /// held by the other live edge that hasn't been processed yet. Because `work_edges`
    /// is a HashSet, neither processing order can avoid the in-pass collision, so this
    /// fails deterministically today (replace_link_between returns LinkExists and the
    /// whole pass aborts) — the deterministic instance of the move/reuse class flagged
    /// in review.
    #[tokio::test]
    async fn test_revalidate_swaps_link_ids_between_valid_edges() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        let d = ip("fd5a:5052::4");
        // New policy keeps both edges but swaps their link ids.
        let policy_mgr = make_policy_mgr_from_bytes(
            db.clone(),
            policy_bytes_from_peerings(&[
                peering(a, b, "link-2", vec![]),
                peering(c, d, "link-1", vec![]),
            ]),
        )
        .await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_node(c).unwrap();
        topo.add_node(d).unwrap();
        // Live router currently has the ids the policy is about to swap.
        topo.add_link(a, b, LinkId("link-1".into()), vec![], 1)
            .unwrap();
        topo.add_link(c, d, LinkId("link-2".into()), vec![], 1)
            .unwrap();
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        LinkRepo::new(db.clone()).add_edge(&c, &d).await.unwrap();

        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b, c, d])
            .await
            .expect("id reassignment between valid edges must reconcile, not abort");

        assert_eq!(report.links_updated, 2, "both edges' ids refreshed");
        assert_eq!(report.links_removed, 0, "neither edge is stale");
        assert_eq!(
            topo.router.link_between(&a, &b).unwrap().id.0,
            "link-2",
            "a<->b took the new id"
        );
        assert_eq!(
            topo.router.link_between(&c, &d).unwrap().id.0,
            "link-1",
            "c<->d took the new id"
        );
    }

    /// A known node whose links were all pruned is reported as orphaned (but not removed).
    #[tokio::test]
    async fn test_revalidate_reports_orphaned_node() {
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let c = ip("fd5a:5052::3");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));

        // `c` is a known node with no links.
        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b, c])
            .await
            .unwrap();

        assert!(
            report.orphaned_nodes.contains(&c),
            "linkless known node must be reported orphaned"
        );
        assert!(!report.orphaned_nodes.contains(&a));
        assert!(
            topo.add_node(c).is_err(),
            "orphaned node must remain in the topology"
        );
    }

    // --- Link-state reports (zl-zipline#224) ---

    use std::collections::HashMap;
    use zpr::vsapi_types::{LinkState, LinkStateReport};

    fn report(cn: &str, state: LinkState) -> LinkStateReport {
        LinkStateReport {
            peer_cn: cn.to_string(),
            state,
        }
    }

    /// A CN lookup over a fixed address -> CN table, standing in for policy.
    fn cn_table(pairs: &[(IpAddr, &str)]) -> impl Fn(&IpAddr) -> Option<String> + use<> {
        let map: HashMap<IpAddr, String> = pairs.iter().map(|(a, c)| (*a, c.to_string())).collect();
        move |addr: &IpAddr| map.get(addr).cloned()
    }

    #[test]
    fn test_link_state_reports_drive_the_router_flag() {
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let topo = TopologyMgr::new(LinkRepo::new(Arc::new(FakeDb::new())));
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let cn_of = cn_table(&[(a, "a.zpr"), (b, "b.zpr")]);

        // A says up, B has not reported (legacy): still up, nothing went down.
        let down =
            topo.record_link_states_with_cns(&a, vec![report("b.zpr", LinkState::Up)], &cn_of);
        assert!(down.is_empty());
        assert!(topo.router.link_between(&a, &b).unwrap().up);

        // B says down: the edge goes down and is reported as such, once.
        let down =
            topo.record_link_states_with_cns(&b, vec![report("a.zpr", LinkState::Down)], &cn_of);
        assert_eq!(down, vec![(b, a)]);
        assert!(!topo.router.link_between(&a, &b).unwrap().up);
        assert!(topo.get_best_route(&a, &b).is_none());
        let again =
            topo.record_link_states_with_cns(&b, vec![report("a.zpr", LinkState::Down)], &cn_of);
        assert!(
            again.is_empty(),
            "an edge already down is not reported again"
        );

        // B says up again: the edge comes back; coming up is not a "went down".
        let down =
            topo.record_link_states_with_cns(&b, vec![report("a.zpr", LinkState::Up)], &cn_of);
        assert!(down.is_empty());
        assert!(topo.router.link_between(&a, &b).unwrap().up);
        assert!(topo.get_best_route(&a, &b).is_some());
    }

    #[tokio::test]
    async fn test_report_before_link_exists_applies_when_link_is_installed() {
        // A reports an empty snapshot (no link up) before its link to B is installed.
        // When B joins and the link is installed, it must start down.
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let actor_mgr = make_actor_mgr(db.clone());
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();

        let down = topo.record_link_states_with_cns(&a, vec![], &|_: &IpAddr| None);
        assert!(down.is_empty(), "no edge yet, so nothing went down");

        let actor_b = make_node_actor_defexp(&b.to_string(), "node-b", "[fd5a:5052::100]:1234");
        topo.add_linked_node(
            &policy_mgr.get_current_snapshot(),
            &actor_mgr,
            &actor_b,
            &a,
            &b,
        )
        .await
        .unwrap();

        let link = topo.router.link_between(&a, &b).expect("link installed");
        assert!(!link.up, "A's earlier report says the link is not up");
    }

    #[tokio::test]
    async fn test_removing_a_node_forgets_its_reports() {
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let topo = TopologyMgr::new(LinkRepo::new(Arc::new(FakeDb::new())));
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let cn_of = cn_table(&[(a, "a.zpr"), (b, "b.zpr")]);
        topo.record_link_states_with_cns(&a, vec![report("b.zpr", LinkState::Down)], &cn_of);
        assert!(!topo.router.link_between(&a, &b).unwrap().up);

        topo.remove_node(&a).await;
        topo.add_node(a).unwrap();
        topo.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        topo.refresh_links_for_node(&a, &cn_of);
        assert!(
            topo.router.link_between(&a, &b).unwrap().up,
            "a re-joined node is a non-reporter until it reports again"
        );
    }

    #[tokio::test]
    async fn test_revalidate_reapplies_link_state_to_kept_links() {
        // A link that is unchanged in policy (same id, cost, attributes) must still get
        // its up/down flag re-evaluated: the node-to-CN index comes from policy, so a
        // new policy can change which reports match the link.
        let db = Arc::new(FakeDb::new());
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        // This policy declares the link but names no CNs.
        let policy_mgr = make_policy_mgr(db.clone(), a, b, "link-ab").await;
        let topo = TopologyMgr::new(LinkRepo::new(db.clone()));
        topo.add_node(a).unwrap();
        topo.add_node(b).unwrap();
        topo.add_link(a, b, LinkId("link-ab".into()), vec![], 1)
            .unwrap();
        LinkRepo::new(db.clone()).add_edge(&a, &b).await.unwrap();

        // Under an earlier CN mapping, A's report matches B and the link is up.
        let old_cns = cn_table(&[(a, "a.zpr"), (b, "b.zpr")]);
        topo.record_link_states_with_cns(&a, vec![report("b.zpr", LinkState::Up)], &old_cns);
        assert!(topo.router.link_between(&a, &b).unwrap().up);

        // The current policy no longer knows B's CN, so A's entry cannot match it.
        let report = topo
            .revalidate_against_policy(&policy_mgr.get_current_snapshot(), &[a, b])
            .await
            .unwrap();
        assert_eq!(report.links_removed, 0);
        assert!(
            !topo.router.link_between(&a, &b).unwrap().up,
            "the kept link must follow the new CN mapping"
        );
        assert_eq!(
            report.links_down.len(),
            1,
            "the up->down transition is reported so its visas get revoked"
        );
        let (x, y) = report.links_down[0];
        assert!((x, y) == (a, b) || (x, y) == (b, a));
    }

    #[test]
    fn test_report_from_a_node_no_longer_in_the_router_is_not_stored() {
        // A stale handle whose node was disconnected (removed from the router) must
        // not leave a snapshot behind that would govern the link after a reconnect.
        let a = ip("fd5a:5052::1");
        let b = ip("fd5a:5052::2");
        let topo = TopologyMgr::new(LinkRepo::new(Arc::new(FakeDb::new())));
        topo.add_node(b).unwrap();
        let cn_of = cn_table(&[(a, "a.zpr"), (b, "b.zpr")]);

        // A is not a router node: its (down) report is dropped.
        topo.record_link_states_with_cns(&a, vec![report("b.zpr", LinkState::Down)], &cn_of);

        // A reconnects and its link is installed: A is a non-reporter, so legacy-up.
        topo.add_node(a).unwrap();
        topo.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        topo.refresh_links_for_node(&a, &cn_of);
        assert!(topo.router.link_between(&a, &b).unwrap().up);
    }
}
