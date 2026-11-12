//! Router keeps track of nodes and their connections. It does not know anything about adapters.
//! So to route between two actors you first need to determine their docking nodes.  Then you
//! can query this Router to see if there is a path.
//!
//! Must be kept in sync with the coming and going of nodes, and for each node the coming and
//! going of links. (TODO)

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;

use libeval::attribute::Attribute;
use libeval::eval_route::RouteHint;
use libeval::route::{LinkId, NodeId, Route, RouteKind};

use crate::error::TopologyError;

/// Memoization key for [Router::get_routes].
///
/// ## Route cache strategy
///
/// `get_routes` runs a DFS over the full topology to enumerate all simple paths between two
/// nodes, which is expensive on large or dense graphs.  Results are stored in
/// `RouterInner::route_cache` keyed by `(src, dst, hint)`.
///
/// ### Concurrency model
///
/// `RouterInner` is protected by a `RwLock`.  Cache hits and DFS computation on cache misses
/// both proceed under a **read** lock, so concurrent route lookups run in parallel.  Only the
/// brief final step of inserting a computed result into the cache requires a **write** lock.
///
/// Because the DFS runs under a read lock, a topology mutation (write lock) may land between
/// the DFS and the write-lock acquisition.  `RouterInner::topo_generation` is incremented on every
/// topology change; `get_routes` compares the topo_generation it read against the topo_generation it sees
/// when it acquires the write lock.  A mismatch means the computed routes may be stale: the
/// call re-computes from the current topology under the write lock and skips caching to keep
/// the critical section short.  The caller always receives correct routes.
///
/// Note that we are assuming that the co-occurance of full DFS and node changes is infrequent.
/// If this turns out not to be the case we can look to something like an `ArcSwap<RwLock<>>`.
///
/// ### Targeted invalidation
///
/// `RouterInner` maintains one reverse index:
///
/// - **`link_to_cache_keys`** — maps each `LinkId` → set of cache keys whose routes traverse
///   that link.  `remove_link` uses this to evict only the entries that actually use the
///   removed link.  `remove_node` uses it transitively via the node's incident links.
///
/// The index is populated in `get_routes` at cache-insert time and cleaned up atomically
/// by `RouterInner::invalidate_keys` whenever entries are evicted.
///
/// ### add_link always flushes the full cache
///
/// Targeted invalidation on link *removal* is exact: any affected route must traverse the
/// removed link, so `link_to_cache_keys` identifies the precise affected set.
///
/// Link *addition* cannot use the same index.  A new link a→b may render stale a cached
/// entry for (x, y) whose existing routes never touched a or b
/// (e.g. x→a and b→y existed, a→b did not, so the only cached route was x→y direct;
/// that entry is now incomplete).  `link_to_cache_keys` won't find it because the entry
/// doesn't traverse the new link.
///
/// A tighter bound exists — the *topological horizon*: only pairs (x, y) where x can
/// reach {a, b} and {a, b} can reach y are potentially affected; pairs in disconnected
/// subgraphs are safe.  Computing that reachable set requires a BFS from a and b,
/// O(V + E).  For shortest-path caches a further *cost horizon* applies: only pairs
/// where d(x,a) + cost(a,b) + d(b,y) < d(x,y) are actually affected (the incremental
/// SSSP problem; see Ramalingam & Reps 1996).  Because this cache covers all simple
/// paths — not just shortest paths — the cost horizon does not directly apply here.
///
/// For now `add_link` flushes the entire route cache; targeted invalidation can be
/// added later if profiling shows link addition is a hot path.
///
/// ### Ordering constraint
///
/// `invalidate_keys` walks `topology.edges` to resolve a `LinkId` → `(node_a, node_b)` for
/// link-index cleanup.  It must therefore be called **before** the topology mutation that
/// removes the link/node, otherwise those entries are gone and the index leaks stale entries.
#[derive(Hash, Eq, PartialEq, Clone)]
struct RouteCacheKey {
    a: NodeId,
    b: NodeId,
    hint: Option<RouteHint>,
}

struct RouterInner {
    topology: Graph,
    route_cache: HashMap<RouteCacheKey, Vec<Route>>,
    /// Reverse index: cache keys whose routes traverse a given link. See [RouteCacheKey].
    link_to_cache_keys: HashMap<LinkId, HashSet<RouteCacheKey>>,
    /// Incremented on every topology mutation; lets `get_routes` detect stale DFS results.
    topo_generation: u64,
}

impl RouterInner {
    /// Removes a set of cache keys and cleans up `link_to_cache_keys` for each removed entry.
    ///
    /// Must be called before any topology mutation that removes links, because it resolves
    /// `LinkId` → endpoints via `topology.edges`.  Duplicate keys are safe — a missing
    /// `route_cache` entry is a no-op.
    fn invalidate_keys(&mut self, keys: impl IntoIterator<Item = RouteCacheKey>) {
        for key in keys {
            let Some(routes) = self.route_cache.remove(&key) else {
                continue;
            };
            let affected_links: HashSet<LinkId> = routes
                .iter()
                .flat_map(|r| r.links.iter().cloned())
                .collect();
            for link_id in &affected_links {
                if let Some(s) = self.link_to_cache_keys.get_mut(link_id) {
                    s.remove(&key);
                    if s.is_empty() {
                        self.link_to_cache_keys.remove(link_id);
                    }
                }
            }
        }
    }
}

/// A snapshot of a single live link in the router, used by topology revalidation to
/// compare the live router graph against what policy currently describes.
#[derive(Debug, Clone)]
pub struct RouterLink {
    pub a: IpAddr,
    pub b: IpAddr,
    pub id: LinkId,
    pub attributes: Vec<Attribute>,
    pub cost: u32,
    /// False while link-state reports say the link is down; see [Router::set_link_up].
    pub up: bool,
}

/// One link to install as part of an [Router::apply_link_batch] reconciliation.
pub struct LinkSpec {
    pub a: IpAddr,
    pub b: IpAddr,
    pub id: LinkId,
    pub attributes: Vec<Attribute>,
    pub cost: u32,
    /// Up/down flag for the installed link. A reconcile that rebuilds an existing
    /// link carries its current flag over, so a policy change cannot bring up a link
    /// that link-state reports say is down.
    pub up: bool,
}

pub struct Router {
    inner: RwLock<RouterInner>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RouterInner {
                topology: Graph::default(),
                route_cache: HashMap::new(),
                link_to_cache_keys: HashMap::new(),
                topo_generation: 0,
            }),
        }
    }

    /// Adds a node to the Routers view of the network topology.
    /// Nodes are identified by their IP address.
    /// Nodes are all alone until links are added that include them.
    ///
    ///TODO: This does error if nodes exists... should we instead just merge it in?
    ///
    /// ## Errors
    /// - If node already exists then this returns [TopologyError::NodeExists]
    pub fn add_node(&self, node_addr: IpAddr) -> Result<(), TopologyError> {
        let mut inner = self.inner.write().unwrap();
        inner.topology.add_node(node_addr)?;
        inner.topo_generation += 1;
        Ok(())
    }

    /// TRUE if node exists in the network graph.
    pub fn has_node(&self, node_addr: &IpAddr) -> bool {
        let inner = self.inner.read().unwrap();
        inner.topology.nodes.contains_key(&node_addr.into())
    }

    /// Removes a node and all its incident links from the topology.
    pub fn remove_node(&self, node_addr: &IpAddr) {
        let mut inner = self.inner.write().unwrap();
        let nid: NodeId = node_addr.into();

        // Phase 1: evict entries whose routes traverse any of the node's incident links.
        // Collect the union of link_to_cache_keys for each incident link first to avoid
        // simultaneous borrows.
        let incident_link_ids: Vec<LinkId> = inner
            .topology
            .nodes
            .get(&nid)
            .map(|n| n.edges.iter().cloned().collect())
            .unwrap_or_default();
        let keys: Vec<RouteCacheKey> = incident_link_ids
            .iter()
            .flat_map(|lid| {
                inner
                    .link_to_cache_keys
                    .get(lid)
                    .into_iter()
                    .flat_map(|s| s.iter().cloned())
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        inner.invalidate_keys(keys);

        // Phase 2: scan for entries where the node is an explicit endpoint.  These arise
        // when compute_routes returned an empty Vec (no links → phase 1 finds nothing).
        let endpoint_keys: Vec<RouteCacheKey> = inner
            .route_cache
            .keys()
            .filter(|k| k.a == nid || k.b == nid)
            .cloned()
            .collect();
        inner.invalidate_keys(endpoint_keys);

        // Topology mutation comes last — invalidate_keys needs topology.edges intact.
        inner.topology.remove_node(&nid);
        inner.topo_generation += 1;
    }

    /// Adds a link between the two nodes identified by the given IP addresses.
    /// The two nodes must be distinct and must already exist in the topology.
    ///
    /// ## Errors
    /// - If attempt to create link from a node to itself then this returns [TopologyError::LinkToSelf]
    /// - If a or b do not exist returns [TopologyError::NodeNotFound]
    /// - If link id already exists then this returns [TopologyError::LinkExists]
    ///
    pub fn add_link(
        &self,
        zpr_addr_a: IpAddr,
        zpr_addr_b: IpAddr,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        self.add_link_with_state(zpr_addr_a, zpr_addr_b, id, attributes, cost, true)
    }

    /// As [Router::add_link], but installs the link with the given up/down flag under
    /// the same write lock, so a link that link-state reports already veto is never
    /// usable, not even between the install and a later [Router::set_link_up].
    pub fn add_link_with_state(
        &self,
        zpr_addr_a: IpAddr,
        zpr_addr_b: IpAddr,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
        up: bool,
    ) -> Result<(), TopologyError> {
        let mut inner = self.inner.write().unwrap();
        let a: NodeId = zpr_addr_a.into();
        let b: NodeId = zpr_addr_b.into();

        // A new link can create routes for pairs whose cached routes never touched a or b
        // (e.g. dormant x→a and b→y segments now form x→a→b→y).  Identifying all affected
        // pairs would require a full graph traversal, so we flush the entire cache instead.
        inner.route_cache.clear();
        inner.link_to_cache_keys.clear();

        inner
            .topology
            .add_link(a, b, id.clone(), attributes, cost)?;
        if !up {
            inner.topology.set_link_up(&id, false);
        }
        inner.topo_generation += 1;
        Ok(())
    }

    /// Atomically apply a batch of link removals followed by additions under a single
    /// write lock, so no concurrent route observes a partially-rewritten graph. If an
    /// addition fails, every change is undone -- added links removed, removed links
    /// restored with their flags -- and the error returned.
    pub fn apply_link_batch(
        &self,
        removals: &[LinkId],
        additions: Vec<LinkSpec>,
    ) -> Result<(), TopologyError> {
        let mut inner = self.inner.write().unwrap();
        // Keep what was removed, so a failed addition can put the graph back exactly.
        let mut removed: Vec<(LinkId, Link)> = Vec::with_capacity(removals.len());
        for id in removals {
            if let Some(link) = inner.topology.remove_link(id) {
                removed.push((id.clone(), link));
            }
        }
        let mut added: Vec<LinkId> = Vec::with_capacity(additions.len());
        for spec in additions {
            let added_result = inner.topology.add_link(
                spec.a,
                spec.b,
                spec.id.clone(),
                spec.attributes,
                spec.cost,
            );
            if added_result.is_ok() && !spec.up {
                inner.topology.set_link_up(&spec.id, false);
            }
            if let Err(e) = added_result {
                // Undo the batch: drop what was added, then restore what was removed
                // (with its up/down flag), so a rejected reconcile leaves the live
                // topology untouched.
                for done in added.iter().rev() {
                    inner.topology.remove_link(done);
                }
                for (id, link) in removed {
                    let up = link.up;
                    if inner
                        .topology
                        .add_link(link.a, link.b, id.clone(), link.attributes, link.cost)
                        .is_ok()
                        && !up
                    {
                        inner.topology.set_link_up(&id, false);
                    }
                }
                inner.route_cache.clear();
                inner.link_to_cache_keys.clear();
                inner.topo_generation += 1;
                return Err(e);
            }
            added.push(spec.id);
        }
        // A reconcile touches arbitrary edges, so a full cache flush is the only sound
        // invalidation; targeted eviction is not worth the bookkeeping on this cold path.
        inner.route_cache.clear();
        inner.link_to_cache_keys.clear();
        inner.topo_generation += 1;
        Ok(())
    }

    /// Given a route, return the ordered sequence of NodeIds that must be traversed to follow the route,
    /// including the starting node as the first element.
    ///
    /// The passed `starting_node` is used to get the direction of the path correct.
    ///
    /// ## Errors
    /// - If any of the links in the route are not found in the topology then this returns [TopologyError::LinkNotFound]
    /// - If any of the links in the route do not connect to the current node in the path then this returns [TopologyError::NodeNotFound]
    pub fn route_to_path(
        &self,
        route: &Route,
        starting_node: &NodeId,
    ) -> Result<Vec<NodeId>, TopologyError> {
        match &route.kind {
            RouteKind::DirectSameNode { node_id: nid } => {
                // For sanity, make sure that the node_id embedded in the RouteKind matches our starting node.
                if nid != starting_node {
                    return Err(TopologyError::NodeNotFound(format!(
                        "route_to_path: starting node {:?} does not match direct-route node {:?}",
                        starting_node, nid
                    )));
                }
                Ok(vec![starting_node.clone()])
            }
            RouteKind::Multihop => {
                let inner = self.inner.read().unwrap();
                let mut path = vec![starting_node.clone()];
                let mut current_node = starting_node.clone();
                for link_id in &route.links {
                    let Some(link) = inner.topology.link(link_id) else {
                        return Err(TopologyError::LinkNotFound(format!(
                            "route_to_path: link {:?} not found",
                            link_id
                        )));
                    };
                    let next_node = if link.a == current_node {
                        link.b.clone()
                    } else if link.b == current_node {
                        link.a.clone()
                    } else {
                        return Err(TopologyError::NodeNotFound(format!(
                            "route_to_path: link {:?} does not connect to current node {:?}",
                            link_id, current_node
                        )));
                    };
                    path.push(next_node.clone());
                    current_node = next_node;
                }
                Ok(path)
            }
        }
    }

    /// Remove a link by its id. If the link does not exist this is a no-op.
    #[allow(dead_code)]
    pub fn remove_link(&self, id: &LinkId) {
        let mut inner = self.inner.write().unwrap();

        // Only evict entries that actually traverse this specific link — routes on
        // completely disjoint parts of the topology are unaffected.
        // Collect before calling invalidate_keys to release the shared borrow.
        let keys: Vec<RouteCacheKey> = inner
            .link_to_cache_keys
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        // Invalidation must precede topology.remove_link so that topology.edges still
        // contains the link's endpoint info needed for node-index cleanup.
        inner.invalidate_keys(keys);
        inner.link_to_cache_keys.remove(id);

        inner.topology.remove_link(id);
        inner.topo_generation += 1;
    }

    /// Mark a link usable (`up`) or not. A down link stays in the graph -- its id,
    /// attributes and cost are kept, and so is its persisted adjacency -- but neither
    /// route query uses it. Link-state reports drive this (zl-zipline#224): the edge
    /// is up only while both ends report it up.
    ///
    /// Returns true if the flag changed. An unknown link id, or a flag that already
    /// has the requested value, is a no-op that returns false.
    pub fn set_link_up(&self, id: &LinkId, up: bool) -> bool {
        let mut inner = self.inner.write().unwrap();
        if !inner.topology.set_link_up(id, up) {
            return false;
        }
        // Down removes routes and up can create routes between pairs that never
        // touched this link, so flush the whole cache, as add_link does.
        inner.route_cache.clear();
        inner.link_to_cache_keys.clear();
        inner.topo_generation += 1;
        true
    }

    /// True if every link in `ids` exists and is up. An empty list (a route that
    /// stays on one node) is trivially up. Used to check, when a visa is committed,
    /// that its route has not lost a link since it was chosen.
    pub fn links_up(&self, ids: &[LinkId]) -> bool {
        let inner = self.inner.read().unwrap();
        ids.iter()
            .all(|id| inner.topology.edges.get(id).is_some_and(|l| l.up))
    }

    /// Current link between two node addrs, in either order (edges are undirected).
    /// Returns `None` if no link connects them.
    pub fn link_between(&self, a: &IpAddr, b: &IpAddr) -> Option<RouterLink> {
        let inner = self.inner.read().unwrap();
        let na: NodeId = a.into();
        let nb: NodeId = b.into();
        let id = inner.topology.link_id_between(&na, &nb)?;
        let link = inner.topology.edges.get(&id)?;
        Some(RouterLink {
            a: link.a.0,
            b: link.b.0,
            id,
            attributes: link.attributes.clone(),
            cost: link.cost,
            up: link.up,
        })
    }

    /// Snapshot of all live router links.
    pub fn link_snapshot(&self) -> Vec<RouterLink> {
        let inner = self.inner.read().unwrap();
        inner
            .topology
            .edges
            .iter()
            .map(|(id, link)| RouterLink {
                a: link.a.0,
                b: link.b.0,
                id: id.clone(),
                attributes: link.attributes.clone(),
                cost: link.cost,
                up: link.up,
            })
            .collect()
    }

    /// Replace the existing link between two endpoints under a single router write lock.
    ///
    /// This validates fully before mutating, so a rejected replacement leaves the old
    /// working link intact. It avoids the unsafe `remove_link(old)` + `add_link(new)`
    /// sequence where the add can fail after the working link is already gone.
    ///
    /// ## Errors
    /// - [TopologyError::LinkToSelf] if `a == b`.
    /// - [TopologyError::NodeNotFound] if either endpoint is missing.
    /// - [TopologyError::LinkNotFound] if no link currently connects `a` and `b`.
    /// - [TopologyError::LinkExists] if `id` differs from the old id but is already used
    ///   by another live edge.
    // Retained as a tested Router primitive; revalidation now does remove-then-install
    // so it has no live caller.
    #[allow(dead_code)]
    pub fn replace_link_between(
        &self,
        a: &IpAddr,
        b: &IpAddr,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        let mut inner = self.inner.write().unwrap();
        let na: NodeId = a.into();
        let nb: NodeId = b.into();
        inner
            .topology
            .replace_link(&na, &nb, id, attributes, cost)?;

        // A link's id/cost change can affect arbitrary cached pairs (as with add_link),
        // so conservatively flush the whole route cache.
        inner.route_cache.clear();
        inner.link_to_cache_keys.clear();
        inner.topo_generation += 1;
        Ok(())
    }

    /// Given a node address, return the connected peers,
    /// or empty list if the node is not in the graph or has no peers.
    pub fn get_peers(&self, zpr_addr: &IpAddr) -> Vec<IpAddr> {
        let inner = self.inner.read().unwrap();
        let node_id: NodeId = zpr_addr.into();
        inner
            .topology
            .neighbors(&node_id)
            .unwrap_or_default()
            .into_iter()
            .map(|nid| nid.into())
            .collect()
    }

    /// "Best" route is defined as the route with the lowest cost. A tie goes to the
    /// route with fewer hops, then to the smaller last-link id (see `dijkstra_from`).
    /// These routes are cached and only updated when topology changes.
    ///
    /// Note `addr_a` and `addr_b` are NODE addresses (not adapters).
    pub fn get_best_route(&self, addr_a: &IpAddr, addr_b: &IpAddr) -> Option<Route> {
        let a: NodeId = addr_a.into();
        let b: NodeId = addr_b.into();
        if a == b {
            return Some(Route {
                kind: RouteKind::DirectSameNode { node_id: a },
                links: vec![],
                cost: 0,
            });
        }
        let inner = self.inner.read().unwrap();
        let (links, cost) = inner.topology.get_low_cost_path(&a, &b)?;
        Some(Route {
            kind: RouteKind::Multihop,
            links,
            cost,
        })
    }

    /// Returns list of routes between addr_a and addr_b that satisfy the hint.
    ///
    /// Results are cached; only the affected subset of the cache is invalidated when the
    /// topology changes.  See [RouteCacheKey] for the full caching strategy.
    pub fn get_routes(
        &self,
        addr_a: &IpAddr,
        addr_b: &IpAddr,
        hint: Option<&RouteHint>,
    ) -> Vec<Route> {
        let key = RouteCacheKey {
            a: addr_a.into(),
            b: addr_b.into(),
            hint: hint.cloned(),
        };

        // Fast path: cache hit under read lock.
        // Cache miss: compute DFS under read lock so concurrent callers run in parallel.
        let (topo_gen, computed) = {
            let inner = self.inner.read().unwrap();
            if let Some(routes) = inner.route_cache.get(&key) {
                return routes.clone();
            }
            let topo_gen = inner.topo_generation;
            (
                topo_gen,
                Self::compute_routes(&inner.topology, addr_a, addr_b, hint),
            )
        };

        // Commit under write lock.  If the topology changed while we were computing
        // (detected via topo_generation mismatch), re-compute from the current topology
        // and skip caching to keep the write critical section short.
        let mut inner = self.inner.write().unwrap();
        if inner.topo_generation != topo_gen {
            return Self::compute_routes(&inner.topology, addr_a, addr_b, hint);
        }
        // Another thread may have won the race and already populated this key.
        if let Some(routes) = inner.route_cache.get(&key) {
            return routes.clone();
        }
        // Populate link_to_cache_keys so remove_link can do targeted eviction.
        for route in &computed {
            for link_id in &route.links {
                inner
                    .link_to_cache_keys
                    .entry(link_id.clone())
                    .or_default()
                    .insert(key.clone());
            }
        }
        inner.route_cache.insert(key, computed.clone());
        computed
    }

    /// Unlike `get_best_route` this returns all the routes between addr_a and addr_b.
    /// If the optional hint is provided it is used to reduce the set of returned routes. (not yet implemented)
    ///
    /// For now the hint is ignored.
    /// TODO implement ZPL for route policy and then build this out.
    fn compute_routes(
        topology: &Graph,
        addr_a: &IpAddr,
        addr_b: &IpAddr,
        _hint: Option<&RouteHint>,
    ) -> Vec<Route> {
        let a: NodeId = addr_a.into();
        let b: NodeId = addr_b.into();
        if a == b {
            return vec![Route {
                kind: RouteKind::DirectSameNode { node_id: a },
                links: vec![],
                cost: 0,
            }];
        }
        topology
            .get_all_paths(&a, &b)
            .into_iter()
            .map(|(links, cost)| Route {
                kind: RouteKind::Multihop,
                links,
                cost,
            })
            .collect()
    }
}

#[derive(Debug)]
struct Node {
    edges: HashSet<LinkId>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct Link {
    a: NodeId,
    b: NodeId,
    attributes: Vec<Attribute>,
    cost: u32,
    /// Route queries skip a link that is not up. New links start up.
    up: bool,
}

#[derive(Debug, Default)]
struct Graph {
    nodes: HashMap<NodeId, Node>,
    edges: HashMap<LinkId, Link>,
    best_routes: HashMap<(NodeId, NodeId), (Vec<LinkId>, u32)>,
}

impl Graph {
    /// Add a node into the graph. Node is all alone unless a link is added that includes it.
    ///
    /// ## Errors
    /// - If node already exists then this returns [TopologyError::NodeExists]
    fn add_node(&mut self, node_id: impl Into<NodeId>) -> Result<NodeId, TopologyError> {
        let nid = node_id.into();

        // If node exists call that an error.
        if self.nodes.contains_key(&nid) {
            return Err(TopologyError::NodeExists(nid.0.to_string()));
        }

        self.nodes.insert(
            nid.clone(),
            Node {
                edges: HashSet::new(),
            },
        );
        Ok(nid)
    }

    /// Add a link between two nodes. The two nodes must be distinct.
    ///
    /// ## Errors
    /// - If attempt to create link from a node to itself then this returns [TopologyError::LinkToSelf]
    /// - If a or b do not exist returns [TopologyError::NodeNotFound]
    /// - If link id already exists then this returns [TopologyError::LinkExists]
    fn add_link(
        &mut self,
        a: impl Into<NodeId>,
        b: impl Into<NodeId>,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        let a = a.into();
        let b = b.into();
        if a == b {
            return Err(TopologyError::LinkToSelf(
                "add_link: self-links are not allowed".into(),
            ));
        }

        if !self.nodes.contains_key(&a) {
            return Err(TopologyError::NodeNotFound(format!(
                "add_link: node {:?} does not exist",
                a
            )));
        }

        if !self.nodes.contains_key(&b) {
            return Err(TopologyError::NodeNotFound(format!(
                "add_link: node {:?} does not exist",
                b
            )));
        }

        if self.edges.contains_key(&id) {
            return Err(TopologyError::LinkExists(id.0)); // Well the ID exists anyway...
        }

        self.edges.insert(
            id.clone(),
            Link {
                a: a.clone(),
                b: b.clone(),
                attributes,
                cost,
                up: true,
            },
        );

        self.nodes.get_mut(&a).unwrap().edges.insert(id.clone());
        self.nodes.get_mut(&b).unwrap().edges.insert(id);
        self.recompute();

        Ok(())
    }

    /// Look up a link by id. Returns `None` if not found.
    #[allow(dead_code)]
    fn link(&self, id: &LinkId) -> Option<&Link> {
        self.edges.get(id)
    }

    /// Return the id of the link connecting `a` and `b` (in either order), or `None`.
    /// Scans `a`'s incident edges for the one whose other endpoint is `b`.
    fn link_id_between(&self, a: &NodeId, b: &NodeId) -> Option<LinkId> {
        let node = self.nodes.get(a)?;
        for link_id in &node.edges {
            let link = self.edges.get(link_id)?;
            let other = if &link.a == a { &link.b } else { &link.a };
            if other == b {
                return Some(link_id.clone());
            }
        }
        None
    }

    /// Replace the link currently connecting `a` and `b` with one carrying the given id,
    /// attributes, and cost. Validates fully before mutating so a rejected replacement
    /// leaves the existing link untouched. See [Router::replace_link_between].
    #[allow(dead_code)]
    fn replace_link(
        &mut self,
        a: &NodeId,
        b: &NodeId,
        new_id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        if a == b {
            return Err(TopologyError::LinkToSelf(
                "replace_link: self-links are not allowed".into(),
            ));
        }
        if !self.nodes.contains_key(a) {
            return Err(TopologyError::NodeNotFound(format!(
                "replace_link: node {:?} does not exist",
                a
            )));
        }
        if !self.nodes.contains_key(b) {
            return Err(TopologyError::NodeNotFound(format!(
                "replace_link: node {:?} does not exist",
                b
            )));
        }
        let old_id = self.link_id_between(a, b).ok_or_else(|| {
            TopologyError::LinkNotFound(format!(
                "replace_link: no existing link between {:?} and {:?}",
                a, b
            ))
        })?;
        // A new id colliding with a different live edge would corrupt that edge.
        if new_id != old_id && self.edges.contains_key(&new_id) {
            return Err(TopologyError::LinkExists(new_id.0));
        }

        // Validated: swap the edge in place, then recompute once. The up/down flag
        // comes from link-state reports, not policy, so the new edge keeps it.
        let was_up = self.remove_link_impl(&old_id).map_or(true, |old| old.up);
        self.edges.insert(
            new_id.clone(),
            Link {
                a: a.clone(),
                b: b.clone(),
                attributes,
                cost,
                up: was_up,
            },
        );
        self.nodes.get_mut(a).unwrap().edges.insert(new_id.clone());
        self.nodes.get_mut(b).unwrap().edges.insert(new_id);
        self.recompute();
        Ok(())
    }

    /// Look up a link by id for mutation. Returns `None` if not found.
    #[allow(dead_code)]
    fn link_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.edges.get_mut(id)
    }

    /// Set a link's up flag and recompute best routes if it changed. Returns true if
    /// the flag changed; false for an unknown link or an unchanged flag.
    fn set_link_up(&mut self, id: &LinkId, up: bool) -> bool {
        match self.edges.get_mut(id) {
            Some(link) if link.up != up => link.up = up,
            _ => return false,
        }
        self.recompute();
        true
    }

    /// Returns all nodes directly connected to `node_id` by a single link, or `None` if the node does not exist.
    #[allow(dead_code)]
    fn neighbors(&self, node_id: &NodeId) -> Option<Vec<NodeId>> {
        let node = self.nodes.get(node_id)?;
        let mut out = Vec::new();

        for edge_id in &node.edges {
            let edge = self.edges.get(edge_id)?;
            let other = if &edge.a == node_id {
                edge.b.clone()
            } else {
                edge.a.clone()
            };
            out.push(other);
        }

        Some(out)
    }

    /// Remove a link from the edge map and from both endpoint nodes' edge sets without triggering a recompute.
    /// Used internally so callers can batch multiple removals before calling `recompute` once.
    fn remove_link_impl(&mut self, link_id: &LinkId) -> Option<Link> {
        let link = self.edges.remove(link_id)?;
        if let Some(node) = self.nodes.get_mut(&link.a) {
            node.edges.remove(link_id);
        }
        if let Some(node) = self.nodes.get_mut(&link.b) {
            node.edges.remove(link_id);
        }
        Some(link)
    }

    /// Returns None if link not found. If link does exist then it is removed and returned.
    fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        let result = self.remove_link_impl(link_id);
        self.recompute();
        result
    }

    /// Returns None if node not found. If node does exist then it is removed and returned.
    fn remove_node(&mut self, node_id: &NodeId) -> Option<Node> {
        let link_ids: Vec<LinkId> = self.nodes.get(node_id)?.edges.iter().cloned().collect();
        for link_id in &link_ids {
            self.remove_link_impl(link_id);
        }
        let result = self.nodes.remove(node_id);
        self.recompute();
        result
    }

    /// Get the lowest cost path from a to b, with ties broken as in `dijkstra_from`.
    fn get_low_cost_path(&self, a: &NodeId, b: &NodeId) -> Option<(Vec<LinkId>, u32)> {
        self.best_routes.get(&(a.clone(), b.clone())).cloned()
    }

    /// Return every simple path from `start` to `end` (no repeated nodes).
    /// Uses an explicit heap-allocated stack to avoid recursion depth limits.
    fn get_all_paths(&self, start: &NodeId, end: &NodeId) -> Vec<(Vec<LinkId>, u32)> {
        struct Frame {
            current: NodeId,
            /// Remaining edges to try; treated as a stack (pop from end).
            remaining: Vec<LinkId>,
            /// Link used to reach this node — popped from `path` on backtrack.
            entered_via: Option<LinkId>,
            /// Neighbor added to `visited` on entry — removed on backtrack.
            entered_neighbor: Option<NodeId>,
            cost: u32,
        }

        if start == end {
            return vec![(vec![], 0)];
        }
        let Some(start_node) = self.nodes.get(start) else {
            return vec![];
        };

        let mut results = Vec::new();
        let mut visited: HashSet<NodeId> = HashSet::new();
        visited.insert(start.clone());
        let mut path: Vec<LinkId> = Vec::new();
        let mut stack = vec![Frame {
            current: start.clone(),
            remaining: start_node.edges.iter().cloned().collect(),
            entered_via: None,
            entered_neighbor: None,
            cost: 0,
        }];

        loop {
            // Phase 1: backtrack if this frame's edges are exhausted.
            let exhausted = match stack.last() {
                None => break,
                Some(f) => f.remaining.is_empty(),
            };
            if exhausted {
                let f = stack.pop().unwrap();
                if f.entered_via.is_some() {
                    path.pop();
                }
                if let Some(nb) = f.entered_neighbor {
                    visited.remove(&nb);
                }
                continue;
            }

            // Phase 2: take the next edge (borrow ends before any stack.push below).
            let (link_id, cost, current) = {
                let f = stack.last_mut().unwrap();
                (f.remaining.pop().unwrap(), f.cost, f.current.clone())
            };

            let Some(link) = self.edges.get(&link_id) else {
                continue;
            };
            if !link.up {
                continue;
            }
            let neighbor = if &link.a == &current {
                &link.b
            } else {
                &link.a
            };

            if visited.contains(neighbor) {
                continue;
            }

            let new_cost = cost.saturating_add(link.cost);

            if neighbor == end {
                let mut full_path = path.clone();
                full_path.push(link_id);
                results.push((full_path, new_cost));
                continue;
            }

            // Descend: mark neighbor visited, extend path, push a new frame.
            let neighbor = neighbor.clone();
            if let Some(nb_node) = self.nodes.get(&neighbor) {
                visited.insert(neighbor.clone());
                path.push(link_id.clone());
                stack.push(Frame {
                    current: neighbor.clone(),
                    remaining: nb_node.edges.iter().cloned().collect(),
                    entered_via: Some(link_id),
                    entered_neighbor: Some(neighbor),
                    cost: new_cost,
                });
            }
        }

        results
    }

    /// Recompute the `best_routes` cache by running Dijkstra from every node.
    /// Called after any topology change (add/remove node or link).
    fn recompute(&mut self) {
        self.best_routes.clear();
        let starts: Vec<NodeId> = self.nodes.keys().cloned().collect();
        for start in &starts {
            for (dest, path_and_cost) in self.dijkstra_from(start) {
                self.best_routes
                    .insert((start.clone(), dest), path_and_cost);
            }
        }
    }

    /// Run Dijkstra from `start` and return, for each reachable destination, the
    /// ordered sequence of link ids on the shortest path and its total cost.
    ///
    /// Ties are broken deterministically (zl-zipline#224), in this order:
    /// 1. lower total cost;
    /// 2. fewer hops -- so a direct link beats a multi-hop path of equal cost;
    /// 3. the lexicographically smaller id of the last link into the node.
    ///
    /// Without (2) and (3) the winner of a tie would depend on heap pop order and on
    /// `HashSet` iteration order, so the same graph could route differently.
    fn dijkstra_from(&self, start: &NodeId) -> HashMap<NodeId, (Vec<LinkId>, u32)> {
        // Best known (cost, hops) per node.
        let mut dist: HashMap<NodeId, (u64, u32)> = HashMap::new();
        let mut prev: HashMap<NodeId, LinkId> = HashMap::new();
        let mut heap: BinaryHeap<Reverse<(u64, u32, NodeId)>> = BinaryHeap::new();

        dist.insert(start.clone(), (0, 0));
        heap.push(Reverse((0, 0, start.clone())));

        while let Some(Reverse((cost, hops, node))) = heap.pop() {
            if (cost, hops) > *dist.get(&node).unwrap_or(&(u64::MAX, u32::MAX)) {
                continue;
            }

            let Some(node_data) = self.nodes.get(&node) else {
                continue;
            };
            for link_id in &node_data.edges {
                let Some(link) = self.edges.get(link_id) else {
                    continue;
                };
                if !link.up {
                    continue;
                }
                let neighbor = if link.a == node { &link.b } else { &link.a };
                let candidate = (cost + link.cost as u64, hops + 1);
                let best = *dist.get(neighbor).unwrap_or(&(u64::MAX, u32::MAX));
                if candidate < best {
                    dist.insert(neighbor.clone(), candidate);
                    prev.insert(neighbor.clone(), link_id.clone());
                    heap.push(Reverse((candidate.0, candidate.1, neighbor.clone())));
                } else if candidate == best && prev.get(neighbor).is_some_and(|p| link_id.0 < p.0) {
                    // Same cost and hops: keep the smaller last-link id. The node's
                    // distance is unchanged, so nothing needs re-queueing; paths
                    // through it are rebuilt from `prev` at the end.
                    prev.insert(neighbor.clone(), link_id.clone());
                }
            }
        }

        let mut result = HashMap::new();
        for dest in dist.keys() {
            if dest == start {
                continue;
            }
            let mut path = vec![];
            let mut cur = dest.clone();
            while let Some(link_id) = prev.get(&cur) {
                let link = self.edges.get(link_id).unwrap();
                path.push(link_id.clone());
                cur = if link.a == cur {
                    link.b.clone()
                } else {
                    link.a.clone()
                };
            }
            debug_assert_eq!(&cur, start, "prev chain must terminate at start");
            path.reverse();
            result.insert(
                dest.clone(),
                (path, dist[dest].0.min(u32::MAX as u64) as u32),
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn make_router_abc() -> (Router, IpAddr, IpAddr, IpAddr) {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_node(c).unwrap();
        (r, a, b, c)
    }

    fn no_hint() -> RouteHint {
        RouteHint {
            direct_only: false,
            require_linked_path: false,
            any_link_has: vec![],
            no_link_has: vec![],
            all_links_have: vec![],
        }
    }

    #[test]
    fn test_get_peers_unknown_node_returns_empty() {
        // Node not in the graph: get_peers returns empty vec rather than panicking.
        let r = Router::new();
        let unknown = ip("10.0.0.99");
        assert!(r.get_peers(&unknown).is_empty());
    }

    #[test]
    fn test_get_peers_no_links_returns_empty() {
        // Node exists but has no links: get_peers returns empty vec.
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(a).unwrap();
        assert!(r.get_peers(&a).is_empty());
    }

    #[test]
    fn test_get_peers_single_link() {
        // Node connected to one other node: get_peers returns exactly that peer.
        let (r, a, b, _c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let peers_a = r.get_peers(&a);
        assert_eq!(peers_a, vec![b]);
        // Symmetry: b also sees a as its peer.
        let peers_b = r.get_peers(&b);
        assert_eq!(peers_b, vec![a]);
    }

    #[test]
    fn test_get_peers_multiple_links() {
        // Node connected to two peers: get_peers returns both, regardless of order.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], 1).unwrap();
        let mut peers = r.get_peers(&a);
        peers.sort();
        let mut expected = vec![b, c];
        expected.sort();
        assert_eq!(peers, expected);
        // b and c are not connected to each other.
        assert_eq!(r.get_peers(&b), vec![a]);
        assert_eq!(r.get_peers(&c), vec![a]);
    }

    #[test]
    fn test_direct_same_node() {
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(a).unwrap();
        let route = r.get_best_route(&a, &a).unwrap();
        assert!(route.is_direct());
        assert_eq!(route.cost, 0);
        assert!(route.links.is_empty());
    }

    #[test]
    fn test_single_link() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 5).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert!(!route.is_direct());
        assert_eq!(route.cost, 5);
        assert_eq!(route.links, vec![LinkId("ab".into())]);
    }

    #[test]
    fn test_multihop() {
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&a, &c).unwrap();
        assert!(!route.is_direct());
        assert_eq!(route.cost, 2);
        assert_eq!(route.links, vec![LinkId("ab".into()), LinkId("bc".into())]);
    }

    #[test]
    fn test_prefers_lower_cost() {
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab-direct".into()), vec![], 10)
            .unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], 3).unwrap();
        r.add_link(c, b, LinkId("cb".into()), vec![], 3).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert_eq!(route.cost, 6);
        assert_eq!(route.links, vec![LinkId("ac".into()), LinkId("cb".into())]);
    }

    #[test]
    fn test_high_cost_multihop_is_reachable() {
        // Verifies the u64 fix: with saturating_add the old code would compute
        // u32::MAX + 1 == u32::MAX and fail the < guard, silently dropping node b.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, c, LinkId("ac".into()), vec![], u32::MAX)
            .unwrap();
        r.add_link(c, b, LinkId("cb".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert_eq!(route.links, vec![LinkId("ac".into()), LinkId("cb".into())]);
    }

    #[test]
    fn test_high_cost_prefers_cheaper_over_saturating_path() {
        // A direct link costing u32::MAX-1 must beat a 2-hop path whose u64
        // accumulated cost exceeds u32::MAX (old u32 arithmetic would saturate
        // both to u32::MAX and pick arbitrarily).
        let (r, a, b, c) = make_router_abc();
        let half = u32::MAX / 2 + 1;
        r.add_link(a, b, LinkId("ab".into()), vec![], u32::MAX - 1)
            .unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], half).unwrap();
        r.add_link(c, b, LinkId("cb".into()), vec![], half).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert_eq!(route.links, vec![LinkId("ab".into())]);
        assert_eq!(route.cost, u32::MAX - 1);
    }

    #[test]
    fn test_unreachable() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        assert!(r.get_best_route(&a, &b).is_none());
    }

    #[test]
    fn test_compute_routes_returns_all_paths() {
        // A-B, B-C, A-C: routes from A to C should include both A-B-C and A-C.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], 5).unwrap();
        let hint = no_hint();
        let routes = r.get_routes(&a, &c, Some(&hint));
        assert_eq!(routes.len(), 2);
        let mut link_sets: Vec<Vec<LinkId>> = routes.into_iter().map(|r| r.links).collect();
        link_sets.sort_by_key(|v| v.iter().map(|l| l.0.clone()).collect::<Vec<_>>());
        assert_eq!(
            link_sets,
            vec![
                vec![LinkId("ab".into()), LinkId("bc".into())],
                vec![LinkId("ac".into())],
            ]
        );
    }

    #[test]
    fn test_route_cache_invalidated_after_remove_link() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        r.remove_link(&LinkId("ab".into()));
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_route_cache_invalidated_after_add_link() {
        // Cache is warmed with an empty result, then add_link must bust it so the new route appears.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_route_cache_invalidated_after_remove_node() {
        // Cache is warmed with a route through an intermediate node; removing that node must bust the cache.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_node(c).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &c, Some(&hint)).len(), 1);
        r.remove_node(&b);
        assert_eq!(r.get_routes(&a, &c, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_route_cache_not_disturbed_by_add_node() {
        // Adding an isolated node must not invalidate existing cached routes between other nodes.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let d = ip("10.0.0.4");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        r.add_node(d).unwrap();
        // Route a->b still valid and served from cache.
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        // New isolated node d has no routes to a.
        assert_eq!(r.get_routes(&a, &d, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_targeted_invalidation_preserves_unrelated_entries() {
        // Removing link a-b must not evict the cached route for the disjoint pair c-d.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let d = ip("10.0.0.4");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_node(c).unwrap();
        r.add_node(d).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(c, d, LinkId("cd".into()), vec![], 1).unwrap();
        let hint = no_hint();
        // Warm both cache entries.
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        assert_eq!(r.get_routes(&c, &d, Some(&hint)).len(), 1);
        // Removing link ab should evict (a,b) but leave (c,d) intact.
        r.remove_link(&LinkId("ab".into()));
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        assert_eq!(r.get_routes(&c, &d, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_empty_result_invalidated_by_add_link() {
        // A cached "unreachable" empty result must be evicted when add_link creates a path.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        let hint = no_hint();
        // Warm cache with empty result (no path exists yet).
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        // Adding a link between a and b must bust the stale empty entry.
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_add_link_bridge_invalidates_unrelated_cached_pair() {
        // Regression: add_link(a,b) must evict a cached (x,y) entry even when the previously
        // cached routes for (x,y) never traversed a or b, if adding a-b creates a new path
        // x→a→b→y via pre-existing x-a and b-y links.
        let x = ip("10.0.0.10");
        let y = ip("10.0.0.20");
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(x).unwrap();
        r.add_node(y).unwrap();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        // Direct x-y link and dormant legs x-a and b-y; no a-b yet.
        r.add_link(x, y, LinkId("xy".into()), vec![], 10).unwrap();
        r.add_link(x, a, LinkId("xa".into()), vec![], 1).unwrap();
        r.add_link(b, y, LinkId("by".into()), vec![], 1).unwrap();
        let hint = no_hint();
        // Warm the cache: only the direct x-y route exists.
        assert_eq!(r.get_routes(&x, &y, Some(&hint)).len(), 1);
        // Adding the bridge a-b creates a second path x→a→b→y.
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        // Cache must be invalidated; both routes should now be returned.
        assert_eq!(r.get_routes(&x, &y, Some(&hint)).len(), 2);
    }

    // --- route_to_path tests ---

    #[test]
    fn test_route_to_path_direct_same_node_returns_self() {
        // A same-node route produces a path containing only the starting node.
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(a).unwrap();
        let route = r.get_best_route(&a, &a).unwrap();
        let na: NodeId = (&a).into();
        assert_eq!(r.route_to_path(&route, &na).unwrap(), vec![na]);
    }

    #[test]
    fn test_route_to_path_multihop_empty_links_returns_starting_node() {
        // A Multihop route with no links produces a path containing only the starting node.
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(a).unwrap();
        let na: NodeId = (&a).into();
        let route = Route {
            kind: RouteKind::Multihop,
            links: vec![],
            cost: 0,
        };
        assert_eq!(r.route_to_path(&route, &na).unwrap(), vec![na.clone()]);
    }

    #[test]
    fn test_route_to_path_single_hop_forward() {
        // A one-link A→B route starting from A should yield [A, B].
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        let na: NodeId = (&a).into();
        let nb: NodeId = (&b).into();
        assert_eq!(r.route_to_path(&route, &na).unwrap(), vec![na, nb]);
    }

    #[test]
    fn test_route_to_path_single_hop_reverse() {
        // The same link traversed starting from B should yield [B, A].
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&b, &a).unwrap();
        let na: NodeId = (&a).into();
        let nb: NodeId = (&b).into();
        assert_eq!(r.route_to_path(&route, &nb).unwrap(), vec![nb, na]);
    }

    #[test]
    fn test_route_to_path_multihop_forward() {
        // A two-hop A→B→C route starting from A should yield [A, B, C] in traversal order.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&a, &c).unwrap();
        let na: NodeId = (&a).into();
        let nb: NodeId = (&b).into();
        let nc: NodeId = (&c).into();
        assert_eq!(r.route_to_path(&route, &na).unwrap(), vec![na, nb, nc]);
    }

    #[test]
    fn test_route_to_path_multihop_reverse() {
        // The same topology traversed from C should yield [C, B, A].
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        let route = r.get_best_route(&c, &a).unwrap();
        let na: NodeId = (&a).into();
        let nb: NodeId = (&b).into();
        let nc: NodeId = (&c).into();
        assert_eq!(r.route_to_path(&route, &nc).unwrap(), vec![nc, nb, na]);
    }

    #[test]
    fn test_route_to_path_link_not_found_returns_error() {
        // A route referencing a link_id absent from the topology returns LinkNotFound.
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(a).unwrap();
        let na: NodeId = (&a).into();
        let route = Route {
            kind: RouteKind::Multihop,
            links: vec![LinkId("ghost".into())],
            cost: 0,
        };
        assert!(matches!(
            r.route_to_path(&route, &na),
            Err(TopologyError::LinkNotFound(_))
        ));
    }

    #[test]
    fn test_route_to_path_disconnected_link_returns_error() {
        // A link that does not touch the current node returns NodeNotFound.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_node(c).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        // Route claims to start at `a` but the only link connects b and c.
        let na: NodeId = (&a).into();
        let route = Route {
            kind: RouteKind::Multihop,
            links: vec![LinkId("bc".into())],
            cost: 0,
        };
        assert!(matches!(
            r.route_to_path(&route, &na),
            Err(TopologyError::NodeNotFound(_))
        ));
    }

    // --- link_between / link_snapshot / replace_link_between tests ---

    #[test]
    fn test_link_between_returns_link_in_either_order() {
        // link_between finds the link regardless of argument order.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 7).unwrap();
        let fwd = r.link_between(&a, &b).unwrap();
        assert_eq!(fwd.id, LinkId("ab".into()));
        assert_eq!(fwd.cost, 7);
        // Reverse order finds the same link.
        assert_eq!(r.link_between(&b, &a).unwrap().id, LinkId("ab".into()));
    }

    #[test]
    fn test_link_between_none_when_absent() {
        // link_between returns None when no link connects the two nodes.
        let (r, a, b, _c) = make_router_abc();
        assert!(r.link_between(&a, &b).is_none());
    }

    #[test]
    fn test_link_snapshot_returns_all_links() {
        // link_snapshot returns one entry per live link.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        let mut ids: Vec<String> = r.link_snapshot().into_iter().map(|l| l.id.0).collect();
        ids.sort();
        assert_eq!(ids, vec!["ab".to_string(), "bc".to_string()]);
    }

    #[test]
    fn test_replace_link_between_updates_cost() {
        // Replacing a link with the same id but a new cost updates routing.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(a).unwrap();
        r.add_node(b).unwrap();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.replace_link_between(&a, &b, LinkId("ab".into()), vec![], 42)
            .unwrap();
        assert_eq!(r.get_best_route(&a, &b).unwrap().cost, 42);
        assert_eq!(r.link_between(&a, &b).unwrap().cost, 42);
    }

    #[test]
    fn test_replace_link_between_id_collision_errors_and_preserves() {
        // Replacing with an id already used by another live link is rejected, leaving the
        // original link intact.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], 1).unwrap();
        let err = r.replace_link_between(&a, &b, LinkId("ac".into()), vec![], 5);
        assert!(matches!(err, Err(TopologyError::LinkExists(_))));
        // Original a-b link unchanged.
        let link = r.link_between(&a, &b).unwrap();
        assert_eq!(link.id, LinkId("ab".into()));
        assert_eq!(link.cost, 1);
    }

    #[test]
    fn test_replace_link_between_no_link_errors() {
        // Replacing a link that does not exist returns LinkNotFound.
        let (r, a, b, _c) = make_router_abc();
        let err = r.replace_link_between(&a, &b, LinkId("ab".into()), vec![], 1);
        assert!(matches!(err, Err(TopologyError::LinkNotFound(_))));
    }

    // --- Graph unit tests ---

    fn nid(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn lid(s: &str) -> LinkId {
        LinkId(s.into())
    }

    fn make_graph_abc() -> Graph {
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_node(ip("10.0.0.3")).unwrap();
        g
    }

    #[test]
    fn test_graph_add_node_success() {
        // Adding a new node returns its NodeId and stores the node.
        let mut g = Graph::default();
        let nid = g.add_node(ip("10.0.0.1")).unwrap();
        assert_eq!(nid, NodeId(ip("10.0.0.1")));
        assert!(g.nodes.contains_key(&nid));
    }

    #[test]
    fn test_graph_add_node_duplicate_errors() {
        // Adding a node whose ID already exists returns an error.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        assert!(g.add_node(ip("10.0.0.1")).is_err());
    }

    #[test]
    fn test_graph_add_link_inserts_into_both_nodes() {
        // A new link is stored in the edges map and in both endpoint nodes' edge sets.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(g.edges.contains_key(&lid("ab")));
        assert!(g.nodes[&nid("10.0.0.1")].edges.contains(&lid("ab")));
        assert!(g.nodes[&nid("10.0.0.2")].edges.contains(&lid("ab")));
    }

    #[test]
    fn test_graph_add_link_self_loop_errors() {
        // A link whose two endpoints are the same node is rejected.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        assert!(
            g.add_link(ip("10.0.0.1"), ip("10.0.0.1"), lid("aa"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_missing_node_a_errors() {
        // A link referencing a non-existent source node is rejected.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.2")).unwrap();
        assert!(
            g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_missing_node_b_errors() {
        // A link referencing a non-existent destination node is rejected.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        assert!(
            g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_duplicate_id_errors() {
        // Inserting two links with the same ID is rejected.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(
            g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 2)
                .is_err()
        );
    }

    #[test]
    fn test_graph_remove_link_cleans_up() {
        // Removing a link returns it and clears it from both nodes' edge sets.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        let removed = g.remove_link(&lid("ab"));
        assert!(removed.is_some());
        assert!(!g.edges.contains_key(&lid("ab")));
        assert!(!g.nodes[&nid("10.0.0.1")].edges.contains(&lid("ab")));
        assert!(!g.nodes[&nid("10.0.0.2")].edges.contains(&lid("ab")));
    }

    #[test]
    fn test_graph_remove_link_not_found_returns_none() {
        // Removing a link that does not exist succeeds with Ok(None).
        let mut g = Graph::default();
        assert!(g.remove_link(&lid("nope")).is_none());
    }

    #[test]
    fn test_graph_remove_node_removes_incident_links() {
        // Removing a node removes it along with all its incident links and clears peer edge sets.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 1)
            .unwrap();
        g.remove_node(&nid("10.0.0.1"));
        assert!(!g.nodes.contains_key(&nid("10.0.0.1")));
        assert!(!g.edges.contains_key(&lid("ab")));
        assert!(!g.edges.contains_key(&lid("ac")));
        assert!(g.nodes[&nid("10.0.0.2")].edges.is_empty());
        assert!(g.nodes[&nid("10.0.0.3")].edges.is_empty());
    }

    #[test]
    fn test_graph_remove_node_not_found_returns_none() {
        // Removing a node that does not exist succeeds with Ok(None).
        let mut g = Graph::default();
        assert!(g.remove_node(&nid("10.0.0.99")).is_none());
    }

    #[test]
    fn test_graph_neighbors_returns_connected_nodes() {
        // neighbors() returns all nodes directly connected by a link.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 1)
            .unwrap();
        let mut nbrs = g.neighbors(&nid("10.0.0.1")).unwrap();
        nbrs.sort();
        assert_eq!(nbrs, vec![nid("10.0.0.2"), nid("10.0.0.3")]);
    }

    #[test]
    fn test_graph_neighbors_unknown_node_returns_none() {
        // neighbors() returns None when the node does not exist.
        let g = Graph::default();
        assert!(g.neighbors(&nid("10.0.0.99")).is_none());
    }

    #[test]
    fn test_graph_no_path_returns_none() {
        // get_low_cost_path returns None when no links connect the two nodes.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        assert!(
            g.get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
                .is_none()
        );
    }

    #[test]
    fn test_graph_single_link_path() {
        // A direct one-link path is found with the correct cost and link sequence.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 7)
            .unwrap();
        let (path, cost) = g
            .get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
            .unwrap();
        assert_eq!(cost, 7);
        assert_eq!(path, vec![lid("ab")]);
    }

    #[test]
    fn test_graph_path_is_symmetric() {
        // The cost of a→b and b→a are equal (graph is undirected).
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 4)
            .unwrap();
        let (_, fwd) = g
            .get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
            .unwrap();
        let (_, rev) = g
            .get_low_cost_path(&nid("10.0.0.2"), &nid("10.0.0.1"))
            .unwrap();
        assert_eq!(fwd, rev);
    }

    #[test]
    fn test_graph_multihop_path() {
        // A two-hop path through an intermediate node is returned in traversal order.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.2"), ip("10.0.0.3"), lid("bc"), vec![], 1)
            .unwrap();
        let (path, cost) = g
            .get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.3"))
            .unwrap();
        assert_eq!(cost, 2);
        assert_eq!(path, vec![lid("ab"), lid("bc")]);
    }

    #[test]
    fn test_graph_prefers_lower_cost_path() {
        // Dijkstra chooses the cheaper multi-hop route over a costlier direct link.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab-direct"), vec![], 10)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 3)
            .unwrap();
        g.add_link(ip("10.0.0.3"), ip("10.0.0.2"), lid("cb"), vec![], 3)
            .unwrap();
        let (path, cost) = g
            .get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
            .unwrap();
        assert_eq!(cost, 6);
        assert_eq!(path, vec![lid("ac"), lid("cb")]);
    }

    #[test]
    fn test_graph_remove_link_invalidates_route() {
        // After the only link between two nodes is removed, no path remains.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(
            g.get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
                .is_some()
        );
        g.remove_link(&lid("ab"));
        assert!(
            g.get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.2"))
                .is_none()
        );
    }

    #[test]
    fn test_graph_remove_intermediate_node_invalidates_route() {
        // Removing the only intermediate node on a path leaves the endpoints unreachable.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.2"), ip("10.0.0.3"), lid("bc"), vec![], 1)
            .unwrap();
        assert!(
            g.get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.3"))
                .is_some()
        );
        g.remove_node(&nid("10.0.0.2"));
        assert!(
            g.get_low_cost_path(&nid("10.0.0.1"), &nid("10.0.0.3"))
                .is_none()
        );
    }

    #[test]
    fn test_graph_link_accessor() {
        // link() returns the stored link with correct endpoints and cost.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 9)
            .unwrap();
        let l = g.link(&lid("ab")).unwrap();
        assert_eq!(l.a, nid("10.0.0.1"));
        assert_eq!(l.b, nid("10.0.0.2"));
        assert_eq!(l.cost, 9);
    }

    // --- get_all_paths cycle tests ---

    fn sorted_paths(mut paths: Vec<(Vec<LinkId>, u32)>) -> Vec<Vec<LinkId>> {
        // Sort by the sequence of link-ID strings so assertions are deterministic.
        paths.sort_by_key(|(links, _)| links.iter().map(|l| l.0.clone()).collect::<Vec<_>>());
        paths.into_iter().map(|(l, _)| l).collect()
    }

    #[test]
    fn test_graph_get_all_paths_triangle() {
        // Triangle a-b, b-c, a-c: node c is reachable from a via a direct link
        // and via b, so get_all_paths must return exactly two paths.
        let mut g = make_graph_abc();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.2"), ip("10.0.0.3"), lid("bc"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 5)
            .unwrap();
        let paths = sorted_paths(g.get_all_paths(&nid("10.0.0.1"), &nid("10.0.0.3")));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![lid("ab"), lid("bc")]));
        assert!(paths.contains(&vec![lid("ac")]));
    }

    #[test]
    fn test_graph_get_all_paths_diamond() {
        // Diamond a-b, a-c, b-d, c-d: node d is reachable from a via two
        // vertex-disjoint paths.  The DFS must not revisit nodes and must
        // enumerate both routes exactly once each.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_node(ip("10.0.0.3")).unwrap();
        g.add_node(ip("10.0.0.4")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.2"), ip("10.0.0.4"), lid("bd"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.3"), ip("10.0.0.4"), lid("cd"), vec![], 1)
            .unwrap();
        let paths = sorted_paths(g.get_all_paths(&nid("10.0.0.1"), &nid("10.0.0.4")));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![lid("ab"), lid("bd")]));
        assert!(paths.contains(&vec![lid("ac"), lid("cd")]));
    }

    #[test]
    fn test_graph_get_all_paths_4node_ring_with_chord() {
        // 4-node ring a-b-c-d-a plus a direct chord a-c.
        // Paths from a to c: the chord (a-c), the clockwise hop via b (a-b-c),
        // and the counter-clockwise hop via d (a-d-c).
        // This verifies that the iterative DFS correctly backtracks through cycles
        // without revisiting any node.
        let mut g = Graph::default();
        g.add_node(ip("10.0.0.1")).unwrap();
        g.add_node(ip("10.0.0.2")).unwrap();
        g.add_node(ip("10.0.0.3")).unwrap();
        g.add_node(ip("10.0.0.4")).unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.2"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.2"), ip("10.0.0.3"), lid("bc"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.3"), ip("10.0.0.4"), lid("cd"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.4"), ip("10.0.0.1"), lid("da"), vec![], 1)
            .unwrap();
        g.add_link(ip("10.0.0.1"), ip("10.0.0.3"), lid("ac"), vec![], 3)
            .unwrap();
        let paths = sorted_paths(g.get_all_paths(&nid("10.0.0.1"), &nid("10.0.0.3")));
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&vec![lid("ab"), lid("bc")]));
        assert!(paths.contains(&vec![lid("ac")]));
        assert!(paths.contains(&vec![lid("da"), lid("cd")]));
    }

    // --- Link up/down flag and deterministic tie-break (zl-zipline#224) ---

    /// Triangle a-b, b-c, a-c, all cost 1, for the link-state tests.
    fn make_triangle() -> (Router, IpAddr, IpAddr, IpAddr) {
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        r.add_link(a, c, LinkId("ac".into()), vec![], 1).unwrap();
        (r, a, b, c)
    }

    #[test]
    fn test_down_link_is_skipped_by_best_route_and_all_routes() {
        let (r, a, _b, c) = make_triangle();
        assert_eq!(
            r.get_best_route(&a, &c).unwrap().links,
            vec![LinkId("ac".into())]
        );

        assert!(r.set_link_up(&LinkId("ac".into()), false));

        let best = r.get_best_route(&a, &c).unwrap();
        assert_eq!(best.links, vec![LinkId("ab".into()), LinkId("bc".into())]);
        assert_eq!(best.cost, 2);
        let all = r.get_routes(&a, &c, Some(&no_hint()));
        assert!(
            all.iter()
                .all(|rt| !rt.links.contains(&LinkId("ac".into())))
        );
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_link_back_up_restores_the_direct_route() {
        let (r, a, _b, c) = make_triangle();
        // Warm the all-routes cache so the flag change must invalidate it.
        assert_eq!(r.get_routes(&a, &c, Some(&no_hint())).len(), 2);
        r.set_link_up(&LinkId("ac".into()), false);
        assert_eq!(r.get_routes(&a, &c, Some(&no_hint())).len(), 1);
        assert!(r.set_link_up(&LinkId("ac".into()), true));
        assert_eq!(
            r.get_best_route(&a, &c).unwrap().links,
            vec![LinkId("ac".into())]
        );
        assert_eq!(r.get_routes(&a, &c, Some(&no_hint())).len(), 2);
    }

    #[test]
    fn test_set_link_up_reports_change_only() {
        let (r, _a, _b, _c) = make_triangle();
        assert!(
            !r.set_link_up(&LinkId("ac".into()), true),
            "already up: no change"
        );
        assert!(r.set_link_up(&LinkId("ac".into()), false));
        assert!(
            !r.set_link_up(&LinkId("ac".into()), false),
            "already down: no change"
        );
        assert!(
            !r.set_link_up(&LinkId("nope".into()), false),
            "unknown link: no change"
        );
    }

    #[test]
    fn test_link_flag_visible_and_kept_across_replace() {
        let (r, a, _b, c) = make_triangle();
        r.set_link_up(&LinkId("ac".into()), false);
        assert!(!r.link_between(&a, &c).unwrap().up);
        r.replace_link_between(&a, &c, LinkId("ac".into()), vec![], 7)
            .unwrap();
        let link = r.link_between(&a, &c).unwrap();
        assert!(!link.up, "replacing a link's cost must not bring it up");
        assert_eq!(link.cost, 7);
        let snap = r.link_snapshot();
        assert!(snap.iter().any(|l| l.id == LinkId("ac".into()) && !l.up));
        assert!(snap.iter().any(|l| l.id == LinkId("ab".into()) && l.up));
    }

    #[test]
    fn test_default_costs_prefer_direct_link_over_two_hops() {
        // Direct endpoint link vs the two-hop path through a relay, all at the
        // default cost 1: the direct link wins on cost alone.
        let (r, a, _b, c) = make_triangle();
        assert_eq!(
            r.get_best_route(&a, &c).unwrap().links,
            vec![LinkId("ac".into())]
        );
    }

    #[test]
    fn test_equal_cost_tie_prefers_fewer_hops() {
        // Direct link cost 2 vs two hops of cost 1: equal cost, the direct link wins.
        let (r, a, b, c) = make_router_abc();
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, c, LinkId("bc".into()), vec![], 1).unwrap();
        r.add_link(a, c, LinkId("zz-direct".into()), vec![], 2)
            .unwrap();
        let best = r.get_best_route(&a, &c).unwrap();
        assert_eq!(best.links, vec![LinkId("zz-direct".into())]);
        assert_eq!(best.cost, 2);
    }

    #[test]
    fn test_equal_cost_tie_prefers_fewer_hops_regardless_of_node_order() {
        // a-b-d-c (3 hops, cost 3) vs a-e-c (2 hops, cost 3). d and e both reach
        // distance 2; d sorts before e, so plain Dijkstra settles c through d. The
        // tie-break must pick the 2-hop path.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let d = ip("10.0.0.4");
        let e = ip("10.0.0.5");
        let r = Router::new();
        for n in [a, b, c, d, e] {
            r.add_node(n).unwrap();
        }
        r.add_link(a, b, LinkId("ab".into()), vec![], 1).unwrap();
        r.add_link(b, d, LinkId("bd".into()), vec![], 1).unwrap();
        r.add_link(d, c, LinkId("dc".into()), vec![], 1).unwrap();
        r.add_link(a, e, LinkId("ae".into()), vec![], 2).unwrap();
        r.add_link(e, c, LinkId("ec".into()), vec![], 1).unwrap();
        let best = r.get_best_route(&a, &c).unwrap();
        assert_eq!(best.cost, 3);
        assert_eq!(best.links, vec![LinkId("ae".into()), LinkId("ec".into())]);
    }

    #[test]
    fn test_equal_cost_equal_hops_tie_is_deterministic() {
        // Two two-hop paths a-x-b and a-y-b of equal cost: the one whose last link
        // id is smaller wins, every time the graph is rebuilt (HashSet order varies).
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let x = ip("10.0.0.3");
        let y = ip("10.0.0.4");
        for _ in 0..100 {
            let r = Router::new();
            for n in [a, b, x, y] {
                r.add_node(n).unwrap();
            }
            r.add_link(a, x, LinkId("ax".into()), vec![], 1).unwrap();
            r.add_link(x, b, LinkId("xb".into()), vec![], 1).unwrap();
            r.add_link(a, y, LinkId("ay".into()), vec![], 1).unwrap();
            r.add_link(y, b, LinkId("yb".into()), vec![], 1).unwrap();
            let best = r.get_best_route(&a, &b).unwrap();
            assert_eq!(best.links, vec![LinkId("ax".into()), LinkId("xb".into())]);
        }
    }

    #[test]
    fn test_apply_link_batch_keeps_spec_down_flag() {
        // A reconcile that rebuilds a down link (e.g. its policy cost changed) must
        // install it down, not silently bring it back up.
        let (r, a, _b, c) = make_triangle();
        r.set_link_up(&LinkId("ac".into()), false);
        r.apply_link_batch(
            &[LinkId("ac".into())],
            vec![LinkSpec {
                a,
                b: c,
                id: LinkId("ac".into()),
                attributes: vec![],
                cost: 5,
                up: false,
            }],
        )
        .unwrap();
        let link = r.link_between(&a, &c).unwrap();
        assert!(!link.up);
        assert_eq!(link.cost, 5);
        assert_eq!(
            r.get_best_route(&a, &c).unwrap().cost,
            2,
            "route avoids the down link"
        );
    }

    #[test]
    fn test_add_link_with_state_installs_down_atomically() {
        // A link installed down is never usable, not even briefly.
        let (r, a, _b, c) = make_router_abc();
        r.add_link_with_state(a, c, LinkId("ac".into()), vec![], 1, false)
            .unwrap();
        assert!(!r.link_between(&a, &c).unwrap().up);
        assert!(r.get_best_route(&a, &c).is_none());
        r.add_link_with_state(a, ip("10.0.0.2"), LinkId("ab".into()), vec![], 1, true)
            .unwrap();
        assert!(r.link_between(&a, &ip("10.0.0.2")).unwrap().up);
    }

    #[test]
    fn test_links_up_requires_every_link_present_and_up() {
        let (r, _a, _b, _c) = make_triangle();
        let ab = LinkId("ab".into());
        let bc = LinkId("bc".into());
        assert!(r.links_up(&[ab.clone(), bc.clone()]));
        r.set_link_up(&bc, false);
        assert!(!r.links_up(&[ab.clone(), bc]));
        assert!(
            !r.links_up(&[ab, LinkId("gone".into())]),
            "a missing link is not up"
        );
        assert!(r.links_up(&[]), "no links (direct route) is trivially up");
    }

    #[test]
    fn test_apply_link_batch_restores_removed_links_when_an_addition_fails() {
        // A failed addition must leave the graph as it was, including the links the
        // batch removed first (and their up/down flags).
        let (r, a, b, _c) = make_triangle();
        r.set_link_up(&LinkId("ab".into()), false);
        let err = r.apply_link_batch(
            &[LinkId("ab".into())],
            vec![LinkSpec {
                a,
                b: ip("10.9.9.9"), // not a node: this addition fails
                id: LinkId("ax".into()),
                attributes: vec![],
                cost: 1,
                up: true,
            }],
        );
        assert!(err.is_err());
        let ab = r.link_between(&a, &b).expect("removed link restored");
        assert_eq!(ab.id, LinkId("ab".into()));
        assert!(!ab.up, "restored with its flag");
        assert_eq!(r.link_snapshot().len(), 3);
    }
}
