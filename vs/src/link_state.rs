//! Link-state reports from nodes, and the rule that turns them into usable edges
//! (zl-zipline#224; R14 of zl-zpr-dev-context `docs/ZODE_LINKS.md`).
//!
//! A node (Zode) tells the visa service which of its links are up with
//! `VSHandle.reportLinkStates`. Each call is a **snapshot**: it lists every link the
//! node has, by the peer's link-certificate CN, and replaces whatever the node
//! reported before. A link the node leaves out is not up.
//!
//! The router uses a link only while **both** of its ends report it up, so one node
//! cannot claim a link its peer denies. A link with no report counts as **down**
//! (R14): a node that has not reported, or whose reports were forgotten, agrees to
//! none of its links. This module holds the latest snapshot of every reporting node
//! and answers that question for one edge; `TopologyMgr` applies the answer to the
//! router (`Router::set_link_up`).
//!
//! Reports are stored by CN, exactly as sent, and resolved to addresses only when an
//! edge is evaluated. A Zode reports its link to the relay before the endpoint at the
//! other end has authenticated; resolving at receipt would drop that entry, and the
//! snapshot is not re-sent while nothing changes.
//!
//! The table lives in memory only. After a visa-service restart, or once a node's
//! reports are forgotten ([LinkStateTable::remove_node]), that node's links are down
//! until it reports again, which nodes do after every (re)connect.
//!
//! The table also remembers **failed pairs** (R13a): node pairs whose link the owner
//! reported `failed`. The visa service leaves such a link out of both ends' topology
//! until something about the pair changes ([LinkStateTable::clear_failed_for]), so a
//! link that cannot come up is not proposed, and retried, over and over. Like the
//! reports, the marks are in memory only: a visa-service restart forgets them, and
//! every link is proposed again.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use zpr::vsapi_types::{LinkState, LinkStateReport};

/// Latest link-state snapshot of every node that has reported.
#[derive(Debug, Default)]
pub struct LinkStateTable {
    /// Reporting node's ZPR address -> (peer CN -> reported state).
    snapshots: HashMap<IpAddr, HashMap<String, LinkState>>,
    /// Node's ZPR address -> the highest VS-API session generation a report from it
    /// has carried (see [session_generation]). A report from a lower generation is from
    /// a session the node has since replaced, and is dropped.
    latest_session: HashMap<IpAddr, u64>,
    /// Unordered node pairs whose link the owner reported `failed` (R13a), each stored
    /// as (lower address, higher address); see [failed_pair_key].
    failed_pairs: HashSet<(IpAddr, IpAddr)>,
    /// (reporter, peer) for every peer the reporter's latest accepted snapshot lists as
    /// `failed`, so a repeated `failed` does not count as a new failure
    /// ([Self::record_failures]). Kept across [Self::remove_node]: the first report after
    /// a reconnect may still list the failure the reconnect has just cleared.
    listed_failed: HashSet<(IpAddr, IpAddr)>,
}

/// The key of the unordered pair {a, b} in [LinkStateTable::failed_pairs].
fn failed_pair_key(a: IpAddr, b: IpAddr) -> (IpAddr, IpAddr) {
    if a <= b { (a, b) } else { (b, a) }
}

/// The generation of a VS-API session id: the decimal number before the first `-`
/// (`stamp_new_session` in vsapi_worker mints `"<generation>-<uuid>"` from a counter
/// that only goes up). An id without one, or no session, counts as generation 0.
pub fn session_generation(session: Option<&str>) -> u64 {
    session
        .and_then(|s| s.split_once('-'))
        .and_then(|(generation, _)| generation.parse().ok())
        .unwrap_or(0)
}

impl LinkStateTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `reporter`'s snapshot with `entries`. The entries must already have
    /// passed [validate_snapshot].
    pub fn set_snapshot(&mut self, reporter: IpAddr, entries: Vec<LinkStateReport>) {
        let snapshot = entries.into_iter().map(|e| (e.peer_cn, e.state)).collect();
        self.snapshots.insert(reporter, snapshot);
    }

    /// Remember that the link between `a` and `b` failed: its owner reported `failed`
    /// after the link-up window (R13a). The mark stays until [Self::clear_failed_for]
    /// clears it; `up` and `down` reports never touch it. Reports mark through
    /// [Self::record_failures].
    fn mark_failed(&mut self, a: IpAddr, b: IpAddr) {
        self.failed_pairs.insert(failed_pair_key(a, b));
    }

    /// Apply the `failed` entries of `reporter`'s latest accepted snapshot (resolved to
    /// peer addresses) and return the peers whose pair this newly marked (R13a).
    ///
    /// Only a **new** failure marks a pair: one the reporter's previous snapshot did not
    /// already list as failed. A snapshot sends every link again, so a repeated `failed`
    /// is the failure already accounted for; if the pair has been cleared since (the
    /// peer reconnected and the link is being proposed again), re-marking it would leave
    /// the link out of the very topology that asks the owner to retry.
    ///
    /// This relies on the reporting contract (vs.capnp `LinkState`, ZODE_LINKS.md R6):
    /// the owner lists a link as `failed` only once the link-up window has passed
    /// without it coming up. While a retry is under way the entry is not `failed` (the
    /// link is simply not listed), so a retry that fails again is a new failure.
    pub fn record_failures(&mut self, reporter: IpAddr, failed_peers: &[IpAddr]) -> Vec<IpAddr> {
        let mut newly_marked = Vec::new();
        for peer in failed_peers {
            if self.listed_failed.insert((reporter, *peer)) {
                self.mark_failed(reporter, *peer);
                newly_marked.push(*peer);
            }
        }
        self.listed_failed
            .retain(|(r, p)| *r != reporter || failed_peers.contains(p));
        newly_marked
    }

    /// True if the link between `a` and `b` is marked failed (in either order).
    pub fn is_failed(&self, a: &IpAddr, b: &IpAddr) -> bool {
        self.failed_pairs.contains(&failed_pair_key(*a, *b))
    }

    /// Clear every failed pair `node` is part of, because something about those pairs
    /// changed (R13a). Returns the other end of each cleared pair.
    pub fn clear_failed_for(&mut self, node: &IpAddr) -> Vec<IpAddr> {
        let mut others = Vec::new();
        self.failed_pairs.retain(|&(x, y)| {
            let other = if x == *node {
                y
            } else if y == *node {
                x
            } else {
                return true;
            };
            others.push(other);
            false
        });
        others
    }

    /// Forget a node's reports (it disconnected or was reset). Afterwards it counts as a
    /// non-reporter again, so its links are down until it reports again (R14). Its
    /// failed pairs, and which failures it last listed, are kept: only a (re)connect
    /// clears a pair (R13a).
    pub fn remove_node(&mut self, node: &IpAddr) {
        self.snapshots.remove(node);
        self.latest_session.remove(node);
    }

    /// True if a report from `session` may be stored for `node`: its generation is at
    /// least the highest seen from the node, which it then becomes. A late report from
    /// a session the node has replaced (lower generation) is refused, whichever handle
    /// happened to be minted last.
    pub fn accept_session(&mut self, node: IpAddr, session: Option<&str>) -> bool {
        let generation = session_generation(session);
        let latest = self.latest_session.entry(node).or_insert(0);
        if generation < *latest {
            return false;
        }
        *latest = generation;
        true
    }

    /// Does the `reporter` end of a link agree that the link to the peer whose CN is
    /// `peer_cn` is up? Only if its latest snapshot lists `peer_cn` as `up`.
    ///
    /// A node that has never reported (or whose reports were forgotten) agrees to
    /// nothing: a link with no report counts as down (R14). A peer whose CN is unknown
    /// (`None`) can never match, so the link is not up.
    fn end_agrees(&self, reporter: &IpAddr, peer_cn: Option<&str>) -> bool {
        let Some(snapshot) = self.snapshots.get(reporter) else {
            return false;
        };
        peer_cn.is_some_and(|cn| snapshot.get(cn) == Some(&LinkState::Up))
    }

    /// True if the link between `a` and `b` may carry routes: each end has reported the
    /// link to the other as up (R14). A link either end has not reported is not
    /// usable. `a_cn` and `b_cn` are the nodes' CNs as policy declares them (`None` if
    /// policy names no CN for the address).
    pub fn edge_usable(
        &self,
        a: &IpAddr,
        a_cn: Option<&str>,
        b: &IpAddr,
        b_cn: Option<&str>,
    ) -> bool {
        self.end_agrees(a, b_cn) && self.end_agrees(b, a_cn)
    }
}

/// Check a `reportLinkStates` snapshot before it is stored. This is a trust boundary:
/// the entries come from the node.
///
/// `declared_links` is the number of links policy declares for the reporting node; a
/// snapshot cannot honestly list more links than that. Every entry must name a peer
/// CN, and no CN may appear twice. An empty snapshot is valid: the node has no link up.
///
/// Returns the entries unchanged, or a description of the first problem (the caller
/// answers `paramError`).
pub fn validate_snapshot(
    entries: Vec<LinkStateReport>,
    declared_links: usize,
) -> Result<Vec<LinkStateReport>, String> {
    if entries.len() > declared_links {
        return Err(format!(
            "report lists {} links but policy declares {} for this node",
            entries.len(),
            declared_links
        ));
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for e in &entries {
        if e.peer_cn.is_empty() {
            return Err("report entry has an empty peerCn".to_string());
        }
        if !seen.insert(e.peer_cn.as_str()) {
            return Err(format!("report lists peerCn '{}' twice", e.peer_cn));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn entry(cn: &str, state: LinkState) -> LinkStateReport {
        LinkStateReport {
            peer_cn: cn.to_string(),
            state,
        }
    }

    const A: &str = "fd5a:5052::1";
    const B: &str = "fd5a:5052::2";

    fn usable(t: &LinkStateTable) -> bool {
        t.edge_usable(&ip(A), Some("a.zpr"), &ip(B), Some("b.zpr"))
    }

    #[test]
    fn both_ends_up_is_usable() {
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Up)]);
        assert!(usable(&t));
    }

    #[test]
    fn one_end_down_or_failed_is_not_usable() {
        for bad in [LinkState::Down, LinkState::Failed] {
            let mut t = LinkStateTable::new();
            t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
            t.set_snapshot(ip(B), vec![entry("a.zpr", bad)]);
            assert!(
                !usable(&t),
                "{bad:?} on one end must make the edge unusable"
            );
        }
    }

    #[test]
    fn peer_missing_from_snapshot_is_not_up() {
        // B reports, but lists only some other peer: under snapshot semantics its link
        // to A is not up, whatever A says.
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("relay.zpr", LinkState::Up)]);
        assert!(!usable(&t));
    }

    #[test]
    fn neither_end_reported_is_not_usable() {
        // R14 (ZODE_LINKS.md): a link with no report counts as down.
        let t = LinkStateTable::new();
        assert!(!usable(&t));
    }

    #[test]
    fn one_end_up_and_the_other_never_reported_is_not_usable() {
        // R14: both ends must report up. B never reported, so B does not agree, in
        // either argument order.
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        assert!(!usable(&t));
        assert!(!t.edge_usable(&ip(B), Some("b.zpr"), &ip(A), Some("a.zpr")));
    }

    #[test]
    fn unknown_peer_cn_never_matches_for_a_reporter() {
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Up)]);
        // Policy names no CN for B: A's entry cannot be matched to B.
        assert!(!t.edge_usable(&ip(A), Some("a.zpr"), &ip(B), None));
    }

    #[test]
    fn new_snapshot_replaces_the_old_one() {
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Up)]);
        assert!(usable(&t));
        // B's next snapshot no longer lists A at all.
        t.set_snapshot(ip(B), vec![]);
        assert!(!usable(&t));
    }

    #[test]
    fn removing_a_node_makes_its_links_down() {
        // R14: once B's reports are forgotten (disconnect or reset), B is a
        // non-reporter, and a non-reporter's links are down until it reports again.
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Up)]);
        assert!(usable(&t));
        t.remove_node(&ip(B));
        assert!(!usable(&t), "B's reports went with it; the link is down");
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Up)]);
        assert!(usable(&t), "B reported up again");
    }

    // --- R13a: failed pairs ---

    const C: &str = "fd5a:5052::3";

    #[test]
    fn a_failed_pair_is_unordered() {
        let mut t = LinkStateTable::new();
        assert!(!t.is_failed(&ip(A), &ip(B)));
        t.mark_failed(ip(B), ip(A));
        assert!(t.is_failed(&ip(A), &ip(B)));
        assert!(t.is_failed(&ip(B), &ip(A)));
        assert!(!t.is_failed(&ip(A), &ip(C)));
    }

    #[test]
    fn clearing_a_node_clears_only_its_pairs_and_returns_the_other_ends() {
        let mut t = LinkStateTable::new();
        t.mark_failed(ip(A), ip(B));
        t.mark_failed(ip(C), ip(A));
        t.mark_failed(ip(B), ip(C));
        let mut others = t.clear_failed_for(&ip(A));
        others.sort();
        assert_eq!(others, vec![ip(B), ip(C)]);
        assert!(!t.is_failed(&ip(A), &ip(B)));
        assert!(!t.is_failed(&ip(A), &ip(C)));
        assert!(t.is_failed(&ip(B), &ip(C)), "a pair without A stays marked");
        assert!(
            t.clear_failed_for(&ip(A)).is_empty(),
            "nothing left to clear"
        );
    }

    #[test]
    fn a_repeated_failure_does_not_re_mark_a_cleared_pair() {
        // Review (Copilot, #66): after B reconnects and the pair is cleared, A may send
        // a snapshot that still lists B as failed (it has not received the re-proposed
        // topology yet). That is the failure already accounted for, not a new one.
        let mut t = LinkStateTable::new();
        assert_eq!(
            t.record_failures(ip(A), &[ip(B)]),
            vec![ip(B)],
            "new failure"
        );
        assert!(t.is_failed(&ip(A), &ip(B)));
        t.clear_failed_for(&ip(B));
        assert!(
            t.record_failures(ip(A), &[ip(B)]).is_empty(),
            "stale repeat"
        );
        assert!(!t.is_failed(&ip(A), &ip(B)));
        // A's entry leaves `failed` (its retry is under way), then fails again: a new
        // failure, marked.
        assert!(t.record_failures(ip(A), &[]).is_empty());
        assert_eq!(t.record_failures(ip(A), &[ip(B)]), vec![ip(B)]);
        assert!(t.is_failed(&ip(A), &ip(B)));
    }

    #[test]
    fn a_stale_failure_after_a_reconnect_does_not_re_mark() {
        // A disconnects (its reports are forgotten) and reconnects, which clears its
        // pairs; its first report still lists the old failure. Not a new one.
        let mut t = LinkStateTable::new();
        t.record_failures(ip(A), &[ip(B)]);
        t.remove_node(&ip(A));
        assert_eq!(t.clear_failed_for(&ip(A)), vec![ip(B)]);
        assert!(t.record_failures(ip(A), &[ip(B)]).is_empty());
        assert!(!t.is_failed(&ip(A), &ip(B)));
    }

    #[test]
    fn forgetting_a_nodes_reports_keeps_its_failed_pairs() {
        // Only a (re)connect clears a mark (R13a); a disconnect forgets the reports
        // but the visa service still must not propose the link again.
        let mut t = LinkStateTable::new();
        t.mark_failed(ip(A), ip(B));
        t.remove_node(&ip(A));
        assert!(t.is_failed(&ip(A), &ip(B)));
    }

    #[test]
    fn session_generation_parses_the_prefix() {
        assert_eq!(session_generation(Some("42-6f1c")), 42);
        assert_eq!(session_generation(Some("6f1c-no-number")), 0);
        assert_eq!(session_generation(Some("plain")), 0);
        assert_eq!(session_generation(None), 0);
    }

    #[test]
    fn validate_accepts_a_good_snapshot_and_an_empty_one() {
        let good = vec![
            entry("b.zpr", LinkState::Up),
            entry("c.zpr", LinkState::Failed),
        ];
        assert_eq!(validate_snapshot(good.clone(), 2).unwrap(), good);
        assert!(validate_snapshot(vec![], 0).unwrap().is_empty());
    }

    #[test]
    fn validate_rejects_more_entries_than_declared_links() {
        let entries = vec![entry("b.zpr", LinkState::Up), entry("c.zpr", LinkState::Up)];
        assert!(validate_snapshot(entries, 1).is_err());
        assert!(validate_snapshot(vec![entry("b.zpr", LinkState::Up)], 0).is_err());
    }

    #[test]
    fn validate_rejects_empty_and_duplicate_cns() {
        assert!(validate_snapshot(vec![entry("", LinkState::Up)], 3).is_err());
        let dup = vec![
            entry("b.zpr", LinkState::Up),
            entry("b.zpr", LinkState::Down),
        ];
        assert!(validate_snapshot(dup, 3).is_err());
    }
}
