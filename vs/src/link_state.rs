//! Link-state reports from nodes, and the rule that turns them into usable edges
//! (zl-zipline#224).
//!
//! A node (Zode) tells the visa service which of its links are up with
//! `VSHandle.reportLinkStates`. Each call is a **snapshot**: it lists every link the
//! node has, by the peer's link-certificate CN, and replaces whatever the node
//! reported before. A link the node leaves out is not up.
//!
//! The router uses a link only while **both** of its ends report it up, so one node
//! cannot claim a link its peer denies. This module holds the latest snapshot of every
//! reporting node and answers that question for one edge; `TopologyMgr` applies the
//! answer to the router (`Router::set_link_up`).
//!
//! Reports are stored by CN, exactly as sent, and resolved to addresses only when an
//! edge is evaluated. A Zode reports its link to the relay before the endpoint at the
//! other end has authenticated; resolving at receipt would drop that entry, and the
//! snapshot is not re-sent while nothing changes.
//!
//! The table lives in memory only. After a visa-service restart every node counts as a
//! non-reporter (see [LinkStateTable::end_agrees]) until it re-sends its snapshot, which
//! nodes do after every (re)connect.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use zpr::vsapi_types::{LinkState, LinkStateReport};

/// Latest link-state snapshot of every node that has reported.
#[derive(Debug, Default)]
pub struct LinkStateTable {
    /// Reporting node's ZPR address -> (peer CN -> reported state).
    snapshots: HashMap<IpAddr, HashMap<String, LinkState>>,
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

    /// Forget a node's reports (it disconnected or was reset). Afterwards it counts as a
    /// non-reporter again.
    pub fn remove_node(&mut self, node: &IpAddr) {
        self.snapshots.remove(node);
    }

    /// Does the `reporter` end of a link agree that the link to the peer whose CN is
    /// `peer_cn` is up?
    ///
    /// - A node that has reported: only if its snapshot lists `peer_cn` as `up`. A peer
    ///   whose CN is unknown (`None`) can never match, so the link is not up.
    /// - A node that has never reported agrees (the legacy rule below).
    fn end_agrees(&self, reporter: &IpAddr, peer_cn: Option<&str>) -> bool {
        match self.snapshots.get(reporter) {
            Some(snapshot) => peer_cn.is_some_and(|cn| snapshot.get(cn) == Some(&LinkState::Up)),
            // LEGACY RULE -- remove with zl-zipline#242 once every node reports (#223).
            // A node that has never sent reportLinkStates (today's `ph`) keeps the old
            // behaviour: a policy-declared link between two connected nodes counts as up.
            // Its peer can still veto the link by reporting it down. Operator decision on
            // pd gate g43 (q2 = legacy).
            None => true,
        }
    }

    /// True if the link between `a` and `b` may carry routes: each end agrees that the
    /// link to the other is up. `a_cn` and `b_cn` are the nodes' CNs as policy declares
    /// them (`None` if policy names no CN for the address).
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
    fn non_reporter_agrees_legacy_rule() {
        // Neither end has reported: today's behaviour, the edge is usable.
        let t = LinkStateTable::new();
        assert!(usable(&t));

        // Only A reports, and says up: B is legacy, so the edge is usable.
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        assert!(usable(&t));

        // Only A reports, and says down: A vetoes the link.
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Down)]);
        assert!(!usable(&t));
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
    fn removing_a_node_makes_it_a_non_reporter() {
        let mut t = LinkStateTable::new();
        t.set_snapshot(ip(A), vec![entry("b.zpr", LinkState::Up)]);
        t.set_snapshot(ip(B), vec![entry("a.zpr", LinkState::Down)]);
        assert!(!usable(&t));
        t.remove_node(&ip(B));
        assert!(usable(&t), "B's veto goes with its reports");
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
