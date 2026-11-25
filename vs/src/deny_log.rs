//! A bounded, in-memory record of recent visa denials.
//!
//! Denies are collapsed on a key of addresses, protocol, destination port (or
//! ICMP type and code) and deny code, so a chatty source does not flush the
//! window; a repeat bumps a count and moves the entry to the newest end.
//! Not persisted: the log starts empty on every VS restart.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::SystemTime;

use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{DenyCode, VsapiFiveTuple};

use crate::config::DENY_LOG_SIZE;

/// One collapsed deny, keyed by
/// (source_addr, dest_addr, protocol, dest_port, icmp_type, deny_code).
///
/// The source port of TCP/UDP traffic is deliberately not kept: it is usually
/// ephemeral, so keying on it would give every connection attempt its own entry
/// and flood the window.
#[derive(Clone)]
pub struct DenyEntry {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    /// Raw IP protocol number.
    pub protocol: u8,
    /// Destination port for TCP/UDP; the ICMP **code** for ICMP and ICMPv6
    /// (`VsapiFiveTuple` carries it in `dest_port`).
    pub dest_port: u16,
    /// The ICMP **type** for ICMP and ICMPv6 (`VsapiFiveTuple` carries it in
    /// `source_port`); `None` for every other protocol, and for a malformed
    /// ICMP tuple whose type does not fit in a byte.
    pub icmp_type: Option<u8>,
    pub count: u64,
    pub last_deny_ms: u64,
    pub deny_code: String, // stable API spelling produced by deny_code_name
}

/// Bounded request-recency-ordered window of denies. Oldest at the front.
#[derive(Default)]
pub struct DenyLog {
    entries: Mutex<VecDeque<DenyEntry>>,
}

/// The stable wire spelling for a deny code.
pub fn deny_code_name(code: &DenyCode) -> &'static str {
    match code {
        DenyCode::NoReason => "NoReason",
        DenyCode::NoMatch => "NoMatch",
        DenyCode::Denied => "Denied",
        DenyCode::SourceNotFound => "SourceNotFound",
        DenyCode::DestNotFound => "DestNotFound",
        DenyCode::SourceAuthError => "SourceAuthError",
        DenyCode::DestAuthError => "DestAuthError",
        DenyCode::QuotaExceeded => "QuotaExceeded",
        DenyCode::NoRoute => "NoRoute",
    }
}

/// The ICMP type of an ICMP or ICMPv6 five-tuple, or `None` for any other
/// protocol. An ICMP type is one byte; a larger value can only come from a
/// malformed request and is reported as `None` rather than truncated.
fn icmp_type_of(ft: &VsapiFiveTuple) -> Option<u8> {
    match ft.l4_protocol {
        ip_proto::ICMP | ip_proto::IPV6_ICMP => u8::try_from(ft.source_port).ok(),
        _ => None,
    }
}

/// Epoch milliseconds, clamped rather than panicking: a pre-epoch clock reads
/// as 0 and an absurdly future one saturates at `u64::MAX`.
fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl DenyLog {
    /// Record a deny at the current wall-clock time.
    pub fn record(&self, ft: &VsapiFiveTuple, code: &DenyCode) {
        self.record_at_ms(ft, code, epoch_ms_now());
    }

    /// Record a deny at an explicit epoch-millisecond time.
    ///
    // Note: O(N) scan under one mutex, N=500; add a HashMap key index if
    // the deny rate makes this hot.
    pub(crate) fn record_at_ms(&self, ft: &VsapiFiveTuple, code: &DenyCode, now_ms: u64) {
        let name = deny_code_name(code);
        let icmp_type = icmp_type_of(ft);
        let mut entries = self.entries.lock().expect("deny log mutex poisoned");

        let hit = entries.iter().position(|e| {
            e.source_addr == ft.source_addr
                && e.dest_addr == ft.dest_addr
                && e.protocol == ft.l4_protocol
                && e.dest_port == ft.dest_port
                && e.icmp_type == icmp_type
                && e.deny_code == name
        });

        match hit {
            Some(idx) => {
                let mut entry = entries
                    .remove(idx)
                    .expect("position() returned a valid index");
                entry.count += 1;
                entry.last_deny_ms = now_ms;
                entries.push_back(entry);
            }
            None => {
                entries.push_back(DenyEntry {
                    source_addr: ft.source_addr,
                    dest_addr: ft.dest_addr,
                    protocol: ft.l4_protocol,
                    dest_port: ft.dest_port,
                    icmp_type,
                    count: 1,
                    last_deny_ms: now_ms,
                    deny_code: name.to_string(),
                });
                while entries.len() > DENY_LOG_SIZE {
                    entries.pop_front();
                }
            }
        }
    }

    /// Snapshot of the window, newest request first, optionally filtered to
    /// `last_deny_ms >= since` and truncated to `limit` entries.
    pub fn recent(&self, since: Option<u64>, limit: Option<usize>) -> Vec<DenyEntry> {
        let entries = self.entries.lock().expect("deny log mutex poisoned");
        entries
            .iter()
            .rev()
            .filter(|e| since.is_none_or(|s| e.last_deny_ms >= s))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zpr::packet_info::L3Type;
    use zpr::vsapi_types::PacketDesc;

    /// Builds a five-tuple for tests; source port is deliberately varied to
    /// prove it is not part of the collapsing key.
    fn ft(src: &str, dst: &str, proto: u8, dest_port: u16) -> VsapiFiveTuple {
        VsapiFiveTuple::new(
            L3Type::Ipv6,
            src.parse().unwrap(),
            dst.parse().unwrap(),
            proto,
            u16::from(proto) + dest_port, // arbitrary, ignored by the key
            dest_port,
        )
    }

    /// Builds an ICMP five-tuple (ICMPv6 for a v6 source, ICMP for v4) carrying
    /// `icmp_type` in the source port and `icmp_code` in the dest port, as the
    /// node's classifier does.
    fn icmp(src: &str, dst: &str, icmp_type: u8, icmp_code: u8) -> VsapiFiveTuple {
        PacketDesc::new_icmp(src, dst, icmp_type, icmp_code)
            .unwrap()
            .five_tuple
    }

    /// Renders the log as (source, deny code, count) triples, newest first.
    fn snapshot(log: &DenyLog) -> Vec<(String, String, u64)> {
        log.recent(None, None)
            .into_iter()
            .map(|e| (e.source_addr.to_string(), e.deny_code, e.count))
            .collect()
    }

    /// The worked example from the spec: a repeat of the middle entry moves it
    /// to the newest end and bumps its count, leaving the others in place.
    #[test]
    fn repeat_moves_entry_to_newest_and_increments_count() {
        let log = DenyLog::default();
        let a = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let b = ft(
            "fd5a:5052:1000::8",
            "fd5a:5052:1000::10",
            ip_proto::TCP,
            443,
        );
        let c = ft(
            "fd5a:5052:1000::22",
            "fd5a:5052:1000::29",
            ip_proto::UDP,
            17,
        );
        log.record_at_ms(&a, &DenyCode::Denied, 1_000);
        log.record_at_ms(&b, &DenyCode::NoMatch, 2_000);
        log.record_at_ms(&c, &DenyCode::Denied, 3_000);

        log.record_at_ms(&b, &DenyCode::NoMatch, 4_000);

        assert_eq!(
            snapshot(&log),
            vec![
                ("fd5a:5052:1000::8".to_string(), "NoMatch".to_string(), 2),
                ("fd5a:5052:1000::22".to_string(), "Denied".to_string(), 1),
                ("fd5a:5052:1000::1".to_string(), "Denied".to_string(), 1),
            ]
        );
    }

    /// Overfilling the window evicts the oldest entry and caps the length.
    #[test]
    fn window_evicts_oldest_beyond_capacity() {
        let log = DenyLog::default();
        for i in 0..=DENY_LOG_SIZE {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::ffff",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i as u64);
        }

        let all = log.recent(None, None);
        assert_eq!(all.len(), DENY_LOG_SIZE);
        assert!(
            !all.iter()
                .any(|e| e.source_addr.to_string() == "fd5a:5052:1000::1"),
            "the first-recorded key should have been evicted"
        );
    }

    /// A repeat on the oldest entry rescues it from eviction, which proves the
    /// hit path moves the entry rather than only bumping its count.
    #[test]
    fn repeat_rescues_oldest_entry_from_eviction() {
        let log = DenyLog::default();
        let oldest = ft(
            "fd5a:5052:1000::1",
            "fd5a:5052:1000::ffff",
            ip_proto::TCP,
            80,
        );
        log.record_at_ms(&oldest, &DenyCode::Denied, 1_000);
        for i in 1..DENY_LOG_SIZE {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::ffff",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i as u64);
        }

        // Refresh the oldest, then push one more distinct key to force an eviction.
        log.record_at_ms(&oldest, &DenyCode::Denied, 9_000);
        let extra = ft(
            "fd5a:5052:2000::1",
            "fd5a:5052:1000::ffff",
            ip_proto::TCP,
            80,
        );
        log.record_at_ms(&extra, &DenyCode::Denied, 9_001);

        let all = log.recent(None, None);
        assert_eq!(all.len(), DENY_LOG_SIZE);
        let rescued = all
            .iter()
            .find(|e| e.source_addr.to_string() == "fd5a:5052:1000::1")
            .expect("refreshed entry should have survived eviction");
        assert_eq!(rescued.count, 2);
        assert!(
            !all.iter()
                .any(|e| e.source_addr.to_string() == "fd5a:5052:1000::2"),
            "the now-oldest key should have been evicted instead"
        );
    }

    /// The deny code is part of the key: the same traffic denied two ways gets
    /// two entries, and a repeat only increments its own.
    #[test]
    fn different_deny_codes_are_separate_entries() {
        let log = DenyLog::default();
        let t = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        log.record_at_ms(&t, &DenyCode::Denied, 1_000);
        log.record_at_ms(&t, &DenyCode::NoMatch, 2_000);
        log.record_at_ms(&t, &DenyCode::NoMatch, 3_000);

        let all = log.recent(None, None);
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].deny_code.as_str(), all[0].count), ("NoMatch", 2));
        assert_eq!((all[1].deny_code.as_str(), all[1].count), ("Denied", 1));
    }

    /// `since` is inclusive and `limit` truncates from the newest-request end.
    #[test]
    fn since_is_inclusive_and_limit_truncates_from_newest() {
        let log = DenyLog::default();
        for i in 0..4u64 {
            let t = ft(
                &format!("fd5a:5052:1000::{:x}", i + 1),
                "fd5a:5052:1000::9",
                ip_proto::TCP,
                80,
            );
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + i * 1_000);
        }

        let since = log.recent(Some(2_000), None);
        assert_eq!(
            since
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [4_000, 3_000, 2_000],
            "the entry exactly at `since` must be included"
        );

        let limited = log.recent(None, Some(2));
        assert_eq!(
            limited
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [4_000, 3_000]
        );
    }

    /// A wall-clock rollback leaves an old timestamp in the middle of the
    /// window; `recent` must scan past it rather than stopping there.
    #[test]
    fn recent_scans_past_out_of_order_timestamps() {
        let log = DenyLog::default();
        let newer = ft("fd5a:5052:1000::1", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let rolled_back = ft("fd5a:5052:1000::2", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        let recovered = ft("fd5a:5052:1000::3", "fd5a:5052:1000::9", ip_proto::TCP, 80);
        log.record_at_ms(&newer, &DenyCode::Denied, 5_000);
        log.record_at_ms(&rolled_back, &DenyCode::Denied, 1_000); // clock went backwards
        log.record_at_ms(&recovered, &DenyCode::Denied, 6_000);

        let found = log.recent(Some(5_000), None);
        assert_eq!(
            found
                .iter()
                .map(|e| e.last_deny_ms)
                .collect::<Vec<_>>()
                .as_slice(),
            [6_000, 5_000],
            "the 1_000 entry must not terminate the scan"
        );
    }

    /// ICMP denies with the same code but different types (echo request vs
    /// neighbor solicitation) are different traffic and must stay separate
    /// entries, each reporting its type (zl-zipline#296).
    #[test]
    fn icmp_types_with_same_code_are_separate_entries() {
        let log = DenyLog::default();
        let echo = icmp("fd5a:5052:1000::1", "fd5a:5052:1000::9", 128, 0);
        let ns = icmp("fd5a:5052:1000::1", "fd5a:5052:1000::9", 135, 0);
        log.record_at_ms(&echo, &DenyCode::NoMatch, 1_000);
        log.record_at_ms(&ns, &DenyCode::NoMatch, 2_000);

        let all = log.recent(None, None);
        assert_eq!(
            all.len(),
            2,
            "two ICMP types must not collapse into one entry"
        );
        assert_eq!((all[0].icmp_type, all[0].dest_port), (Some(135), 0));
        assert_eq!((all[1].icmp_type, all[1].dest_port), (Some(128), 0));
    }

    /// A repeat of the same ICMP type and code collapses into one entry.
    #[test]
    fn icmp_repeat_of_same_type_and_code_collapses() {
        let log = DenyLog::default();
        let ns = icmp("fd5a:5052:1000::1", "fd5a:5052:1000::9", 135, 0);
        log.record_at_ms(&ns, &DenyCode::NoMatch, 1_000);
        log.record_at_ms(&ns, &DenyCode::NoMatch, 2_000);

        let all = log.recent(None, None);
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].icmp_type, all[0].count), (Some(135), 2));
    }

    /// IPv4 ICMP (protocol 1) records its type just like ICMPv6.
    #[test]
    fn icmpv4_records_its_type() {
        let log = DenyLog::default();
        let echo = icmp("10.0.0.1", "10.0.0.9", 8, 0);
        log.record_at_ms(&echo, &DenyCode::NoMatch, 1_000);

        let all = log.recent(None, None);
        assert_eq!(all[0].protocol, ip_proto::ICMP);
        assert_eq!(all[0].icmp_type, Some(8));
    }

    /// TCP source ports are ephemeral, so they are not keyed: two attempts
    /// differing only in source port are one entry, with no ICMP type.
    #[test]
    fn tcp_source_port_is_not_keyed_and_icmp_type_is_none() {
        let log = DenyLog::default();
        let dst: IpAddr = "fd5a:5052:1000::9".parse().unwrap();
        let src: IpAddr = "fd5a:5052:1000::1".parse().unwrap();
        for sport in [40_000u16, 40_001] {
            let t = VsapiFiveTuple::new(L3Type::Ipv6, src, dst, ip_proto::TCP, sport, 443);
            log.record_at_ms(&t, &DenyCode::Denied, 1_000 + u64::from(sport));
        }

        let all = log.recent(None, None);
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].icmp_type, all[0].count), (None, 2));
    }

    /// A malformed ICMP tuple whose type does not fit in a byte records no
    /// type rather than panicking or truncating it.
    #[test]
    fn icmp_type_out_of_range_is_none() {
        let log = DenyLog::default();
        let t = VsapiFiveTuple::new(
            L3Type::Ipv6,
            "fd5a:5052:1000::1".parse().unwrap(),
            "fd5a:5052:1000::9".parse().unwrap(),
            ip_proto::IPV6_ICMP,
            300,
            0,
        );
        log.record_at_ms(&t, &DenyCode::NoMatch, 1_000);

        assert_eq!(log.recent(None, None)[0].icmp_type, None);
    }
}
