use std::net::IpAddr;

use zpr::vsapi_types::VsapiFiveTuple;
use zpr::vsapi_types::vsapi_ip_number as ip_proto;

use crate::error::ServiceError;

pub fn make_fivetuple_tcp(
    source: IpAddr,
    dest: IpAddr,
    source_port: u16,
    dest_port: u16,
) -> Result<VsapiFiveTuple, ServiceError> {
    if (source.is_ipv4() && dest.is_ipv6()) || (source.is_ipv6() && dest.is_ipv4()) {
        return Err(ServiceError::Internal(
            "make_fivetuple_tcp: source and destination IP addresses must be of the same family"
                .into(),
        ));
    }
    let l3t = match source {
        IpAddr::V4(_) => zpr::packet_info::L3Type::Ipv4,
        IpAddr::V6(_) => zpr::packet_info::L3Type::Ipv6,
    };
    Ok(VsapiFiveTuple {
        source_addr: source,
        dest_addr: dest,
        l3_type: l3t,
        l4_protocol: ip_proto::TCP,
        source_port,
        dest_port,
    })
}

/// One-line description of a request's flow for logging:
/// `src:port -> dst:port proto N`, or for ICMP and ICMPv6, whose five-tuple
/// carries the type in the source port and the code in the dest port,
/// `src -> dst proto N icmp type T code C`.
pub fn describe_five_tuple(ft: &VsapiFiveTuple) -> String {
    match ft.l4_protocol {
        ip_proto::ICMP | ip_proto::IPV6_ICMP => format!(
            "{} -> {} proto {} icmp type {} code {}",
            ft.source_addr, ft.dest_addr, ft.l4_protocol, ft.source_port, ft.dest_port
        ),
        _ => format!(
            "{}:{} -> {}:{} proto {}",
            ft.source_addr, ft.source_port, ft.dest_addr, ft.dest_port, ft.l4_protocol
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zpr::vsapi_types::PacketDesc;

    /// ICMP carries its type and code in the port fields; the description names
    /// them as such instead of printing them as ports (zl-zipline#296).
    #[test]
    fn describe_five_tuple_names_icmp_type_and_code() {
        let ns = PacketDesc::new_icmp("fd5a:5052:1000::1", "fd5a:5052:1000::9", 135, 0).unwrap();
        assert_eq!(
            describe_five_tuple(&ns.five_tuple),
            "fd5a:5052:1000::1 -> fd5a:5052:1000::9 proto 58 icmp type 135 code 0"
        );
        let echo = PacketDesc::new_icmp("10.0.0.1", "10.0.0.9", 8, 0).unwrap();
        assert_eq!(
            describe_five_tuple(&echo.five_tuple),
            "10.0.0.1 -> 10.0.0.9 proto 1 icmp type 8 code 0"
        );
    }

    /// TCP/UDP keep the `src:port -> dst:port proto N` form.
    #[test]
    fn describe_five_tuple_shows_tcp_ports() {
        let tcp =
            PacketDesc::new_tcp("fd5a:5052:1000::1", "fd5a:5052:1000::9", 40000, 443).unwrap();
        assert_eq!(
            describe_five_tuple(&tcp.five_tuple),
            "fd5a:5052:1000::1:40000 -> fd5a:5052:1000::9:443 proto 6"
        );
    }
}
