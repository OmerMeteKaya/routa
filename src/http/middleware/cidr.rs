//! Shared CIDR (network prefix) matching, used by both `acl` (IP
//! allow/deny rules) and `ratelimit` (trusted-proxy detection for safe
//! client-IP resolution). Kept as one shared implementation rather
//! than duplicated in each -- the same bitmask arithmetic, the same
//! edge cases (prefix length 0, IPv4/IPv6 never cross-matching), one
//! place to get right.

use std::net::IpAddr;

/// A parsed CIDR range: an address and how many leading bits of it
/// must match for another address to be considered "in" the range.
#[derive(Debug, Clone, Copy)]
pub struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    /// Parses a string of the form `"IP"` or `"IP/PREFIX"` (e.g.
    /// `"10.0.0.0/8"`, `"192.168.1.100"`, `"2001:db8::/32"`). A bare IP
    /// with no prefix is treated as a full-length match (/32 for IPv4,
    /// /128 for IPv6).
    pub fn parse(s: &str) -> Option<CidrRange> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let network: IpAddr = addr_str.parse().ok()?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_str {
            Some(p) => p.parse::<u8>().ok()?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return None;
        }
        Some(CidrRange {
            network,
            prefix_len,
        })
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                ipv4_prefix_matches(net.to_bits(), a.to_bits(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                ipv6_prefix_matches(net.to_bits(), a.to_bits(), self.prefix_len)
            }
            _ => false, // range and address are different IP versions
        }
    }
}

fn ipv4_prefix_matches(network: u32, addr: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix_len as u32);
    (network & mask) == (addr & mask)
}

fn ipv6_prefix_matches(network: u128, addr: u128, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix_len as u32);
    (network & mask) == (addr & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ip_matches_only_itself() {
        let range = CidrRange::parse("192.168.1.100").unwrap();
        assert!(range.contains(&"192.168.1.100".parse().unwrap()));
        assert!(!range.contains(&"192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn ipv4_cidr_range() {
        let range = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(range.contains(&"10.1.2.3".parse().unwrap()));
        assert!(range.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!range.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_range() {
        let range = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(range.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!range.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn invalid_input_rejected() {
        assert!(CidrRange::parse("not-an-ip").is_none());
        assert!(CidrRange::parse("10.0.0.0/99").is_none());
    }

    #[test]
    fn ipv4_and_ipv6_never_cross_match() {
        let range = CidrRange::parse("10.0.0.0/8").unwrap();
        let v6_addr: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(!range.contains(&v6_addr));
    }

    #[test]
    fn zero_prefix_matches_everything_of_same_family() {
        let range = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(range.contains(&"1.2.3.4".parse().unwrap()));
        assert!(range.contains(&"255.255.255.255".parse().unwrap()));
    }
}
