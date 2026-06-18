// =============================================================================
// vault/acl.rs — client-IP resolution and IP/subnet ACL matching
//
// Source IP is taken from the TCP peer, unless that peer is a configured trusted
// proxy, in which case the first X-Forwarded-For hop is used. ACL entries may be
// bare IPs or CIDR subnets; an empty ACL means "no restriction".
// =============================================================================

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

// ─────────────────────────────────────────────────────────────────────────────
// client_ip
// Resolve the effective client IP: the TCP peer, or the first X-Forwarded-For
// entry when the peer is a trusted reverse proxy.
// ─────────────────────────────────────────────────────────────────────────────
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted_proxies: &[String]) -> IpAddr {
    let peer_ip = peer.ip();
    let trusted = trusted_proxies
        .iter()
        .filter_map(|p| p.parse::<IpAddr>().ok())
        .any(|t| t == peer_ip);
    if trusted {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer_ip
}

// ─────────────────────────────────────────────────────────────────────────────
// ip_allowed
// True if `ip` matches any ACL entry (IP or CIDR). An empty ACL = no restriction.
// ─────────────────────────────────────────────────────────────────────────────
pub fn ip_allowed(ip: IpAddr, entries: &[String]) -> bool {
    if entries.is_empty() {
        return true;
    }
    entries.iter().any(|e| entry_matches(e, ip))
}

// ─────────────────────────────────────────────────────────────────────────────
// entry_matches
// Match a single ACL entry, accepting either an exact IP or a CIDR subnet.
// ─────────────────────────────────────────────────────────────────────────────
fn entry_matches(entry: &str, ip: IpAddr) -> bool {
    let entry = entry.trim();
    if let Ok(addr) = entry.parse::<IpAddr>() {
        return addr == ip;
    }
    if let Ok(net) = entry.parse::<IpNet>() {
        return net.contains(&ip);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acl_allows_all() {
        assert!(ip_allowed("10.0.0.5".parse().unwrap(), &[]));
    }

    #[test]
    fn exact_ip_and_subnet_match() {
        let acl = vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()];
        assert!(ip_allowed("1.2.3.4".parse().unwrap(), &acl));
        assert!(ip_allowed("10.9.9.9".parse().unwrap(), &acl));
        assert!(!ip_allowed("192.168.1.1".parse().unwrap(), &acl));
    }
}
