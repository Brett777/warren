//! Network policy shared by the hub and the node:
//!
//! - [`exit_key`]: which nodes leave through the same public address.
//! - [`fair_order`]: rotate across exit addresses instead of across devices, so
//!   three phones on one home Wi-Fi count as one exit, not three.
//! - [`is_local_target`]: targets a node refuses to dial (its own LAN, loopback,
//!   carrier-internal ranges), so the proxy cannot be used to reach devices on
//!   whatever network the node happens to sit on.
//! - [`Gate`]: the hub-side network gate. With it on, a node serves only while
//!   its exit address is a trusted (home) network or a cellular one; on any other
//!   network (a school, an office, a cafe) it stays connected but is held idle.
//!
//! Everything here is pure, so the rules are unit-tested without a network.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

/// Prefix of a [`warren_proto::NodeToHub::DialFailed`] reason that means the node
/// refused the target on policy grounds. The hub does not count it against the
/// node's health and does not fail over: every other node would refuse it too.
pub const BLOCKED_PREFIX: &str = "blocked: ";

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as its IPv4 form; anything else
/// unchanged. A dual-stack listener reports IPv4 peers in the mapped form.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Key under which nodes share an exit. IPv4: the address itself (one NAT). IPv6:
/// the /64, because devices behind one router each hold their own address inside
/// the router's /64, and they share its IPv4 exit as well.
pub fn exit_key(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn is_local_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || o[0] == 0
        // 100.64.0.0/10: carrier-grade NAT space, internal to the ISP or carrier.
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
}

/// True if `ip` is not a public internet address: loopback, private (RFC 1918),
/// link-local, carrier-grade NAT, unspecified, multicast, IPv6 unique-local, and
/// the IPv4 forms of those embedded in IPv6 (mapped or NAT64).
pub fn is_local_target(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // 64:ff9b::/96 (NAT64) carries an IPv4 address in its last 32 bits.
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                let v4 = Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    (s[6] & 0xff) as u8,
                    (s[7] >> 8) as u8,
                    (s[7] & 0xff) as u8,
                );
                return is_local_v4(v4);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Routing rank of one node; lower sorts first. Built by the hub's `route_rank`:
/// (unhealthy overall, unhealthy on this host, in-flight, host fails, fails).
pub type Rank = (bool, bool, u32, u32, u32);

/// Order in which to try the candidate nodes for one request.
///
/// Candidates sharing an exit key form one group. The rotation (`start`, a
/// counter that advances per request) moves across GROUPS, so each exit address
/// gets an equal share of requests however many devices sit behind it; devices
/// inside a group take turns. Healthy groups come before unhealthy ones and a
/// less-loaded exit before a busier one, as before. After one device per group
/// has been tried, the remaining devices follow as further fallbacks.
///
/// A candidate with no key (exit address not known yet) is a group of its own.
pub fn fair_order(keys: &[Option<String>], ranks: &[Rank], start: usize) -> Vec<usize> {
    debug_assert_eq!(keys.len(), ranks.len());
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut by_key: HashMap<&str, usize> = HashMap::new();
    for (i, key) in keys.iter().enumerate() {
        match key.as_deref() {
            Some(k) => match by_key.get(k) {
                Some(&g) => groups[g].push(i),
                None => {
                    by_key.insert(k, groups.len());
                    groups.push(vec![i]);
                }
            },
            None => groups.push(vec![i]),
        }
    }
    let n_groups = groups.len();
    if n_groups == 0 {
        return Vec::new();
    }
    // Devices inside a group take turns each time the rotation comes back to the
    // group (`start / n_groups`), not on every request: rotating them by `start`
    // itself would land on the same device whenever both counts share a factor.
    let turn = start / n_groups;
    for g in groups.iter_mut() {
        let n = g.len();
        g.rotate_left(turn % n);
        g.sort_by_key(|&i| ranks[i]); // stable: turn order kept within a tier
    }
    groups.rotate_left(start % n_groups);
    groups.sort_by_key(|g| {
        let best = ranks[g[0]];
        // Load of an exit is the load of every device behind it.
        let load = g
            .iter()
            .fold(0u32, |acc, &i| acc.saturating_add(ranks[i].2));
        (best.0, best.1, load, best.3, best.4)
    });
    let deepest = groups.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::with_capacity(keys.len());
    for depth in 0..deepest {
        for g in &groups {
            if let Some(&i) = g.get(depth) {
                out.push(i);
            }
        }
    }
    out
}

/// An IP network in CIDR form (`203.0.113.7`, `203.0.113.0/24`, `2001:db8::/48`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("'{s}' is not an IP address or CIDR network"))?;
        let addr = canonical(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("'{s}': prefix length must be 0 to {max}"))?,
            None => max,
        };
        Ok(Net { addr, prefix })
    }
}

/// Why a node may, or may not, serve requests under the network gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The gate is off: every connected node serves.
    Open,
    /// The node's exit is a trusted network (listed, or shared with an anchor).
    Trusted,
    /// The node's exit is a cellular carrier address.
    Cellular,
    /// Neither: the node stays connected but is given no requests.
    Held,
}

impl Verdict {
    pub fn serves(self) -> bool {
        !matches!(self, Verdict::Held)
    }
    /// Label for the API and dashboard.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Open => "open",
            Verdict::Trusted => "trusted",
            Verdict::Cellular => "cellular",
            Verdict::Held => "held",
        }
    }
}

/// Network gate settings. `Default` is the gate off (upstream behaviour).
#[derive(Debug, Clone, Default)]
pub struct Gate {
    /// Off: every node serves. On: only trusted and cellular exits serve.
    pub enabled: bool,
    /// Networks that are always trusted (e.g. the home's public address).
    pub trusted: Vec<Net>,
    /// Nodes that joined with the enroll token of this name are anchors: always
    /// trusted themselves, and any node sharing an anchor's exit is trusted too.
    /// A device that never leaves home makes the home address follow itself, with
    /// nothing to reconfigure when the ISP changes that address.
    pub anchor_group: Option<String>,
}

impl Gate {
    pub fn is_anchor(&self, group: Option<&str>) -> bool {
        match (self.anchor_group.as_deref(), group) {
            (Some(a), Some(g)) => a.eq_ignore_ascii_case(g),
            _ => false,
        }
    }

    /// Decide for one node. `anchor_keys` are the exit keys of the anchors that
    /// are connected right now. `mobile` is what the IP lookup said: `None` while
    /// unknown, which fails closed (held) unless the address is trusted.
    pub fn verdict(
        &self,
        ip: Option<IpAddr>,
        mobile: Option<bool>,
        group: Option<&str>,
        anchor_keys: &HashSet<String>,
    ) -> Verdict {
        if !self.enabled {
            return Verdict::Open;
        }
        if self.is_anchor(group) {
            return Verdict::Trusted;
        }
        if let Some(ip) = ip {
            if self.trusted.iter().any(|n| n.contains(ip)) || anchor_keys.contains(&exit_key(ip)) {
                return Verdict::Trusted;
            }
        }
        if mobile == Some(true) {
            return Verdict::Cellular;
        }
        Verdict::Held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exit_key_groups_one_router() {
        assert_eq!(exit_key(ip("203.0.113.7")), "203.0.113.7");
        // IPv4-mapped form is the same exit as the plain IPv4 address.
        assert_eq!(exit_key(ip("::ffff:203.0.113.7")), "203.0.113.7");
        // Two devices in one /64 share a key; a different /64 does not.
        let a = exit_key(ip("2001:db8:1:2:aaaa::1"));
        assert_eq!(a, exit_key(ip("2001:db8:1:2:bbbb::9")));
        assert_ne!(a, exit_key(ip("2001:db8:1:3:aaaa::1")));
    }

    #[test]
    fn local_targets_are_refused() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            "64:ff9b::c0a8:101",
        ] {
            assert!(is_local_target(ip(s)), "{s} should be local");
        }
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "203.0.113.7",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(!is_local_target(ip(s)), "{s} should be public");
        }
    }

    const OK: Rank = (false, false, 0, 0, 0);
    const BAD: Rank = (true, false, 0, 0, 3);

    fn keys(ks: &[&str]) -> Vec<Option<String>> {
        ks.iter()
            .map(|k| (!k.is_empty()).then(|| k.to_string()))
            .collect()
    }

    #[test]
    fn fair_order_shares_requests_by_exit_not_by_device() {
        // Three phones on the home address, two on their own carrier addresses.
        let k = keys(&["home", "home", "home", "cell1", "cell2"]);
        let r = vec![OK; 5];
        let mut first_by_exit: HashMap<String, u32> = HashMap::new();
        let mut first_by_node = [0u32; 5];
        for start in 0..900 {
            let order = fair_order(&k, &r, start);
            assert_eq!(order.len(), 5);
            let mut seen = order.clone();
            seen.sort_unstable();
            assert_eq!(seen, vec![0, 1, 2, 3, 4], "every node tried exactly once");
            *first_by_exit
                .entry(k[order[0]].clone().unwrap())
                .or_default() += 1;
            first_by_node[order[0]] += 1;
        }
        // Each exit address gets a third of the requests...
        assert_eq!(first_by_exit["home"], 300);
        assert_eq!(first_by_exit["cell1"], 300);
        assert_eq!(first_by_exit["cell2"], 300);
        // ...and the three home phones split the home share evenly.
        assert_eq!(&first_by_node[..3], &[100, 100, 100]);
    }

    #[test]
    fn fair_order_tries_other_exits_before_a_second_device_on_the_same_one() {
        let k = keys(&["home", "home", "cell1"]);
        let order = fair_order(&k, &[OK; 3], 0);
        // First two tries are on two different exits.
        assert_ne!(k[order[0]], k[order[1]]);
    }

    #[test]
    fn fair_order_puts_unhealthy_exits_last() {
        let k = keys(&["home", "cell1", "cell2"]);
        let r = vec![BAD, OK, OK];
        for start in 0..6 {
            let order = fair_order(&k, &r, start);
            assert_eq!(order[2], 0, "the unhealthy exit is the last resort");
        }
        // A healthy device behind the same exit keeps that exit in rotation.
        let k = keys(&["home", "home", "cell1"]);
        let r = vec![BAD, OK, OK];
        let firsts: HashSet<usize> = (0..6).map(|s| fair_order(&k, &r, s)[0]).collect();
        assert!(firsts.contains(&1) && firsts.contains(&2) && !firsts.contains(&0));
    }

    #[test]
    fn fair_order_prefers_the_less_loaded_exit() {
        let k = keys(&["home", "home", "cell1"]);
        // Each home phone has one request in flight: the home EXIT carries two.
        let r = vec![(false, false, 1, 0, 0), (false, false, 1, 0, 0), OK];
        for start in 0..6 {
            assert_eq!(fair_order(&k, &r, start)[0], 2);
        }
    }

    #[test]
    fn fair_order_unknown_exit_is_its_own_group() {
        let k = keys(&["", "", "home"]);
        let firsts: HashSet<usize> = (0..6).map(|s| fair_order(&k, &[OK; 3], s)[0]).collect();
        assert_eq!(firsts.len(), 3);
        assert!(fair_order(&[], &[], 7).is_empty());
    }

    #[test]
    fn net_parses_and_matches() {
        let n: Net = "203.0.113.0/24".parse().unwrap();
        assert!(n.contains(ip("203.0.113.200")));
        assert!(n.contains(ip("::ffff:203.0.113.200")));
        assert!(!n.contains(ip("203.0.114.1")));
        let one: Net = "198.51.100.9".parse().unwrap();
        assert!(one.contains(ip("198.51.100.9")) && !one.contains(ip("198.51.100.10")));
        let v6: Net = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")) && !v6.contains(ip("2001:db9::1")));
        assert!(!v6.contains(ip("203.0.113.1")));
        let all: Net = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")));
        assert!("203.0.113.0/33".parse::<Net>().is_err());
        assert!("home".parse::<Net>().is_err());
        assert!("2001:db8::/129".parse::<Net>().is_err());
    }

    #[test]
    fn gate_off_serves_everything() {
        let g = Gate::default();
        assert_eq!(g.verdict(None, None, None, &HashSet::new()), Verdict::Open);
        assert!(Verdict::Open.serves());
    }

    #[test]
    fn gate_on_serves_only_trusted_and_cellular() {
        let g = Gate {
            enabled: true,
            trusted: vec!["198.51.100.9".parse().unwrap()],
            anchor_group: Some("home".into()),
        };
        let anchors: HashSet<String> = [exit_key(ip("203.0.113.7"))].into();
        // The anchor itself, whatever its address and before any lookup.
        assert_eq!(
            g.verdict(None, None, Some("Home"), &anchors),
            Verdict::Trusted
        );
        // A family phone on the same Wi-Fi as the anchor.
        assert_eq!(
            g.verdict(
                Some(ip("203.0.113.7")),
                Some(false),
                Some("family"),
                &anchors
            ),
            Verdict::Trusted
        );
        // A listed network.
        assert_eq!(
            g.verdict(Some(ip("198.51.100.9")), None, Some("family"), &anchors),
            Verdict::Trusted
        );
        // On cellular.
        assert_eq!(
            g.verdict(Some(ip("192.0.2.50")), Some(true), Some("family"), &anchors),
            Verdict::Cellular
        );
        // Someone else's Wi-Fi: held.
        let held = g.verdict(
            Some(ip("192.0.2.50")),
            Some(false),
            Some("family"),
            &anchors,
        );
        assert_eq!(held, Verdict::Held);
        assert!(!held.serves());
        // Lookup not back yet (or failed): held, not served.
        assert_eq!(
            g.verdict(Some(ip("192.0.2.50")), None, Some("family"), &anchors),
            Verdict::Held
        );
        // The anchor went offline: its address is no longer vouched for.
        assert_eq!(
            g.verdict(
                Some(ip("203.0.113.7")),
                Some(false),
                Some("family"),
                &HashSet::new()
            ),
            Verdict::Held
        );
    }
}
