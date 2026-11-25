//! Name resolution for the node.
//!
//! Normally the operating system resolves names. That does not work for the
//! static Linux build running under Termux on Android: the C library looks for
//! nameservers in `/etc/resolv.conf`, Android has no such file, and the lookup
//! falls back to a nameserver on 127.0.0.1 that is not there. Every name then
//! fails, including the hub's own hostname.
//!
//! So when `/etc/resolv.conf` is missing on Linux, the node resolves names
//! itself, asking the nameservers Termux lists in `$PREFIX/etc/resolv.conf`, or
//! public ones if that is missing too. `WARREN_DNS=1.1.1.1,8.8.8.8` forces the
//! built-in resolver with the given servers on any platform.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Used when no nameserver list can be found at all.
const FALLBACK_SERVERS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

enum Resolver {
    System,
    Builtin(Box<TokioAsyncResolver>),
}

static RESOLVER: OnceLock<Resolver> = OnceLock::new();

/// `nameserver` addresses from resolv.conf text, in file order.
fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                // A scoped IPv6 address ("fe80::1%wlan0") parses without its zone.
                (Some("nameserver"), Some(addr)) => {
                    addr.split('%').next().and_then(|a| a.parse().ok())
                }
                _ => None,
            }
        })
        .collect()
}

/// Comma- or space-separated IP addresses (the `WARREN_DNS` format).
fn parse_server_list(text: &str) -> Vec<IpAddr> {
    text.split([',', ' '])
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Which nameservers the built-in resolver should use, or None to leave
/// resolution to the operating system. Pure, so the choice is testable:
/// `forced` is `WARREN_DNS`, `system_conf_exists` is whether `/etc/resolv.conf`
/// is there, `termux_conf` is the text of `$PREFIX/etc/resolv.conf` if readable.
fn choose_servers(
    forced: Option<&str>,
    is_linux: bool,
    system_conf_exists: bool,
    termux_conf: Option<&str>,
) -> Option<Vec<IpAddr>> {
    let fallback = || parse_server_list(&FALLBACK_SERVERS.join(","));
    if let Some(list) = forced.filter(|s| !s.trim().is_empty()) {
        let servers = parse_server_list(list);
        return Some(if servers.is_empty() {
            fallback()
        } else {
            servers
        });
    }
    if !is_linux || system_conf_exists {
        return None;
    }
    let servers = termux_conf.map(parse_resolv_conf).unwrap_or_default();
    Some(if servers.is_empty() {
        fallback()
    } else {
        servers
    })
}

fn init() -> Resolver {
    let forced = std::env::var("WARREN_DNS").ok();
    let termux_conf = std::env::var("PREFIX")
        .ok()
        .and_then(|p| std::fs::read_to_string(format!("{p}/etc/resolv.conf")).ok());
    let servers = choose_servers(
        forced.as_deref(),
        cfg!(target_os = "linux"),
        std::path::Path::new("/etc/resolv.conf").exists(),
        termux_conf.as_deref(),
    );
    match servers {
        None => Resolver::System,
        Some(servers) => {
            tracing::info!(
                ?servers,
                "resolving names with the built-in resolver (no usable system resolver, or WARREN_DNS set)"
            );
            let group = NameServerConfigGroup::from_ips_clear(&servers, 53, true);
            let config = ResolverConfig::from_parts(None, vec![], group);
            let mut opts = ResolverOpts::default();
            // A dial is bounded at 10s overall; do not spend it all on one server.
            opts.timeout = std::time::Duration::from_secs(3);
            opts.attempts = 2;
            Resolver::Builtin(Box::new(TokioAsyncResolver::tokio(config, opts)))
        }
    }
}

/// Resolve `host:port` to socket addresses. An IP literal never touches a
/// resolver. Errors are `io::Error`, like `tokio::net::lookup_host`.
pub async fn lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    // Bracketed IPv6 literals arrive as "[::1]" from some callers.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match RESOLVER.get_or_init(init) {
        Resolver::System => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
        Resolver::Builtin(r) => {
            let ips = r
                .lookup_ip(host)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;
            Ok(ips.iter().map(|ip| SocketAddr::new(ip, port)).collect())
        }
    }
}

/// Split `host:port` (or `[v6]:port`) and resolve it. For the hub address.
pub async fn lookup_addr(addr: &str) -> std::io::Result<Vec<SocketAddr>> {
    let bad = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{addr}' is not host:port"),
        )
    };
    let (host, port) = addr.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    lookup(host, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn reads_nameservers_from_resolv_conf() {
        let text = "# Termux default\nnameserver 8.8.8.8\nnameserver 8.8.4.4 # second\n\
                    options timeout:2\nsearch lan\n; nameserver 9.9.9.9\n\
                    nameserver fe80::1%wlan0\nnameserver not-an-ip\n";
        assert_eq!(
            parse_resolv_conf(text),
            ips(&["8.8.8.8", "8.8.4.4", "fe80::1"])
        );
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn system_resolver_is_kept_where_it_works() {
        // Linux with /etc/resolv.conf, and anything that is not Linux.
        assert_eq!(choose_servers(None, true, true, None), None);
        assert_eq!(choose_servers(None, false, false, None), None);
        assert_eq!(choose_servers(Some("  "), true, true, None), None);
    }

    #[test]
    fn android_uses_termux_nameservers_then_public_ones() {
        // Termux: no /etc/resolv.conf, nameservers in $PREFIX/etc/resolv.conf.
        assert_eq!(
            choose_servers(None, true, false, Some("nameserver 8.8.8.8\n")),
            Some(ips(&["8.8.8.8"]))
        );
        // Neither file: public fallback rather than no resolution at all.
        assert_eq!(
            choose_servers(None, true, false, None),
            Some(ips(&["1.1.1.1", "8.8.8.8"]))
        );
        assert_eq!(
            choose_servers(None, true, false, Some("# empty\n")),
            Some(ips(&["1.1.1.1", "8.8.8.8"]))
        );
    }

    #[test]
    fn warren_dns_forces_the_built_in_resolver() {
        assert_eq!(
            choose_servers(Some("9.9.9.9, 1.0.0.1"), false, true, None),
            Some(ips(&["9.9.9.9", "1.0.0.1"]))
        );
        // Set but unusable: still built-in, with the fallback servers.
        assert_eq!(
            choose_servers(Some("nonsense"), true, true, None),
            Some(ips(&["1.1.1.1", "8.8.8.8"]))
        );
    }

    #[tokio::test]
    async fn ip_literals_skip_resolution() {
        assert_eq!(
            lookup("203.0.113.7", 443).await.unwrap(),
            vec!["203.0.113.7:443".parse().unwrap()]
        );
        assert_eq!(
            lookup("[2001:db8::1]", 80).await.unwrap(),
            vec!["[2001:db8::1]:80".parse().unwrap()]
        );
        assert_eq!(
            lookup_addr("127.0.0.1:7000").await.unwrap(),
            vec!["127.0.0.1:7000".parse().unwrap()]
        );
        assert_eq!(
            lookup_addr("[::1]:7000").await.unwrap(),
            vec!["[::1]:7000".parse().unwrap()]
        );
        assert!(lookup_addr("no-port").await.is_err());
        assert!(lookup_addr("host:notaport").await.is_err());
    }
}
