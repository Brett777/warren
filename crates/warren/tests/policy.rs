//! End-to-end checks of the network policy: a node refuses local-network
//! targets, and the hub's network gate holds a node that is on a network it
//! does not trust.
//!
//! Each test boots a real hub (with the admin API) and one real node on
//! loopback, then drives requests through the proxy port and reads the node's
//! state back from `/api/nodes`.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use warren::hub::{run_with_listeners, HubConfig};
use warren::netpolicy::Gate;
use warren::node::{run_agent, RunArgs};

const ADMIN_TOKEN: &str = "admin-secret";

struct Pool {
    proxy: SocketAddr,
    admin: SocketAddr,
    target: SocketAddr,
}

/// Echo target + hub + one node. `tag` keeps the node key files apart.
async fn boot(tag: &str, gate: Gate, allow_local_targets: bool) -> Pool {
    let target_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target_l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = target_l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                }
            });
        }
    });

    let node_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = node_l.local_addr().unwrap();
    let proxy_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = proxy_l.local_addr().unwrap();
    // The hub binds the admin address itself: reserve a free port, then release it.
    let admin = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    tokio::spawn(async move {
        let store = std::sync::Arc::new(warren::store::Store::open(":memory:").unwrap());
        store.add_token("secret", "family").unwrap();
        let _ = run_with_listeners(
            node_l,
            proxy_l,
            HubConfig {
                store,
                tls: None,
                admin: Some((admin.to_string(), ADMIN_TOKEN.to_string())),
                public_node_addr: None,
                public_proxy_addr: None,
                fingerprint: None,
                udp_relay: None,
                gate,
            },
        )
        .await;
    });
    let key_file = format!("{}/warren-policy-{tag}.key", std::env::temp_dir().display());
    tokio::spawn(async move {
        let _ = run_agent(RunArgs {
            join: None,
            hub: Some(node_addr.to_string()),
            token: Some("secret".into()),
            key_file: Some(key_file),
            name: "phone".into(),
            tls: false,
            hub_fingerprint: None,
            insecure: false,
            auto_update: false,
            allow_local_targets,
        })
        .await;
    });
    Pool {
        proxy,
        admin,
        target,
    }
}

/// `GET /api/nodes` as JSON; None while the admin server is not up yet.
async fn nodes(admin: SocketAddr) -> Option<Vec<serde_json::Value>> {
    let mut c = TcpStream::connect(admin).await.ok()?;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("x:{ADMIN_TOKEN}"));
    let req = format!(
        "GET /api/nodes HTTP/1.1\r\nHost: {admin}\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n"
    );
    c.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    c.read_to_end(&mut buf).await.ok()?;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n")?;
    assert!(head.starts_with("HTTP/1.1 200"), "admin API said: {head}");
    // `Connection: close` + a small body: axum answers with Content-Length, but
    // tolerate a chunked reply by taking the JSON array out of the body.
    let json = &body[body.find('[')?..=body.rfind(']')?];
    serde_json::from_str(json).ok()
}

/// Wait for the one node to enroll and return its `/api/nodes` row.
async fn enrolled_node(admin: SocketAddr) -> serde_json::Value {
    for _ in 0..100 {
        if let Some(rows) = nodes(admin).await {
            if let Some(n) = rows.into_iter().next() {
                return n;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never enrolled");
}

/// One CONNECT through the pool: Some(true) on a full echo round trip,
/// Some(false) if the hub answered anything but 200.
async fn connect(proxy: SocketAddr, target: &str) -> std::io::Result<bool> {
    let mut c = TcpStream::connect(proxy).await?;
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    c.write_all(req.as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        c.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.len() > 1024 {
            break;
        }
    }
    if !String::from_utf8_lossy(&head).contains(" 200 ") {
        return Ok(false);
    }
    c.write_all(b"PING").await?;
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).await?;
    Ok(&buf == b"PING")
}

#[tokio::test]
async fn node_refuses_local_targets_without_losing_health() {
    // Default node (no --allow-local-targets); the echo target is on loopback.
    let pool = boot("local", Gate::default(), false).await;
    enrolled_node(pool.admin).await;

    // Asked several times: more than the three failures that mark a node
    // unhealthy. By literal address and by a name that resolves to loopback.
    for _ in 0..4 {
        assert!(!connect(pool.proxy, &pool.target.to_string()).await.unwrap());
    }
    let by_name = format!("localhost:{}", pool.target.port());
    assert!(!connect(pool.proxy, &by_name).await.unwrap());

    // A policy refusal is not a failing node: no failures counted against it.
    let n = enrolled_node(pool.admin).await;
    assert_eq!(n["fails"], 0, "refusals must not count as failures: {n}");
    assert_eq!(n["dials"], 0, "refusals must not count as dials: {n}");
    assert_eq!(n["gate"], "open");
}

#[tokio::test]
async fn gate_holds_a_node_on_an_untrusted_network() {
    // Gate on, nothing trusted: the node's address (loopback here) is neither a
    // trusted network nor a cellular one.
    let gate = Gate {
        enabled: true,
        ..Gate::default()
    };
    let pool = boot("held", gate, true).await;
    let n = enrolled_node(pool.admin).await;
    assert_eq!(n["gate"], "held", "{n}");
    // Connected, but given no requests: by pool or pinned by name.
    assert!(!connect(pool.proxy, &pool.target.to_string()).await.unwrap());
    let n = enrolled_node(pool.admin).await;
    assert_eq!(n["dials"], 0, "a held node must not be dialed: {n}");
}

#[tokio::test]
async fn gate_serves_a_node_on_a_trusted_network() {
    let gate = Gate {
        enabled: true,
        trusted: vec!["127.0.0.0/8".parse().unwrap()],
        anchor_group: None,
    };
    let pool = boot("trusted", gate, true).await;
    let n = enrolled_node(pool.admin).await;
    assert_eq!(n["gate"], "trusted", "{n}");
    assert!(connect(pool.proxy, &pool.target.to_string()).await.unwrap());
}

#[tokio::test]
async fn gate_trusts_the_anchor_group() {
    // The node joined with the token named "family"; make that the anchor group.
    let gate = Gate {
        enabled: true,
        trusted: vec![],
        anchor_group: Some("family".into()),
    };
    let pool = boot("anchor", gate, true).await;
    let n = enrolled_node(pool.admin).await;
    assert_eq!(n["gate"], "trusted", "{n}");
    assert!(connect(pool.proxy, &pool.target.to_string()).await.unwrap());
}
