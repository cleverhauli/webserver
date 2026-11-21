//! The status page, the counters behind it, and who may see them.

mod common;

use common::{FakeUpstream, TestServer, get, parse_responses, raw_exchange, read_until_closed};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webserver::config::ProxyRoute;

async fn status_server(name: &str) -> TestServer {
    TestServer::start_with(name, |config| config.status_page = true).await
}

#[tokio::test]
async fn the_status_page_is_off_by_default() {
    let server = TestServer::start("status-off").await;
    assert_eq!(get(server.addr, "/status").await.status, 404);
}

#[tokio::test]
async fn the_counters_follow_the_traffic() {
    let server = status_server("status-counters").await;

    assert_eq!(get(server.addr, "/health").await.status, 200);
    assert_eq!(get(server.addr, "/health").await.status, 200);
    assert_eq!(get(server.addr, "/nope").await.status, 404);
    let garbage = raw_exchange(server.addr, b"\x00\x01garbage\r\n\r\n").await;
    assert_eq!(parse_responses(&garbage)[0].status, 400);

    let response = get(server.addr, "/status").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("cache-control"), Some("no-store"));

    let body = response.text();
    for expected in [
        r#""served":3"#,
        r#""rejected":1"#,
        r#""2xx":2"#,
        r#""4xx":1"#,
        r#""accepted":5"#,
        r#""refused":0"#,
        r#""timed_out":0"#,
        r#""proxied":0"#,
    ] {
        assert!(body.contains(expected), "{expected} is missing from {body}");
    }
    assert!(body.contains(r#""uptime_seconds":"#));
    assert!(body.contains(r#""active":"#));
    assert!(!body.contains(r#""bytes_sent":0"#), "{body}");
}

#[tokio::test]
async fn only_allowed_addresses_see_the_status_page() {
    let server = TestServer::start_with("status-allowlist", |config| {
        config.status_page = true;
        config.status_allowed_ips = vec!["10.9.8.7".to_string()];
    })
    .await;

    // The test client connects from 127.0.0.1, which is not on the list.
    let response = get(server.addr, "/status").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.text(), "404 Not Found\n");
}

#[tokio::test]
async fn requests_that_came_through_a_proxy_are_refused() {
    let server = status_server("status-forwarded").await;
    assert_eq!(get(server.addr, "/status").await.status, 200);

    for header in [
        "X-Forwarded-For: 1.2.3.4",
        "Forwarded: for=1.2.3.4",
        "X-Real-IP: 1.2.3.4",
        "X-Forwarded-Host: example.com",
    ] {
        let raw =
            format!("GET /status HTTP/1.1\r\nHost: x\r\n{header}\r\nConnection: close\r\n\r\n");
        let data = raw_exchange(server.addr, raw.as_bytes()).await;
        assert_eq!(parse_responses(&data)[0].status, 404, "{header}");
    }
}

#[tokio::test]
async fn only_get_and_head_are_allowed() {
    let server = status_server("status-methods").await;

    let post = "POST /status HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, post.as_bytes()).await;
    let response = parse_responses(&data).into_iter().next().unwrap();
    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("GET, HEAD"));

    let head = "HEAD /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, head.as_bytes()).await;
    let response = parse_responses(&data).into_iter().next().unwrap();
    assert_eq!(response.status, 200);
    assert_ne!(response.header("content-length"), Some("0"));
    assert!(data.ends_with(b"\r\n\r\n"), "a HEAD answer has no body");
}

#[tokio::test]
async fn a_proxy_cannot_be_used_to_reach_an_upstreams_status_page() {
    // The upstream allows loopback, and our proxy IS on loopback...
    let upstream = TestServer::start_with("status-upstream", |c| c.status_page = true).await;
    assert_eq!(get(upstream.addr, "/status").await.status, 200);

    let route = ProxyRoute {
        prefix: "/api".to_string(),
        upstream: upstream.addr.to_string(),
        ..ProxyRoute::default()
    };
    let front = TestServer::start_with("status-front", move |c| c.proxy = vec![route]).await;

    // ...but the proxy marks every request with X-Forwarded-For, so it is refused.
    assert_eq!(get(front.addr, "/api/status").await.status, 404);
}

#[tokio::test]
async fn proxied_requests_are_counted() {
    let upstream =
        FakeUpstream::start(|_| Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()))
            .await;
    let route = ProxyRoute {
        prefix: "/api".to_string(),
        upstream: upstream.addr.to_string(),
        ..ProxyRoute::default()
    };
    let server = TestServer::start_with("status-proxied", move |config| {
        config.status_page = true;
        config.proxy = vec![route];
    })
    .await;

    assert_eq!(get(server.addr, "/api/a").await.status, 200);
    assert_eq!(get(server.addr, "/api/b").await.status, 200);

    let body = get(server.addr, "/status").await.text();
    assert!(body.contains(r#""proxied":2"#), "{body}");
    assert!(body.contains(r#""served":2"#), "{body}");
}

#[tokio::test]
async fn refused_connections_are_counted() {
    let server = TestServer::start_with("status-refused", |config| {
        config.status_page = true;
        config.max_connections = 1;
    })
    .await;

    // A half-finished request holds the only slot.
    let mut holder = TcpStream::connect(server.addr).await.unwrap();
    holder.write_all(b"GET ").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data = raw_exchange(server.addr, b"").await;
    assert_eq!(parse_responses(&data)[0].status, 503);

    drop(holder);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let body = get(server.addr, "/status").await.text();
    assert!(body.contains(r#""refused":1"#), "{body}");
}

#[tokio::test]
async fn slow_clients_are_counted() {
    let server = TestServer::start_with("status-timeouts", |config| {
        config.status_page = true;
        config.read_timeout_secs = 1;
    })
    .await;

    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let data = read_until_closed(&mut stream).await;
    assert_eq!(parse_responses(&data)[0].status, 408);

    let body = get(server.addr, "/status").await.text();
    assert!(body.contains(r#""timed_out":1"#), "{body}");
}

#[tokio::test]
async fn failed_tls_handshakes_are_counted() {
    let server = TestServer::start_tls("status-tls", |config| {
        config.status_page = true;
        config.redirect_http_to_https = false;
    })
    .await;

    // Plain text sent to the HTTPS port is not a TLS handshake.
    let _ = raw_exchange(server.https_addr.unwrap(), b"GET / HTTP/1.1\r\n\r\n").await;

    let body = get(server.addr, "/status").await.text();
    assert!(body.contains(r#""tls_handshake_failures":1"#), "{body}");
}
