//! Tests that send raw bytes: the broken, sneaky and slow requests that a
//! normal HTTP client library would never produce.

mod common;

use common::{TestServer, get, parse_responses, raw_exchange, read_until_closed};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

// ---------- connections: keep-alive, pipelining, limits ----------

#[tokio::test]
async fn pipelined_requests_get_one_response_each() {
    let server = TestServer::start("pipelined").await;
    let request = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n\
                   GET /about HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

    let data = raw_exchange(server.addr, request.as_bytes()).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].status, 200);
    assert_eq!(responses[0].header("connection"), Some("keep-alive"));
    assert_eq!(responses[0].text(), r#"{"status":"ok"}"#);
    assert_eq!(responses[1].status, 200);
    assert_eq!(responses[1].header("connection"), Some("close"));
    assert!(responses[1].text().contains("A small web server"));
}

#[tokio::test]
async fn http10_requests_close_the_connection() {
    let server = TestServer::start("http10").await;

    let data = raw_exchange(server.addr, b"GET /health HTTP/1.0\r\n\r\n").await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status, 200);
    assert_eq!(responses[0].header("connection"), Some("close"));
}

#[tokio::test]
async fn max_requests_per_connection_is_enforced() {
    let server = TestServer::start_with("max-requests", |c| {
        c.max_requests_per_connection = 2;
    })
    .await;

    let one = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    let data = raw_exchange(server.addr, one.repeat(3).as_bytes()).await;
    let responses = parse_responses(&data);

    // Only two are answered, and the second says it is the last.
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].header("connection"), Some("keep-alive"));
    assert_eq!(responses[1].header("connection"), Some("close"));
}

#[tokio::test]
async fn idle_keep_alive_connections_are_closed() {
    let server = TestServer::start_with("idle", |c| c.keep_alive_timeout_secs = 1).await;

    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    // Returns when the server hangs up after the idle wait.
    let started = Instant::now();
    let data = read_until_closed(&mut stream).await;
    let waited = started.elapsed();

    let responses = parse_responses(&data);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].header("connection"), Some("keep-alive"));
    assert!(
        waited >= Duration::from_millis(800),
        "closed too early: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(5),
        "closed too late: {waited:?}"
    );
}

#[tokio::test]
async fn the_connection_limit_gives_503_and_then_recovers() {
    let server = TestServer::start_with("limit", |c| c.max_connections = 1).await;

    // Start a request but never finish it: this holds the only slot.
    let mut holder = TcpStream::connect(server.addr).await.unwrap();
    holder.write_all(b"GET ").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data = raw_exchange(server.addr, b"").await;
    let responses = parse_responses(&data);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status, 503);
    assert_eq!(responses[0].header("retry-after"), Some("5"));

    // Once the slot is free again, normal service resumes.
    drop(holder);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(get(server.addr, "/health").await.status, 200);
}

// ---------- slow and silent clients ----------

#[tokio::test]
async fn a_half_sent_request_gets_408() {
    let server = TestServer::start_with("half-sent", |c| c.read_timeout_secs = 1).await;

    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let started = Instant::now();
    let data = read_until_closed(&mut stream).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status, 408);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn trickling_bytes_cannot_hold_a_connection_open() {
    let server = TestServer::start_with("slowloris", |c| c.read_timeout_secs = 1).await;

    let stream = TcpStream::connect(server.addr).await.unwrap();
    let (mut reader, mut writer) = stream.into_split();

    // One byte every 100 ms: this would take about 8 seconds to finish.
    let slow: &'static [u8] =
        b"GET /health HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let trickle = tokio::spawn(async move {
        for byte in slow {
            if writer.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        writer
    });

    let started = Instant::now();
    let data = read_until_closed(&mut reader).await;
    let elapsed = started.elapsed();
    trickle.abort();

    let responses = parse_responses(&data);
    assert_eq!(responses.first().map(|r| r.status), Some(408));
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[tokio::test]
async fn silent_connections_are_closed_without_a_response() {
    let server = TestServer::start_with("silent", |c| c.read_timeout_secs = 1).await;

    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    let data = read_until_closed(&mut stream).await;

    assert!(
        data.is_empty(),
        "expected no response, got {} bytes",
        data.len()
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

// ---------- malformed requests ----------

#[tokio::test]
async fn garbage_gets_400() {
    let server = TestServer::start("garbage").await;
    let data = raw_exchange(server.addr, b"\x00\x01garbage\r\n\r\n").await;
    assert_eq!(parse_responses(&data)[0].status, 400);
}

#[tokio::test]
async fn http11_without_a_host_header_gets_400() {
    let server = TestServer::start("no-host").await;
    let data = raw_exchange(server.addr, b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(parse_responses(&data)[0].status, 400);
}

#[tokio::test]
async fn unsupported_versions_get_505() {
    let server = TestServer::start("version").await;
    let data = raw_exchange(server.addr, b"GET / HTTP/2.0\r\nHost: x\r\n\r\n").await;
    assert_eq!(parse_responses(&data)[0].status, 505);
}

#[tokio::test]
async fn very_long_targets_get_414() {
    let server = TestServer::start("long-target").await;
    let request = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(3000));
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    assert_eq!(parse_responses(&data)[0].status, 414);
}

#[tokio::test]
async fn oversized_headers_get_431() {
    // A small limit, so the whole request arrives in one read.
    let server = TestServer::start_with("big-headers", |c| c.max_header_bytes = 200).await;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\n\r\n",
        "a".repeat(300)
    );
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    assert_eq!(parse_responses(&data)[0].status, 431);
}

#[tokio::test]
async fn oversized_bodies_get_413_before_they_are_sent() {
    let server = TestServer::start_with("big-body", |c| c.max_body_bytes = 10).await;

    // The client announces 100 bytes but sends none: the server must refuse
    // right away, not wait for them.
    let request = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n";
    let started = Instant::now();
    let data = raw_exchange(server.addr, request.as_bytes()).await;

    assert_eq!(parse_responses(&data)[0].status, 413);
    assert!(started.elapsed() < Duration::from_secs(5));
}

// ---------- request smuggling defenses ----------

#[tokio::test]
async fn conflicting_content_lengths_get_400() {
    let server = TestServer::start("conflicting-lengths").await;
    let request = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\
                   Content-Length: 6\r\n\r\nhello";
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    assert_eq!(parse_responses(&data)[0].status, 400);
}

#[tokio::test]
async fn content_length_together_with_transfer_encoding_gets_400() {
    let server = TestServer::start("cl-and-te").await;
    let request = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\
                   Transfer-Encoding: chunked\r\n\r\nhello";
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    assert_eq!(parse_responses(&data)[0].status, 400);
}

#[tokio::test]
async fn chunked_bodies_are_decoded() {
    let server = TestServer::start("chunked").await;
    let request = "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\
                   Connection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let data = raw_exchange(server.addr, request.as_bytes()).await;

    let responses = parse_responses(&data);
    assert_eq!(responses[0].status, 200);
    assert!(
        responses[0]
            .text()
            .contains("Body (11 bytes):\nhello world"),
        "{}",
        responses[0].text()
    );
}

// ---------- security ----------

#[tokio::test]
async fn path_traversal_attempts_never_leak_files() {
    let server = TestServer::start("traversal").await;

    for target in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E/secret.txt",
        "/..%2fsecret.txt",
        "/..%5csecret.txt",
        "/docs/../../secret.txt",
        "/docs/%2e%2e/%2e%2e/secret.txt",
        "/.hidden",
        "/%2ehidden",
        "/%00",
        "/index.html%00.png",
        "/C:/Windows/win.ini",
        "/NUL",
    ] {
        let response = get(server.addr, target).await;
        assert_eq!(response.status, 404, "should block {target}");
        assert!(
            !response.text().contains("TOP-SECRET"),
            "leaked via {target}"
        );
        assert!(!response.text().contains("hidden"), "leaked via {target}");
    }
}

#[tokio::test]
async fn wrong_methods_get_405_with_an_allow_header() {
    let server = TestServer::start("methods").await;
    let request = "DELETE /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, request.as_bytes()).await;

    let responses = parse_responses(&data);
    assert_eq!(responses[0].status, 405);
    assert_eq!(responses[0].header("allow"), Some("GET, HEAD"));
}
