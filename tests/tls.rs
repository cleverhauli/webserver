//! HTTPS tests, with a real server and a real TLS client.

mod common;

use common::{
    TestServer, parse_responses, raw_exchange, read_until_closed, tls_connect, tls_connector,
    tls_connector_trusting_nothing, tls_exchange, tls_try_connect,
};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webserver::config::Config;
use webserver::server::Server;

#[tokio::test]
async fn https_serves_pages_and_files() {
    let server = TestServer::start_tls("https-pages", |_| {}).await;
    let addr = server.https_addr.expect("HTTPS should be on");
    let connector = tls_connector(server.cert_path.as_ref().unwrap());

    for (target, expected) in [
        ("/", "<h1>home</h1>"),
        ("/health", r#"{"status":"ok"}"#),
        ("/docs/", "<h1>docs</h1>"),
    ] {
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let data = tls_exchange(addr, &connector, request.as_bytes()).await;
        let responses = parse_responses(&data);

        assert_eq!(responses.len(), 1, "{target}");
        assert_eq!(responses[0].status, 200, "{target}");
        assert_eq!(responses[0].text(), expected, "{target}");
    }
}

#[tokio::test]
async fn keep_alive_and_pipelining_work_over_tls() {
    let server = TestServer::start_tls("https-pipelined", |_| {}).await;
    let addr = server.https_addr.unwrap();
    let connector = tls_connector(server.cert_path.as_ref().unwrap());

    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n\
                   GET /about HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let data = tls_exchange(addr, &connector, request.as_bytes()).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].header("connection"), Some("keep-alive"));
    assert_eq!(responses[1].header("connection"), Some("close"));
}

#[tokio::test]
async fn plain_http_is_redirected_to_https() {
    let server = TestServer::start_tls("redirect", |_| {}).await;
    let https_port = server.https_addr.unwrap().port();

    let request = "GET /docs/?x=1 HTTP/1.1\r\nHost: localhost:9090\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status, 308);
    let expected = format!("https://localhost:{https_port}/docs/?x=1");
    assert_eq!(responses[0].header("location"), Some(expected.as_str()));
    assert!(!responses[0].text().contains("<h1>docs</h1>"));
}

#[tokio::test]
async fn the_redirect_refuses_suspicious_host_headers() {
    let server = TestServer::start_tls("redirect-bad-host", |_| {}).await;

    for host in [
        "evil.com/path",
        "a@evil.com",
        "evil.com:abc",
        "[::1",
        "exa mple.com",
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let data = raw_exchange(server.addr, request.as_bytes()).await;
        let responses = parse_responses(&data);

        assert_eq!(responses[0].status, 400, "Host: {host}");
        assert!(responses[0].header("location").is_none(), "Host: {host}");
    }

    // HTTP/1.0 without any Host header has nowhere to redirect to.
    let data = raw_exchange(server.addr, b"GET / HTTP/1.0\r\n\r\n").await;
    assert_eq!(parse_responses(&data)[0].status, 400);
}

#[tokio::test]
async fn the_redirect_can_be_turned_off() {
    let server = TestServer::start_tls("no-redirect", |c| c.redirect_http_to_https = false).await;

    // Plain HTTP now serves the site itself...
    let data = raw_exchange(
        server.addr,
        b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(parse_responses(&data)[0].status, 200);

    // ...and HTTPS still works.
    let connector = tls_connector(server.cert_path.as_ref().unwrap());
    let data = tls_exchange(
        server.https_addr.unwrap(),
        &connector,
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(parse_responses(&data)[0].status, 200);
}

#[tokio::test]
async fn hsts_is_sent_only_over_https() {
    let server = TestServer::start_tls("hsts", |c| {
        c.redirect_http_to_https = false;
        c.hsts_max_age_secs = 3600;
    })
    .await;
    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let connector = tls_connector(server.cert_path.as_ref().unwrap());
    let over_tls = tls_exchange(server.https_addr.unwrap(), &connector, request).await;
    assert_eq!(
        parse_responses(&over_tls)[0].header("strict-transport-security"),
        Some("max-age=3600")
    );

    let over_http = raw_exchange(server.addr, request).await;
    assert!(
        parse_responses(&over_http)[0]
            .header("strict-transport-security")
            .is_none()
    );
}

#[tokio::test]
async fn hsts_is_off_unless_configured() {
    let server = TestServer::start_tls("no-hsts", |_| {}).await;
    let connector = tls_connector(server.cert_path.as_ref().unwrap());
    let data = tls_exchange(
        server.https_addr.unwrap(),
        &connector,
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        parse_responses(&data)[0]
            .header("strict-transport-security")
            .is_none()
    );
}

#[tokio::test]
async fn plain_http_sent_to_the_https_port_gets_no_answer() {
    let server = TestServer::start_tls("plain-to-tls", |_| {}).await;
    let addr = server.https_addr.unwrap();

    let data = raw_exchange(
        addr,
        b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        !String::from_utf8_lossy(&data).contains("HTTP/1.1 200"),
        "a plain-text answer must never come out of the TLS port"
    );

    // The server carries on as normal afterwards.
    let connector = tls_connector(server.cert_path.as_ref().unwrap());
    let data = tls_exchange(
        addr,
        &connector,
        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(parse_responses(&data)[0].status, 200);
}

#[tokio::test]
async fn silent_connections_to_the_https_port_are_dropped() {
    let server = TestServer::start_tls("handshake-timeout", |c| {
        c.tls_handshake_timeout_secs = 1;
    })
    .await;

    let mut stream = TcpStream::connect(server.https_addr.unwrap())
        .await
        .unwrap();
    let started = Instant::now();
    let data = read_until_closed(&mut stream).await;

    assert!(
        data.is_empty(),
        "expected silence, got {} bytes",
        data.len()
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_certificate_is_refused() {
    let server = TestServer::start_tls("untrusted", |_| {}).await;
    let addr = server.https_addr.unwrap();

    // Trusting nothing: the handshake must fail. Encryption without
    // verification would let anyone impersonate the server.
    let result = tls_try_connect(addr, &tls_connector_trusting_nothing()).await;
    assert!(result.is_err());

    // The server is unharmed.
    let connector = tls_connector(server.cert_path.as_ref().unwrap());
    let mut stream = tls_connect(addr, &connector).await;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let data = read_until_closed(&mut stream).await;
    assert_eq!(parse_responses(&data)[0].status, 200);
}

#[tokio::test]
async fn shutdown_closes_both_ports() {
    let server = TestServer::start_tls("tls-shutdown", |_| {}).await;
    let http_addr = server.addr;
    let https_addr = server.https_addr.unwrap();

    server.shutdown().await.unwrap();

    assert!(TcpStream::connect(http_addr).await.is_err());
    assert!(TcpStream::connect(https_addr).await.is_err());
}

#[tokio::test]
async fn a_bad_certificate_stops_the_server_from_starting() {
    let config = Config {
        port: 0,
        https_port: 0,
        tls_cert_path: Some("no-such-certificate.pem".to_string()),
        tls_key_path: Some("no-such-key.pem".to_string()),
        ..Config::default()
    };

    let error = Server::bind(config)
        .await
        .err()
        .expect("starting with a missing certificate must fail");
    assert!(
        error
            .to_string()
            .contains("could not read certificate file"),
        "{error}"
    );
}
