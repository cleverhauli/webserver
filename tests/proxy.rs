//! The reverse proxy, tested with a real server and a fake upstream program.

mod common;

use common::{
    FakeUpstream, RawResponse, TestServer, free_address, parse_responses, raw_exchange,
    tls_connector, tls_exchange,
};
use std::time::{Duration, Instant};
use webserver::config::ProxyRoute;

fn route(prefix: &str, upstream: &FakeUpstream) -> ProxyRoute {
    ProxyRoute {
        prefix: prefix.to_string(),
        upstream: upstream.addr.to_string(),
        ..ProxyRoute::default()
    }
}

async fn proxy_server(name: &str, routes: Vec<ProxyRoute>) -> TestServer {
    TestServer::start_with(name, move |config| config.proxy = routes).await
}

/// A GET that asks the server to close afterwards.
fn request(target: &str, extra_headers: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: public.example\r\n{extra_headers}Connection: close\r\n\r\n"
    )
}

async fn fetch(server: &TestServer, raw_request: &str) -> RawResponse {
    let data = raw_exchange(server.addr, raw_request.as_bytes()).await;
    parse_responses(&data)
        .into_iter()
        .next()
        .expect("the server sent no response")
}

/// A canned upstream answer with a correct Content-Length.
fn answer(status_line: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// ---------- forwarding ----------

#[tokio::test]
async fn requests_are_forwarded_and_answers_come_back() {
    let upstream = FakeUpstream::start(|_| {
        Some(answer(
            "201 Created",
            "Content-Type: application/json\r\nX-App: demo\r\n",
            r#"{"ok":true}"#,
        ))
    })
    .await;
    let server = proxy_server("proxy-basic", vec![route("/api", &upstream)]).await;

    let response = fetch(&server, &request("/api/users?id=5", "")).await;
    assert_eq!(response.status, 201);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("x-app"), Some("demo"));
    assert_eq!(response.text(), r#"{"ok":true}"#);

    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].starts_with("GET /users?id=5 HTTP/1.1\r\n"),
        "{}",
        seen[0]
    );
}

#[tokio::test]
async fn the_prefix_can_be_kept_or_reduced_to_the_root() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let mut kept = route("/keep", &upstream);
    kept.strip_prefix = false;
    let server = proxy_server("proxy-prefix", vec![route("/api", &upstream), kept]).await;

    fetch(&server, &request("/api", "")).await;
    fetch(&server, &request("/api/", "")).await;
    fetch(&server, &request("/keep/users", "")).await;

    let seen = upstream.requests();
    assert!(seen[0].starts_with("GET / HTTP/1.1\r\n"), "{}", seen[0]);
    assert!(seen[1].starts_with("GET / HTTP/1.1\r\n"), "{}", seen[1]);
    assert!(
        seen[2].starts_with("GET /keep/users HTTP/1.1\r\n"),
        "{}",
        seen[2]
    );
}

#[tokio::test]
async fn prefixes_only_match_whole_path_segments() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-segments", vec![route("/api", &upstream)]).await;

    for target in ["/apix", "/api-v2/x", "/ap"] {
        let response = fetch(&server, &request(target, "")).await;
        assert_eq!(response.status, 404, "{target}");
    }
    assert_eq!(upstream.request_count(), 0);
}

#[tokio::test]
async fn the_longest_matching_prefix_wins() {
    let general = FakeUpstream::start(|_| Some(answer("200 OK", "", "general"))).await;
    let specific = FakeUpstream::start(|_| Some(answer("200 OK", "", "specific"))).await;
    let server = proxy_server(
        "proxy-longest",
        vec![route("/api", &general), route("/api/v2", &specific)],
    )
    .await;

    assert_eq!(
        fetch(&server, &request("/api/v2/users", "")).await.text(),
        "specific"
    );
    assert_eq!(
        fetch(&server, &request("/api/v1/users", "")).await.text(),
        "general"
    );
    assert_eq!(
        fetch(&server, &request("/api/v2x", "")).await.text(),
        "general"
    );
}

#[tokio::test]
async fn a_root_route_forwards_everything_including_built_in_pages() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "from upstream"))).await;
    let server = proxy_server("proxy-root", vec![route("/", &upstream)]).await;

    for target in ["/anything", "/health", "/index.html"] {
        assert_eq!(
            fetch(&server, &request(target, "")).await.text(),
            "from upstream",
            "{target}"
        );
    }
    let seen = upstream.requests();
    assert!(seen[0].starts_with("GET /anything HTTP/1.1"));
    assert!(seen[1].starts_with("GET /health HTTP/1.1"));
}

#[tokio::test]
async fn files_and_built_in_pages_still_work_beside_a_proxy_route() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "from upstream"))).await;
    let server = proxy_server("proxy-beside", vec![route("/api", &upstream)]).await;

    assert_eq!(fetch(&server, &request("/health", "")).await.status, 200);
    assert_eq!(
        fetch(&server, &request("/style.css", "")).await.text(),
        "body {}"
    );
    assert_eq!(upstream.request_count(), 0);
}

// ---------- bodies and methods ----------

#[tokio::test]
async fn request_bodies_are_forwarded() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-post", vec![route("/api", &upstream)]).await;

    let raw = "POST /api/items HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello=world";
    assert_eq!(fetch(&server, raw).await.status, 200);

    let seen = &upstream.requests()[0];
    assert!(seen.starts_with("POST /items HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("\r\nContent-Length: 11\r\n"));
    assert!(seen.contains("\r\nContent-Type: text/plain\r\n"));
    assert!(seen.ends_with("\r\n\r\nhello=world"));
}

#[tokio::test]
async fn chunked_request_bodies_are_decoded_before_forwarding() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-chunked-in", vec![route("/api", &upstream)]).await;

    let raw = "POST /api/items HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    assert_eq!(fetch(&server, raw).await.status, 200);

    let seen = &upstream.requests()[0];
    assert!(seen.contains("\r\nContent-Length: 11\r\n"), "{seen}");
    assert!(!seen.to_lowercase().contains("transfer-encoding"));
    assert!(seen.ends_with("\r\n\r\nhello world"));
}

#[tokio::test]
async fn head_requests_get_headers_but_no_body() {
    let upstream =
        FakeUpstream::start(|_| Some(answer("200 OK", "X-App: demo\r\n", "hello"))).await;
    let server = proxy_server("proxy-head", vec![route("/api", &upstream)]).await;

    let raw = "HEAD /api/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, raw.as_bytes()).await;
    let response = parse_responses(&data).into_iter().next().unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-length"), Some("5"));
    assert_eq!(response.header("x-app"), Some("demo"));
    assert!(
        data.ends_with(b"\r\n\r\n"),
        "no body may follow a HEAD response"
    );
    // The upstream was asked with GET, so the length is the real one.
    assert!(upstream.requests()[0].starts_with("GET /x HTTP/1.1"));
}

#[tokio::test]
async fn pipelined_proxied_requests_are_both_answered() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-pipelined", vec![route("/api", &upstream)]).await;

    let raw = "GET /api/one HTTP/1.1\r\nHost: x\r\n\r\nGET /api/two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, raw.as_bytes()).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].header("connection"), Some("keep-alive"));
    assert_eq!(responses[1].header("connection"), Some("close"));
    let seen = upstream.requests();
    assert!(seen[0].starts_with("GET /one "));
    assert!(seen[1].starts_with("GET /two "));
}

// ---------- headers ----------

#[tokio::test]
async fn forwarding_headers_are_ours_and_spoofed_ones_are_discarded() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-headers", vec![route("/api", &upstream)]).await;

    let headers = "X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\nX-Forwarded-Host: evil.example\r\nX-Custom: kept\r\n";
    fetch(&server, &request("/api/x", headers)).await;

    let seen = upstream.requests()[0].to_lowercase();
    assert!(
        seen.contains("\r\nx-forwarded-for: 127.0.0.1\r\n"),
        "{seen}"
    );
    assert!(seen.contains("\r\nx-forwarded-proto: http\r\n"));
    assert!(seen.contains("\r\nx-forwarded-host: public.example\r\n"));
    assert!(seen.contains("\r\nx-custom: kept\r\n"));
    assert!(seen.contains(&format!("\r\nhost: {}\r\n", upstream.addr)));
    assert!(!seen.contains("6.6.6.6"));
    assert!(!seen.contains("evil.example"));
    assert!(!seen.contains("\r\nhost: public.example"));
}

#[tokio::test]
async fn hop_by_hop_request_headers_are_not_forwarded() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-hop-in", vec![route("/api", &upstream)]).await;

    let raw = "GET /api/x HTTP/1.1\r\nHost: x\r\nConnection: close, X-Secret\r\nX-Secret: s3cret\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\nUpgrade: websocket\r\nProxy-Authorization: Basic abc\r\nX-Normal: yes\r\n\r\n";
    assert_eq!(fetch(&server, raw).await.status, 200);

    let seen = upstream.requests()[0].to_lowercase();
    for forbidden in [
        "s3cret",
        "x-secret",
        "keep-alive",
        "\r\nte:",
        "upgrade",
        "proxy-authorization",
        "basic abc",
    ] {
        assert!(!seen.contains(forbidden), "{forbidden} leaked: {seen}");
    }
    assert!(seen.contains("\r\nx-normal: yes\r\n"));
    assert!(seen.contains("\r\nconnection: close\r\n"));
}

#[tokio::test]
async fn hop_by_hop_response_headers_are_not_passed_on() {
    let upstream = FakeUpstream::start(|_| {
        Some(
            b"HTTP/1.1 200 OK\r\nConnection: close, X-Internal\r\nX-Internal: secret\r\nKeep-Alive: timeout=1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nServer: nginx\r\nDate: Sat, 01 Jan 2000 00:00:00 GMT\r\nContent-Length: 2\r\n\r\nhi"
                .to_vec(),
        )
    })
    .await;
    let server = proxy_server("proxy-hop-out", vec![route("/api", &upstream)]).await;

    let response = fetch(&server, &request("/api/x", "")).await;
    assert_eq!(response.text(), "hi");
    assert!(response.header("x-internal").is_none());
    assert!(response.header("keep-alive").is_none());
    let cookies = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .count();
    assert_eq!(cookies, 2, "both cookies must survive");
    // Our own Server and Date, not the upstream's.
    assert_eq!(response.header("server"), Some("webserver/0.1"));
    assert!(!response.header("date").unwrap().contains("2000"));
}

// ---------- the upstream's framing ----------

#[tokio::test]
async fn chunked_answers_are_decoded() {
    let upstream = FakeUpstream::start(|_| {
        Some(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec())
    })
    .await;
    let server = proxy_server("proxy-chunked-out", vec![route("/api", &upstream)]).await;

    let response = fetch(&server, &request("/api/x", "")).await;
    assert_eq!(response.text(), "hello world");
    assert_eq!(response.header("content-length"), Some("11"));
    assert!(response.header("transfer-encoding").is_none());
}

#[tokio::test]
async fn answers_that_end_when_the_connection_closes_are_read() {
    let upstream = FakeUpstream::start(|_| {
        Some(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the end".to_vec())
    })
    .await;
    let server = proxy_server("proxy-close-delimited", vec![route("/api", &upstream)]).await;

    let response = fetch(&server, &request("/api/x", "")).await;
    assert_eq!(response.text(), "until the end");
    assert_eq!(response.header("content-length"), Some("13"));
}

#[tokio::test]
async fn bodyless_statuses_stay_bodyless() {
    let no_content =
        FakeUpstream::start(|_| Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())).await;
    let not_modified = FakeUpstream::start(|_| {
        Some(b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\n\r\n".to_vec())
    })
    .await;
    let server = proxy_server(
        "proxy-bodyless",
        vec![route("/a", &no_content), route("/b", &not_modified)],
    )
    .await;

    let first = fetch(&server, &request("/a/x", "")).await;
    assert_eq!(first.status, 204);
    assert!(first.body.is_empty());
    assert!(first.header("content-length").is_none());

    let second = fetch(&server, &request("/b/x", "")).await;
    assert_eq!(second.status, 304);
    assert_eq!(second.header("etag"), Some("\"abc\""));
}

#[tokio::test]
async fn interim_answers_are_skipped() {
    let upstream = FakeUpstream::start(|_| {
        Some(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        )
    })
    .await;
    let server = proxy_server("proxy-interim", vec![route("/api", &upstream)]).await;

    let response = fetch(&server, &request("/api/x", "")).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "ok");
}

#[tokio::test]
async fn error_answers_from_the_upstream_pass_through() {
    let upstream = FakeUpstream::start(|_| {
        Some(answer(
            "401 Unauthorized",
            "WWW-Authenticate: Basic\r\n",
            "log in please",
        ))
    })
    .await;
    let server = proxy_server("proxy-401", vec![route("/api", &upstream)]).await;

    let data = raw_exchange(server.addr, request("/api/x", "").as_bytes()).await;
    assert!(String::from_utf8_lossy(&data).starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    let response = parse_responses(&data).into_iter().next().unwrap();
    assert_eq!(response.header("www-authenticate"), Some("Basic"));
    assert_eq!(response.text(), "log in please");
}

// ---------- when the upstream misbehaves ----------

#[tokio::test]
async fn a_dead_upstream_gets_502_without_leaking_details() {
    let dead = free_address();
    let routes = vec![ProxyRoute {
        prefix: "/api".to_string(),
        upstream: dead.to_string(),
        ..ProxyRoute::default()
    }];
    let server = proxy_server("proxy-dead", routes).await;

    let started = Instant::now();
    let response = fetch(&server, &request("/api/x", "")).await;

    assert_eq!(response.status, 502);
    assert_eq!(response.text(), "502 Bad Gateway\n");
    assert!(!response.text().contains("127.0.0.1"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn an_upstream_that_never_answers_gets_504() {
    let upstream = FakeUpstream::start(|_| None).await;
    let mut hanging = route("/api", &upstream);
    hanging.timeout_secs = 1;
    let server = proxy_server("proxy-timeout", vec![hanging]).await;

    let started = Instant::now();
    let response = fetch(&server, &request("/api/x", "")).await;
    let waited = started.elapsed();

    assert_eq!(response.status, 504);
    assert!(
        waited >= Duration::from_millis(800),
        "too early: {waited:?}"
    );
    assert!(waited < Duration::from_secs(5), "too late: {waited:?}");
}

#[tokio::test]
async fn misbehaving_upstreams_get_502() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", b"this is not http at all\r\n\r\n".to_vec()),
        ("nothing at all", Vec::new()),
        ("cut off in the headers", b"HTTP/1.1 200 OK\r\nContent-Le".to_vec()),
        ("cut off in the body", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()),
        ("bad chunk", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec()),
        ("conflicting lengths", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!".to_vec()),
        ("length and chunked", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()),
        ("upgrade", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec()),
        ("invalid status", b"HTTP/1.1 700 Nope\r\nContent-Length: 0\r\n\r\n".to_vec()),
    ];

    for (name, bytes) in cases {
        let upstream = FakeUpstream::start(move |_| Some(bytes.clone())).await;
        let server = proxy_server("proxy-misbehaving", vec![route("/api", &upstream)]).await;

        let response = fetch(&server, &request("/api/x", "")).await;
        assert_eq!(response.status, 502, "{name}");
        assert_eq!(response.text(), "502 Bad Gateway\n", "{name}");
    }
}

#[tokio::test]
async fn oversized_upstream_answers_get_502() {
    let big = "x".repeat(5000);
    let cases = [
        ("length", answer("200 OK", "", &big)),
        (
            "chunked",
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{big}\r\n0\r\n\r\n",
                big.len()
            )
            .into_bytes(),
        ),
        (
            "until close",
            format!("HTTP/1.0 200 OK\r\n\r\n{big}").into_bytes(),
        ),
    ];

    for (name, bytes) in cases {
        let upstream = FakeUpstream::start(move |_| Some(bytes.clone())).await;
        let routes = vec![route("/api", &upstream)];
        let server = TestServer::start_with("proxy-oversized", move |config| {
            config.proxy = routes;
            config.proxy_max_response_bytes = 1000;
        })
        .await;

        let response = fetch(&server, &request("/api/x", "")).await;
        assert_eq!(response.status, 502, "{name}");
    }
}

// ---------- security ----------

#[tokio::test]
async fn paths_cannot_climb_out_of_the_route() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-traversal", vec![route("/api", &upstream)]).await;

    for target in [
        "/api/../admin",
        "/api/./x",
        "/api/%2e%2e/admin",
        "/api/%2E%2E/admin",
        "/api/..%2fadmin",
        "/api/a/..%2f..%2fb",
        "/api/a%5cb",
        "/api/%00",
    ] {
        let response = fetch(&server, &request(target, "")).await;
        assert_eq!(response.status, 400, "{target}");
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "nothing may reach the upstream"
    );
}

#[tokio::test]
async fn the_proxy_cannot_be_used_as_an_open_relay() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let server = proxy_server("proxy-relay", vec![route("/api", &upstream)]).await;
    let target = upstream.addr;

    for raw in [
        // A full URL instead of a path.
        format!(
            "GET http://{target}/api/x HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        ),
        "GET http://other.example/ HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n"
            .to_string(),
        // A tunnel request.
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
        // Headers that try to choose the destination.
        format!(
            "GET /nothing HTTP/1.1\r\nHost: {target}\r\nX-Forwarded-Host: {target}\r\nConnection: close\r\n\r\n"
        ),
    ] {
        let response = fetch(&server, &raw).await;
        assert!(
            [400, 404, 405].contains(&response.status),
            "unexpected {} for {raw:?}",
            response.status
        );
    }
    assert_eq!(upstream.request_count(), 0, "no request may be forwarded");
}

#[tokio::test]
async fn forwarded_requests_say_https_when_the_client_used_it() {
    let upstream = FakeUpstream::start(|_| Some(answer("200 OK", "", "ok"))).await;
    let routes = vec![route("/api", &upstream)];
    let server = TestServer::start_tls("proxy-tls", move |config| config.proxy = routes).await;
    let connector = tls_connector(server.cert_path.as_ref().unwrap());

    let raw = "GET /api/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let data = tls_exchange(server.https_addr.unwrap(), &connector, raw.as_bytes()).await;
    let response = parse_responses(&data).into_iter().next().unwrap();
    assert_eq!(response.text(), "ok");

    let seen = upstream.requests()[0].to_lowercase();
    assert!(seen.contains("\r\nx-forwarded-proto: https\r\n"), "{seen}");
    assert!(seen.contains("\r\nx-forwarded-host: localhost\r\n"));
}
