//! Compression and caching, with a real server and raw requests.

mod common;

use common::{RawResponse, TestServer, parse_responses, raw_exchange, tls_connector, tls_exchange};
use std::io::{Cursor, Read};
use webserver::config::CacheRule;

fn script() -> String {
    "console.log('hello from the web server');\n".repeat(100)
}

fn write_script(server: &TestServer) {
    std::fs::write(server.site.root.join("app.js"), script()).unwrap();
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn unbrotli(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut Cursor::new(bytes), &mut out).unwrap();
    out
}

/// A request that asks the server to close afterwards.
fn request(method: &str, target: &str, extra_headers: &str) -> String {
    format!("{method} {target} HTTP/1.1\r\nHost: x\r\n{extra_headers}Connection: close\r\n\r\n")
}

async fn fetch(server: &TestServer, request: &str) -> RawResponse {
    let data = raw_exchange(server.addr, request.as_bytes()).await;
    parse_responses(&data)
        .into_iter()
        .next()
        .expect("the server sent no response")
}

#[tokio::test]
async fn gzip_works_over_the_wire() {
    let server = TestServer::start("wire-gzip").await;
    write_script(&server);

    let response = fetch(
        &server,
        &request("GET", "/app.js", "Accept-Encoding: gzip\r\n"),
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), Some("gzip"));
    assert_eq!(response.header("vary"), Some("Accept-Encoding"));
    assert!(response.header("etag").unwrap().starts_with("W/\""));
    assert_eq!(
        response.header("content-length"),
        Some(response.body.len().to_string().as_str())
    );
    assert_eq!(gunzip(&response.body), script().as_bytes());
}

#[tokio::test]
async fn brotli_works_over_the_wire() {
    let server = TestServer::start("wire-brotli").await;
    write_script(&server);

    let response = fetch(
        &server,
        &request("GET", "/app.js", "Accept-Encoding: gzip, br\r\n"),
    )
    .await;

    assert_eq!(response.header("content-encoding"), Some("br"));
    assert_eq!(unbrotli(&response.body), script().as_bytes());
}

#[tokio::test]
async fn plain_clients_get_the_plain_file() {
    let server = TestServer::start("wire-plain").await;
    write_script(&server);

    let response = fetch(&server, &request("GET", "/app.js", "")).await;
    assert_eq!(response.status, 200);
    assert!(response.header("content-encoding").is_none());
    assert_eq!(response.header("vary"), Some("Accept-Encoding"));
    assert_eq!(response.body, script().as_bytes());
}

#[tokio::test]
async fn head_reports_the_compressed_length_without_a_body() {
    let server = TestServer::start("wire-head").await;
    write_script(&server);

    let get = fetch(
        &server,
        &request("GET", "/app.js", "Accept-Encoding: gzip\r\n"),
    )
    .await;

    let data = raw_exchange(
        server.addr,
        request("HEAD", "/app.js", "Accept-Encoding: gzip\r\n").as_bytes(),
    )
    .await;
    let head = parse_responses(&data).into_iter().next().unwrap();

    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-encoding"), Some("gzip"));
    assert_eq!(head.header("content-length"), get.header("content-length"));
    // Nothing follows the headers.
    assert!(data.ends_with(b"\r\n\r\n"));
}

#[tokio::test]
async fn compressed_responses_revalidate_with_304() {
    let server = TestServer::start("wire-304").await;
    write_script(&server);

    let first = fetch(
        &server,
        &request("GET", "/app.js", "Accept-Encoding: gzip\r\n"),
    )
    .await;
    let etag = first.header("etag").unwrap().to_string();

    let headers = format!("Accept-Encoding: gzip\r\nIf-None-Match: {etag}\r\n");
    let second = fetch(&server, &request("GET", "/app.js", &headers)).await;

    assert_eq!(second.status, 304);
    assert!(second.body.is_empty());
    assert_eq!(second.header("etag"), Some(etag.as_str()));
    assert_eq!(second.header("vary"), Some("Accept-Encoding"));
}

#[tokio::test]
async fn range_requests_skip_compression_over_the_wire() {
    let server = TestServer::start("wire-range").await;
    write_script(&server);

    let response = fetch(
        &server,
        &request(
            "GET",
            "/app.js",
            "Accept-Encoding: gzip\r\nRange: bytes=0-9\r\n",
        ),
    )
    .await;

    assert_eq!(response.status, 206);
    assert!(response.header("content-encoding").is_none());
    assert_eq!(response.body, &script().as_bytes()[..10]);
}

#[tokio::test]
async fn compressed_bodies_are_framed_correctly_with_keep_alive() {
    let server = TestServer::start("wire-keep-alive").await;
    write_script(&server);

    // Two pipelined requests: if a compressed Content-Length were wrong,
    // the second response would be garbled.
    let raw = "GET /app.js HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n\
               GET /app.js HTTP/1.1\r\nHost: x\r\nAccept-Encoding: br\r\nConnection: close\r\n\r\n";
    let data = raw_exchange(server.addr, raw.as_bytes()).await;
    let responses = parse_responses(&data);

    assert_eq!(responses.len(), 2);
    assert_eq!(gunzip(&responses[0].body), script().as_bytes());
    assert_eq!(unbrotli(&responses[1].body), script().as_bytes());
}

#[tokio::test]
async fn cache_control_rules_apply_over_the_wire() {
    let server = TestServer::start_with("wire-cache", |config| {
        config.cache_rules = vec![CacheRule {
            extensions: vec!["css".to_string()],
            cache_control: "public, max-age=3600".to_string(),
        }];
    })
    .await;

    let css = fetch(&server, &request("GET", "/style.css", "")).await;
    assert_eq!(css.header("cache-control"), Some("public, max-age=3600"));

    let html = fetch(&server, &request("GET", "/index.html", "")).await;
    assert_eq!(html.header("cache-control"), Some("no-cache"));
}

#[tokio::test]
async fn compression_works_over_https() {
    let server = TestServer::start_tls("wire-https-gzip", |_| {}).await;
    write_script(&server);
    let connector = tls_connector(server.cert_path.as_ref().unwrap());

    let raw = "GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
    let data = tls_exchange(server.https_addr.unwrap(), &connector, raw.as_bytes()).await;
    let response = parse_responses(&data).into_iter().next().unwrap();

    assert_eq!(response.header("content-encoding"), Some("gzip"));
    assert_eq!(gunzip(&response.body), script().as_bytes());
}
