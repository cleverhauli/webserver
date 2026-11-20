//! A reverse proxy: some requests are answered by another program.
//!
//! The client talks to us, and we talk to the "upstream" program on its
//! behalf. The rules that keep this safe:
//!
//! - Upstream addresses come ONLY from the config file, never from the request.
//! - Headers that belong to one connection are never passed on.
//! - We write the X-Forwarded-* headers ourselves and discard the client's.
//! - Paths containing ".." (in any disguise) are refused, so a request
//!   cannot climb out of the part of the upstream it is meant to reach.
//! - Every step has a time limit, and responses have a size limit.

use crate::config::{Config, ProxyRoute};
use crate::http::chunked::decode_chunked;
use crate::http::parser::ParseError;
use crate::http::request::{Method, Request};
use crate::http::response::Response;
use crate::net_util::{ReadOutcome, read_with_deadline};
use crate::static_files::percent_decode;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::warn;

/// The most bytes of response headers we accept from an upstream.
const MAX_UPSTREAM_HEAD_BYTES: usize = 64 * 1024;
const MAX_UPSTREAM_HEADERS: usize = 100;

/// Facts about the client that the upstream is told.
pub struct ClientInfo {
    pub ip: IpAddr,
    /// Did the client use HTTPS to reach us?
    pub secure: bool,
}

/// Why a request could not be answered by the upstream.
#[derive(Debug, PartialEq)]
pub enum ProxyError {
    /// The request cannot be forwarded safely (400).
    BadRequest(&'static str),
    /// The upstream misbehaved or could not be reached (502).
    BadGateway(&'static str),
    /// The upstream took too long (504).
    TimedOut(&'static str),
}

impl ProxyError {
    /// A message for our own logs. Clients never see it.
    fn reason(&self) -> &'static str {
        match self {
            ProxyError::BadRequest(reason)
            | ProxyError::BadGateway(reason)
            | ProxyError::TimedOut(reason) => reason,
        }
    }
}

/// What the client is told: deliberately vague, so internal details never leak.
fn error_response(error: &ProxyError) -> Response {
    let (status, message) = match error {
        ProxyError::BadRequest(_) => (400, "400 Bad Request\n"),
        ProxyError::BadGateway(_) => (502, "502 Bad Gateway\n"),
        ProxyError::TimedOut(_) => (504, "504 Gateway Timeout\n"),
    };
    Response::text(status, message).header("Cache-Control", "no-store")
}

// ---------- choosing a route ----------

fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    // Whole segments only: "/api" matches "/api" and "/api/x", never "/apix".
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The route that handles this request target, if any. When several match,
/// the longest prefix wins.
pub fn find_route<'a>(routes: &'a [ProxyRoute], target: &str) -> Option<&'a ProxyRoute> {
    let path = target.split('?').next().unwrap_or("");
    routes
        .iter()
        .filter(|route| prefix_matches(&route.prefix, path))
        .max_by_key(|route| route.prefix.len())
}

// ---------- header rules ----------

/// Headers that belong to ONE connection and must never be passed on.
fn is_hop_by_hop(lowercase_name: &str) -> bool {
    matches!(
        lowercase_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Request headers we write ourselves, so the client's version is discarded.
fn is_set_by_proxy(lowercase_name: &str) -> bool {
    matches!(
        lowercase_name,
        "host"
            | "content-length"
            | "expect"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-real-ip"
    )
}

/// Extra header names that "Connection: a, b" marks as hop-by-hop.
fn connection_tokens(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

// ---------- building the request for the upstream ----------

/// Is this path safe to forward? Dot segments are refused even when
/// disguised ("%2e%2e", "..%2f"), because the upstream might tidy them up
/// and land somewhere we never meant to expose.
fn path_is_safe(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let Some(decoded) = percent_decode(path) else {
        return false;
    };
    if decoded.chars().any(|c| c.is_control() || c == '\\') {
        return false;
    }
    decoded
        .split('/')
        .all(|segment| segment != ".." && segment != ".")
}

/// A Host header worth repeating to the upstream as X-Forwarded-Host.
fn is_plain_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// The exact bytes to send to the upstream. We write the request again from
/// scratch, with our own framing, rather than copying the client's.
pub fn build_upstream_request(
    request: &Request,
    route: &ProxyRoute,
    client: &ClientInfo,
) -> Result<Vec<u8>, ProxyError> {
    let (path, query) = match request.target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (request.target.as_str(), None),
    };
    if !path_is_safe(path) {
        return Err(ProxyError::BadRequest("unsafe path"));
    }
    if query.is_some_and(|q| q.chars().any(|c| c.is_control() || c == ' ')) {
        return Err(ProxyError::BadRequest("unsafe query string"));
    }

    // "/api/users" becomes "/users"; "/api" becomes "/".
    let forwarded_path = if route.strip_prefix && route.prefix != "/" {
        match path.strip_prefix(route.prefix.as_str()) {
            Some("") => "/",
            Some(rest) => rest,
            None => path,
        }
    } else {
        path
    };
    if !forwarded_path.starts_with('/') {
        return Err(ProxyError::BadRequest(
            "the path does not belong to this route",
        ));
    }

    // A HEAD request is sent as GET. We drop the body ourselves, which keeps
    // the Content-Length we report correct.
    let method = match &request.method {
        Method::Head => "GET",
        other => other.as_str(),
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ProxyError::BadRequest("unsupported method"));
    }

    let mut head = format!("{method} {forwarded_path}");
    if let Some(query) = query {
        head.push('?');
        head.push_str(query);
    }
    head.push_str(" HTTP/1.1\r\n");
    head.push_str(&format!("Host: {}\r\n", route.upstream));

    let listed = connection_tokens(&request.headers);
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower) || is_set_by_proxy(&lower) || listed.contains(&lower) {
            continue;
        }
        if value.contains(['\r', '\n', '\0']) {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }

    // Our own facts. These are the only X-Forwarded-* headers the upstream sees.
    head.push_str(&format!("X-Forwarded-For: {}\r\n", client.ip));
    head.push_str(&format!(
        "X-Forwarded-Proto: {}\r\n",
        if client.secure { "https" } else { "http" }
    ));
    if let Some(host) = request.header("host")
        && is_plain_host(host)
    {
        head.push_str(&format!("X-Forwarded-Host: {host}\r\n"));
    }

    // The body was already read completely (and de-chunked) by our own
    // parser, so we simply announce its true length.
    let needs_length = !request.body.is_empty()
        || matches!(request.method, Method::Post | Method::Put | Method::Patch);
    if needs_length {
        head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&request.body);
    Ok(bytes)
}

// ---------- reading the upstream's answer ----------

/// What the upstream answered, before we adapt it for the client.
#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
    consumed: usize,
}

enum HeadParse {
    Complete(Head),
    Partial,
}

fn parse_head(buf: &[u8]) -> Result<HeadParse, ProxyError> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
    let mut parsed = httparse::Response::new(&mut slots);

    let consumed = match parsed.parse(buf) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) => return Ok(HeadParse::Partial),
        Err(_) => {
            return Err(ProxyError::BadGateway(
                "the upstream sent malformed response headers",
            ));
        }
    };
    let status = parsed
        .code
        .ok_or(ProxyError::BadGateway("the upstream sent no status code"))?;

    let mut headers = Vec::with_capacity(parsed.headers.len());
    for header in parsed.headers.iter() {
        match std::str::from_utf8(header.value) {
            Ok(value) => headers.push((header.name.to_string(), value.trim().to_string())),
            Err(_) => {
                // Framing headers must be readable. Anything else is just dropped.
                if header.name.eq_ignore_ascii_case("content-length")
                    || header.name.eq_ignore_ascii_case("transfer-encoding")
                {
                    return Err(ProxyError::BadGateway(
                        "the upstream sent an unreadable length header",
                    ));
                }
            }
        }
    }

    Ok(HeadParse::Complete(Head {
        status,
        headers,
        consumed,
    }))
}

/// How the upstream's response body is delimited.
#[derive(Debug, PartialEq)]
enum BodyKind {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

/// Work out where the body ends. Strict on purpose: unclear framing means
/// "502", never a guess.
fn response_framing(
    status: u16,
    headers: &[(String, String)],
    max_bytes: usize,
) -> Result<BodyKind, ProxyError> {
    if status == 204 || status == 304 {
        return Ok(BodyKind::None);
    }

    let named = |wanted: &'static str| {
        headers
            .iter()
            .filter(move |(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
    };
    let transfer = named("transfer-encoding");
    let lengths = named("content-length");

    if !transfer.is_empty() {
        // Both together is the classic smuggling trick.
        if !lengths.is_empty() {
            return Err(ProxyError::BadGateway(
                "the upstream sent both Content-Length and Transfer-Encoding",
            ));
        }
        if transfer.len() == 1 && transfer[0].trim().eq_ignore_ascii_case("chunked") {
            return Ok(BodyKind::Chunked);
        }
        return Err(ProxyError::BadGateway(
            "the upstream used an unsupported Transfer-Encoding",
        ));
    }

    let mut length: Option<usize> = None;
    for value in lengths {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ProxyError::BadGateway(
                "the upstream sent an invalid Content-Length",
            ));
        }
        let parsed: usize = value
            .parse()
            .map_err(|_| ProxyError::BadGateway("the upstream's response is too large"))?;
        match length {
            Some(existing) if existing != parsed => {
                return Err(ProxyError::BadGateway(
                    "the upstream sent conflicting Content-Length headers",
                ));
            }
            _ => length = Some(parsed),
        }
    }

    match length {
        Some(n) if n > max_bytes => Err(ProxyError::BadGateway(
            "the upstream's response is too large",
        )),
        Some(n) => Ok(BodyKind::Length(n)),
        // No length at all: the body runs until the upstream hangs up.
        None => Ok(BodyKind::UntilClose),
    }
}

/// Read some more bytes. `Ok(false)` means the upstream closed the connection.
async fn read_more<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<bool, ProxyError> {
    let mut chunk = [0u8; 8192];
    match read_with_deadline(reader, &mut chunk, deadline).await {
        Ok(ReadOutcome::Data(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(ReadOutcome::Closed) => Ok(false),
        Ok(ReadOutcome::TimedOut) => Err(ProxyError::TimedOut("the upstream took too long")),
        Err(_) => Err(ProxyError::BadGateway("could not read from the upstream")),
    }
}

/// Read one complete response from the upstream, never waiting past
/// `deadline` and never holding more than `max_bytes` of body.
pub async fn read_upstream_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    deadline: Instant,
) -> Result<UpstreamResponse, ProxyError> {
    let mut buf: Vec<u8> = Vec::new();

    // 1. The status line and headers. Interim "1xx" answers are skipped.
    let (status, headers) = loop {
        match parse_head(&buf)? {
            HeadParse::Complete(head) => {
                buf.drain(..head.consumed);
                if head.status == 101 {
                    return Err(ProxyError::BadGateway(
                        "the upstream tried to switch protocols",
                    ));
                }
                if (100..200).contains(&head.status) {
                    continue;
                }
                if !(200..=599).contains(&head.status) {
                    return Err(ProxyError::BadGateway(
                        "the upstream sent an invalid status code",
                    ));
                }
                break (head.status, head.headers);
            }
            HeadParse::Partial => {
                if buf.len() > MAX_UPSTREAM_HEAD_BYTES {
                    return Err(ProxyError::BadGateway(
                        "the upstream's response headers are too large",
                    ));
                }
            }
        }
        if !read_more(reader, &mut buf, deadline).await? {
            return Err(ProxyError::BadGateway(
                "the upstream closed the connection before answering",
            ));
        }
    };

    // 2. The body.
    let body = match response_framing(status, &headers, max_bytes)? {
        BodyKind::None => Vec::new(),

        BodyKind::Length(length) => {
            while buf.len() < length {
                if !read_more(reader, &mut buf, deadline).await? {
                    return Err(ProxyError::BadGateway(
                        "the upstream closed the connection before sending the whole body",
                    ));
                }
            }
            buf.truncate(length);
            buf
        }

        BodyKind::Chunked => {
            let mut body = Vec::new();
            let mut pos = 0;
            loop {
                match decode_chunked(&buf, &mut pos, &mut body, max_bytes) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(ParseError::PayloadTooLarge) => {
                        return Err(ProxyError::BadGateway(
                            "the upstream's response is too large",
                        ));
                    }
                    Err(_) => {
                        return Err(ProxyError::BadGateway(
                            "the upstream sent a malformed chunked body",
                        ));
                    }
                }
                buf.drain(..pos);
                pos = 0;
                if !read_more(reader, &mut buf, deadline).await? {
                    return Err(ProxyError::BadGateway(
                        "the upstream closed the connection in the middle of a chunked body",
                    ));
                }
            }
            body
        }

        BodyKind::UntilClose => {
            loop {
                if buf.len() > max_bytes {
                    return Err(ProxyError::BadGateway(
                        "the upstream's response is too large",
                    ));
                }
                if !read_more(reader, &mut buf, deadline).await? {
                    break;
                }
            }
            buf
        }
    };

    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

// ---------- the answer for the client ----------

/// Turn the upstream's answer into ours: connection-level headers are
/// dropped, and the framing headers are rebuilt from the real body.
fn into_client_response(upstream: UpstreamResponse) -> Response {
    let listed = connection_tokens(&upstream.headers);
    let mut response = Response::new(upstream.status);

    for (name, value) in &upstream.headers {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower)
            || matches!(lower.as_str(), "content-length" | "date" | "server")
            || listed.contains(&lower)
        {
            continue;
        }
        // Names or values that could break the response are dropped here.
        response = response.header(name, value);
    }
    response.body(upstream.body)
}

// ---------- the whole trip ----------

/// Forward a request to the route's upstream and return its answer, or
/// an error response when anything goes wrong.
pub async fn forward(
    request: &Request,
    route: &ProxyRoute,
    client: &ClientInfo,
    config: &Config,
) -> Response {
    match try_forward(request, route, client, config).await {
        Ok(response) => response,
        Err(error) => {
            warn!(
                "proxy {} {} to {} failed: {}",
                request.method.as_str(),
                request.target,
                route.upstream,
                error.reason()
            );
            error_response(&error)
        }
    }
}

async fn try_forward(
    request: &Request,
    route: &ProxyRoute,
    client: &ClientInfo,
    config: &Config,
) -> Result<Response, ProxyError> {
    let bytes = build_upstream_request(request, route, client)?;

    let connect_limit = Duration::from_secs(config.proxy_connect_timeout_secs);
    let mut stream = match timeout(connect_limit, TcpStream::connect(route.upstream.as_str())).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            return Err(ProxyError::BadGateway("could not connect to the upstream"));
        }
        Err(_) => {
            return Err(ProxyError::TimedOut(
                "connecting to the upstream took too long",
            ));
        }
    };

    // One deadline for the whole exchange: sending, waiting and reading.
    let deadline = Instant::now() + Duration::from_secs(route.timeout_secs);

    let sent = timeout_at(deadline, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await;
    match sent {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            return Err(ProxyError::BadGateway(
                "could not send the request to the upstream",
            ));
        }
        Err(_) => {
            return Err(ProxyError::TimedOut(
                "sending the request to the upstream took too long",
            ));
        }
    }

    let upstream =
        read_upstream_response(&mut stream, config.proxy_max_response_bytes, deadline).await?;
    Ok(into_client_response(upstream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Version;
    use tokio::io::AsyncWriteExt;

    fn route(prefix: &str) -> ProxyRoute {
        ProxyRoute {
            prefix: prefix.to_string(),
            upstream: "127.0.0.1:3000".to_string(),
            ..ProxyRoute::default()
        }
    }

    fn client() -> ClientInfo {
        ClientInfo {
            ip: "203.0.113.9".parse().unwrap(),
            secure: false,
        }
    }

    fn request(method: Method, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
        Request {
            method,
            target: target.to_string(),
            version: Version::Http11,
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    fn built(request: &Request, route: &ProxyRoute) -> String {
        String::from_utf8(build_upstream_request(request, route, &client()).unwrap()).unwrap()
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    // ---------- choosing a route ----------

    #[test]
    fn routes_match_whole_path_segments() {
        let routes = vec![route("/api")];
        for target in ["/api", "/api/", "/api/users", "/api?x=1", "/api/users?x=1"] {
            assert!(find_route(&routes, target).is_some(), "{target}");
        }
        for target in ["/apix", "/ap", "/", "/other/api", "/API", "api", ""] {
            assert!(find_route(&routes, target).is_none(), "{target}");
        }
    }

    #[test]
    fn the_longest_prefix_wins() {
        let routes = vec![route("/api"), route("/api/v2"), route("/")];
        assert_eq!(
            find_route(&routes, "/api/v2/users").unwrap().prefix,
            "/api/v2"
        );
        assert_eq!(find_route(&routes, "/api/v1/users").unwrap().prefix, "/api");
        assert_eq!(find_route(&routes, "/api/v2x").unwrap().prefix, "/api");
        assert_eq!(find_route(&routes, "/anything").unwrap().prefix, "/");
    }

    // ---------- path safety ----------

    #[test]
    fn ordinary_paths_are_safe() {
        for path in [
            "/",
            "/users",
            "/a/b/c.json",
            "/a%20b",
            "/a/.hidden",
            "/a/b/",
        ] {
            assert!(path_is_safe(path), "{path}");
        }
    }

    #[test]
    fn dot_segments_are_refused_in_every_disguise() {
        for path in [
            "/api/../admin",
            "/api/./x",
            "/..",
            "/%2e%2e/admin",
            "/%2E%2e/admin",
            "/api/..%2fadmin",
            "/api/%2e%2e%2fadmin",
            "/a%5cb",
            "/a\\b",
            "/%00",
            "/%0a",
            "/%zz",
            "relative",
        ] {
            assert!(!path_is_safe(path), "{path}");
        }
    }

    // ---------- building the upstream request ----------

    #[test]
    fn the_prefix_is_stripped() {
        let req = request(Method::Get, "/api/users?id=5", &[], b"");
        let text = built(&req, &route("/api"));
        assert!(text.starts_with("GET /users?id=5 HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nHost: 127.0.0.1:3000\r\n"));
    }

    #[test]
    fn the_bare_prefix_becomes_the_root() {
        for target in ["/api", "/api/", "/api?x=1"] {
            let req = request(Method::Get, target, &[], b"");
            let text = built(&req, &route("/api"));
            let expected = if target.contains('?') {
                "GET /?x=1 HTTP/1.1"
            } else {
                "GET / HTTP/1.1"
            };
            assert!(text.starts_with(expected), "{target}: {text}");
        }
    }

    #[test]
    fn the_prefix_can_be_kept() {
        let mut kept = route("/api");
        kept.strip_prefix = false;
        let req = request(Method::Get, "/api/users", &[], b"");
        assert!(built(&req, &kept).starts_with("GET /api/users HTTP/1.1\r\n"));
    }

    #[test]
    fn the_root_route_forwards_paths_unchanged() {
        let req = request(Method::Get, "/users", &[], b"");
        assert!(built(&req, &route("/")).starts_with("GET /users HTTP/1.1\r\n"));
    }

    #[test]
    fn head_is_sent_as_get() {
        let req = request(Method::Head, "/api/x", &[], b"");
        assert!(built(&req, &route("/api")).starts_with("GET /x HTTP/1.1\r\n"));
    }

    #[test]
    fn forwarding_headers_are_ours_alone() {
        let req = request(
            Method::Get,
            "/api/x",
            &[
                ("Host", "public.example"),
                ("X-Forwarded-For", "6.6.6.6"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.example"),
                ("X-Real-IP", "6.6.6.6"),
                ("Forwarded", "for=6.6.6.6"),
                ("X-Custom", "kept"),
            ],
            b"",
        );
        let text = built(&req, &route("/api"));
        assert!(text.contains("\r\nX-Forwarded-For: 203.0.113.9\r\n"));
        assert!(text.contains("\r\nX-Forwarded-Proto: http\r\n"));
        assert!(text.contains("\r\nX-Forwarded-Host: public.example\r\n"));
        assert!(text.contains("\r\nX-Custom: kept\r\n"));
        assert!(!text.contains("6.6.6.6"));
        assert!(!text.contains("evil.example"));
        assert!(!text.contains("Forwarded: for"));
        // The upstream is addressed by its own name, not the client's.
        assert!(!text.contains("\r\nHost: public.example"));
    }

    #[test]
    fn secure_clients_and_ipv6_are_described_correctly() {
        let secure = ClientInfo {
            ip: "::1".parse().unwrap(),
            secure: true,
        };
        let req = request(Method::Get, "/api/x", &[], b"");
        let bytes = build_upstream_request(&req, &route("/api"), &secure).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("X-Forwarded-For: ::1\r\n"));
        assert!(text.contains("X-Forwarded-Proto: https\r\n"));
    }

    #[test]
    fn strange_host_headers_are_not_repeated() {
        let req = request(Method::Get, "/api/x", &[("Host", "evil.com/<script>")], b"");
        let text = built(&req, &route("/api"));
        assert!(!text.contains("X-Forwarded-Host"));
        assert!(!text.contains("script"));
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        let req = request(
            Method::Get,
            "/api/x",
            &[
                ("Connection", "keep-alive, X-Secret"),
                ("X-Secret", "s3cret"),
                ("Keep-Alive", "timeout=5"),
                ("TE", "trailers"),
                ("Upgrade", "websocket"),
                ("Proxy-Authorization", "Basic abc"),
                ("Trailer", "X-Sum"),
                ("Expect", "100-continue"),
                ("X-Normal", "yes"),
            ],
            b"",
        );
        let text = built(&req, &route("/api")).to_lowercase();
        for forbidden in [
            "s3cret",
            "x-secret",
            "keep-alive",
            "\r\nte:",
            "upgrade",
            "proxy-authorization",
            "trailer",
            "expect",
            "100-continue",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} leaked: {text}");
        }
        assert!(text.contains("\r\nx-normal: yes\r\n"));
        // The only Connection header is our own.
        assert_eq!(text.matches("connection:").count(), 1);
        assert!(text.contains("connection: close\r\n\r\n"));
    }

    #[test]
    fn bodies_get_an_honest_content_length() {
        let req = request(
            Method::Post,
            "/api/x",
            &[("Content-Length", "999")],
            b"hello=world",
        );
        let text = built(&req, &route("/api"));
        assert!(text.contains("\r\nContent-Length: 11\r\n"));
        assert!(!text.contains("999"));
        assert!(text.ends_with("\r\n\r\nhello=world"));
    }

    #[test]
    fn the_transfer_encoding_of_a_chunked_request_is_replaced() {
        // Our parser already decoded the chunks, so only the plain body remains.
        let req = request(
            Method::Post,
            "/api/x",
            &[("Transfer-Encoding", "chunked")],
            b"decoded body",
        );
        let text = built(&req, &route("/api"));
        assert!(!text.to_lowercase().contains("transfer-encoding"));
        assert!(text.contains("\r\nContent-Length: 12\r\n"));
    }

    #[test]
    fn content_length_appears_only_when_needed() {
        let get = built(&request(Method::Get, "/api/x", &[], b""), &route("/api"));
        assert!(!get.contains("Content-Length"));
        let post = built(&request(Method::Post, "/api/x", &[], b""), &route("/api"));
        assert!(post.contains("\r\nContent-Length: 0\r\n"));
    }

    #[test]
    fn unsafe_requests_are_refused_before_anything_is_sent() {
        for target in [
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/..%2fadmin",
            "/api/a%5cb",
            "/api/%00",
            "/api/x?a b",
            "/api/x?a\u{7}b",
        ] {
            let req = request(Method::Get, target, &[], b"");
            let result = build_upstream_request(&req, &route("/api"), &client());
            assert!(
                matches!(result, Err(ProxyError::BadRequest(_))),
                "should refuse {target:?}"
            );
        }
    }

    #[test]
    fn odd_methods_and_mismatched_routes_are_refused() {
        let weird = request(Method::Other("BAD METHOD".to_string()), "/api/x", &[], b"");
        assert!(build_upstream_request(&weird, &route("/api"), &client()).is_err());

        let fine = request(Method::Other("PURGE".to_string()), "/api/x", &[], b"");
        assert!(build_upstream_request(&fine, &route("/api"), &client()).is_ok());

        // A route that does not match the path must never produce a bad request line.
        let req = request(Method::Get, "/apix", &[], b"");
        assert!(build_upstream_request(&req, &route("/api"), &client()).is_err());
    }

    // ---------- reading the upstream's answer ----------

    async fn read_from(bytes: &[u8], max: usize) -> Result<UpstreamResponse, ProxyError> {
        let (mut writer, mut reader) = tokio::io::duplex(256 * 1024);
        writer.write_all(bytes).await.unwrap();
        drop(writer);
        read_upstream_response(&mut reader, max, Instant::now() + Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn a_content_length_response_is_read() {
        let response = read_from(
            b"HTTP/1.1 200 OK\r\nContent-Type:  text/plain \r\nContent-Length: 5\r\n\r\nhello",
            1000,
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert!(
            response
                .headers
                .contains(&("Content-Type".to_string(), "text/plain".to_string()))
        );
    }

    #[tokio::test]
    async fn bytes_beyond_the_content_length_are_ignored() {
        let response = read_from(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", 1000)
            .await
            .unwrap();
        assert_eq!(response.body, b"ok");
    }

    #[tokio::test]
    async fn an_empty_body_is_fine() {
        let response = read_from(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 1000)
            .await
            .unwrap();
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn chunked_responses_are_decoded() {
        let response = read_from(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n",
            1000,
        )
        .await
        .unwrap();
        assert_eq!(response.body, b"hello world");
    }

    #[tokio::test]
    async fn bodies_that_run_until_the_connection_closes_are_read() {
        let response = read_from(b"HTTP/1.0 200 OK\r\n\r\nuntil the end", 1000)
            .await
            .unwrap();
        assert_eq!(response.body, b"until the end");
    }

    #[tokio::test]
    async fn no_content_and_not_modified_never_have_bodies() {
        for status in ["204 No Content", "304 Not Modified"] {
            let text = format!("HTTP/1.1 {status}\r\nETag: \"x\"\r\n\r\n");
            let response = read_from(text.as_bytes(), 1000).await.unwrap();
            assert!(response.body.is_empty(), "{status}");
        }
    }

    #[tokio::test]
    async fn interim_responses_are_skipped() {
        let response = read_from(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            1000,
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[tokio::test]
    async fn a_response_that_arrives_in_pieces_is_assembled() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            writer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Le")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer.write_all(b"ngth: 10\r\n\r\n01234").await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer.write_all(b"56789").await.unwrap();
        });
        let response =
            read_upstream_response(&mut reader, 1000, Instant::now() + Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(response.body, b"0123456789");
    }

    #[tokio::test]
    async fn unreadable_non_framing_headers_are_dropped() {
        let mut bytes = b"HTTP/1.1 200 OK\r\nX-Odd: ".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b"\r\nX-Fine: yes\r\nContent-Length: 0\r\n\r\n");
        let response = read_from(&bytes, 1000).await.unwrap();
        assert!(response.headers.iter().any(|(n, _)| n == "X-Fine"));
        assert!(!response.headers.iter().any(|(n, _)| n == "X-Odd"));
    }

    #[tokio::test]
    async fn broken_responses_are_bad_gateways() {
        let mut huge_head = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge_head.extend(std::iter::repeat_n(b'a', 70_000));

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("garbage", b"this is not http\r\n\r\n".to_vec()),
            ("nothing at all", Vec::new()),
            ("cut off in the headers", b"HTTP/1.1 200 OK\r\nContent-Le".to_vec()),
            ("cut off in the body", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()),
            ("cut off in a chunk", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel".to_vec()),
            ("bad chunk size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec()),
            ("conflicting lengths", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!".to_vec()),
            ("length and chunked", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello".to_vec()),
            ("gzip chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_vec()),
            ("two transfer encodings", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()),
            ("negative length", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".to_vec()),
            ("spaced length", b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\n\r\n".to_vec()),
            ("upgrade", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec()),
            ("status too high", b"HTTP/1.1 700 Nope\r\nContent-Length: 0\r\n\r\n".to_vec()),
            ("headers too large", huge_head),
        ];

        for (name, bytes) in cases {
            let result = read_from(&bytes, 1000).await;
            assert!(
                matches!(result, Err(ProxyError::BadGateway(_))),
                "{name}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_responses_are_refused() {
        let big = "x".repeat(5000);
        let with_length = format!("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n{big}");
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{big}\r\n0\r\n\r\n",
            big.len()
        );
        let until_close = format!("HTTP/1.0 200 OK\r\n\r\n{big}");
        let enormous =
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n".to_string();

        for (name, text) in [
            ("length", with_length),
            ("chunked", chunked),
            ("until close", until_close),
            ("enormous length", enormous),
        ] {
            let result = read_from(text.as_bytes(), 1000).await;
            assert!(
                matches!(result, Err(ProxyError::BadGateway(_))),
                "{name}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn silence_times_out() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let result = read_upstream_response(
            &mut reader,
            1000,
            Instant::now() + Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Err(ProxyError::TimedOut(_))));
    }

    #[test]
    fn framing_rules() {
        let none: Vec<(String, String)> = Vec::new();
        assert_eq!(response_framing(200, &none, 100), Ok(BodyKind::UntilClose));
        assert_eq!(response_framing(204, &none, 100), Ok(BodyKind::None));
        assert_eq!(
            response_framing(200, &pairs(&[("content-length", "5")]), 100),
            Ok(BodyKind::Length(5))
        );
        assert_eq!(
            response_framing(
                200,
                &pairs(&[("Content-Length", "5"), ("content-length", "5")]),
                100
            ),
            Ok(BodyKind::Length(5))
        );
        assert_eq!(
            response_framing(200, &pairs(&[("Transfer-Encoding", "Chunked")]), 100),
            Ok(BodyKind::Chunked)
        );
        assert!(response_framing(200, &pairs(&[("Content-Length", "101")]), 100).is_err());
    }

    // ---------- the answer for the client ----------

    #[test]
    fn upstream_answers_are_adapted_for_the_client() {
        let upstream = UpstreamResponse {
            status: 200,
            headers: pairs(&[
                ("Connection", "close, X-Internal"),
                ("X-Internal", "secret"),
                ("Keep-Alive", "timeout=1"),
                ("Transfer-Encoding", "chunked"),
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
                ("Server", "nginx"),
                ("Date", "Sat, 01 Jan 2000 00:00:00 GMT"),
                ("Content-Length", "999"),
                ("Content-Type", "text/plain"),
            ]),
            body: b"hi".to_vec(),
        };
        let response = into_client_response(upstream);
        let text = String::from_utf8(response.to_bytes(true)).unwrap();

        assert!(!text.contains("X-Internal"));
        assert!(!text.contains("Keep-Alive"));
        assert!(!text.contains("chunked"));
        assert!(!text.contains("nginx"));
        assert!(!text.contains("2000"));
        assert!(!text.contains("999"));
        assert_eq!(text.matches("Set-Cookie:").count(), 2);
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.contains("Server: webserver/0.1\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn errors_become_vague_responses() {
        for (error, status) in [
            (ProxyError::BadRequest("secret detail"), 400),
            (ProxyError::BadGateway("secret detail"), 502),
            (ProxyError::TimedOut("secret detail"), 504),
        ] {
            let response = error_response(&error);
            assert_eq!(response.status, status);
            let text = String::from_utf8(response.body).unwrap();
            assert!(!text.contains("secret"));
        }
    }
}
