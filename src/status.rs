//! The /status page: counters as JSON, for people who run the server.

use crate::config::Config;
use crate::http::request::{Method, Request};
use crate::http::response::Response;
use crate::metrics::Metrics;
use std::net::IpAddr;

/// Headers that show a request came through another proxy. The address we
/// see is then the proxy's, not the real client's, so "this is local" can
/// no longer be trusted. Such requests never get the status page.
const PROXY_SIGNS: [&str; 4] = [
    "x-forwarded-for",
    "forwarded",
    "x-real-ip",
    "x-forwarded-host",
];

fn is_status_path(target: &str) -> bool {
    target.split('?').next() == Some("/status")
}

/// Answer a request for /status, or return `None` when the request is
/// about something else (or the page is switched off), so normal routing
/// carries on.
pub fn handle(
    request: &Request,
    peer: IpAddr,
    config: &Config,
    metrics: &Metrics,
    active_connections: usize,
) -> Option<Response> {
    if !config.status_page || !is_status_path(&request.target) {
        return None;
    }

    // Anyone who may not look gets exactly the answer for a page that does
    // not exist, so nothing is revealed.
    let came_through_a_proxy = PROXY_SIGNS
        .iter()
        .any(|name| request.header(name).is_some());
    if came_through_a_proxy || !config.status_ip_allowed(peer) {
        return Some(Response::text(404, "404 Not Found\n"));
    }

    if !matches!(request.method, Method::Get | Method::Head) {
        return Some(Response::text(405, "405 Method Not Allowed\n").header("Allow", "GET, HEAD"));
    }

    let body = metrics.snapshot(active_connections).to_json();
    Some(
        Response::json(200, body)
            .header("Cache-Control", "no-store")
            .header("X-Content-Type-Options", "nosniff"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Version;

    fn status_config() -> Config {
        Config {
            status_page: true,
            ..Config::default()
        }
    }

    fn request(method: Method, target: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method,
            target: target.to_string(),
            version: Version::Http11,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    fn local() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn ask(config: &Config, request: &Request, peer: IpAddr) -> Option<Response> {
        handle(request, peer, config, &Metrics::new(), 1)
    }

    #[test]
    fn other_paths_are_left_alone() {
        let config = status_config();
        for target in ["/health", "/statuses", "/status/x", "/", "/Status"] {
            let req = request(Method::Get, target, &[]);
            assert!(ask(&config, &req, local()).is_none(), "{target}");
        }
    }

    #[test]
    fn a_switched_off_page_does_not_exist() {
        let req = request(Method::Get, "/status", &[]);
        assert!(ask(&Config::default(), &req, local()).is_none());
    }

    #[test]
    fn allowed_addresses_get_the_counters() {
        let req = request(Method::Get, "/status?pretty=1", &[]);
        let response = ask(&status_config(), &req, local()).unwrap();
        assert_eq!(response.status, 200);

        let header = |name: &str| {
            response
                .headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("Content-Type"), Some("application/json"));
        assert_eq!(header("Cache-Control"), Some("no-store"));
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.starts_with("{\"uptime_seconds\":"));
    }

    #[test]
    fn the_active_connection_count_is_shown() {
        let req = request(Method::Get, "/status", &[]);
        let response = handle(&req, local(), &status_config(), &Metrics::new(), 7).unwrap();
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("\"active\":7"), "{body}");
    }

    #[test]
    fn other_addresses_get_an_ordinary_404() {
        let req = request(Method::Get, "/status", &[]);
        let response = ask(&status_config(), &req, "203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"404 Not Found\n");
    }

    #[test]
    fn requests_that_came_through_a_proxy_are_refused_even_from_loopback() {
        for header in [
            ("X-Forwarded-For", "1.2.3.4"),
            ("Forwarded", "for=1.2.3.4"),
            ("X-Real-IP", "1.2.3.4"),
            ("x-forwarded-host", "example.com"),
        ] {
            let req = request(Method::Get, "/status", &[header]);
            let response = ask(&status_config(), &req, local()).unwrap();
            assert_eq!(response.status, 404, "{header:?}");
        }
    }

    #[test]
    fn only_get_and_head_are_allowed() {
        let post = request(Method::Post, "/status", &[]);
        let response = ask(&status_config(), &post, local()).unwrap();
        assert_eq!(response.status, 405);

        let head = request(Method::Head, "/status", &[]);
        assert_eq!(ask(&status_config(), &head, local()).unwrap().status, 200);
    }

    #[test]
    fn strangers_cannot_probe_with_the_wrong_method() {
        // A stranger must see 404 for every method, never a 405 that proves the page exists.
        let post = request(Method::Post, "/status", &[]);
        let response = ask(&status_config(), &post, "203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(response.status, 404);
    }
}
