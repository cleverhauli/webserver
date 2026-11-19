//! Sending plain-HTTP visitors to the HTTPS version of the page.

use crate::http::request::Request;
use crate::http::response::Response;

/// Pull the host name out of a Host header, or `None` if it looks wrong.
///
/// The redirect address is built from this text, so it is checked strictly:
/// only plain host names ("example.com"), IPv4 addresses, and bracketed IPv6
/// addresses ("[::1]") pass, each with an optional ":port".
fn hostname_from_host_header(value: &str) -> Option<String> {
    let value = value.trim();

    let (host, port): (String, Option<&str>) = if let Some(rest) = value.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let looks_like_ipv6 = !inside.is_empty()
            && inside
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
        if !looks_like_ipv6 {
            return None;
        }
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (format!("[{inside}]"), port)
    } else {
        match value.split_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (value.to_string(), None),
        }
    };

    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }

    if !host.starts_with('[') {
        let allowed = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.';
        if host.is_empty() || host.len() > 253 || !host.bytes().all(allowed) {
            return None;
        }
    }

    Some(host)
}

/// Answer a plain-HTTP request with a permanent redirect to the same page
/// on the HTTPS port. The method and body are preserved by 308.
pub fn https_redirect(request: &Request, https_port: u16) -> Response {
    let Some(host) = request.header("host").and_then(hostname_from_host_header) else {
        return Response::text(400, "400 Bad Request\n");
    };

    // Only ordinary "/path" targets are redirected.
    if !request.target.starts_with('/') {
        return Response::text(400, "400 Bad Request\n");
    }

    let port = if https_port == 443 {
        String::new()
    } else {
        format!(":{https_port}")
    };
    let location = format!("https://{host}{port}{}", request.target);

    Response::new(308)
        .header("Location", &location)
        // Browsers cache permanent redirects very eagerly. While you are
        // setting things up, that causes confusing "it still redirects" bugs.
        .header("Cache-Control", "no-store")
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(format!("Redirecting to {location}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::{Method, Version};

    fn request(target: &str, host: Option<&str>) -> Request {
        Request {
            method: Method::Get,
            target: target.to_string(),
            version: Version::Http11,
            headers: host
                .map(|h| vec![("Host".to_string(), h.to_string())])
                .unwrap_or_default(),
            body: Vec::new(),
        }
    }

    fn header(response: &Response, name: &str) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn redirects_to_the_same_page_on_https() {
        let response = https_redirect(&request("/docs/a.html", Some("example.com")), 8443);
        assert_eq!(response.status, 308);
        assert_eq!(
            header(&response, "Location").as_deref(),
            Some("https://example.com:8443/docs/a.html")
        );
    }

    #[test]
    fn the_http_port_in_the_host_header_is_replaced() {
        let response = https_redirect(&request("/", Some("example.com:8080")), 8443);
        assert_eq!(
            header(&response, "Location").as_deref(),
            Some("https://example.com:8443/")
        );
    }

    #[test]
    fn port_443_is_left_out() {
        let response = https_redirect(&request("/", Some("example.com")), 443);
        assert_eq!(
            header(&response, "Location").as_deref(),
            Some("https://example.com/")
        );
    }

    #[test]
    fn the_query_string_is_kept() {
        let response = https_redirect(&request("/search?q=rust&page=2", Some("example.com")), 8443);
        assert_eq!(
            header(&response, "Location").as_deref(),
            Some("https://example.com:8443/search?q=rust&page=2")
        );
    }

    #[test]
    fn ipv4_and_ipv6_hosts_work() {
        let v4 = https_redirect(&request("/x", Some("127.0.0.1:9090")), 8443);
        assert_eq!(
            header(&v4, "Location").as_deref(),
            Some("https://127.0.0.1:8443/x")
        );
        let v6 = https_redirect(&request("/x", Some("[::1]:9090")), 8443);
        assert_eq!(
            header(&v6, "Location").as_deref(),
            Some("https://[::1]:8443/x")
        );
    }

    #[test]
    fn the_destination_is_always_our_own_host() {
        // "//evil.com" is just part of the path, never a new destination.
        let response = https_redirect(&request("//evil.com/x", Some("example.com")), 8443);
        let location = header(&response, "Location").unwrap();
        assert!(
            location.starts_with("https://example.com:8443/"),
            "{location}"
        );
    }

    #[test]
    fn suspicious_host_headers_are_rejected() {
        for host in [
            "evil.com/path",
            "a@evil.com",
            "evil.com:abc",
            "evil.com:",
            "evil.com:99999999",
            "[::1",
            "[]",
            "[zz]",
            "exa mple.com",
            "evil.com#x",
            "evil.com?x",
            "evil.com\\x",
            "",
        ] {
            let response = https_redirect(&request("/", Some(host)), 8443);
            assert_eq!(response.status, 400, "should reject Host: {host:?}");
            assert!(header(&response, "Location").is_none());
        }
    }

    #[test]
    fn a_missing_host_header_is_rejected() {
        let response = https_redirect(&request("/", None), 8443);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn only_ordinary_paths_are_redirected() {
        for target in ["*", "http://evil.com/", "evil.com:443", ""] {
            let response = https_redirect(&request(target, Some("example.com")), 8443);
            assert_eq!(response.status, 400, "should reject target {target:?}");
        }
    }

    #[test]
    fn redirects_are_not_cached() {
        let response = https_redirect(&request("/", Some("example.com")), 8443);
        assert_eq!(
            header(&response, "Cache-Control").as_deref(),
            Some("no-store")
        );
    }

    #[test]
    fn host_parsing_examples() {
        assert_eq!(
            hostname_from_host_header("Example.COM"),
            Some("Example.COM".to_string())
        );
        assert_eq!(
            hostname_from_host_header(" example.com:80 "),
            Some("example.com".to_string())
        );
        assert_eq!(
            hostname_from_host_header("[2001:db8::1]:8080"),
            Some("[2001:db8::1]".to_string())
        );
        assert_eq!(hostname_from_host_header("a:b:c"), None);
    }
}
