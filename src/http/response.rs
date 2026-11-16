use super::status::reason_phrase;
use std::time::SystemTime;

/// An HTTP response, built step by step.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Start a response with a status code and nothing else.
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header. Unsafe names or values are silently ignored, because a
    /// line break inside a header would let an attacker inject extra headers.
    pub fn header(mut self, name: &str, value: &str) -> Response {
        if is_valid_header_name(name) && is_safe_header_value(value) {
            self.headers.push((name.to_string(), value.to_string()));
        }
        self
    }

    /// Set the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Response {
        self.body = body.into();
        self
    }

    /// A plain text response.
    pub fn text(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response::new(status)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body)
    }

    /// An HTML response.
    pub fn html(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response::new(status)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(body)
    }

    /// A JSON response (you supply the JSON text).
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response::new(status)
            .header("Content-Type", "application/json")
            .body(body)
    }

    /// Turn the response into the exact bytes sent over the network.
    /// For HEAD requests pass `include_body = false`: the headers (including
    /// Content-Length) stay the same, but the body is left out.
    pub fn to_bytes(&self, include_body: bool) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason_phrase(self.status)
        );

        for (name, value) in &self.headers {
            // The server controls these four, so handlers cannot override them.
            let reserved = ["content-length", "connection", "date", "server"];
            if reserved.iter().any(|r| name.eq_ignore_ascii_case(r)) {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }

        head.push_str(&format!(
            "Date: {}\r\n",
            httpdate::fmt_http_date(SystemTime::now())
        ));
        head.push_str("Server: webserver/0.1\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        head.push_str("Connection: close\r\n\r\n");

        let mut bytes = head.into_bytes();
        if include_body {
            bytes.extend_from_slice(&self.body);
        }
        bytes
    }
}

/// Header names may only contain letters, digits and '-' here.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Header values must not contain line breaks or NUL bytes.
fn is_safe_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_text(bytes: Vec<u8>) -> String {
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[test]
    fn serializes_status_line_headers_and_body() {
        let text = as_text(Response::text(200, "hello").to_bytes(true));
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.contains("Server: webserver/0.1\r\n"));
        assert!(text.contains(" GMT\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn head_keeps_the_length_but_leaves_out_the_body() {
        let text = as_text(Response::text(200, "hello").to_bytes(false));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.contains("hello"));
    }

    #[test]
    fn header_injection_is_blocked() {
        let response = Response::new(200).header("X-Test", "ok\r\nSet-Cookie: evil=1");
        assert!(response.headers.is_empty());
        let text = as_text(response.to_bytes(true));
        assert!(!text.contains("evil"));
    }

    #[test]
    fn bad_header_names_are_ignored() {
        for bad in ["", "Bad Name", "A:B", "X\r\nY"] {
            let response = Response::new(200).header(bad, "value");
            assert!(response.headers.is_empty(), "should ignore name {bad:?}");
        }
    }

    #[test]
    fn handlers_cannot_override_content_length() {
        let response = Response::new(200)
            .header("Content-Length", "999")
            .body("hi");
        let text = as_text(response.to_bytes(true));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.contains("999"));
    }

    #[test]
    fn error_statuses_use_the_right_reason_phrase() {
        let text = as_text(Response::text(404, "nope").to_bytes(true));
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn json_and_html_set_the_content_type() {
        let json = as_text(Response::json(200, "{}").to_bytes(true));
        assert!(json.contains("Content-Type: application/json\r\n"));
        let html = as_text(Response::html(200, "<p>hi</p>").to_bytes(true));
        assert!(html.contains("Content-Type: text/html; charset=utf-8\r\n"));
    }
}
