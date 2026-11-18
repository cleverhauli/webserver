use super::status::reason_phrase;
use std::path::PathBuf;
use std::time::SystemTime;

/// A piece of a file that is streamed to the client instead of being
/// held in memory.
#[derive(Debug, Clone)]
pub struct FileSlice {
    pub path: PathBuf,
    /// The first byte to send.
    pub start: u64,
    /// How many bytes to send.
    pub len: u64,
}

/// An HTTP response, built step by step.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// A body held in memory. Used when `file` is `None`.
    pub body: Vec<u8>,
    /// A file slice to stream. When set, it is the body and `body` is unused.
    pub file: Option<FileSlice>,
}

impl Response {
    /// Start a response with a status code and nothing else.
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            file: None,
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

    /// Make the body a slice of a file, streamed from disk when sent.
    pub fn with_file(mut self, path: PathBuf, start: u64, len: u64) -> Response {
        self.file = Some(FileSlice { path, start, len });
        self
    }

    /// A plain text response.
    pub fn text(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response::new(status)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body)
    }

    /// An HTML response.
    #[allow(dead_code)]
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

    /// How many body bytes this response carries.
    pub fn content_length(&self) -> u64 {
        match &self.file {
            Some(slice) => slice.len,
            None => self.body.len() as u64,
        }
    }

    /// 204 and 304 responses never have a body or a Content-Length.
    fn status_has_no_body(&self) -> bool {
        self.status == 204 || self.status == 304
    }

    /// Just the status line and headers, ending with the blank line.
    pub fn head_bytes(&self) -> Vec<u8> {
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
        if !self.status_has_no_body() {
            head.push_str(&format!("Content-Length: {}\r\n", self.content_length()));
        }
        head.push_str("Connection: close\r\n\r\n");

        head.into_bytes()
    }

    /// Headers plus the in-memory body, as one block of bytes.
    /// For HEAD requests pass `include_body = false`: the headers (including
    /// Content-Length) stay the same, but the body is left out.
    /// A streamed `file` is NOT included here; the server sends it separately.
    pub fn to_bytes(&self, include_body: bool) -> Vec<u8> {
        let mut bytes = self.head_bytes();
        if include_body && !self.status_has_no_body() {
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

    #[test]
    fn not_modified_has_no_body_and_no_content_length() {
        let response = Response::new(304).header("ETag", "\"abc\"").body("ignored");
        let text = as_text(response.to_bytes(true));
        assert!(text.starts_with("HTTP/1.1 304 Not Modified\r\n"));
        assert!(text.contains("ETag: \"abc\"\r\n"));
        assert!(!text.contains("Content-Length"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.contains("ignored"));
    }

    #[test]
    fn no_content_has_no_body_and_no_content_length() {
        let text = as_text(Response::new(204).to_bytes(true));
        assert!(!text.contains("Content-Length"));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
