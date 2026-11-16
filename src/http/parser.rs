use super::request::{Method, Request, Version};

/// Most headers we accept in one request.
pub const MAX_HEADERS: usize = 64;
/// Longest request target (path plus query) we accept.
pub const MAX_TARGET_BYTES: usize = 2048;

/// Everything that can go wrong while parsing. Each maps to an HTTP status code.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    BadRequest(&'static str),
    UriTooLong,
    HeadersTooLarge,
    VersionNotSupported,
}

impl ParseError {
    pub fn status_code(&self) -> u16 {
        match self {
            ParseError::BadRequest(_) => 400,
            ParseError::UriTooLong => 414,
            ParseError::HeadersTooLarge => 431,
            ParseError::VersionNotSupported => 505,
        }
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            ParseError::BadRequest(_) => "Bad Request",
            ParseError::UriTooLong => "URI Too Long",
            ParseError::HeadersTooLarge => "Request Header Fields Too Large",
            ParseError::VersionNotSupported => "HTTP Version Not Supported",
        }
    }
}

/// Either we have a whole request, or we need to read more bytes.
#[derive(Debug)]
pub enum ParseResult {
    Complete { request: Request, consumed: usize },
    Incomplete,
}

/// Try to parse one request from the start of `buf`.
/// `consumed` is how many bytes the request used, so any extra bytes
/// (like a second pipelined request) are left for later.
pub fn parse_request(buf: &[u8], max_header_bytes: usize) -> Result<ParseResult, ParseError> {
    let mut header_slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut raw = httparse::Request::new(&mut header_slots);

    let consumed = match raw.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            // Not finished yet. If we already have too much data, give up.
            if buf.len() > max_header_bytes {
                return Err(ParseError::HeadersTooLarge);
            }
            return Ok(ParseResult::Incomplete);
        }
        Err(httparse::Error::TooManyHeaders) => return Err(ParseError::HeadersTooLarge),
        Err(httparse::Error::Version) => return Err(ParseError::VersionNotSupported),
        Err(_) => return Err(ParseError::BadRequest("malformed request")),
    };

    if consumed > max_header_bytes {
        return Err(ParseError::HeadersTooLarge);
    }

    let (Some(method), Some(target), Some(minor)) = (raw.method, raw.path, raw.version) else {
        return Err(ParseError::BadRequest("malformed request line"));
    };

    if target.len() > MAX_TARGET_BYTES {
        return Err(ParseError::UriTooLong);
    }

    let version = match minor {
        0 => Version::Http10,
        1 => Version::Http11,
        _ => return Err(ParseError::VersionNotSupported),
    };

    let mut headers = Vec::with_capacity(raw.headers.len());
    for header in raw.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| ParseError::BadRequest("header value is not valid text"))?;
        headers.push((header.name.to_string(), value.trim().to_string()));
    }

    let request = Request {
        method: Method::parse(method),
        target: target.to_string(),
        version,
        headers,
    };

    // HTTP/1.1 requires a Host header.
    if request.version == Version::Http11 && request.header("host").is_none() {
        return Err(ParseError::BadRequest("missing Host header"));
    }

    Ok(ParseResult::Complete { request, consumed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_get_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\n";
        match parse_request(raw, 8192).unwrap() {
            ParseResult::Complete { request, consumed } => {
                assert_eq!(request.method, Method::Get);
                assert_eq!(request.target, "/index.html");
                assert_eq!(request.version, Version::Http11);
                assert_eq!(request.header("host"), Some("localhost"));
                assert_eq!(consumed, raw.len());
            }
            ParseResult::Incomplete => panic!("expected a complete request"),
        }
    }

    #[test]
    fn half_a_request_is_incomplete() {
        let raw = b"GET / HTTP/1.1\r\nHost: loc";
        assert!(matches!(
            parse_request(raw, 8192).unwrap(),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn http11_without_host_is_rejected() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let err = parse_request(raw, 8192).unwrap_err();
        assert!(matches!(err, ParseError::BadRequest(_)));
    }

    #[test]
    fn http10_without_host_is_allowed() {
        let raw = b"GET / HTTP/1.0\r\n\r\n";
        assert!(parse_request(raw, 8192).is_ok());
    }

    #[test]
    fn too_many_headers_is_rejected() {
        let mut raw = String::from("GET / HTTP/1.1\r\nHost: a\r\n");
        for i in 0..70 {
            raw.push_str(&format!("X-{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        let err = parse_request(raw.as_bytes(), 65536).unwrap_err();
        assert_eq!(err, ParseError::HeadersTooLarge);
    }

    #[test]
    fn oversized_complete_headers_are_rejected() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\n";
        let err = parse_request(raw, 50).unwrap_err();
        assert_eq!(err, ParseError::HeadersTooLarge);
    }

    #[test]
    fn oversized_partial_headers_are_rejected() {
        let raw = b"GET / HTTP/1.1\r\nHost: loc";
        let err = parse_request(raw, 10).unwrap_err();
        assert_eq!(err, ParseError::HeadersTooLarge);
    }

    #[test]
    fn very_long_target_is_rejected() {
        let raw = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(3000));
        let err = parse_request(raw.as_bytes(), 65536).unwrap_err();
        assert_eq!(err, ParseError::UriTooLong);
    }

    #[test]
    fn garbage_is_rejected() {
        let raw = b"\x00\x01garbage\r\n\r\n";
        let err = parse_request(raw, 8192).unwrap_err();
        assert!(matches!(err, ParseError::BadRequest(_)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let raw = b"GET / HTTP/2.0\r\nHost: a\r\n\r\n";
        let err = parse_request(raw, 8192).unwrap_err();
        assert_eq!(err, ParseError::VersionNotSupported);
    }

    #[test]
    fn only_the_first_of_two_pipelined_requests_is_consumed() {
        let raw = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let first_len = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n".len();
        match parse_request(raw, 8192).unwrap() {
            ParseResult::Complete { request, consumed } => {
                assert_eq!(request.target, "/a");
                assert_eq!(consumed, first_len);
            }
            ParseResult::Incomplete => panic!("expected a complete request"),
        }
    }

    #[test]
    fn header_lookup_ignores_case() {
        let raw = b"GET / HTTP/1.1\r\nHost: Example.com\r\n\r\n";
        match parse_request(raw, 8192).unwrap() {
            ParseResult::Complete { request, .. } => {
                assert_eq!(request.header("HOST"), Some("Example.com"));
            }
            ParseResult::Incomplete => panic!("expected a complete request"),
        }
    }
}
