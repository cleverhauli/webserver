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
    PayloadTooLarge,
    NotImplemented,
}

impl ParseError {
    pub fn status_code(&self) -> u16 {
        match self {
            ParseError::BadRequest(_) => 400,
            ParseError::UriTooLong => 414,
            ParseError::HeadersTooLarge => 431,
            ParseError::VersionNotSupported => 505,
            ParseError::PayloadTooLarge => 413,
            ParseError::NotImplemented => 501,
        }
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            ParseError::BadRequest(_) => "Bad Request",
            ParseError::UriTooLong => "URI Too Long",
            ParseError::HeadersTooLarge => "Request Header Fields Too Large",
            ParseError::VersionNotSupported => "HTTP Version Not Supported",
            ParseError::PayloadTooLarge => "Payload Too Large",
            ParseError::NotImplemented => "Not Implemented",
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
        body: Vec::new(),
    };

    // HTTP/1.1 requires a Host header.
    if request.version == Version::Http11 && request.header("host").is_none() {
        return Err(ParseError::BadRequest("missing Host header"));
    }

    Ok(ParseResult::Complete { request, consumed })
}

/// How the body of a request is delimited.
#[derive(Debug, PartialEq)]
pub enum BodyFraming {
    /// No body to read.
    None,
    /// Exactly this many bytes follow the headers.
    ContentLength(usize),
    /// The body arrives as a series of chunks.
    Chunked,
}

/// Work out whether a request has a body and how it is delimited.
/// Strict on purpose: unclear framing is rejected, never guessed.
pub fn body_framing(request: &Request, max_body_bytes: usize) -> Result<BodyFraming, ParseError> {
    let mut encodings = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));

    if let Some((_, value)) = encodings.next() {
        if encodings.next().is_some() {
            return Err(ParseError::BadRequest("multiple Transfer-Encoding headers"));
        }
        if request.version == Version::Http10 {
            return Err(ParseError::BadRequest(
                "Transfer-Encoding is not allowed in HTTP/1.0",
            ));
        }
        // Both headers present is the classic request smuggling trick.
        if request.header("content-length").is_some() {
            return Err(ParseError::BadRequest(
                "both Content-Length and Transfer-Encoding",
            ));
        }
        if value.eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        // Other encodings (like gzip) are not supported.
        return Err(ParseError::NotImplemented);
    }

    let mut length: Option<usize> = None;
    for (name, value) in &request.headers {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        // Digits only: no signs, spaces, or hex.
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseError::BadRequest("invalid Content-Length"));
        }
        // A number too big to even fit counts as too large, not a crash.
        let parsed: usize = value.parse().map_err(|_| ParseError::PayloadTooLarge)?;
        match length {
            Some(existing) if existing != parsed => {
                return Err(ParseError::BadRequest("conflicting Content-Length headers"));
            }
            _ => length = Some(parsed),
        }
    }

    match length {
        None | Some(0) => Ok(BodyFraming::None),
        Some(n) if n > max_body_bytes => Err(ParseError::PayloadTooLarge),
        Some(n) => Ok(BodyFraming::ContentLength(n)),
    }
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

    /// Build a POST request with extra headers, for testing.
    fn request_with(extra_headers: &str) -> Request {
        let raw = format!("POST /submit HTTP/1.1\r\nHost: x\r\n{extra_headers}\r\n");
        match parse_request(raw.as_bytes(), 8192).unwrap() {
            ParseResult::Complete { request, .. } => request,
            ParseResult::Incomplete => panic!("expected a complete request"),
        }
    }

    #[test]
    fn no_body_headers_means_no_body() {
        let req = request_with("");
        assert_eq!(body_framing(&req, 1000), Ok(BodyFraming::None));
    }

    #[test]
    fn content_length_is_understood() {
        let req = request_with("Content-Length: 5\r\n");
        assert_eq!(body_framing(&req, 1000), Ok(BodyFraming::ContentLength(5)));
    }

    #[test]
    fn identical_duplicate_lengths_are_allowed() {
        let req = request_with("Content-Length: 5\r\nContent-Length: 5\r\n");
        assert_eq!(body_framing(&req, 1000), Ok(BodyFraming::ContentLength(5)));
    }

    #[test]
    fn conflicting_lengths_are_rejected() {
        let req = request_with("Content-Length: 5\r\nContent-Length: 6\r\n");
        assert!(matches!(
            body_framing(&req, 1000),
            Err(ParseError::BadRequest(_))
        ));
    }

    #[test]
    fn non_numbers_are_rejected() {
        for bad in ["abc", "-5", "+5", "5 5", "0x10"] {
            let req = request_with(&format!("Content-Length: {bad}\r\n"));
            assert!(
                matches!(body_framing(&req, 1000), Err(ParseError::BadRequest(_))),
                "should reject Content-Length: {bad}"
            );
        }
    }

    #[test]
    fn both_length_and_transfer_encoding_is_rejected() {
        let req = request_with("Content-Length: 5\r\nTransfer-Encoding: chunked\r\n");
        assert!(matches!(
            body_framing(&req, 1000),
            Err(ParseError::BadRequest(_))
        ));
    }

    #[test]
    fn too_large_bodies_are_rejected() {
        let req = request_with("Content-Length: 2000\r\n");
        assert_eq!(body_framing(&req, 1000), Err(ParseError::PayloadTooLarge));
    }

    #[test]
    fn absurdly_large_numbers_do_not_crash() {
        let req = request_with("Content-Length: 99999999999999999999999999\r\n");
        assert_eq!(body_framing(&req, 1000), Err(ParseError::PayloadTooLarge));
    }

    #[test]
    fn chunked_is_understood() {
        let req = request_with("Transfer-Encoding: chunked\r\n");
        assert_eq!(body_framing(&req, 1000), Ok(BodyFraming::Chunked));
    }

    #[test]
    fn chunked_name_and_value_ignore_case() {
        let req = request_with("transfer-encoding: CHUNKED\r\n");
        assert_eq!(body_framing(&req, 1000), Ok(BodyFraming::Chunked));
    }

    #[test]
    fn other_encodings_are_not_implemented() {
        let req = request_with("Transfer-Encoding: gzip, chunked\r\n");
        assert_eq!(body_framing(&req, 1000), Err(ParseError::NotImplemented));
    }

    #[test]
    fn duplicate_transfer_encoding_is_rejected() {
        let req = request_with("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n");
        assert!(matches!(
            body_framing(&req, 1000),
            Err(ParseError::BadRequest(_))
        ));
    }

    #[test]
    fn transfer_encoding_in_http10_is_rejected() {
        let raw = b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n";
        let request = match parse_request(raw, 8192).unwrap() {
            ParseResult::Complete { request, .. } => request,
            ParseResult::Incomplete => panic!("expected a complete request"),
        };
        assert!(matches!(
            body_framing(&request, 1000),
            Err(ParseError::BadRequest(_))
        ));
    }
}
