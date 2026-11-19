#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Component;
use webserver::http::chunked::decode_chunked;
use webserver::http::parser::{ParseResult, body_framing, parse_request};
use webserver::static_files::safe_relative_path;

const MAX_HEADER_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 1 << 20;

// The fuzzer calls this over and over with inputs it evolves to reach new
// code. A panic or a failed assert here is a bug it has found.
fuzz_target!(|data: &[u8]| {
    // 1. Request parsing, then body framing.
    if let Ok(ParseResult::Complete { request, consumed }) = parse_request(data, MAX_HEADER_BYTES) {
        assert!(consumed <= data.len());
        let _ = body_framing(&request, MAX_BODY_BYTES);
    }

    // 2. Chunked decoding.
    let mut pos = 0;
    let mut body = Vec::new();
    let _ = decode_chunked(data, &mut pos, &mut body, MAX_BODY_BYTES);
    assert!(pos <= data.len());
    assert!(body.len() <= MAX_BODY_BYTES);

    // 3. Path safety: nothing but plain names may come out.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(path) = safe_relative_path(text) {
            for component in path.components() {
                assert!(matches!(component, Component::Normal(_)));
            }
        }
    }
});
