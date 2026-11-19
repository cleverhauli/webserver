//! Property tests. Instead of hand-picked examples, these state rules that
//! must ALWAYS hold, then try thousands of random and deliberately damaged
//! inputs. When a rule breaks, proptest shrinks the input to the smallest
//! one that still fails, and saves it in a `proptest-regressions` folder.
//! Commit that folder: it replays old failures forever.

use proptest::prelude::*;
use std::path::Component;
use webserver::http::chunked::decode_chunked;
use webserver::http::parser::{BodyFraming, ParseResult, body_framing, parse_request};
use webserver::http::request::{Method, Request, Version};
use webserver::http::response::Response;
use webserver::server::build_router;
use webserver::static_files::safe_relative_path;

const MAX_HEADER_BYTES: usize = 8192;
const MAX_BODY_BYTES: usize = 1 << 20;

/// Valid requests used as starting points for damage.
const PLAIN_POST: &[u8] = b"POST /echo?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fuzz\r\nContent-Length: 11\r\n\r\nhello=world";
const CHUNKED_POST: &[u8] = b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

/// Damage some bytes: overwrite one, insert one, delete one, or cut the rest off.
fn mutate(base: &[u8], edits: &[(usize, u8, u8)]) -> Vec<u8> {
    let mut data = base.to_vec();
    for &(position, value, action) in edits {
        if data.is_empty() {
            break;
        }
        let i = position % data.len();
        match action % 4 {
            0 => data[i] = value,
            1 => data.insert(i, value),
            2 => {
                let _ = data.remove(i);
            }
            _ => data.truncate(i + 1),
        }
    }
    data
}

/// Turn chunks into a valid chunked body.
fn encode_chunks(chunks: &[Vec<u8>], with_trailer: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    if with_trailer {
        out.extend_from_slice(b"X-Trailer: 1\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Feed bytes to the request parser. Panics (and so fails the test) if any
/// rule is broken.
fn exercise_parser(data: &[u8]) {
    if let Ok(ParseResult::Complete { request, consumed }) = parse_request(data, MAX_HEADER_BYTES) {
        assert!(consumed <= data.len(), "consumed more bytes than exist");
        assert!(
            consumed <= MAX_HEADER_BYTES,
            "header limit was not enforced"
        );

        // A request is self-contained: parsing just its own bytes gives the same answer.
        match parse_request(&data[..consumed], MAX_HEADER_BYTES) {
            Ok(ParseResult::Complete {
                consumed: again, ..
            }) => assert_eq!(again, consumed),
            other => panic!("re-parsing the consumed bytes gave {other:?}"),
        }

        // If the body is chunked, decoding whatever follows must be safe too.
        if let Ok(BodyFraming::Chunked) = body_framing(&request, MAX_BODY_BYTES) {
            let rest = &data[consumed..];
            let mut pos = 0;
            let mut body = Vec::new();
            let _ = decode_chunked(rest, &mut pos, &mut body, MAX_BODY_BYTES);
            assert!(pos <= rest.len());
            assert!(body.len() <= MAX_BODY_BYTES);
        }
    }
}

// ---------- the request parser ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Completely random bytes never crash the parser.
    #[test]
    fn parser_survives_random_bytes(
        data in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        exercise_parser(&data);
    }

    /// Valid requests with a few bytes damaged: much closer to real attacks.
    #[test]
    fn parser_survives_mutated_requests(
        base in prop::sample::select(vec![PLAIN_POST, CHUNKED_POST]),
        edits in prop::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..8),
    ) {
        exercise_parser(&mutate(base, &edits));
    }
}

// ---------- the chunked body decoder ----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn chunked_decoder_survives_random_bytes(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        max in 0usize..64,
    ) {
        let mut pos = 0;
        let mut body = Vec::new();
        let _ = decode_chunked(&data, &mut pos, &mut body, max);
        prop_assert!(pos <= data.len());
        prop_assert!(body.len() <= max, "the body limit was exceeded");
    }

    #[test]
    fn chunked_decoder_survives_mutated_streams(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..20), 0..6),
        edits in prop::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..6),
        max in 0usize..128,
    ) {
        let stream = mutate(&encode_chunks(&chunks, false), &edits);
        let mut pos = 0;
        let mut body = Vec::new();
        let _ = decode_chunked(&stream, &mut pos, &mut body, max);
        prop_assert!(pos <= stream.len());
        prop_assert!(body.len() <= max, "the body limit was exceeded");
    }

    /// A valid chunked body decodes to exactly the original data, even when
    /// the network delivers it in two pieces, split at ANY byte.
    #[test]
    fn chunked_round_trip_at_any_split(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..20), 0..6),
        trailer in any::<bool>(),
        split in any::<usize>(),
    ) {
        let stream = encode_chunks(&chunks, trailer);
        let expected: Vec<u8> = chunks.concat();
        let split = split % (stream.len() + 1);

        let mut pos = 0;
        let mut body = Vec::new();

        // The first piece arrives...
        let first = decode_chunked(&stream[..split], &mut pos, &mut body, MAX_BODY_BYTES);
        prop_assert!(first.is_ok(), "a valid prefix must never be an error");

        // ...and unless that was already everything, the rest arrives.
        if first != Ok(true) {
            let second = decode_chunked(&stream, &mut pos, &mut body, MAX_BODY_BYTES);
            prop_assert_eq!(second, Ok(true));
        }
        prop_assert_eq!(body, expected);
        prop_assert_eq!(pos, stream.len());
    }
}

// ---------- safe paths ----------

/// The safety rules for any path that `safe_relative_path` accepts.
fn assert_path_is_safe(target: &str) {
    let Some(path) = safe_relative_path(target) else {
        return; // rejected: always safe
    };

    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                assert!(
                    !name.starts_with('.'),
                    "hidden or '..' segment from {target:?}"
                );
                assert!(
                    !name.contains(['/', '\\', ':']),
                    "separator from {target:?}"
                );
                assert!(
                    !name.chars().any(|c| c.is_control()),
                    "control char from {target:?}"
                );
            }
            other => panic!("unsafe component {other:?} from {target:?}"),
        }
    }

    // Joined onto any folder, the result stays inside that folder.
    let root = std::env::temp_dir();
    assert!(
        root.join(&path).starts_with(&root),
        "escaped the root: {target:?}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Any text at all.
    #[test]
    fn paths_from_any_text_are_safe(text in any::<String>()) {
        assert_path_is_safe(&text);
    }

    /// Text built only from the characters attackers use.
    #[test]
    fn paths_from_attack_characters_are_safe(text in r"[/.%2eE5cCfF:\\a-z0-9 ?#]{0,40}") {
        assert_path_is_safe(&text);
    }

    /// Paths assembled from a dictionary of known tricks.
    #[test]
    fn paths_built_from_attack_pieces_are_safe(
        pieces in prop::collection::vec(
            prop::sample::select(vec![
                "..", ".", "%2e%2e", "%2E%2e", "%2e", "a", "b.txt", ".hidden", "CON",
                "nul.txt", "C:", "C%3A", "a%5Cb", "%00", "%252e", "", "..%2f..",
                "%2e%2e%2f", "a%20", "x.",
            ]),
            0..6,
        ),
        suffix in prop::sample::select(vec!["", "/", "?x=1", "#frag", "/?q"]),
    ) {
        assert_path_is_safe(&format!("/{}{suffix}", pieces.join("/")));
    }
}

// ---------- the router and responses ----------

proptest! {
    /// Whatever arrives, the router answers with a sensible status.
    #[test]
    fn router_always_answers_with_a_known_status(
        method in prop::sample::select(vec![
            "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "FOO",
        ]),
        target in "/[a-z/?=&.%]{0,30}",
    ) {
        let request = Request {
            method: Method::parse(method),
            target,
            version: Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = build_router().handle(&request);
        prop_assert!([200, 404, 405].contains(&response.status));
    }

    /// No header name or value, however nasty, can add extra lines to a response.
    #[test]
    fn header_injection_is_impossible(
        name in prop_oneof![any::<String>(), "[A-Za-z][A-Za-z0-9-]{0,10}"],
        value in prop_oneof![
            any::<String>(),
            (any::<String>(), any::<String>(), any::<String>())
                .prop_map(|(a, b, c)| format!("{a}\r\n{b}: {c}")),
        ],
    ) {
        let response = Response::new(200).header(&name, &value).body("hi");
        let bytes = response.to_bytes(true);
        let text = String::from_utf8_lossy(&bytes);
        let (head, body) = text.split_once("\r\n\r\n").unwrap();

        // Status line, the headers we stored, and the four the server adds.
        let reserved = ["content-length", "connection", "date", "server"];
        let stored = response
            .headers
            .iter()
            .filter(|(n, _)| !reserved.iter().any(|r| n.eq_ignore_ascii_case(r)))
            .count();
        prop_assert_eq!(head.split("\r\n").count(), 1 + stored + 4);
        prop_assert_eq!(body, "hi");
    }
}
