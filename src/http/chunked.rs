use super::parser::ParseError;

/// Longest chunk-size line we accept (hex size plus any extension).
const MAX_CHUNK_LINE_BYTES: usize = 128;
/// Most bytes of trailer headers we will skip over.
const MAX_TRAILER_BYTES: usize = 8192;

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Decode as many complete chunks as `buf` contains.
///
/// - `pos` is where to start in `buf`. It only moves forward past chunks that
///   were fully decoded, so calling this again with more data resumes cleanly.
/// - Decoded bytes are appended to `body`.
///
/// Returns `Ok(true)` when the final chunk has been read, `Ok(false)` when more
/// data is needed, or an error for anything invalid.
pub fn decode_chunked(
    buf: &[u8],
    pos: &mut usize,
    body: &mut Vec<u8>,
    max_body_bytes: usize,
) -> Result<bool, ParseError> {
    loop {
        let rest = &buf[*pos..];

        // 1. Find the end of the chunk-size line.
        let window = &rest[..rest.len().min(MAX_CHUNK_LINE_BYTES)];
        let Some(line_len) = find_crlf(window) else {
            if rest.len() >= MAX_CHUNK_LINE_BYTES {
                return Err(ParseError::BadRequest("chunk size line too long"));
            }
            return Ok(false);
        };
        let line = &rest[..line_len];

        // 2. Read the size. Anything after ';' is an extension we ignore.
        let size_text = match line.iter().position(|&b| b == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        if size_text.is_empty() || !size_text.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::BadRequest("invalid chunk size"));
        }
        if size_text.len() > 16 {
            return Err(ParseError::PayloadTooLarge);
        }
        let size_str = std::str::from_utf8(size_text)
            .map_err(|_| ParseError::BadRequest("invalid chunk size"))?;
        let size = usize::from_str_radix(size_str, 16).map_err(|_| ParseError::PayloadTooLarge)?;
        let after_line = line_len + 2;

        // 3. Size 0 is the last chunk. Skip any trailers, then we are done.
        if size == 0 {
            let tail = &rest[after_line..];
            if tail.starts_with(b"\r\n") {
                *pos += after_line + 2;
                return Ok(true);
            }
            return match find_double_crlf(tail) {
                Some(i) => {
                    *pos += after_line + i + 4;
                    Ok(true)
                }
                None if tail.len() > MAX_TRAILER_BYTES => Err(ParseError::HeadersTooLarge),
                None => Ok(false),
            };
        }

        // 4. Check the size limit BEFORE waiting for the data to arrive.
        let too_big = body
            .len()
            .checked_add(size)
            .map_or(true, |total| total > max_body_bytes);
        if too_big {
            return Err(ParseError::PayloadTooLarge);
        }

        // 5. Wait until the whole chunk (data plus CRLF) has arrived.
        let needed = after_line + size + 2;
        if rest.len() < needed {
            return Ok(false);
        }
        if &rest[after_line + size..needed] != b"\r\n" {
            return Err(ParseError::BadRequest("chunk data not followed by CRLF"));
        }

        body.extend_from_slice(&rest[after_line..after_line + size]);
        *pos += needed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode `input` from scratch. Returns (finished, body, position).
    fn decode(input: &[u8], max: usize) -> Result<(bool, Vec<u8>, usize), ParseError> {
        let mut pos = 0;
        let mut body = Vec::new();
        let done = decode_chunked(input, &mut pos, &mut body, max)?;
        Ok((done, body, pos))
    }

    #[test]
    fn decodes_simple_chunks() {
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (done, body, pos) = decode(input, 1000).unwrap();
        assert!(done);
        assert_eq!(body, b"hello world");
        assert_eq!(pos, input.len());
    }

    #[test]
    fn partial_chunk_is_incomplete() {
        let (done, body, pos) = decode(b"5\r\nhel", 1000).unwrap();
        assert!(!done);
        assert!(body.is_empty());
        assert_eq!(pos, 0);
    }

    #[test]
    fn decoding_can_resume() {
        let full = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let partial = b"5\r\nhello\r\n3\r\nab";
        let mut pos = 0;
        let mut body = Vec::new();

        let done = decode_chunked(partial, &mut pos, &mut body, 1000).unwrap();
        assert!(!done);
        assert_eq!(body, b"hello");
        assert_eq!(pos, 10);

        let done = decode_chunked(full, &mut pos, &mut body, 1000).unwrap();
        assert!(done);
        assert_eq!(body, b"helloabc");
        assert_eq!(pos, full.len());
    }

    #[test]
    fn hex_sizes_are_case_insensitive() {
        let (done, body, _) = decode(b"A\r\n0123456789\r\n0\r\n\r\n", 1000).unwrap();
        assert!(done);
        assert_eq!(body.len(), 10);
        let (_, body, _) = decode(b"a\r\n0123456789\r\n0\r\n\r\n", 1000).unwrap();
        assert_eq!(body.len(), 10);
    }

    #[test]
    fn extensions_are_ignored() {
        let (done, body, _) = decode(b"5;name=value\r\nhello\r\n0\r\n\r\n", 1000).unwrap();
        assert!(done);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn trailers_are_skipped() {
        let input = b"3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n";
        let (done, body, pos) = decode(input, 1000).unwrap();
        assert!(done);
        assert_eq!(body, b"abc");
        assert_eq!(pos, input.len());
    }

    #[test]
    fn incomplete_trailers_wait_for_more() {
        let (done, _, _) = decode(b"3\r\nabc\r\n0\r\nX-Sum: 1\r\n", 1000).unwrap();
        assert!(!done);
    }

    #[test]
    fn invalid_sizes_are_rejected() {
        for bad in ["zz", "-1", "", " 5", "0x5"] {
            let input = format!("{bad}\r\n");
            assert!(
                matches!(
                    decode(input.as_bytes(), 1000),
                    Err(ParseError::BadRequest(_))
                ),
                "should reject chunk size {bad:?}"
            );
        }
    }

    #[test]
    fn missing_crlf_after_data_is_rejected() {
        let result = decode(b"3\r\nabcXY0\r\n\r\n", 1000);
        assert!(matches!(result, Err(ParseError::BadRequest(_))));
    }

    #[test]
    fn oversized_chunk_is_rejected_before_data_arrives() {
        // 0x20 = 32 bytes announced, limit is 10, and no data has been sent yet.
        let result = decode(b"20\r\n", 10);
        assert!(matches!(result, Err(ParseError::PayloadTooLarge)));
    }

    #[test]
    fn enormous_sizes_do_not_crash() {
        for digits in [16, 17] {
            let input = format!("{}\r\n", "F".repeat(digits));
            assert!(matches!(
                decode(input.as_bytes(), 1000),
                Err(ParseError::PayloadTooLarge)
            ));
        }
    }

    #[test]
    fn total_size_across_chunks_is_limited() {
        let input = b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
        let result = decode(input, 8);
        assert!(matches!(result, Err(ParseError::PayloadTooLarge)));
    }

    #[test]
    fn overlong_size_line_is_rejected() {
        let input = vec![b'a'; 200];
        let result = decode(&input, 1000);
        assert!(matches!(result, Err(ParseError::BadRequest(_))));
    }
}
