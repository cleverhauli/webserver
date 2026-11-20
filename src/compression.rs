//! Choosing and applying content encodings (gzip and brotli).

use std::io::{Cursor, Write};
use std::sync::Arc;

/// A content encoding we can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Brotli,
    Gzip,
}

impl Encoding {
    /// The name used in the Accept-Encoding and Content-Encoding headers.
    pub fn token(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }

    /// The extension of a precompressed copy of a file.
    pub fn file_extension(self) -> &'static str {
        match self {
            Encoding::Brotli => ".br",
            Encoding::Gzip => ".gz",
        }
    }
}

/// Our own order of preference, best first. It breaks ties between encodings
/// the client likes equally.
const PREFERENCE: [Encoding; 2] = [Encoding::Brotli, Encoding::Gzip];

/// Read a quality value like "0.8" as thousandths (800). Only "0" to "1"
/// with up to three decimals is valid.
fn parse_qvalue(text: &str) -> Option<u16> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let fraction_value: u16 = if fraction.is_empty() {
        0
    } else {
        // "5" means 0.5, so pad to three digits: "500".
        format!("{fraction:0<3}").parse().ok()?
    };
    match whole {
        "0" => Some(fraction_value),
        "1" if fraction_value == 0 => Some(1000),
        _ => None,
    }
}

/// Split an Accept-Encoding header into (name, quality) pairs. An entry
/// with a malformed quality value is ignored.
fn parse_entries(header: &str) -> Vec<(String, u16)> {
    header
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.split(';');
            let coding = pieces.next()?.trim();
            if coding.is_empty() {
                return None;
            }
            let mut quality = 1000;
            for parameter in pieces {
                let parameter = parameter.trim();
                if let Some(value) = parameter
                    .strip_prefix("q=")
                    .or_else(|| parameter.strip_prefix("Q="))
                {
                    quality = parse_qvalue(value.trim())?;
                }
            }
            Some((coding.to_ascii_lowercase(), quality))
        })
        .collect()
}

/// Every encoding the client accepts, best first: highest quality value
/// wins, and ties go to our own preference. An empty list means "send the
/// file as it is".
pub fn acceptable_encodings(header: &str) -> Vec<Encoding> {
    let entries = parse_entries(header);
    let wildcard = entries
        .iter()
        .find(|(coding, _)| coding == "*")
        .map(|(_, quality)| *quality);

    let mut found: Vec<(u16, usize, Encoding)> = Vec::new();
    for (index, encoding) in PREFERENCE.into_iter().enumerate() {
        let quality = entries
            .iter()
            .find(|(coding, _)| coding == encoding.token())
            .map(|(_, quality)| *quality)
            .or(wildcard)
            .unwrap_or(0);
        if quality > 0 {
            found.push((quality, index, encoding));
        }
    }

    found.sort_by_key(|&(quality, index, _)| (std::cmp::Reverse(quality), index));
    found.into_iter().map(|(_, _, encoding)| encoding).collect()
}

/// The single best encoding for a client, if any.
pub fn negotiate(header: &str) -> Option<Encoding> {
    acceptable_encodings(header).first().copied()
}

/// Is this kind of content worth compressing? Images, video, fonts and
/// archives are already compressed, so trying again only wastes CPU.
pub fn is_compressible(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    essence.starts_with("text/")
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
        || matches!(
            essence.as_str(),
            "application/json"
                | "application/javascript"
                | "application/ecmascript"
                | "application/xml"
                | "application/wasm"
        )
}

/// Compress a block of bytes. This is CPU-heavy work, so call it from a
/// blocking thread (see `compress_shared`).
pub fn compress(encoding: Encoding, data: &[u8]) -> std::io::Result<Vec<u8>> {
    match encoding {
        Encoding::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
            encoder.write_all(data)?;
            encoder.finish()
        }
        Encoding::Brotli => {
            // Quality 5 is a good speed/size balance for work done per request.
            // (Quality 11 is far smaller but very slow: precompress with it instead.)
            let params = brotli::enc::BrotliEncoderParams {
                quality: 5,
                ..Default::default()
            };
            let mut output = Vec::new();
            brotli::BrotliCompress(&mut Cursor::new(data), &mut output, &params)?;
            Ok(output)
        }
    }
}

/// Compress on a blocking thread, so the server keeps answering other
/// clients meanwhile.
pub async fn compress_shared(encoding: Encoding, data: Arc<Vec<u8>>) -> std::io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || compress(encoding, &data))
        .await
        .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn unbrotli(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::BrotliDecompress(&mut Cursor::new(bytes), &mut out).unwrap();
        out
    }

    #[test]
    fn quality_values_are_read_correctly() {
        assert_eq!(parse_qvalue("1"), Some(1000));
        assert_eq!(parse_qvalue("1.0"), Some(1000));
        assert_eq!(parse_qvalue("1.000"), Some(1000));
        assert_eq!(parse_qvalue("0"), Some(0));
        assert_eq!(parse_qvalue("0.5"), Some(500));
        assert_eq!(parse_qvalue("0.85"), Some(850));
        assert_eq!(parse_qvalue("0.001"), Some(1));
        assert_eq!(parse_qvalue("0."), Some(0));
    }

    #[test]
    fn bad_quality_values_are_refused() {
        for bad in ["", "2", "1.5", "-1", "0.1234", "abc", "0.a", ".5", "1.001"] {
            assert_eq!(parse_qvalue(bad), None, "should refuse {bad:?}");
        }
    }

    #[test]
    fn a_single_accepted_encoding_is_chosen() {
        assert_eq!(negotiate("gzip"), Some(Encoding::Gzip));
        assert_eq!(negotiate("br"), Some(Encoding::Brotli));
        assert_eq!(negotiate("GZIP"), Some(Encoding::Gzip));
    }

    #[test]
    fn brotli_wins_ties() {
        assert_eq!(negotiate("gzip, br"), Some(Encoding::Brotli));
        assert_eq!(negotiate("br, gzip"), Some(Encoding::Brotli));
        assert_eq!(negotiate("gzip, deflate, br"), Some(Encoding::Brotli));
    }

    #[test]
    fn quality_values_decide_between_encodings() {
        assert_eq!(negotiate("gzip;q=1.0, br;q=0.5"), Some(Encoding::Gzip));
        assert_eq!(negotiate("gzip; q=0.8, br; q=0.9"), Some(Encoding::Brotli));
        assert_eq!(negotiate("br;q=0, gzip"), Some(Encoding::Gzip));
        assert_eq!(negotiate("br;q=0.001"), Some(Encoding::Brotli));
    }

    #[test]
    fn zero_means_never() {
        assert_eq!(negotiate("gzip;q=0"), None);
        assert_eq!(negotiate("gzip;q=0, br;q=0"), None);
    }

    #[test]
    fn wildcards_are_understood() {
        assert_eq!(negotiate("*"), Some(Encoding::Brotli));
        assert_eq!(negotiate("*;q=0"), None);
        assert_eq!(negotiate("gzip, *;q=0"), Some(Encoding::Gzip));
        assert_eq!(negotiate("*;q=0.1, gzip;q=0.5"), Some(Encoding::Gzip));
    }

    #[test]
    fn unsupported_or_missing_encodings_mean_no_compression() {
        for header in ["", "identity", "deflate", "compress", ",", "  "] {
            assert_eq!(negotiate(header), None, "{header:?}");
        }
    }

    #[test]
    fn malformed_entries_are_ignored_not_fatal() {
        assert_eq!(negotiate("br;q=abc, gzip"), Some(Encoding::Gzip));
        assert_eq!(negotiate("gzip;q=1.5"), None);
        assert_eq!(negotiate(",,gzip,,"), Some(Encoding::Gzip));
    }

    #[test]
    fn every_acceptable_encoding_is_listed_best_first() {
        assert_eq!(
            acceptable_encodings("gzip;q=0.9, br;q=0.4"),
            vec![Encoding::Gzip, Encoding::Brotli]
        );
        assert_eq!(
            acceptable_encodings("gzip, br"),
            vec![Encoding::Brotli, Encoding::Gzip]
        );
        assert!(acceptable_encodings("").is_empty());
    }

    #[test]
    fn text_like_types_are_compressible() {
        for kind in [
            "text/html; charset=utf-8",
            "text/css",
            "text/plain",
            "text/javascript",
            "application/json",
            "application/javascript",
            "application/xml",
            "image/svg+xml",
            "application/ld+json",
            "application/atom+xml",
            "APPLICATION/JSON",
            "application/wasm",
        ] {
            assert!(is_compressible(kind), "{kind} should be compressible");
        }
    }

    #[test]
    fn already_compressed_types_are_not() {
        for kind in [
            "image/png",
            "image/jpeg",
            "image/webp",
            "video/mp4",
            "audio/mpeg",
            "font/woff2",
            "application/zip",
            "application/gzip",
            "application/pdf",
            "application/octet-stream",
            "",
        ] {
            assert!(!is_compressible(kind), "{kind} should not be compressible");
        }
    }

    #[test]
    fn gzip_round_trips() {
        let text = "hello compression ".repeat(200);
        let compressed = compress(Encoding::Gzip, text.as_bytes()).unwrap();
        assert!(compressed.len() < text.len() / 5);
        assert_eq!(gunzip(&compressed), text.as_bytes());
    }

    #[test]
    fn brotli_round_trips() {
        let text = "hello compression ".repeat(200);
        let compressed = compress(Encoding::Brotli, text.as_bytes()).unwrap();
        assert!(compressed.len() < text.len() / 5);
        assert_eq!(unbrotli(&compressed), text.as_bytes());
    }

    #[test]
    fn empty_input_round_trips() {
        let gz = compress(Encoding::Gzip, b"").unwrap();
        assert!(gunzip(&gz).is_empty());
        let br = compress(Encoding::Brotli, b"").unwrap();
        assert!(unbrotli(&br).is_empty());
    }

    #[test]
    fn compression_is_repeatable() {
        // The same input must always give the same bytes, which is what makes
        // an ETag built from the file's identity honest.
        let text = b"the same input ".repeat(100);
        for encoding in [Encoding::Gzip, Encoding::Brotli] {
            assert_eq!(
                compress(encoding, &text).unwrap(),
                compress(encoding, &text).unwrap(),
                "{encoding:?}"
            );
        }
    }

    #[tokio::test]
    async fn compression_on_a_blocking_thread_works() {
        let data = Arc::new("blocking thread ".repeat(300).into_bytes());
        let compressed = compress_shared(Encoding::Gzip, Arc::clone(&data))
            .await
            .unwrap();
        assert_eq!(gunzip(&compressed), *data);
    }
}
