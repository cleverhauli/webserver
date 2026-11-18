use crate::http::request::Request;
use crate::http::response::Response;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use tracing::warn;

/// Turn the path part of a request target into a SAFE relative path,
/// or `None` if anything about it looks suspicious.
///
/// Examples: "/css/site.css?v=2" becomes "css/site.css", "/" becomes "",
/// and "/../secret" or "/%2e%2e/secret" become `None`.
pub fn safe_relative_path(target: &str) -> Option<PathBuf> {
    // Drop the query string and fragment.
    let path = target.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') {
        return None;
    }

    // Decode BEFORE checking, so "%2e%2e" cannot sneak past as "..".
    let decoded = percent_decode(path)?;

    // Backslashes are path separators on Windows, colons mean drive letters
    // ("C:") or hidden data streams ("file.txt:secret"), and control
    // characters (including NUL) are never legitimate.
    if decoded
        .chars()
        .any(|c| c.is_control() || c == '\\' || c == ':')
    {
        return None;
    }

    let mut result = PathBuf::new();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        // Dotfiles (".git", ".env") are hidden, and ".." is the attack itself.
        if segment.starts_with('.') {
            return None;
        }
        // Windows silently drops trailing dots and spaces, which could
        // disguise one name as another.
        if segment.ends_with('.') || segment.ends_with(' ') {
            return None;
        }
        if is_reserved_windows_name(segment) {
            return None;
        }
        result.push(segment);
    }
    Some(result)
}

/// Windows has special device names (CON, NUL, COM1...) that must never be
/// treated as files, even with an extension like "nul.txt".
fn is_reserved_windows_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();

    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }

    let bytes = stem.as_bytes();
    (stem.starts_with("COM") || stem.starts_with("LPT"))
        && bytes.len() == 4
        && bytes[3].is_ascii_digit()
        && bytes[3] != b'0'
}

/// Decode "%41" style escapes. Returns `None` for broken escapes or
/// results that are not valid UTF-8 text.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let high = hex_value(*bytes.get(i + 1)?)?;
            let low = hex_value(*bytes.get(i + 2)?)?;
            out.push(high * 16 + low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The opposite of decoding: keep letters, digits and "-_.~", escape the rest.
fn percent_encode(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Does the path part of the target end with a slash, like "/docs/"?
fn ends_with_slash(target: &str) -> bool {
    target.split(['?', '#']).next().unwrap_or("").ends_with('/')
}

/// Ask the operating system for the file's real location (following any
/// symlinks), and make sure it is still inside `root`.
async fn resolve_inside(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let canonical = tokio::fs::canonicalize(candidate).await.ok()?;
    if canonical.starts_with(root) {
        Some(canonical)
    } else {
        None
    }
}

fn not_found() -> Response {
    Response::text(404, "404 Not Found\n")
}

/// Pick the Content-Type header for a file.
fn content_type_for(path: &Path) -> String {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    if mime.type_() == mime_guess::mime::TEXT {
        format!("{mime}; charset=utf-8")
    } else {
        mime.to_string()
    }
}

/// Redirect "/docs" to "/docs/". The Location is rebuilt from the cleaned-up
/// path (never copied from the request), so it can only ever point to a
/// path on this same server.
fn redirect_to_folder(relative: &Path, target: &str) -> Response {
    let mut location = String::from("/");
    for component in relative.components() {
        location.push_str(&percent_encode(&component.as_os_str().to_string_lossy()));
        location.push('/');
    }
    // Keep the query string, so "/docs?page=2" becomes "/docs/?page=2".
    if let Some((_, rest)) = target.split_once('?') {
        let query = rest.split('#').next().unwrap_or("");
        location.push('?');
        location.push_str(query);
    }

    Response::new(301)
        .header("Location", &location)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body("301 Moved Permanently\n")
}

/// A file's fingerprint, used to answer "has it changed?".
struct Validators {
    /// Like "\"1a2-17f3b...\"" (size and modification time, in hex).
    etag: String,
    /// Like "Wed, 18 Nov 2026 08:30:00 GMT".
    last_modified: String,
    /// The modification time in whole seconds (HTTP dates have no fractions).
    modified_secs: u64,
}

fn file_validators(metadata: &std::fs::Metadata) -> Option<Validators> {
    let modified = metadata.modified().ok()?;
    let since_epoch = modified.duration_since(UNIX_EPOCH).ok()?;
    let modified_secs = since_epoch.as_secs();

    Some(Validators {
        etag: format!("\"{:x}-{:x}\"", metadata.len(), since_epoch.as_nanos()),
        last_modified: httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(modified_secs)),
        modified_secs,
    })
}

fn with_validators(response: Response, validators: &Validators) -> Response {
    response
        .header("ETag", &validators.etag)
        .header("Last-Modified", &validators.last_modified)
}

/// Does an If-None-Match header value match our ETag?
/// The value can be "*", one tag, or a comma-separated list. A "W/" prefix
/// marks a "weak" tag, which is fine to compare for caching.
fn etag_matches(header_value: &str, etag: &str) -> bool {
    header_value.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// Should we answer "304 Not Modified" instead of sending the file?
fn is_not_modified(request: &Request, validators: &Validators) -> bool {
    // If-None-Match is more precise, so when it is present it alone decides
    // and If-Modified-Since is ignored.
    if let Some(value) = request.header("if-none-match") {
        return etag_matches(value, &validators.etag);
    }

    if let Some(value) = request.header("if-modified-since") {
        // A date we cannot understand is simply ignored.
        if let Ok(since) = httpdate::parse_http_date(value) {
            if let Ok(since) = since.duration_since(UNIX_EPOCH) {
                return validators.modified_secs <= since.as_secs();
            }
        }
    }

    false
}

/// Files up to this size are sent from memory in one go. Bigger files are streamed.
const SMALL_FILE_BYTES: u64 = 64 * 1024;

/// What a Range header asks for.
#[derive(Debug, PartialEq)]
enum RangeOutcome {
    /// No usable Range header: send the whole file.
    Full,
    /// Send bytes `start` to `end`, both inclusive and already inside the file.
    Partial { start: u64, end: u64 },
    /// The range lies outside the file: answer 416.
    Unsatisfiable,
}

/// Digits only. A number too big for u64 becomes "as big as possible",
/// so huge values can never crash anything.
fn parse_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text.parse().unwrap_or(u64::MAX))
}

/// Understand a Range header for a file of `size` bytes.
/// Anything unusual is ignored (`Full`), which HTTP allows.
fn parse_range(header: &str, size: u64) -> RangeOutcome {
    let Some((unit, spec)) = header.trim().split_once('=') else {
        return RangeOutcome::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return RangeOutcome::Full;
    }
    let spec = spec.trim();

    // Several ranges at once ("0-5,10-15") are not supported.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };

    // "-500" means the LAST 500 bytes.
    if first.is_empty() {
        let Some(suffix) = parse_number(last) else {
            return RangeOutcome::Full;
        };
        if suffix == 0 || size == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        return RangeOutcome::Partial {
            start: size.saturating_sub(suffix),
            end: size - 1,
        };
    }

    let Some(start) = parse_number(first) else {
        return RangeOutcome::Full;
    };
    let end = if last.is_empty() {
        None
    } else {
        match parse_number(last) {
            Some(end) => Some(end),
            None => return RangeOutcome::Full,
        }
    };

    // "5-3" is nonsense, so ignore it.
    if let Some(end) = end {
        if end < start {
            return RangeOutcome::Full;
        }
    }
    if start >= size {
        return RangeOutcome::Unsatisfiable;
    }

    RangeOutcome::Partial {
        start,
        end: end.map_or(size - 1, |end| end.min(size - 1)),
    }
}

/// If-Range means "only give me a part if the file is still exactly the
/// version I have". Returns true when the Range header may be used.
fn if_range_allows(request: &Request, validators: &Validators) -> bool {
    let Some(value) = request.header("if-range") else {
        return true;
    };
    let value = value.trim();

    // An ETag. Weak tags ("W/...") never qualify here.
    if value.starts_with('"') {
        return value == validators.etag;
    }

    // Otherwise it must be the exact modification date.
    match httpdate::parse_http_date(value) {
        Ok(date) => date
            .duration_since(UNIX_EPOCH)
            .map_or(false, |d| d.as_secs() == validators.modified_secs),
        Err(_) => false,
    }
}

/// Serve a file from `document_root` for a GET or HEAD request.
pub async fn serve(document_root: &str, request: &Request) -> Response {
    let Some(relative) = safe_relative_path(&request.target) else {
        warn!("blocked suspicious path: {}", request.target);
        return not_found();
    };

    let root = match tokio::fs::canonicalize(document_root).await {
        Ok(root) => root,
        Err(_) => {
            warn!("document root '{document_root}' does not exist or cannot be read");
            return not_found();
        }
    };

    let Some(mut path) = resolve_inside(&root, &root.join(&relative)).await else {
        return not_found();
    };
    let Ok(mut metadata) = tokio::fs::metadata(&path).await else {
        return not_found();
    };

    // A folder: redirect "/docs" to "/docs/", then serve its index.html.
    if metadata.is_dir() {
        if !ends_with_slash(&request.target) {
            return redirect_to_folder(&relative, &request.target);
        }
        let Some(index) = resolve_inside(&root, &path.join("index.html")).await else {
            return not_found();
        };
        let Ok(index_metadata) = tokio::fs::metadata(&index).await else {
            return not_found();
        };
        path = index;
        metadata = index_metadata;
    }

    if !metadata.is_file() {
        return not_found();
    }

    let size = metadata.len();
    let validators = file_validators(&metadata);

    // "Has it changed?" comes first, so a 304 costs almost nothing.
    if let Some(v) = &validators {
        if is_not_modified(request, v) {
            return with_validators(Response::new(304), v).header("Cache-Control", "no-cache");
        }
    }

    // Does the client want only part of the file?
    let range_allowed = match &validators {
        Some(v) => if_range_allows(request, v),
        None => request.header("if-range").is_none(),
    };
    let outcome = match request.header("range") {
        Some(value) if range_allowed => parse_range(value, size),
        _ => RangeOutcome::Full,
    };

    let content_type = content_type_for(&path);
    let base = |status: u16| {
        let mut response = Response::new(status)
            .header("Content-Type", &content_type)
            .header("X-Content-Type-Options", "nosniff")
            .header("Cache-Control", "no-cache")
            .header("Accept-Ranges", "bytes");
        if let Some(v) = &validators {
            response = with_validators(response, v);
        }
        response
    };

    match outcome {
        RangeOutcome::Unsatisfiable => Response::text(416, "416 Range Not Satisfiable\n")
            .header("Content-Range", &format!("bytes */{size}")),

        RangeOutcome::Partial { start, end } => base(206)
            .header("Content-Range", &format!("bytes {start}-{end}/{size}"))
            .with_file(path, start, end - start + 1),

        RangeOutcome::Full if size <= SMALL_FILE_BYTES => match tokio::fs::read(&path).await {
            Ok(bytes) => base(200).body(bytes),
            Err(e) => {
                warn!("could not read {}: {e}", path.display());
                Response::text(500, "500 Internal Server Error\n")
            }
        },

        RangeOutcome::Full => base(200).with_file(path, 0, size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::{Method, Version};

    // ---------- safe_relative_path ----------

    #[test]
    fn normal_paths_are_accepted() {
        assert_eq!(
            safe_relative_path("/index.html"),
            Some(PathBuf::from("index.html"))
        );
        assert_eq!(
            safe_relative_path("/css/site.css"),
            Some(PathBuf::from("css").join("site.css"))
        );
        assert_eq!(safe_relative_path("/"), Some(PathBuf::new()));
    }

    #[test]
    fn query_and_fragment_are_ignored() {
        assert_eq!(
            safe_relative_path("/a.css?v=2"),
            Some(PathBuf::from("a.css"))
        );
        assert_eq!(
            safe_relative_path("/a.css#top"),
            Some(PathBuf::from("a.css"))
        );
    }

    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(
            safe_relative_path("/hello%20world.txt"),
            Some(PathBuf::from("hello world.txt"))
        );
    }

    #[test]
    fn double_encoding_stays_harmless() {
        // "%252e" decodes once to the literal text "%2e", not "..".
        assert_eq!(
            safe_relative_path("/%252e%252e/x"),
            Some(PathBuf::from("%2e%2e").join("x"))
        );
    }

    #[test]
    fn repeated_slashes_collapse() {
        assert_eq!(
            safe_relative_path("//a///b"),
            Some(PathBuf::from("a").join("b"))
        );
    }

    #[test]
    fn dot_dot_in_every_disguise_is_rejected() {
        for target in [
            "/../secret",
            "/a/../b",
            "/a/..",
            "/%2e%2e/secret",
            "/%2E%2E/secret",
            "/..%2fsecret",
            "/%2e%2e%2fsecret",
            "/a/%2e%2e/b",
        ] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
    }

    #[test]
    fn backslashes_and_colons_are_rejected() {
        for target in [
            "/a\\b",
            "/%5Cwindows",
            "/..%5csecret",
            "/C:/Windows/win.ini",
            "/c%3A/x",
            "/file.txt:stream",
        ] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
    }

    #[test]
    fn control_characters_are_rejected() {
        for target in ["/%00", "/a%00.txt", "/%0d%0a", "/%7f"] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
    }

    #[test]
    fn hidden_files_are_rejected() {
        for target in ["/.git/config", "/.env", "/a/.hidden", "/.well-known/x"] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
    }

    #[test]
    fn windows_device_names_are_rejected() {
        for target in ["/CON", "/nul", "/Aux.txt", "/COM1", "/lpt9.log", "/a/PRN"] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
        // These only look similar and are fine.
        assert!(safe_relative_path("/console.txt").is_some());
        assert!(safe_relative_path("/com10").is_some());
    }

    #[test]
    fn trailing_dots_and_spaces_are_rejected() {
        for target in ["/file.", "/a%20/b", "/file.txt%20", "/dir./x"] {
            assert_eq!(safe_relative_path(target), None, "should reject {target}");
        }
    }

    #[test]
    fn broken_input_is_rejected() {
        for target in ["no-slash", "", "/%zz", "/%4", "/%", "/%ff", "/%c0%af"] {
            assert_eq!(safe_relative_path(target), None, "should reject {target:?}");
        }
    }

    // ---------- serve (uses a temporary folder) ----------

    /// A small website in a temp folder, deleted when the test finishes.
    struct TempSite {
        root: PathBuf,
    }

    impl TempSite {
        fn new(name: &str) -> TempSite {
            let root =
                std::env::temp_dir().join(format!("webserver-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("docs")).unwrap();
            std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
            std::fs::write(root.join("docs").join("index.html"), "<h1>docs</h1>").unwrap();
            std::fs::write(root.join("style.css"), "body {}").unwrap();
            std::fs::write(root.join("data.bin"), [1u8, 2, 3]).unwrap();
            std::fs::write(root.join("digits.txt"), "0123456789").unwrap();
            std::fs::write(root.join(".secret"), "hidden").unwrap();
            TempSite { root }
        }

        fn path(&self) -> &str {
            self.root.to_str().unwrap()
        }
    }

    impl Drop for TempSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn get(target: &str) -> Request {
        Request {
            method: Method::Get,
            target: target.to_string(),
            version: Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn content_type(response: &Response) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .map(|(_, value)| value.clone())
    }

    #[tokio::test]
    async fn root_serves_index_html() {
        let site = TempSite::new("root");
        let response = serve(site.path(), &get("/")).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"<h1>home</h1>");
    }

    #[tokio::test]
    async fn files_get_the_right_content_type() {
        let site = TempSite::new("types");

        let css = serve(site.path(), &get("/style.css")).await;
        assert_eq!(css.status, 200);
        assert_eq!(
            content_type(&css).as_deref(),
            Some("text/css; charset=utf-8")
        );

        let html = serve(site.path(), &get("/index.html")).await;
        assert_eq!(
            content_type(&html).as_deref(),
            Some("text/html; charset=utf-8")
        );

        let binary = serve(site.path(), &get("/data.bin")).await;
        assert_eq!(binary.status, 200);
        assert_eq!(binary.body, vec![1u8, 2, 3]);
    }

    #[tokio::test]
    async fn folders_need_a_trailing_slash() {
        let site = TempSite::new("folders");

        let with_slash = serve(site.path(), &get("/docs/")).await;
        assert_eq!(with_slash.status, 200);
        assert_eq!(with_slash.body, b"<h1>docs</h1>");

        let without_slash = serve(site.path(), &get("/docs")).await;
        assert_eq!(without_slash.status, 301);
        assert_eq!(
            header_of(&without_slash, "Location").as_deref(),
            Some("/docs/")
        );
    }

    #[tokio::test]
    async fn missing_files_get_404() {
        let site = TempSite::new("missing");
        let response = serve(site.path(), &get("/nothing-here.html")).await;
        assert_eq!(response.status, 404);
    }

    #[tokio::test]
    async fn attacks_get_404_and_never_leak_files() {
        let site = TempSite::new("attacks");
        for target in [
            "/../Cargo.toml",
            "/%2e%2e/Cargo.toml",
            "/..%5cCargo.toml",
            "/.secret",
            "/docs/../.secret",
            "/C:/Windows/win.ini",
        ] {
            let response = serve(site.path(), &get(target)).await;
            assert_eq!(response.status, 404, "should block {target}");
            assert!(!response.body.starts_with(b"hidden"));
        }
    }

    #[tokio::test]
    async fn missing_document_root_gets_404() {
        let response = serve("this-folder-does-not-exist", &get("/")).await;
        assert_eq!(response.status, 404);
    }

    #[tokio::test]
    async fn file_responses_include_nosniff() {
        let site = TempSite::new("nosniff");
        let response = serve(site.path(), &get("/style.css")).await;
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == "X-Content-Type-Options" && value == "nosniff")
        );
    }

    // ---------- redirects and conditional requests ----------

    fn header_of(response: &Response, name: &str) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn get_with(target: &str, headers: &[(&str, &str)]) -> Request {
        let mut request = get(target);
        for (name, value) in headers {
            request.headers.push((name.to_string(), value.to_string()));
        }
        request
    }

    #[test]
    fn etag_matching_rules() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\", \"y\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("\"other\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));
    }

    #[test]
    fn percent_encoding_escapes_unsafe_characters() {
        assert_eq!(percent_encode("docs"), "docs");
        assert_eq!(percent_encode("my docs"), "my%20docs");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
    }

    #[tokio::test]
    async fn redirect_keeps_the_query_string() {
        let site = TempSite::new("redirect-query");
        let response = serve(site.path(), &get("/docs?page=2")).await;
        assert_eq!(response.status, 301);
        assert_eq!(
            header_of(&response, "Location").as_deref(),
            Some("/docs/?page=2")
        );
    }

    #[tokio::test]
    async fn redirects_never_point_to_another_site() {
        let site = TempSite::new("redirect-safe");
        for target in ["//docs", "///docs", "/./docs", "//docs?x=1"] {
            let response = serve(site.path(), &get(target)).await;
            if response.status == 301 {
                let location = header_of(&response, "Location").unwrap();
                assert!(location.starts_with('/'));
                assert!(!location.starts_with("//"), "bad redirect for {target}");
            }
        }
    }

    #[tokio::test]
    async fn files_come_with_validators() {
        let site = TempSite::new("validators");
        let response = serve(site.path(), &get("/style.css")).await;
        assert_eq!(response.status, 200);

        let etag = header_of(&response, "ETag").unwrap();
        assert!(etag.starts_with('"') && etag.ends_with('"'));
        assert!(
            header_of(&response, "Last-Modified")
                .unwrap()
                .ends_with(" GMT")
        );
        assert_eq!(
            header_of(&response, "Cache-Control").as_deref(),
            Some("no-cache")
        );
    }

    #[tokio::test]
    async fn matching_etag_gets_304_without_a_body() {
        let site = TempSite::new("etag-304");
        let first = serve(site.path(), &get("/style.css")).await;
        let etag = header_of(&first, "ETag").unwrap();

        let request = get_with("/style.css", &[("If-None-Match", etag.as_str())]);
        let second = serve(site.path(), &request).await;
        assert_eq!(second.status, 304);
        assert!(second.body.is_empty());
        assert_eq!(header_of(&second, "ETag"), Some(etag));
    }

    #[tokio::test]
    async fn weak_and_wildcard_etags_also_match() {
        let site = TempSite::new("etag-weak");
        let first = serve(site.path(), &get("/style.css")).await;
        let etag = header_of(&first, "ETag").unwrap();
        let weak = format!("W/{etag}");

        for value in [weak.as_str(), "*"] {
            let request = get_with("/style.css", &[("If-None-Match", value)]);
            assert_eq!(serve(site.path(), &request).await.status, 304);
        }
    }

    #[tokio::test]
    async fn different_etag_gets_the_full_file() {
        let site = TempSite::new("etag-200");
        let request = get_with("/style.css", &[("If-None-Match", "\"something-else\"")]);
        let response = serve(site.path(), &request).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"body {}");
    }

    #[tokio::test]
    async fn etag_changes_when_the_file_changes() {
        let site = TempSite::new("etag-change");
        let before = serve(site.path(), &get("/style.css")).await;

        std::fs::write(site.root.join("style.css"), "body { color: red }").unwrap();

        let after = serve(site.path(), &get("/style.css")).await;
        assert_ne!(header_of(&before, "ETag"), header_of(&after, "ETag"));
    }

    #[tokio::test]
    async fn if_modified_since_in_the_future_gets_304() {
        let site = TempSite::new("since-future");
        let request = get_with(
            "/style.css",
            &[("If-Modified-Since", "Fri, 01 Jan 2100 00:00:00 GMT")],
        );
        let response = serve(site.path(), &request).await;
        assert_eq!(response.status, 304);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn if_modified_since_in_the_past_gets_the_file() {
        let site = TempSite::new("since-past");
        let request = get_with(
            "/style.css",
            &[("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")],
        );
        assert_eq!(serve(site.path(), &request).await.status, 200);
    }

    #[tokio::test]
    async fn garbage_dates_are_ignored() {
        let site = TempSite::new("since-garbage");
        let request = get_with("/style.css", &[("If-Modified-Since", "not a date")]);
        assert_eq!(serve(site.path(), &request).await.status, 200);
    }

    #[tokio::test]
    async fn if_none_match_beats_if_modified_since() {
        let site = TempSite::new("precedence");
        let request = get_with(
            "/style.css",
            &[
                ("If-None-Match", "\"something-else\""),
                ("If-Modified-Since", "Fri, 01 Jan 2100 00:00:00 GMT"),
            ],
        );
        assert_eq!(serve(site.path(), &request).await.status, 200);
    }

    // ---------- streaming and Range requests ----------

    /// The bytes a client would receive as the body, wherever they come from.
    async fn full_body(response: &Response) -> Vec<u8> {
        match &response.file {
            Some(slice) => {
                let bytes = tokio::fs::read(&slice.path).await.unwrap();
                let start = slice.start as usize;
                bytes[start..start + slice.len as usize].to_vec()
            }
            None => response.body.clone(),
        }
    }

    fn with_range(target: &str, range: &str) -> Request {
        get_with(target, &[("Range", range)])
    }

    #[test]
    fn valid_ranges_are_understood() {
        use RangeOutcome::*;
        assert_eq!(parse_range("bytes=0-3", 10), Partial { start: 0, end: 3 });
        assert_eq!(parse_range("bytes=2-", 10), Partial { start: 2, end: 9 });
        assert_eq!(parse_range("bytes=-4", 10), Partial { start: 6, end: 9 });
        assert_eq!(parse_range("bytes=5-500", 10), Partial { start: 5, end: 9 });
        assert_eq!(parse_range("bytes=-500", 10), Partial { start: 0, end: 9 });
        assert_eq!(parse_range("BYTES=0-0", 10), Partial { start: 0, end: 0 });
        assert_eq!(parse_range("  bytes=1-2  ", 10), Partial { start: 1, end: 2 });
        assert_eq!(
            parse_range("bytes=5-99999999999999999999999", 10),
            Partial { start: 5, end: 9 }
        );
        assert_eq!(
            parse_range("bytes=-99999999999999999999999", 10),
            Partial { start: 0, end: 9 }
        );
    }

    #[test]
    fn out_of_file_ranges_are_unsatisfiable() {
        use RangeOutcome::*;
        assert_eq!(parse_range("bytes=10-", 10), Unsatisfiable);
        assert_eq!(parse_range("bytes=10-20", 10), Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 10), Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), Unsatisfiable);
        assert_eq!(parse_range("bytes=-5", 0), Unsatisfiable);
        assert_eq!(
            parse_range("bytes=99999999999999999999999-", 10),
            Unsatisfiable
        );
    }

    #[test]
    fn strange_ranges_are_ignored() {
        for header in [
            "", "bytes", "bytes=", "bytes=-", "bytes=abc", "bytes=a-b", "bytes=5-3",
            "items=0-3", "bytes=0-3,5-6", "bytes=+1-2", "bytes=1 -2", "bytes=--5",
            "bytes=0x1-2",
        ] {
            assert_eq!(
                parse_range(header, 10),
                RangeOutcome::Full,
                "should ignore {header:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_byte_range_gets_206() {
        let site = TempSite::new("range-basic");
        let response = serve(site.path(), &with_range("/digits.txt", "bytes=2-5")).await;
        assert_eq!(response.status, 206);
        assert_eq!(
            header_of(&response, "Content-Range").as_deref(),
            Some("bytes 2-5/10")
        );
        assert_eq!(response.content_length(), 4);
        assert_eq!(full_body(&response).await, b"2345");
        assert!(header_of(&response, "ETag").is_some());
    }

    #[tokio::test]
    async fn open_ended_and_suffix_ranges_work() {
        let site = TempSite::new("range-forms");
        for (range, expected) in [
            ("bytes=7-", "789"),
            ("bytes=-3", "789"),
            ("bytes=0-0", "0"),
            ("bytes=5-500", "56789"),
        ] {
            let response = serve(site.path(), &with_range("/digits.txt", range)).await;
            assert_eq!(response.status, 206, "{range}");
            assert_eq!(full_body(&response).await, expected.as_bytes(), "{range}");
        }
    }

    #[tokio::test]
    async fn unsatisfiable_range_gets_416() {
        let site = TempSite::new("range-416");
        for range in ["bytes=10-", "bytes=50-60", "bytes=-0"] {
            let response = serve(site.path(), &with_range("/digits.txt", range)).await;
            assert_eq!(response.status, 416, "{range}");
            assert_eq!(
                header_of(&response, "Content-Range").as_deref(),
                Some("bytes */10")
            );
        }
    }

    #[tokio::test]
    async fn unusable_range_headers_are_ignored() {
        let site = TempSite::new("range-ignored");
        for range in ["bytes=0-3,5-6", "bytes=5-3", "items=0-3", "garbage"] {
            let response = serve(site.path(), &with_range("/digits.txt", range)).await;
            assert_eq!(response.status, 200, "{range}");
            assert_eq!(full_body(&response).await, b"0123456789", "{range}");
        }
    }

    #[tokio::test]
    async fn full_responses_advertise_range_support() {
        let site = TempSite::new("range-advert");
        let response = serve(site.path(), &get("/digits.txt")).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            header_of(&response, "Accept-Ranges").as_deref(),
            Some("bytes")
        );
    }

    #[tokio::test]
    async fn if_range_with_the_current_etag_allows_the_range() {
        let site = TempSite::new("ifrange-etag");
        let first = serve(site.path(), &get("/digits.txt")).await;
        let etag = header_of(&first, "ETag").unwrap();

        let request = get_with(
            "/digits.txt",
            &[("Range", "bytes=0-1"), ("If-Range", etag.as_str())],
        );
        let response = serve(site.path(), &request).await;
        assert_eq!(response.status, 206);
        assert_eq!(full_body(&response).await, b"01");
    }

    #[tokio::test]
    async fn if_range_with_a_stale_etag_sends_the_whole_file() {
        let site = TempSite::new("ifrange-stale");
        let request = get_with(
            "/digits.txt",
            &[("Range", "bytes=0-1"), ("If-Range", "\"stale\"")],
        );
        let response = serve(site.path(), &request).await;
        assert_eq!(response.status, 200);
        assert_eq!(full_body(&response).await, b"0123456789");
    }

    #[tokio::test]
    async fn weak_etags_never_satisfy_if_range() {
        let site = TempSite::new("ifrange-weak");
        let first = serve(site.path(), &get("/digits.txt")).await;
        let weak = format!("W/{}", header_of(&first, "ETag").unwrap());

        let request = get_with(
            "/digits.txt",
            &[("Range", "bytes=0-1"), ("If-Range", weak.as_str())],
        );
        assert_eq!(serve(site.path(), &request).await.status, 200);
    }

    #[tokio::test]
    async fn if_range_with_the_exact_date_allows_the_range() {
        let site = TempSite::new("ifrange-date");
        let first = serve(site.path(), &get("/digits.txt")).await;
        let date = header_of(&first, "Last-Modified").unwrap();

        let request = get_with(
            "/digits.txt",
            &[("Range", "bytes=0-1"), ("If-Range", date.as_str())],
        );
        assert_eq!(serve(site.path(), &request).await.status, 206);
    }

    #[tokio::test]
    async fn if_range_with_a_different_date_sends_the_whole_file() {
        let site = TempSite::new("ifrange-olddate");
        let request = get_with(
            "/digits.txt",
            &[
                ("Range", "bytes=0-1"),
                ("If-Range", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ],
        );
        assert_eq!(serve(site.path(), &request).await.status, 200);
    }

    #[tokio::test]
    async fn not_modified_beats_range() {
        let site = TempSite::new("range-304");
        let first = serve(site.path(), &get("/digits.txt")).await;
        let etag = header_of(&first, "ETag").unwrap();

        let request = get_with(
            "/digits.txt",
            &[("Range", "bytes=0-1"), ("If-None-Match", etag.as_str())],
        );
        assert_eq!(serve(site.path(), &request).await.status, 304);
    }

    #[tokio::test]
    async fn small_files_are_sent_from_memory() {
        let site = TempSite::new("small");
        let response = serve(site.path(), &get("/digits.txt")).await;
        assert!(response.file.is_none());
        assert_eq!(response.body, b"0123456789");
    }

    #[tokio::test]
    async fn big_files_are_streamed_not_loaded() {
        let site = TempSite::new("big");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(site.root.join("big.bin"), &data).unwrap();

        let whole = serve(site.path(), &get("/big.bin")).await;
        assert_eq!(whole.status, 200);
        assert!(whole.file.is_some());
        assert!(whole.body.is_empty());
        assert_eq!(whole.content_length(), 200_000);
        assert_eq!(full_body(&whole).await, data);

        let part = serve(site.path(), &with_range("/big.bin", "bytes=150000-150099")).await;
        assert_eq!(part.status, 206);
        assert_eq!(
            header_of(&part, "Content-Range").as_deref(),
            Some("bytes 150000-150099/200000")
        );
        assert_eq!(full_body(&part).await, data[150000..150100].to_vec());
    }
}
