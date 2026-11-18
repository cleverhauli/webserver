use crate::http::request::Request;
use crate::http::response::Response;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Largest file we will serve for now. Streaming big files comes in Step 4c.
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

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

/// Does the path part of the target end with a slash, like "/docs/"?
fn ends_with_slash(target: &str) -> bool {
    target
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .ends_with('/')
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

    // A folder: serve its index.html, but only for URLs ending in "/".
    if metadata.is_dir() {
        if !ends_with_slash(&request.target) {
            return not_found();
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

    if metadata.len() > MAX_FILE_BYTES {
        warn!("file too large to serve yet: {}", path.display());
        return Response::text(500, "500 Internal Server Error\n");
    }

    match tokio::fs::read(&path).await {
        Ok(bytes) => Response::new(200)
            .header("Content-Type", &content_type_for(&path))
            .header("X-Content-Type-Options", "nosniff")
            .body(bytes),
        Err(e) => {
            warn!("could not read {}: {e}", path.display());
            Response::text(500, "500 Internal Server Error\n")
        }
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
        assert_eq!(safe_relative_path("//a///b"), Some(PathBuf::from("a").join("b")));
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
            let root = std::env::temp_dir()
                .join(format!("webserver-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("docs")).unwrap();
            std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
            std::fs::write(root.join("docs").join("index.html"), "<h1>docs</h1>").unwrap();
            std::fs::write(root.join("style.css"), "body {}").unwrap();
            std::fs::write(root.join("data.bin"), [1u8, 2, 3]).unwrap();
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
        assert_eq!(content_type(&css).as_deref(), Some("text/css; charset=utf-8"));

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
        assert_eq!(without_slash.status, 404);
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
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "X-Content-Type-Options" && value == "nosniff"));
    }
}