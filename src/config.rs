use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

/// One caching rule: files with these extensions get this Cache-Control value.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CacheRule {
    /// Extensions without the dot, like "css". Matching ignores case.
    pub extensions: Vec<String>,
    /// The Cache-Control header value, like "public, max-age=3600".
    pub cache_control: String,
}

/// Printable ASCII only, so no line break or control character can ever
/// reach a response header.
fn is_plain_header_text(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// One reverse-proxy route: requests whose path starts with `prefix` are
/// forwarded to the program listening at `upstream`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyRoute {
    /// The path to forward, like "/api". It matches "/api" and "/api/...",
    /// but not "/apix".
    pub prefix: String,
    /// Where to forward to, as "host:port", like "127.0.0.1:3000".
    pub upstream: String,
    /// Remove the prefix first: "/api/users" is sent to the upstream as "/users".
    pub strip_prefix: bool,
    /// How many seconds the upstream has to answer.
    pub timeout_secs: u64,
}

impl Default for ProxyRoute {
    fn default() -> Self {
        ProxyRoute {
            prefix: String::new(),
            upstream: String::new(),
            strip_prefix: true,
            timeout_secs: 30,
        }
    }
}

impl ProxyRoute {
    fn validate(&self) -> Result<(), String> {
        let prefix = &self.prefix;
        let valid_prefix = prefix.starts_with('/')
            && prefix.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~')
            })
            && (prefix == "/" || !prefix.ends_with('/'))
            && !prefix.contains("//")
            && !prefix
                .split('/')
                .any(|segment| segment == ".." || segment == ".");
        if !valid_prefix {
            return Err(format!(
                "invalid proxy prefix '{prefix}': it must start with '/', use only letters, digits and - _ . ~ /, and not end with '/' (except '/' on its own)"
            ));
        }
        if !is_valid_upstream(&self.upstream) {
            return Err(format!(
                "invalid proxy upstream '{}': use host:port, like 127.0.0.1:3000",
                self.upstream
            ));
        }
        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            return Err(format!(
                "the proxy timeout_secs for '{prefix}' must be between 1 and 3600"
            ));
        }
        Ok(())
    }
}

/// "host:port" where host is a name, an IPv4 address or a bracketed IPv6 address.
fn is_valid_upstream(upstream: &str) -> bool {
    let Some((host, port)) = upstream.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p != 0);
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty()
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    port_ok && host_ok
}

/// All server settings. Any setting missing from the file gets a default.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind_addr: String,
    pub port: u16,
    pub document_root: String,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
    pub keep_alive_timeout_secs: u64,
    pub max_requests_per_connection: usize,
    pub shutdown_grace_secs: u64,
    /// Paths to a PEM certificate chain and private key. Setting both turns HTTPS on.
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub https_port: u16,
    /// The port HTTPS listens on (the normal `port` is plain HTTP).
    pub redirect_http_to_https: bool,
    /// With HTTPS on, answer plain-HTTP requests with a redirect to HTTPS.
    pub hsts_max_age_secs: u64,
    /// Strict-Transport-Security max-age in seconds. 0 means "don't send it".
    pub tls_handshake_timeout_secs: u64,
    /// How long a client has to finish the TLS handshake.
    /// Compress text-like files for clients that ask for it.
    pub compression: bool,
    /// Files smaller than this are not worth compressing.
    pub compress_min_bytes: u64,
    /// Larger files are not compressed on the fly, because they are held in
    /// memory while compressing.
    pub compress_max_bytes: u64,
    /// Use "file.ext.br" and "file.ext.gz" copies when they exist and are up to date.
    pub serve_precompressed: bool,
    /// Cache-Control for files that match no rule. Empty means "send no header".
    pub default_cache_control: String,
    /// Cache-Control rules by file extension. The first matching rule wins.
    pub cache_rules: Vec<CacheRule>,
    /// Paths forwarded to other programs. See the [[proxy]] blocks in config.toml.
    pub proxy: Vec<ProxyRoute>,
    /// Seconds allowed for connecting to a proxied program.
    pub proxy_connect_timeout_secs: u64,
    /// The largest response accepted from a proxied program (held in memory).
    pub proxy_max_response_bytes: usize,
    /// Write one log line per request (log target "access").
    pub access_log: bool,
    /// Include "?query=strings" in the access log. Off by default.
    pub log_query_strings: bool,
    /// Serve a /status page with counters.
    pub status_page: bool,
    /// The addresses allowed to see it. Exact addresses only.
    pub status_allowed_ips: Vec<String>,
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: "127.0.0.1".to_string(),
            port: 8080,
            document_root: "public".to_string(),
            max_header_bytes: 8192,
            max_body_bytes: 1_048_576,
            read_timeout_secs: 10,
            write_timeout_secs: 30,
            keep_alive_timeout_secs: 5,
            max_requests_per_connection: 100,
            shutdown_grace_secs: 10,
            tls_cert_path: None,
            tls_key_path: None,
            https_port: 8443,
            redirect_http_to_https: true,
            hsts_max_age_secs: 0,
            tls_handshake_timeout_secs: 10,
            compression: true,
            compress_min_bytes: 256,
            compress_max_bytes: 2 * 1024 * 1024,
            serve_precompressed: true,
            default_cache_control: "no-cache".to_string(),
            cache_rules: Vec::new(),
            proxy: Vec::new(),
            proxy_connect_timeout_secs: 5,
            proxy_max_response_bytes: 16 * 1024 * 1024,
            access_log: true,
            log_query_strings: false,
            status_page: false,
            status_allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            max_connections: 1000,
        }
    }
}

impl Config {
    /// Read a config file and check every value.
    pub fn load(path: &str) -> Result<Config, String> {
        let config = Config::load_unchecked(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Read and parse a config file WITHOUT checking the values, so the
    /// caller can report every problem at once with `problems()`.
    pub fn load_unchecked(path: &str) -> Result<Config, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("could not read config file '{path}': {e}"))?;
        Config::parse_toml(&text)
    }

    /// Parse config text and check every value. Separate from `load` so
    /// we can test it easily.
    pub fn from_toml_str(text: &str) -> Result<Config, String> {
        let config = Config::parse_toml(text)?;
        config.validate()?;
        Ok(config)
    }

    fn parse_toml(text: &str) -> Result<Config, String> {
        toml::from_str(text).map_err(|e| format!("invalid config: {e}"))
    }

    /// Check the values, stopping at the first problem.
    pub fn validate(&self) -> Result<(), String> {
        let problems = self.problems();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Every problem with these settings, all at once (empty when all is well).
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        if self.port == 0 {
            problems.push("port must not be 0".to_string());
        }
        if self.max_connections == 0 {
            problems.push("max_connections must be at least 1".to_string());
        }
        if self.max_requests_per_connection == 0 {
            problems.push("max_requests_per_connection must be at least 1".to_string());
        }
        for (name, value) in [
            ("read_timeout_secs", self.read_timeout_secs),
            ("write_timeout_secs", self.write_timeout_secs),
            ("keep_alive_timeout_secs", self.keep_alive_timeout_secs),
            ("shutdown_grace_secs", self.shutdown_grace_secs),
            (
                "tls_handshake_timeout_secs",
                self.tls_handshake_timeout_secs,
            ),
            (
                "proxy_connect_timeout_secs",
                self.proxy_connect_timeout_secs,
            ),
        ] {
            if value == 0 {
                problems.push(format!("{name} must be at least 1"));
            }
        }

        // HTTPS
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            problems.push("tls_cert_path and tls_key_path must be set together".to_string());
        }
        if self.tls_enabled() {
            if self.https_port == 0 {
                problems.push("https_port must not be 0".to_string());
            }
            if self.https_port == self.port {
                problems.push("https_port must be different from port".to_string());
            }
        } else if self.hsts_max_age_secs > 0 {
            problems.push(
                "hsts_max_age_secs needs HTTPS (set tls_cert_path and tls_key_path)".to_string(),
            );
        }

        // Compression
        if self.compress_min_bytes > self.compress_max_bytes {
            problems
                .push("compress_min_bytes must not be larger than compress_max_bytes".to_string());
        }
        if self.compress_max_bytes > 64 * 1024 * 1024 {
            problems.push(
                "compress_max_bytes must be at most 67108864 (64 MiB), because files are held in memory while they are compressed"
                    .to_string(),
            );
        }

        // Caching
        if !is_plain_header_text(&self.default_cache_control) {
            problems.push(
                "default_cache_control may only contain printable ASCII characters".to_string(),
            );
        }
        for rule in &self.cache_rules {
            if rule.extensions.is_empty() {
                problems.push("every cache rule needs at least one extension".to_string());
            }
            for extension in &rule.extensions {
                if extension.is_empty() || !extension.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    problems.push(format!(
                        "invalid extension '{extension}' in a cache rule: use letters and digits only, without a dot"
                    ));
                }
            }
            if rule.cache_control.trim().is_empty() || !is_plain_header_text(&rule.cache_control) {
                problems.push(
                    "every cache rule needs a cache_control value made of printable ASCII characters"
                        .to_string(),
                );
            }
        }

        // Reverse proxy
        if self.proxy_max_response_bytes == 0 || self.proxy_max_response_bytes > 256 * 1024 * 1024 {
            problems.push(
                "proxy_max_response_bytes must be between 1 and 268435456 (256 MiB), because responses are held in memory"
                    .to_string(),
            );
        }
        let mut seen: Vec<&str> = Vec::new();
        for route in &self.proxy {
            if let Err(message) = route.validate() {
                problems.push(message);
            }
            if seen.contains(&route.prefix.as_str()) {
                problems.push(format!("the proxy prefix '{}' is used twice", route.prefix));
            }
            seen.push(route.prefix.as_str());
        }

        // Status page
        if self.status_page && self.status_allowed_ips.is_empty() {
            problems
                .push("status_allowed_ips must not be empty when status_page is on".to_string());
        }
        for address in &self.status_allowed_ips {
            if address.parse::<IpAddr>().is_err() {
                problems.push(format!(
                    "invalid address '{address}' in status_allowed_ips: use exact addresses like 127.0.0.1 or ::1"
                ));
            }
        }

        problems
    }

    /// May this address see the status page?
    pub fn status_ip_allowed(&self, ip: IpAddr) -> bool {
        // "::ffff:127.0.0.1" and "127.0.0.1" are the same machine.
        let ip = ip.to_canonical();
        self.status_allowed_ips
            .iter()
            .filter_map(|text| text.parse::<IpAddr>().ok())
            .any(|allowed| allowed.to_canonical() == ip)
    }

    /// Problems that only show up when you look at the machine: a missing
    /// folder, an unreadable certificate.
    pub fn environment_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        if !Path::new(&self.document_root).is_dir() {
            problems.push(format!(
                "document_root '{}' is not a folder",
                self.document_root
            ));
        }
        if let (Some(cert), Some(key)) = (&self.tls_cert_path, &self.tls_key_path)
            && let Err(message) = crate::tls::build_acceptor(cert, key)
        {
            problems.push(message);
        }

        problems
    }

    /// Is HTTPS turned on?
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// The address HTTPS listens on, like "127.0.0.1:8443".
    pub fn https_address(&self) -> String {
        format!("{}:{}", self.bind_addr, self.https_port)
    }

    /// The Cache-Control value for a file, chosen by its extension.
    pub fn cache_control_for(&self, path: &Path) -> &str {
        if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
            for rule in &self.cache_rules {
                if rule
                    .extensions
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(extension))
                {
                    return &rule.cache_control;
                }
            }
        }
        &self.default_cache_control
    }

    /// The address to listen on, like "127.0.0.1:8080".
    pub fn address(&self) -> String {
        format!("{}:{}", self.bind_addr, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.port, 8080);
        assert_eq!(config.bind_addr, "127.0.0.1");
    }

    #[test]
    fn values_can_be_overridden() {
        let config = Config::from_toml_str("port = 9090").unwrap();
        assert_eq!(config.port, 9090);
        assert_eq!(config.address(), "127.0.0.1:9090");
    }

    #[test]
    fn port_zero_is_rejected() {
        assert!(Config::from_toml_str("port = 0").is_err());
    }

    #[test]
    fn wrong_type_is_rejected() {
        assert!(Config::from_toml_str("port = \"abc\"").is_err());
    }

    #[test]
    fn write_timeout_has_a_default() {
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.write_timeout_secs, 30);
    }

    #[test]
    fn zero_timeouts_are_rejected() {
        assert!(Config::from_toml_str("write_timeout_secs = 0").is_err());
        assert!(Config::from_toml_str("read_timeout_secs = 0").is_err());
    }

    #[test]
    fn keep_alive_settings_have_defaults() {
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.keep_alive_timeout_secs, 5);
        assert_eq!(config.max_requests_per_connection, 100);
    }

    #[test]
    fn zero_keep_alive_settings_are_rejected() {
        assert!(Config::from_toml_str("keep_alive_timeout_secs = 0").is_err());
        assert!(Config::from_toml_str("max_requests_per_connection = 0").is_err());
    }

    #[test]
    fn shutdown_grace_has_a_default() {
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.shutdown_grace_secs, 10);
    }

    #[test]
    fn zero_shutdown_grace_is_rejected() {
        assert!(Config::from_toml_str("shutdown_grace_secs = 0").is_err());
    }

    #[test]
    fn https_is_off_by_default() {
        let config = Config::from_toml_str("").unwrap();
        assert!(!config.tls_enabled());
        assert_eq!(config.https_port, 8443);
        assert!(config.redirect_http_to_https);
        assert_eq!(config.hsts_max_age_secs, 0);
    }

    #[test]
    fn certificate_and_key_must_come_together() {
        assert!(Config::from_toml_str("tls_cert_path = \"cert.pem\"").is_err());
        assert!(Config::from_toml_str("tls_key_path = \"key.pem\"").is_err());
    }

    #[test]
    fn certificate_and_key_together_turn_https_on() {
        let config =
            Config::from_toml_str("tls_cert_path = \"cert.pem\"\ntls_key_path = \"key.pem\"")
                .unwrap();
        assert!(config.tls_enabled());
        assert_eq!(config.https_address(), "127.0.0.1:8443");
    }

    #[test]
    fn https_port_must_differ_from_the_http_port() {
        let text = "tls_cert_path = \"c\"\ntls_key_path = \"k\"\nport = 8443";
        assert!(Config::from_toml_str(text).is_err());
    }

    #[test]
    fn hsts_needs_https() {
        assert!(Config::from_toml_str("hsts_max_age_secs = 60").is_err());
        let text = "tls_cert_path = \"c\"\ntls_key_path = \"k\"\nhsts_max_age_secs = 60";
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn zero_handshake_timeout_is_rejected() {
        assert!(Config::from_toml_str("tls_handshake_timeout_secs = 0").is_err());
    }

    #[test]
    fn compression_and_caching_have_defaults() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.compression);
        assert_eq!(config.compress_min_bytes, 256);
        assert_eq!(config.compress_max_bytes, 2 * 1024 * 1024);
        assert!(config.serve_precompressed);
        assert_eq!(config.default_cache_control, "no-cache");
        assert!(config.cache_rules.is_empty());
    }

    const RULES: &str = r#"
cache_rules = [
  { extensions = ["css", "js"], cache_control = "public, max-age=3600" },
  { extensions = ["png"], cache_control = "public, max-age=86400, immutable" },
]
"#;

    #[test]
    fn cache_rules_are_read_from_toml() {
        let config = Config::from_toml_str(RULES).unwrap();
        assert_eq!(config.cache_rules.len(), 2);
        assert_eq!(config.cache_rules[0].extensions, vec!["css", "js"]);
        assert_eq!(
            config.cache_rules[1].cache_control,
            "public, max-age=86400, immutable"
        );
    }

    #[test]
    fn cache_control_is_chosen_by_extension() {
        let config = Config::from_toml_str(RULES).unwrap();
        assert_eq!(
            config.cache_control_for(Path::new("/site/app.CSS")),
            "public, max-age=3600"
        );
        assert_eq!(
            config.cache_control_for(Path::new("a/b/logo.png")),
            "public, max-age=86400, immutable"
        );
        assert_eq!(
            config.cache_control_for(Path::new("index.html")),
            "no-cache"
        );
        assert_eq!(config.cache_control_for(Path::new("README")), "no-cache");
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let text = r#"
cache_rules = [
  { extensions = ["css"], cache_control = "first" },
  { extensions = ["css"], cache_control = "second" },
]
"#;
        let config = Config::from_toml_str(text).unwrap();
        assert_eq!(config.cache_control_for(Path::new("a.css")), "first");
    }

    #[test]
    fn bad_cache_and_compression_settings_are_rejected() {
        for text in [
            "default_cache_control = \"a\\nb\"",
            r#"cache_rules = [{ extensions = [], cache_control = "x" }]"#,
            r#"cache_rules = [{ extensions = [".css"], cache_control = "x" }]"#,
            r#"cache_rules = [{ extensions = ["css"], cache_control = "" }]"#,
            r#"cache_rules = [{ extensions = ["css"], cache_control = "a\r\nSet-Cookie: x=1" }]"#,
            "compress_min_bytes = 100\ncompress_max_bytes = 50",
            "compress_max_bytes = 999999999999",
        ] {
            assert!(
                Config::from_toml_str(text).is_err(),
                "should reject: {text}"
            );
        }
    }

    const PROXY: &str = r#"
[[proxy]]
prefix = "/api"
upstream = "127.0.0.1:3000"

[[proxy]]
prefix = "/api/v2"
upstream = "localhost:4000"
strip_prefix = false
timeout_secs = 5
"#;

    #[test]
    fn there_are_no_proxy_routes_by_default() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.proxy.is_empty());
        assert_eq!(config.proxy_connect_timeout_secs, 5);
        assert_eq!(config.proxy_max_response_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn proxy_routes_are_read_from_toml() {
        let config = Config::from_toml_str(PROXY).unwrap();
        assert_eq!(config.proxy.len(), 2);

        // Unset values get their defaults.
        assert_eq!(config.proxy[0].prefix, "/api");
        assert_eq!(config.proxy[0].upstream, "127.0.0.1:3000");
        assert!(config.proxy[0].strip_prefix);
        assert_eq!(config.proxy[0].timeout_secs, 30);

        assert_eq!(config.proxy[1].upstream, "localhost:4000");
        assert!(!config.proxy[1].strip_prefix);
        assert_eq!(config.proxy[1].timeout_secs, 5);
    }

    #[test]
    fn good_upstream_addresses_are_accepted() {
        for upstream in [
            "127.0.0.1:3000",
            "localhost:4000",
            "[::1]:3000",
            "my-app.internal:8080",
        ] {
            let text = format!("[[proxy]]\nprefix = \"/api\"\nupstream = \"{upstream}\"");
            assert!(
                Config::from_toml_str(&text).is_ok(),
                "should accept {upstream}"
            );
        }
    }

    #[test]
    fn bad_proxy_routes_are_rejected() {
        for (prefix, upstream) in [
            ("api", "127.0.0.1:3000"),
            ("/api/", "127.0.0.1:3000"),
            ("//api", "127.0.0.1:3000"),
            ("/a/../b", "127.0.0.1:3000"),
            ("/a b", "127.0.0.1:3000"),
            ("/ap%69", "127.0.0.1:3000"),
            ("", "127.0.0.1:3000"),
            ("/api", ""),
            ("/api", "localhost"),
            ("/api", "localhost:0"),
            ("/api", "localhost:99999"),
            ("/api", "a b:80"),
            ("/api", "http://x:80"),
            ("/api", "[::1:80"),
            ("/api", "evil.com/path:80"),
        ] {
            let text = format!("[[proxy]]\nprefix = \"{prefix}\"\nupstream = \"{upstream}\"");
            assert!(
                Config::from_toml_str(&text).is_err(),
                "should reject {prefix:?} -> {upstream:?}"
            );
        }
    }

    #[test]
    fn the_root_prefix_is_allowed() {
        let text = "[[proxy]]\nprefix = \"/\"\nupstream = \"127.0.0.1:3000\"";
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn other_bad_proxy_settings_are_rejected() {
        for text in [
            // missing upstream
            "[[proxy]]\nprefix = \"/api\"",
            // timeouts out of range
            "[[proxy]]\nprefix = \"/api\"\nupstream = \"a:80\"\ntimeout_secs = 0",
            "[[proxy]]\nprefix = \"/api\"\nupstream = \"a:80\"\ntimeout_secs = 3601",
            // a misspelt setting must not be silently ignored
            "[[proxy]]\nprefix = \"/api\"\nupstream = \"a:80\"\nstripprefix = false",
            // the same prefix twice
            "[[proxy]]\nprefix = \"/api\"\nupstream = \"a:80\"\n[[proxy]]\nprefix = \"/api\"\nupstream = \"b:80\"",
            "proxy_connect_timeout_secs = 0",
            "proxy_max_response_bytes = 0",
            "proxy_max_response_bytes = 999999999999",
        ] {
            assert!(
                Config::from_toml_str(text).is_err(),
                "should reject: {text}"
            );
        }
    }

    #[test]
    fn a_good_config_has_no_problems() {
        assert!(Config::default().problems().is_empty());
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let config = Config {
            port: 0,
            max_connections: 0,
            read_timeout_secs: 0,
            tls_cert_path: Some("cert.pem".to_string()),
            ..Config::default()
        };
        let problems = config.problems();
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("port must not be 0")));
        assert!(problems.iter().any(|p| p.contains("max_connections")));
        assert!(problems.iter().any(|p| p.contains("read_timeout_secs")));
        assert!(problems.iter().any(|p| p.contains("together")));
    }

    #[test]
    fn validate_joins_the_problems() {
        let config = Config {
            port: 0,
            max_connections: 0,
            ..Config::default()
        };
        let message = config.validate().unwrap_err();
        assert!(message.contains("port must not be 0"));
        assert!(message.contains("max_connections"));
    }

    #[test]
    fn logging_and_status_settings_have_safe_defaults() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.access_log);
        assert!(!config.log_query_strings);
        assert!(!config.status_page);
        assert_eq!(config.status_allowed_ips, vec!["127.0.0.1", "::1"]);
    }

    #[test]
    fn loopback_may_see_the_status_page_by_default() {
        let config = Config::default();
        assert!(config.status_ip_allowed("127.0.0.1".parse().unwrap()));
        assert!(config.status_ip_allowed("::1".parse().unwrap()));
        assert!(config.status_ip_allowed("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!config.status_ip_allowed("203.0.113.9".parse().unwrap()));
        assert!(!config.status_ip_allowed("::2".parse().unwrap()));
    }

    #[test]
    fn bad_status_addresses_are_rejected() {
        assert!(Config::from_toml_str("status_allowed_ips = [\"not an address\"]").is_err());
        assert!(Config::from_toml_str("status_allowed_ips = [\"10.0.0.0/8\"]").is_err());
        assert!(Config::from_toml_str("status_page = true\nstatus_allowed_ips = []").is_err());
        assert!(Config::from_toml_str("status_allowed_ips = []").is_ok());
        assert!(
            Config::from_toml_str(
                "status_page = true\nstatus_allowed_ips = [\"10.1.2.3\", \"2001:db8::1\"]"
            )
            .is_ok()
        );
    }

    #[test]
    fn environment_problems_notice_a_missing_document_root() {
        let missing = Config {
            document_root: "definitely-not-a-folder".to_string(),
            ..Config::default()
        };
        let problems = missing.environment_problems();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("document_root"));

        let fine = Config {
            document_root: std::env::temp_dir().to_str().unwrap().to_string(),
            ..Config::default()
        };
        assert!(fine.environment_problems().is_empty());
    }
}
