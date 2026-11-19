use serde::Deserialize;
use std::fs;

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
            max_connections: 1000,
        }
    }
}

impl Config {
    /// Read and check a config file.
    pub fn load(path: &str) -> Result<Config, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("could not read config file '{path}': {e}"))?;
        Config::from_toml_str(&text)
    }

    /// Parse config text. Separate from `load` so we can test it easily.
    pub fn from_toml_str(text: &str) -> Result<Config, String> {
        let config: Config = toml::from_str(text).map_err(|e| format!("invalid config: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Is HTTPS turned on?
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// The address HTTPS listens on, like "127.0.0.1:8443".
    pub fn https_address(&self) -> String {
        format!("{}:{}", self.bind_addr, self.https_port)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("port must not be 0".to_string());
        }
        if self.max_connections == 0 {
            return Err("max_connections must be at least 1".to_string());
        }
        if self.read_timeout_secs == 0 {
            return Err("read_timeout_secs must be at least 1".to_string());
        }
        if self.write_timeout_secs == 0 {
            return Err("write_timeout_secs must be at least 1".to_string());
        }
        if self.keep_alive_timeout_secs == 0 {
            return Err("keep_alive_timeout_secs must be at least 1".to_string());
        }
        if self.max_requests_per_connection == 0 {
            return Err("max_requests_per_connection must be at least 1".to_string());
        }
        if self.shutdown_grace_secs == 0 {
            return Err("shutdown_grace_secs must be at least 1".to_string());
        }
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            return Err("tls_cert_path and tls_key_path must be set together".to_string());
        }
        if self.tls_handshake_timeout_secs == 0 {
            return Err("tls_handshake_timeout_secs must be at least 1".to_string());
        }
        if self.tls_enabled() {
            if self.https_port == 0 {
                return Err("https_port must not be 0".to_string());
            }
            if self.https_port == self.port {
                return Err("https_port must be different from port".to_string());
            }
        } else if self.hsts_max_age_secs > 0 {
            return Err(
                "hsts_max_age_secs needs HTTPS (set tls_cert_path and tls_key_path)".to_string(),
            );
        }
        Ok(())
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
}
