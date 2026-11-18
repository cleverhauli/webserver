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
}
