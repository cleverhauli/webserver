//! The config.toml that ships with the project must work out of the box.

use std::path::Path;
use webserver::config::Config;

#[test]
fn the_shipped_config_works_on_a_fresh_checkout() {
    // Tests run from the project folder, so this is the real config.toml.
    let config = Config::load("config.toml").expect("config.toml must be valid");

    assert!(
        !config.tls_enabled(),
        "config.toml must ship with HTTPS commented out: certificates are never committed"
    );
    assert_eq!(
        config.hsts_max_age_secs, 0,
        "HSTS must ship switched off: browsers remember it"
    );
    assert!(
        config.cache_rules.is_empty(),
        "cache rules must ship commented out, or edits will not show up while developing"
    );
    assert!(
        config.proxy.is_empty(),
        "config.toml must ship with the example proxy route commented out"
    );
    assert!(
        Path::new(&config.document_root).is_dir(),
        "the document root '{}' must exist in the repository",
        config.document_root
    );
}
