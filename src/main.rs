use clap::Parser;
use tracing::{error, info};
use webserver::config::Config;
use webserver::server::Server;

/// Command-line options.
#[derive(Parser)]
#[command(name = "webserver", about = "A small web server written in Rust")]
struct Args {
    /// Path to the config file
    #[arg(long, default_value = "config.toml")]
    config: String,

    /// Override the port from the config file
    #[arg(long)]
    port: Option<u16>,
}

/// Completes when the user asks the server to stop: Ctrl+C everywhere,
/// and also SIGTERM on Linux and macOS (what service managers send).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }

    if let Err(e) = tokio::signal::ctrl_c().await {
        // Without a working signal handler we can never be asked to stop
        // gracefully, but the server itself should keep running.
        error!("could not listen for Ctrl+C: {e}");
        std::future::pending::<()>().await;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let mut config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(message) => {
            error!("{message}");
            std::process::exit(1);
        }
    };

    if let Some(port) = args.port {
        config.port = port;
    }
    if let Err(message) = config.validate() {
        error!("invalid settings: {message}");
        std::process::exit(1);
    }

    info!("Serving files from '{}'", config.document_root);
    info!(
        "Limits: {} connections, {}s to send a request, {}s write timeout",
        config.max_connections, config.read_timeout_secs, config.write_timeout_secs
    );
    info!(
        "Keep-alive: {}s idle wait, up to {} requests per connection",
        config.keep_alive_timeout_secs, config.max_requests_per_connection
    );
    for route in &config.proxy {
        info!(
            "Proxy: {} -> {} ({}s timeout)",
            route.prefix, route.upstream, route.timeout_secs
        );
    }
    let redirecting = config.tls_enabled() && config.redirect_http_to_https;
    let hsts = config.hsts_max_age_secs;

    let server = match Server::bind(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("could not start the server: {e}");
            std::process::exit(1);
        }
    };

    if let Ok(addr) = server.local_addr() {
        if redirecting {
            info!("Listening on http://{addr} (redirects to HTTPS)");
        } else {
            info!("Listening on http://{addr}");
        }
    }
    if let Some(addr) = server.https_addr() {
        info!("Listening on https://{addr}");
        if hsts > 0 {
            info!("HSTS is on: browsers will insist on HTTPS for {hsts}s");
        }
    }
    info!("Press Ctrl+C to stop");

    // A second Ctrl+C while shutting down stops everything at once.
    let force_stop = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    server.run(shutdown_signal(), force_stop).await
}
