mod config;

use clap::Parser;
use config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Set up logging. The level comes from the RUST_LOG variable, default "info".
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

    // A command-line port beats the config file.
    if let Some(port) = args.port {
        config.port = port;
    }
    if let Err(message) = config.validate() {
        error!("invalid settings: {message}");
        std::process::exit(1);
    }

    let address = config.address();
    let listener = TcpListener::bind(&address).await?;
    info!("Listening on http://{address}");

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("New connection from {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    debug!("Received {n} bytes");

    let body = "Hello from my Rust web server!\n";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
