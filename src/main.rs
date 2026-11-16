mod config;
mod http;

use clap::Parser;
use config::Config;
use http::parser::{BodyFraming, ParseError, ParseResult, body_framing, parse_request};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

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

    let address = config.address();
    let config = Arc::new(config);

    let listener = TcpListener::bind(&address).await?;
    info!("Listening on http://{address}");

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("New connection from {addr}");

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config).await {
                error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, config: Arc<Config>) -> std::io::Result<()> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];

    // Step 1: read until we have all the headers.
    let (mut request, consumed) = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            debug!("client closed the connection before sending a full request");
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..n]);

        match parse_request(&buffer, config.max_header_bytes) {
            Ok(ParseResult::Complete { request, consumed }) => break (request, consumed),
            Ok(ParseResult::Incomplete) => continue,
            Err(e) => {
                reject(&mut stream, e).await?;
                return Ok(());
            }
        }
    };

    // Step 2: decide whether there is a body, and how long it is.
    let framing = match body_framing(&request, config.max_body_bytes) {
        Ok(framing) => framing,
        Err(e) => {
            reject(&mut stream, e).await?;
            return Ok(());
        }
    };

    // Step 3: read exactly that many body bytes.
    if let BodyFraming::ContentLength(length) = framing {
        // Some body bytes may already have arrived together with the headers.
        let mut body = buffer[consumed..].to_vec();
        while body.len() < length {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                debug!("client closed the connection before sending the full body");
                return Ok(());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        // Drop anything beyond the declared length (we close after each response).
        body.truncate(length);
        request.body = body;
    }

    info!(
        "{:?} {} (body: {} bytes)",
        request.method,
        request.target,
        request.body.len()
    );

    // For now, echo back what we understood.
    let mut body = format!(
        "Method: {:?}\nPath: {}\nVersion: {:?}\n\nHeaders:\n",
        request.method, request.target, request.version
    );
    for (name, value) in &request.headers {
        body.push_str(&format!("  {name}: {value}\n"));
    }
    body.push_str(&format!(
        "\nBody ({} bytes):\n{}\n",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    ));

    send_response(&mut stream, 200, "OK", &body).await
}

/// Log a rejected request and tell the client why.
async fn reject(stream: &mut TcpStream, e: ParseError) -> std::io::Result<()> {
    warn!("rejected request: {e:?}");
    let body = format!("{} {}\n", e.status_code(), e.reason_phrase());
    send_response(stream, e.status_code(), e.reason_phrase(), &body).await
}

async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}
