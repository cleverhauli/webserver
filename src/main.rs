mod config;
mod handlers;
mod http;
mod router;
mod static_files;

use clap::Parser;
use config::Config;
use http::chunked::decode_chunked;
use http::parser::{body_framing, parse_request, BodyFraming, ParseError, ParseResult};
use http::request::Method;
use http::response::Response;
use router::Router;
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

/// The special pages this server offers. Everything else is looked up as a
/// file in the document root.
fn build_router() -> Router {
    Router::default()
        .add(Method::Get, "/health", handlers::health)
        .add(Method::Get, "/about", handlers::about)
        .add(Method::Get, "/echo", handlers::echo)
        .add(Method::Post, "/echo", handlers::echo)
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
    info!("Serving files from '{}'", config.document_root);
    let config = Arc::new(config);
    let router = Arc::new(build_router());

    let listener = TcpListener::bind(&address).await?;
    info!("Listening on http://{address}");

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("New connection from {addr}");

        let config = Arc::clone(&config);
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, router).await {
                error!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<Config>,
    router: Arc<Router>,
) -> std::io::Result<()> {
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

    // Step 2: decide whether there is a body, and how it is delimited.
    let framing = match body_framing(&request, config.max_body_bytes) {
        Ok(framing) => framing,
        Err(e) => {
            reject(&mut stream, e).await?;
            return Ok(());
        }
    };

    // Step 3: read the body.
    match framing {
        BodyFraming::None => {}

        BodyFraming::ContentLength(length) => {
            let mut body = buffer[consumed..].to_vec();
            while body.len() < length {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    debug!("client closed the connection before sending the full body");
                    return Ok(());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(length);
            request.body = body;
        }

        BodyFraming::Chunked => {
            buffer.drain(..consumed);
            let mut body: Vec<u8> = Vec::new();
            let mut pos = 0;

            loop {
                match decode_chunked(&buffer, &mut pos, &mut body, config.max_body_bytes) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => {
                        reject(&mut stream, e).await?;
                        return Ok(());
                    }
                }

                buffer.drain(..pos);
                pos = 0;

                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    debug!("client closed the connection in the middle of a chunked body");
                    return Ok(());
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
            request.body = body;
        }
    }

    // Step 4: decide who answers. A registered route wins. Otherwise GET and
    // HEAD requests look for a file in the document root.
    let response = if router.knows_path(&request) {
        router.handle(&request)
    } else if matches!(request.method, Method::Get | Method::Head) {
        static_files::serve(&config.document_root, &request).await
    } else {
        router.handle(&request)
    };

    info!(
        "{} {} -> {}",
        request.method.as_str(),
        request.target,
        response.status
    );

    let include_body = request.method != Method::Head;
    send(&mut stream, response, include_body).await
}

/// Write a response to the client.
async fn send(
    stream: &mut TcpStream,
    response: Response,
    include_body: bool,
) -> std::io::Result<()> {
    stream.write_all(&response.to_bytes(include_body)).await?;
    stream.flush().await
}

/// Log a rejected request and tell the client why.
async fn reject(stream: &mut TcpStream, e: ParseError) -> std::io::Result<()> {
    warn!("rejected request: {e:?}");
    let message = format!("{} {}\n", e.status_code(), e.reason_phrase());
    send(stream, Response::text(e.status_code(), message), true).await
}