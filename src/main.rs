mod config;
mod handlers;
mod http;
mod net_util;
mod router;
mod static_files;

use clap::Parser;
use config::Config;
use http::chunked::decode_chunked;
use http::parser::{body_framing, parse_request, BodyFraming, ParseError, ParseResult};
use http::request::Method;
use http::response::{FileSlice, Response};
use net_util::{is_routine_disconnect, read_with_deadline, write_all_timeout, ReadOutcome};
use router::Router;
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;
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
    info!(
        "Limits: {} connections, {}s to send a request, {}s write timeout",
        config.max_connections, config.read_timeout_secs, config.write_timeout_secs
    );

    let write_timeout = Duration::from_secs(config.write_timeout_secs);
    // The semaphore hands out one "permit" per connection we are willing to
    // handle at once. When all permits are taken, new connections are refused.
    let limiter = Arc::new(Semaphore::new(config.max_connections));
    let config = Arc::new(config);
    let router = Arc::new(build_router());

    let listener = TcpListener::bind(&address).await?;
    info!("Listening on http://{address}");

    loop {
        // A failed accept (for example a connection that died during the
        // handshake) must never stop the whole server.
        let (stream, addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        debug!("New connection from {addr}");

        let permit = match Arc::clone(&limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("connection limit reached, refusing {addr}");
                tokio::spawn(refuse_busy(stream, write_timeout));
                continue;
            }
        };

        let config = Arc::clone(&config);
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            // Holding the permit until this task ends keeps the slot taken.
            let _permit = permit;
            if let Err(e) = handle_connection(stream, config, router).await {
                if is_routine_disconnect(&e) {
                    debug!("{addr}: connection ended early: {e}");
                } else {
                    error!("{addr}: connection error: {e}");
                }
            }
        });
    }
}

/// Tell a client we are full, then hang up.
async fn refuse_busy(mut stream: TcpStream, write_timeout: Duration) {
    let response = Response::text(503, "503 Service Unavailable\n").header("Retry-After", "5");
    let _ = write_all_timeout(&mut stream, &response.to_bytes(true), write_timeout).await;
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<Config>,
    router: Arc<Router>,
) -> std::io::Result<()> {
    let read_limit = Duration::from_secs(config.read_timeout_secs);
    let write_timeout = Duration::from_secs(config.write_timeout_secs);

    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];

    // Step 1: read until we have all the headers, before the deadline.
    let header_deadline = Instant::now() + read_limit;
    let (mut request, consumed) = loop {
        match read_with_deadline(&mut stream, &mut chunk, header_deadline).await? {
            ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
            ReadOutcome::Closed => {
                debug!("client closed the connection before sending a full request");
                return Ok(());
            }
            ReadOutcome::TimedOut => {
                if buffer.is_empty() {
                    // Connected but never said anything: just hang up.
                    debug!("closing a connection that sent nothing");
                    return Ok(());
                }
                return request_timeout(&mut stream, write_timeout).await;
            }
        }

        match parse_request(&buffer, config.max_header_bytes) {
            Ok(ParseResult::Complete { request, consumed }) => break (request, consumed),
            Ok(ParseResult::Incomplete) => continue,
            Err(e) => {
                reject(&mut stream, e, write_timeout).await?;
                return Ok(());
            }
        }
    };

    // Step 2: decide whether there is a body, and how it is delimited.
    let framing = match body_framing(&request, config.max_body_bytes) {
        Ok(framing) => framing,
        Err(e) => {
            reject(&mut stream, e, write_timeout).await?;
            return Ok(());
        }
    };

    // Step 3: read the body, with its own deadline.
    match framing {
        BodyFraming::None => {}

        BodyFraming::ContentLength(length) => {
            let body_deadline = Instant::now() + read_limit;
            let mut body = buffer[consumed..].to_vec();
            while body.len() < length {
                match read_with_deadline(&mut stream, &mut chunk, body_deadline).await? {
                    ReadOutcome::Data(n) => body.extend_from_slice(&chunk[..n]),
                    ReadOutcome::Closed => {
                        debug!("client closed the connection before sending the full body");
                        return Ok(());
                    }
                    ReadOutcome::TimedOut => {
                        return request_timeout(&mut stream, write_timeout).await;
                    }
                }
            }
            body.truncate(length);
            request.body = body;
        }

        BodyFraming::Chunked => {
            let body_deadline = Instant::now() + read_limit;
            buffer.drain(..consumed);
            let mut body: Vec<u8> = Vec::new();
            let mut pos = 0;

            loop {
                match decode_chunked(&buffer, &mut pos, &mut body, config.max_body_bytes) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => {
                        reject(&mut stream, e, write_timeout).await?;
                        return Ok(());
                    }
                }

                buffer.drain(..pos);
                pos = 0;

                match read_with_deadline(&mut stream, &mut chunk, body_deadline).await? {
                    ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
                    ReadOutcome::Closed => {
                        debug!("client closed the connection in the middle of a chunked body");
                        return Ok(());
                    }
                    ReadOutcome::TimedOut => {
                        return request_timeout(&mut stream, write_timeout).await;
                    }
                }
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
    send(&mut stream, response, include_body, write_timeout).await
}

/// The client was too slow sending its request.
async fn request_timeout(stream: &mut TcpStream, write_timeout: Duration) -> std::io::Result<()> {
    warn!("timed out waiting for the client to finish its request");
    let response = Response::text(408, "408 Request Timeout\n");
    send(stream, response, true, write_timeout).await
}

/// Write a response to the client. Small bodies go out in one write. File
/// slices are streamed from disk in small pieces, so memory use stays tiny
/// whatever the file size. Every write has a time limit, so a client that
/// stops reading cannot hold the connection forever.
async fn send(
    stream: &mut TcpStream,
    response: Response,
    include_body: bool,
    write_timeout: Duration,
) -> std::io::Result<()> {
    match &response.file {
        None => {
            write_all_timeout(stream, &response.to_bytes(include_body), write_timeout).await?;
        }
        Some(slice) => {
            // Open the file BEFORE sending any headers, so a failure can still
            // become a clean error response.
            let mut file = match open_slice(slice).await {
                Ok(file) => file,
                Err(e) => {
                    warn!("could not open {}: {e}", slice.path.display());
                    let failure = Response::text(500, "500 Internal Server Error\n");
                    write_all_timeout(stream, &failure.to_bytes(include_body), write_timeout)
                        .await?;
                    return stream.flush().await;
                }
            };

            write_all_timeout(stream, &response.head_bytes(), write_timeout).await?;

            if include_body {
                let mut remaining = slice.len;
                let mut buf = vec![0u8; 32 * 1024];
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    let n = file.read(&mut buf[..want]).await?;
                    if n == 0 {
                        // We promised more bytes than the file had left, so it
                        // changed while we were sending it. Drop the connection.
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "file changed while it was being sent",
                        ));
                    }
                    write_all_timeout(stream, &buf[..n], write_timeout).await?;
                    remaining -= n as u64;
                }
            }
        }
    }
    stream.flush().await
}

/// Open a file and jump to where the slice starts.
async fn open_slice(slice: &FileSlice) -> std::io::Result<tokio::fs::File> {
    let mut file = tokio::fs::File::open(&slice.path).await?;
    file.seek(SeekFrom::Start(slice.start)).await?;
    Ok(file)
}

/// Log a rejected request and tell the client why.
async fn reject(
    stream: &mut TcpStream,
    e: ParseError,
    write_timeout: Duration,
) -> std::io::Result<()> {
    warn!("rejected request: {e:?}");
    let message = format!("{} {}\n", e.status_code(), e.reason_phrase());
    send(
        stream,
        Response::text(e.status_code(), message),
        true,
        write_timeout,
    )
    .await
}