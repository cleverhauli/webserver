mod config;
mod connection;
mod handlers;
mod http;
mod net_util;
mod router;
mod static_files;

use clap::Parser;
use config::Config;
use connection::{Failure, Incoming, client_allows_keep_alive, read_request};
use http::parser::ParseError;
use http::request::Method;
use http::response::{FileSlice, Response};
use net_util::{is_routine_disconnect, write_all_timeout};
use router::Router;
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
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

    let address = config.address();
    info!("Serving files from '{}'", config.document_root);
    info!(
        "Limits: {} connections, {}s to send a request, {}s write timeout",
        config.max_connections, config.read_timeout_secs, config.write_timeout_secs
    );
    info!(
        "Keep-alive: {}s idle wait, up to {} requests per connection",
        config.keep_alive_timeout_secs, config.max_requests_per_connection
    );

    let write_timeout = Duration::from_secs(config.write_timeout_secs);
    let grace = Duration::from_secs(config.shutdown_grace_secs);
    let max_connections = config.max_connections;

    // The semaphore hands out one "permit" per connection we are willing to
    // handle at once. When all permits are taken, new connections are refused.
    // At shutdown, getting ALL the permits back means every connection is done.
    let limiter = Arc::new(Semaphore::new(max_connections));
    let config = Arc::new(config);
    let router = Arc::new(build_router());

    // A one-value broadcast: false while running, true once we are stopping.
    let (stop_tx, stop_rx) = watch::channel(false);

    let listener = TcpListener::bind(&address).await?;
    info!("Listening on http://{address} (press Ctrl+C to stop)");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        // Wait for a new connection OR for the signal to stop.
        let accepted = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };

        // A failed accept (for example a connection that died during the
        // handshake) must never stop the whole server.
        let (stream, addr) = match accepted {
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
        let stop = stop_rx.clone();
        tokio::spawn(async move {
            // Holding the permit until this task ends keeps the slot taken.
            let _permit = permit;
            if let Err(e) = handle_connection(stream, config, router, stop).await {
                if is_routine_disconnect(&e) {
                    debug!("{addr}: connection ended early: {e}");
                } else {
                    error!("{addr}: connection error: {e}");
                }
            }
            debug!("{addr}: connection closed");
        });
    }

    // ---------- graceful shutdown ----------
    info!("Shutting down: no longer accepting new connections");

    // Closing the listener makes the operating system refuse newcomers.
    drop(listener);
    // Tell every connection: finish what you are doing, then close.
    stop_tx.send_replace(true);

    let in_flight = max_connections.saturating_sub(limiter.available_permits());
    if in_flight > 0 {
        info!(
            "Waiting up to {}s for {in_flight} connection(s) to finish (press Ctrl+C again to stop now)",
            grace.as_secs()
        );
    }

    // Getting every permit back means every connection has ended.
    let all_permits = u32::try_from(max_connections).unwrap_or(u32::MAX);
    let finished_in_time = tokio::select! {
        result = tokio::time::timeout(grace, limiter.acquire_many(all_permits)) => result.is_ok(),
        _ = tokio::signal::ctrl_c() => {
            warn!("Second Ctrl+C: not waiting any longer");
            false
        }
    };

    if finished_in_time {
        info!("All connections finished. Goodbye!");
    } else {
        let cut_off = max_connections.saturating_sub(limiter.available_permits());
        warn!("Stopping now. {cut_off} connection(s) were cut off.");
    }

    // Returning from main ends the program and drops any connection left.
    Ok(())
}

/// Tell a client we are full, then hang up.
async fn refuse_busy(mut stream: TcpStream, write_timeout: Duration) {
    let response = Response::text(503, "503 Service Unavailable\n").header("Retry-After", "5");
    let _ = write_all_timeout(&mut stream, &response.to_bytes(true), write_timeout).await;
}

/// Serve requests on one connection until it should close.
async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<Config>,
    router: Arc<Router>,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let first_request_wait = Duration::from_secs(config.read_timeout_secs);
    let idle_wait = Duration::from_secs(config.keep_alive_timeout_secs);
    let write_timeout = Duration::from_secs(config.write_timeout_secs);

    // Bytes read from the client but not yet used. It can hold the start of
    // the next request while we answer the current one.
    let mut buffer: Vec<u8> = Vec::new();
    let mut served: usize = 0;

    loop {
        // A brand-new connection gets the normal read limit to speak up.
        // After that, we only wait the (shorter) idle time for the next request.
        let wait = if served == 0 {
            first_request_wait
        } else {
            idle_wait
        };

        let request = match read_request(&mut stream, &mut buffer, &config, wait, &mut stop).await?
        {
            Incoming::Request(request) => request,
            Incoming::Finished => {
                debug!("connection finished after {served} request(s)");
                return Ok(());
            }
            // After an error we no longer trust where the next request
            // would start, so we always close.
            Incoming::Failed(Failure::Parse(e)) => {
                return reject(&mut stream, e, write_timeout).await;
            }
            Incoming::Failed(Failure::TimedOut) => {
                return request_timeout(&mut stream, write_timeout).await;
            }
        };
        served += 1;

        // Decide who answers. A registered route wins. Otherwise GET and
        // HEAD requests look for a file in the document root.
        let mut response = if router.knows_path(&request) {
            router.handle(&request)
        } else if matches!(request.method, Method::Get | Method::Head) {
            static_files::serve(&config.document_root, &request).await
        } else {
            router.handle(&request)
        };

        // Keep the connection open only if the client allows it, we have not
        // served too many requests, AND the server is not shutting down.
        let keep_open = client_allows_keep_alive(&request)
            && served < config.max_requests_per_connection
            && !*stop.borrow();
        response.keep_alive = keep_open;

        info!(
            "{} {} -> {}",
            request.method.as_str(),
            request.target,
            response.status
        );

        let include_body = request.method != Method::Head;
        let sent_cleanly = send(&mut stream, response, include_body, write_timeout).await?;
        if !keep_open || !sent_cleanly {
            return Ok(());
        }
    }
}

/// The client was too slow sending its request.
async fn request_timeout(stream: &mut TcpStream, write_timeout: Duration) -> std::io::Result<()> {
    warn!("timed out waiting for the client to finish its request");
    let response = Response::text(408, "408 Request Timeout\n");
    send(stream, response, true, write_timeout).await?;
    Ok(())
}

/// Write a response to the client. Returns `true` if the connection may be
/// used again, or `false` if it must be closed.
///
/// Small bodies go out in one write. File slices are streamed from disk in
/// small pieces, so memory use stays tiny whatever the file size. Every
/// write has a time limit, so a client that stops reading cannot hold the
/// connection forever.
async fn send(
    stream: &mut TcpStream,
    response: Response,
    include_body: bool,
    write_timeout: Duration,
) -> std::io::Result<bool> {
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
                    // This error response says "Connection: close", so the
                    // connection must really close afterwards.
                    let failure = Response::text(500, "500 Internal Server Error\n");
                    write_all_timeout(stream, &failure.to_bytes(include_body), write_timeout)
                        .await?;
                    stream.flush().await?;
                    return Ok(false);
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
    stream.flush().await?;
    Ok(true)
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
    .await?;
    Ok(())
}
