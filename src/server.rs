//! The server itself: listening ports, connection limits and graceful shutdown.

use crate::config::Config;
use crate::connection::{
    Failure, Incoming, client_allows_keep_alive, read_request, shutdown_requested,
};
use crate::handlers;
use crate::http::parser::ParseError;
use crate::http::request::Method;
use crate::http::response::{FileSlice, Response};
use crate::net_util::{is_routine_disconnect, write_all_timeout};
use crate::redirect::https_redirect;
use crate::router::Router;
use crate::static_files;
use crate::tls::build_acceptor;
use std::future::Future;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// The special pages this server offers. Everything else is looked up as a
/// file in the document root.
pub fn build_router() -> Router {
    Router::default()
        .add(Method::Get, "/health", handlers::health)
        .add(Method::Get, "/about", handlers::about)
        .add(Method::Get, "/echo", handlers::echo)
        .add(Method::Post, "/echo", handlers::echo)
}

/// What a listening port does with the connections it accepts.
#[derive(Clone)]
enum Listener {
    /// Plain HTTP that serves the site.
    Http,
    /// Plain HTTP that only sends visitors to the HTTPS port.
    Redirect { https_port: u16 },
    /// HTTPS that serves the site.
    Https(TlsAcceptor),
}

/// How the requests on one connection are answered.
#[derive(Clone, Copy)]
enum Mode {
    Site { secure: bool },
    Redirect { https_port: u16 },
}

/// Everything the connection tasks share.
struct Shared {
    config: Config,
    router: Router,
    limiter: Arc<Semaphore>,
}

/// A web server that is listening, but not yet serving requests.
pub struct Server {
    http: TcpListener,
    http_kind: Listener,
    https: Option<(TcpListener, TlsAcceptor)>,
    config: Config,
    router: Router,
    limiter: Arc<Semaphore>,
}

impl Server {
    /// Open the listening ports. Port 0 means "pick any free port", which is
    /// what tests use. Read the real ports back with `local_addr` and
    /// `https_addr`. A bad certificate fails here, with a clear message.
    pub async fn bind(config: Config) -> std::io::Result<Server> {
        // Load the certificate first, so a mistake fails before anything opens.
        let acceptor = match (&config.tls_cert_path, &config.tls_key_path) {
            (Some(cert), Some(key)) => Some(build_acceptor(cert, key).map_err(|message| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
            })?),
            _ => None,
        };

        let http = TcpListener::bind(config.address()).await?;
        let https = match acceptor {
            Some(acceptor) => Some((TcpListener::bind(config.https_address()).await?, acceptor)),
            None => None,
        };

        let http_kind = match &https {
            Some((listener, _)) if config.redirect_http_to_https => Listener::Redirect {
                https_port: listener.local_addr()?.port(),
            },
            _ => Listener::Http,
        };

        Ok(Server {
            http,
            http_kind,
            https,
            limiter: Arc::new(Semaphore::new(config.max_connections)),
            router: build_router(),
            config,
        })
    }

    /// The address the plain-HTTP port is really listening on.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.http.local_addr()
    }

    /// The address the HTTPS port is listening on, if HTTPS is on.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https
            .as_ref()
            .and_then(|(listener, _)| listener.local_addr().ok())
    }

    /// Serve until `stop` completes, then shut down gracefully.
    /// `force_stop` completing during the grace period skips the waiting.
    pub async fn run(
        self,
        stop: impl Future<Output = ()>,
        force_stop: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        let Server {
            http,
            http_kind,
            https,
            config,
            router,
            limiter,
        } = self;

        let grace = Duration::from_secs(config.shutdown_grace_secs);
        let max_connections = config.max_connections;
        let shared = Arc::new(Shared {
            config,
            router,
            limiter: Arc::clone(&limiter),
        });

        // A one-value broadcast: false while running, true once we are stopping.
        let (stop_tx, stop_rx) = watch::channel(false);

        // One accept loop per port. A JoinSet cancels its tasks if dropped.
        let mut accept_loops = JoinSet::new();
        accept_loops.spawn(accept_loop(
            http,
            http_kind,
            Arc::clone(&shared),
            stop_rx.clone(),
        ));
        if let Some((listener, acceptor)) = https {
            accept_loops.spawn(accept_loop(
                listener,
                Listener::Https(acceptor),
                Arc::clone(&shared),
                stop_rx.clone(),
            ));
        }

        stop.await;

        // ---------- graceful shutdown ----------
        info!("Shutting down: no longer accepting new connections");

        // Tell every accept loop and every connection to wind down.
        stop_tx.send_replace(true);
        // When the accept loops are done, their ports are closed.
        while accept_loops.join_next().await.is_some() {}

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
            _ = force_stop => {
                warn!("Stop requested again: not waiting any longer");
                false
            }
        };

        if finished_in_time {
            info!("All connections finished. Goodbye!");
        } else {
            let cut_off = max_connections.saturating_sub(limiter.available_permits());
            warn!("Stopping now. {cut_off} connection(s) were cut off.");
        }

        Ok(())
    }
}

/// Accept connections on one port until told to stop.
async fn accept_loop(
    listener: TcpListener,
    kind: Listener,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let write_timeout = Duration::from_secs(shared.config.write_timeout_secs);

    loop {
        // Wait for a new connection OR for the signal to stop.
        let accepted = tokio::select! {
            _ = shutdown_requested(&mut stop) => break,
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

        let permit = match Arc::clone(&shared.limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("connection limit reached, refusing {addr}");
                // Only plain HTTP can be told "503". A TLS client needs a
                // handshake first, so it is simply dropped.
                if !matches!(kind, Listener::Https(_)) {
                    tokio::spawn(refuse_busy(stream, write_timeout));
                }
                continue;
            }
        };

        let shared = Arc::clone(&shared);
        let kind = kind.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            // Holding the permit until this task ends keeps the slot taken.
            let _permit = permit;
            if let Err(e) = serve_connection(stream, kind, shared, stop).await {
                if is_routine_disconnect(&e) {
                    debug!("{addr}: connection ended early: {e}");
                } else {
                    error!("{addr}: connection error: {e}");
                }
            }
            debug!("{addr}: connection closed");
        });
    }
}

/// Tell a client we are full, then hang up.
async fn refuse_busy(mut stream: TcpStream, write_timeout: Duration) {
    let response = Response::text(503, "503 Service Unavailable\n").header("Retry-After", "5");
    let _ = write_all_timeout(&mut stream, &response.to_bytes(true), write_timeout).await;
}

/// Do whatever this kind of port needs (a TLS handshake, for HTTPS), then
/// serve the connection.
async fn serve_connection(
    stream: TcpStream,
    kind: Listener,
    shared: Arc<Shared>,
    stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    match kind {
        Listener::Http => {
            handle_connection(stream, &shared, Mode::Site { secure: false }, stop).await
        }
        Listener::Redirect { https_port } => {
            handle_connection(stream, &shared, Mode::Redirect { https_port }, stop).await
        }
        Listener::Https(acceptor) => {
            let handshake_limit = Duration::from_secs(shared.config.tls_handshake_timeout_secs);
            match tokio::time::timeout(handshake_limit, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    handle_connection(tls, &shared, Mode::Site { secure: true }, stop).await
                }
                // Scanners and plain-HTTP clients hitting the HTTPS port are common.
                Ok(Err(e)) => {
                    debug!("TLS handshake failed: {e}");
                    Ok(())
                }
                Err(_) => {
                    debug!("TLS handshake timed out");
                    Ok(())
                }
            }
        }
    }
}

/// Serve one connection (plain or TLS), then say goodbye properly.
async fn handle_connection<S>(
    mut stream: S,
    shared: &Shared,
    mode: Mode,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = request_loop(&mut stream, shared, mode, &mut stop).await;

    // For TLS this sends "close_notify", which tells the client "I finished
    // on purpose", as opposed to "the connection was cut off".
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.shutdown()).await;

    result
}

/// Serve requests on one connection until it should close.
async fn request_loop<S>(
    stream: &mut S,
    shared: &Shared,
    mode: Mode,
    stop: &mut watch::Receiver<bool>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = &shared.config;
    let first_request_wait = Duration::from_secs(config.read_timeout_secs);
    let idle_wait = Duration::from_secs(config.keep_alive_timeout_secs);
    let write_timeout = Duration::from_secs(config.write_timeout_secs);

    let scheme = match mode {
        Mode::Site { secure: true } => "https",
        Mode::Site { secure: false } => "http",
        Mode::Redirect { .. } => "http-redirect",
    };

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

        let request = match read_request(stream, &mut buffer, config, wait, stop).await? {
            Incoming::Request(request) => request,
            Incoming::Finished => {
                debug!("connection finished after {served} request(s)");
                return Ok(());
            }
            // After an error we no longer trust where the next request
            // would start, so we always close.
            Incoming::Failed(Failure::Parse(e)) => {
                return reject(stream, e, write_timeout).await;
            }
            Incoming::Failed(Failure::TimedOut) => {
                return request_timeout(stream, write_timeout).await;
            }
        };
        served += 1;

        let mut response = match mode {
            Mode::Redirect { https_port } => https_redirect(&request, https_port),
            Mode::Site { .. } => {
                // A registered route wins. Otherwise GET and HEAD requests
                // look for a file in the document root.
                if shared.router.knows_path(&request) {
                    shared.router.handle(&request)
                } else if matches!(request.method, Method::Get | Method::Head) {
                    static_files::serve(&config.document_root, &request).await
                } else {
                    shared.router.handle(&request)
                }
            }
        };

        // HSTS only makes sense (and only counts) on HTTPS responses.
        if matches!(mode, Mode::Site { secure: true }) && config.hsts_max_age_secs > 0 {
            response = response.header(
                "Strict-Transport-Security",
                &format!("max-age={}", config.hsts_max_age_secs),
            );
        }

        // Keep the connection open only if the client allows it, we have not
        // served too many requests, AND the server is not shutting down.
        let keep_open = client_allows_keep_alive(&request)
            && served < config.max_requests_per_connection
            && !*stop.borrow();
        response.keep_alive = keep_open;

        info!(
            "[{scheme}] {} {} -> {}",
            request.method.as_str(),
            request.target,
            response.status
        );

        let include_body = request.method != Method::Head;
        let sent_cleanly = send(stream, response, include_body, write_timeout).await?;
        if !keep_open || !sent_cleanly {
            return Ok(());
        }
    }
}

/// The client was too slow sending its request.
async fn request_timeout<S: AsyncWrite + Unpin>(
    stream: &mut S,
    write_timeout: Duration,
) -> std::io::Result<()> {
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
async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
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
async fn reject<S: AsyncWrite + Unpin>(
    stream: &mut S,
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
