#![allow(dead_code)]
//! Shared helpers for the integration tests.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use webserver::config::Config;
use webserver::server::Server;

/// A temporary website, deleted when dropped. A "secret" file sits NEXT TO
/// the site folder (not inside it), so tests can prove it never leaks out.
pub struct Site {
    base: PathBuf,
    pub root: PathBuf,
}

impl Site {
    pub fn new(name: &str) -> Site {
        let base = std::env::temp_dir().join(format!("webserver-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("site");
        std::fs::create_dir_all(root.join("docs")).unwrap();

        std::fs::write(base.join("secret.txt"), "TOP-SECRET").unwrap();
        std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(root.join("docs").join("index.html"), "<h1>docs</h1>").unwrap();
        std::fs::write(root.join("style.css"), "body {}").unwrap();
        std::fs::write(root.join("digits.txt"), "0123456789").unwrap();
        std::fs::write(root.join(".hidden"), "hidden").unwrap();

        Site { base, root }
    }

    /// The folder that holds the site folder (and anything NOT served).
    pub fn base(&self) -> &Path {
        &self.base
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Make a self-signed certificate for "localhost" and write it as PEM files.
pub fn write_test_certificate(dir: &Path) -> (PathBuf, PathBuf) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.join("test-cert.pem");
    let key_path = dir.join("test-key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// A real server running on free ports, serving a temporary site.
pub struct TestServer {
    pub addr: SocketAddr,
    /// Set when the server was started with HTTPS.
    pub https_addr: Option<SocketAddr>,
    /// The certificate the HTTPS port uses, so a test client can trust it.
    pub cert_path: Option<PathBuf>,
    pub site: Site,
    stop: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl TestServer {
    /// Start a plain-HTTP server with the default settings.
    pub async fn start(name: &str) -> TestServer {
        TestServer::start_inner(name, false, |_| {}).await
    }

    /// Start a plain-HTTP server, changing some settings first.
    pub async fn start_with(name: &str, tweak: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_inner(name, false, tweak).await
    }

    /// Start a server with HTTPS on, using a freshly made certificate.
    pub async fn start_tls(name: &str, tweak: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_inner(name, true, tweak).await
    }

    async fn start_inner(name: &str, tls: bool, tweak: impl FnOnce(&mut Config)) -> TestServer {
        let site = Site::new(name);
        let mut config = Config {
            bind_addr: "127.0.0.1".to_string(),
            port: 0, // let the operating system pick a free port
            document_root: site.root.to_str().unwrap().to_string(),
            ..Config::default()
        };

        let mut cert_path = None;
        if tls {
            // The certificate lives next to the site folder, never inside it.
            let (cert, key) = write_test_certificate(site.base());
            config.tls_cert_path = Some(cert.to_str().unwrap().to_string());
            config.tls_key_path = Some(key.to_str().unwrap().to_string());
            config.https_port = 0;
            cert_path = Some(cert);
        }
        tweak(&mut config);

        let server = Server::bind(config).await.expect("could not bind");
        let addr = server.local_addr().unwrap();
        let https_addr = server.https_addr();

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(server.run(
            async move {
                let _ = stop_rx.await;
            },
            std::future::pending(),
        ));

        TestServer {
            addr,
            https_addr,
            cert_path,
            site,
            stop: Some(stop_tx),
            handle: Some(handle),
        }
    }

    /// A full URL for a path on this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Ask for a graceful shutdown and wait until the server has finished.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let handle = self.handle.take().expect("server already stopped");
        handle.await.expect("server task panicked")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // A test that did not call shutdown(): just stop the server task.
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Read until the other side closes (or 10 seconds pass). Errors such as a
/// reset connection simply end the reading, keeping whatever arrived.
pub async fn read_until_closed<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut data = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), reader.read_to_end(&mut data)).await;
    data
}

/// Connect, send exactly these bytes, and read everything until the server
/// closes the connection.
pub async fn raw_exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    read_until_closed(&mut stream).await
}

/// One response as it arrived over the wire.
#[derive(Debug)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Split a stream of bytes into responses, using Content-Length to find
/// where each one ends. (Only for responses that have a body, so not HEAD
/// or 304.)
pub fn parse_responses(mut bytes: &[u8]) -> Vec<RawResponse> {
    let mut responses = Vec::new();

    while !bytes.is_empty() {
        let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
            break;
        };
        let head = String::from_utf8_lossy(&bytes[..end]).to_string();
        let mut lines = head.split("\r\n");

        let status: u16 = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .expect("a response must start with a status line");

        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .collect();

        let length = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);

        let body_start = end + 4;
        let body_end = (body_start + length).min(bytes.len());
        responses.push(RawResponse {
            status,
            headers,
            body: bytes[body_start..body_end].to_vec(),
        });
        bytes = &bytes[body_end..];
    }

    responses
}

/// Send one simple GET (asking the server to close afterwards) and return
/// the response. The path is sent exactly as written, with no tidying up.
pub async fn get(addr: SocketAddr, target: &str) -> RawResponse {
    let request = format!("GET {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    let data = raw_exchange(addr, request.as_bytes()).await;
    parse_responses(&data)
        .into_iter()
        .next()
        .expect("the server sent no response")
}

// ---------- TLS clients ----------

fn client_config(roots: RootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A TLS client that trusts exactly one certificate: the test server's.
pub fn tls_connector(cert_path: &Path) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(cert_path).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    TlsConnector::from(Arc::new(client_config(roots)))
}

/// A TLS client that trusts nothing at all.
pub fn tls_connector_trusting_nothing() -> TlsConnector {
    TlsConnector::from(Arc::new(client_config(RootCertStore::empty())))
}

/// Connect and try to complete the TLS handshake (as "localhost").
pub async fn tls_try_connect(
    addr: SocketAddr,
    connector: &TlsConnector,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    connector.connect(name, tcp).await
}

/// Like `tls_try_connect`, but a failed handshake fails the test.
pub async fn tls_connect(addr: SocketAddr, connector: &TlsConnector) -> TlsStream<TcpStream> {
    tls_try_connect(addr, connector)
        .await
        .expect("the TLS handshake failed")
}

/// Over TLS: send exactly these bytes, and read until the server closes.
pub async fn tls_exchange(addr: SocketAddr, connector: &TlsConnector, request: &[u8]) -> Vec<u8> {
    let mut stream = tls_connect(addr, connector).await;
    stream.write_all(request).await.unwrap();
    read_until_closed(&mut stream).await
}
