use crate::config::Config;
use crate::http::chunked::decode_chunked;
use crate::http::parser::{BodyFraming, ParseError, ParseResult, body_framing, parse_request};
use crate::http::request::{Request, Version};
use crate::net_util::{ReadOutcome, read_with_deadline};
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::time::Instant;
use tokio::sync::watch;
use tracing::debug;

/// What reading from a connection produced.
#[derive(Debug)]
pub enum Incoming {
    /// A complete request.
    Request(Request),
    /// The client left, or stayed idle too long. There is nothing to answer.
    Finished,
    /// The request was bad or too slow. Answer with an error, then close.
    Failed(Failure),
}

#[derive(Debug, PartialEq)]
pub enum Failure {
    Parse(ParseError),
    TimedOut,
}


/// Completes when shutdown has been requested. If the sender is gone,
/// nobody can request it any more, so this waits forever instead.
pub async fn shutdown_requested(stop: &mut watch::Receiver<bool>) {
    if stop.wait_for(|stopping| *stopping).await.is_err() {
        std::future::pending::<()>().await;
    }
}


/// Read the next request from a connection.
///
/// `buffer` is kept between calls. It can already hold the start of the NEXT
/// request, because clients may send several requests back to back
/// ("pipelining"). After each call the buffer holds only bytes that belong
/// to later requests.
///
/// `idle_timeout` is how long to wait for a request to START. Once its first
/// byte arrives, the rest must arrive within `config.read_timeout_secs`.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    config: &Config,
    idle_timeout: Duration,
    stop: &mut watch::Receiver<bool>,
) -> std::io::Result<Incoming> {
    let read_limit = Duration::from_secs(config.read_timeout_secs);
    let mut chunk = [0u8; 4096];

    // Wait for the first byte, unless leftover bytes are already waiting.
    // This is the ONLY place a shutdown interrupts us: a connection that is
    // idle can simply be closed, but a request that has started is finished.
    if buffer.is_empty() {
        tokio::select! {
            outcome = read_with_deadline(reader, &mut chunk, Instant::now() + idle_timeout) => {
                match outcome? {
                    ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
                    ReadOutcome::Closed | ReadOutcome::TimedOut => return Ok(Incoming::Finished),
                }
            }
            _ = shutdown_requested(stop) => return Ok(Incoming::Finished),
        }
    }

    // The request has started. It must finish before this deadline, however
    // slowly the bytes trickle in.
    let header_deadline = Instant::now() + read_limit;
    let (mut request, consumed) = loop {
        match parse_request(&buffer[..], config.max_header_bytes) {
            Ok(ParseResult::Complete { request, consumed }) => break (request, consumed),
            Ok(ParseResult::Incomplete) => {}
            Err(e) => return Ok(Incoming::Failed(Failure::Parse(e))),
        }

        match read_with_deadline(reader, &mut chunk, header_deadline).await? {
            ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
            ReadOutcome::Closed => {
                debug!("client closed the connection in the middle of a request");
                return Ok(Incoming::Finished);
            }
            ReadOutcome::TimedOut => return Ok(Incoming::Failed(Failure::TimedOut)),
        }
    };

    // Throw away the header bytes. What is left is the body, and possibly
    // the start of the next request.
    buffer.drain(..consumed);

    let framing = match body_framing(&request, config.max_body_bytes) {
        Ok(framing) => framing,
        Err(e) => return Ok(Incoming::Failed(Failure::Parse(e))),
    };

    match framing {
        BodyFraming::None => {}

        BodyFraming::ContentLength(length) => {
            let body_deadline = Instant::now() + read_limit;
            while buffer.len() < length {
                match read_with_deadline(reader, &mut chunk, body_deadline).await? {
                    ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
                    ReadOutcome::Closed => {
                        debug!("client closed the connection before sending the full body");
                        return Ok(Incoming::Finished);
                    }
                    ReadOutcome::TimedOut => return Ok(Incoming::Failed(Failure::TimedOut)),
                }
            }
            // Take exactly the body. Anything after it belongs to the NEXT request.
            request.body = buffer.drain(..length).collect();
        }

        BodyFraming::Chunked => {
            let body_deadline = Instant::now() + read_limit;
            let mut body: Vec<u8> = Vec::new();
            let mut pos = 0;

            loop {
                match decode_chunked(&buffer[..], &mut pos, &mut body, config.max_body_bytes) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => return Ok(Incoming::Failed(Failure::Parse(e))),
                }

                // Forget bytes we already decoded so the buffer stays small.
                buffer.drain(..pos);
                pos = 0;

                match read_with_deadline(reader, &mut chunk, body_deadline).await? {
                    ReadOutcome::Data(n) => buffer.extend_from_slice(&chunk[..n]),
                    ReadOutcome::Closed => {
                        debug!("client closed the connection in the middle of a chunked body");
                        return Ok(Incoming::Finished);
                    }
                    ReadOutcome::TimedOut => return Ok(Incoming::Failed(Failure::TimedOut)),
                }
            }

            // Bytes after the final chunk belong to the NEXT request.
            buffer.drain(..pos);
            request.body = body;
        }
    }

    Ok(Incoming::Request(request))
}

/// Does this request allow the connection to stay open afterwards?
pub fn client_allows_keep_alive(request: &Request) -> bool {
    // The Connection header holds a comma-separated list, like "keep-alive, Upgrade".
    let tokens: Vec<String> = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();

    if tokens.iter().any(|token| token == "close") {
        return false;
    }

    match request.version {
        // HTTP/1.1 stays open unless told otherwise.
        Version::Http11 => true,
        // HTTP/1.0 closes unless it asks to stay open.
        Version::Http10 => tokens.iter().any(|token| token == "keep-alive"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Method;
    use tokio::io::AsyncWriteExt;

    fn idle() -> Duration {
        Duration::from_millis(100)
    }

    fn expect_request(incoming: Incoming) -> Request {
        match incoming {
            Incoming::Request(request) => request,
            other => panic!("expected a request, got {other:?}"),
        }
    }
    
    /// Most tests never shut down. With the sender dropped, nobody can ask for it.
    async fn read_request<R: AsyncRead + Unpin>(
        reader: &mut R,
        buffer: &mut Vec<u8>,
        config: &Config,
        idle_timeout: Duration,
    ) -> std::io::Result<Incoming> {
        let (_, mut stop) = watch::channel(false);
        super::read_request(reader, buffer, config, idle_timeout, &mut stop).await
    }
    // ---------- reading requests from a connection ----------

    #[tokio::test]
    async fn pipelined_requests_are_read_one_at_a_time() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let config = Config::default();
        let mut buffer = Vec::new();

        let first = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(first.target, "/a");

        let second = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(second.target, "/b");
        assert!(buffer.is_empty());

        // Nothing more is coming, so the idle wait ends the connection.
        let third = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(third, Incoming::Finished));
    }

    #[tokio::test]
    async fn a_content_length_body_does_not_swallow_the_next_request() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(
                b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .await
            .unwrap();

        let config = Config::default();
        let mut buffer = Vec::new();

        let post = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(post.body, b"hello");

        let next = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(next.target, "/next");
        assert_eq!(next.method, Method::Get);
    }

    #[tokio::test]
    async fn a_chunked_body_does_not_swallow_the_next_request() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(
                b"POST /s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .await
            .unwrap();

        let config = Config::default();
        let mut buffer = Vec::new();

        let post = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(post.body, b"hello");

        let next = expect_request(
            read_request(&mut server, &mut buffer, &config, idle())
                .await
                .unwrap(),
        );
        assert_eq!(next.target, "/next");
    }

    #[tokio::test]
    async fn a_body_that_arrives_in_pieces_is_assembled() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n01234")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(b"56789").await.unwrap();
            client
        });

        let config = Config::default();
        let mut buffer = Vec::new();
        let request = expect_request(
            read_request(&mut server, &mut buffer, &config, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!(request.body, b"0123456789");
        let _client = writer.await.unwrap();
    }

    #[tokio::test]
    async fn an_idle_connection_finishes_quietly() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let config = Config::default();
        let mut buffer = Vec::new();

        let outcome = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(outcome, Incoming::Finished));
    }

    #[tokio::test]
    async fn a_closed_connection_finishes_quietly() {
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let config = Config::default();
        let mut buffer = Vec::new();

        let outcome = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(outcome, Incoming::Finished));
    }

    #[tokio::test]
    async fn disconnecting_in_the_middle_of_a_body_finishes_quietly() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n012")
            .await
            .unwrap();
        drop(client);

        let config = Config::default();
        let mut buffer = Vec::new();
        let outcome = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(outcome, Incoming::Finished));
    }

    #[tokio::test]
    async fn garbage_fails_with_a_parse_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\x00\x01garbage\r\n\r\n").await.unwrap();

        let config = Config::default();
        let mut buffer = Vec::new();
        let outcome = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            Incoming::Failed(Failure::Parse(ParseError::BadRequest(_)))
        ));
    }

    #[tokio::test]
    async fn oversized_bodies_fail_before_being_read() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
            .await
            .unwrap();

        let config = Config {
            max_body_bytes: 5,
            ..Config::default()
        };
        let mut buffer = Vec::new();
        let outcome = read_request(&mut server, &mut buffer, &config, idle())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            Incoming::Failed(Failure::Parse(ParseError::PayloadTooLarge))
        ));
    }

    #[tokio::test]
    async fn a_half_sent_request_times_out() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"GET / HT").await.unwrap();

        let config = Config {
            read_timeout_secs: 1,
            ..Config::default()
        };
        let mut buffer = Vec::new();
        let outcome = read_request(&mut server, &mut buffer, &config, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(matches!(outcome, Incoming::Failed(Failure::TimedOut)));
    }

    // ---------- should the connection stay open? ----------

    fn request(version: Version, headers: &[(&str, &str)]) -> Request {
        Request {
            method: Method::Get,
            target: "/".to_string(),
            version,
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn http11_stays_open_by_default() {
        assert!(client_allows_keep_alive(&request(Version::Http11, &[])));
    }

    #[test]
    fn http10_closes_by_default() {
        assert!(!client_allows_keep_alive(&request(Version::Http10, &[])));
    }

    #[test]
    fn connection_close_always_wins() {
        for value in ["close", "Close", "CLOSE", "keep-alive, close", " close "] {
            let r = request(Version::Http11, &[("Connection", value)]);
            assert!(!client_allows_keep_alive(&r), "Connection: {value}");
        }
    }

    #[test]
    fn http10_can_ask_to_stay_open() {
        for value in ["keep-alive", "Keep-Alive", "keep-alive, Upgrade"] {
            let r = request(Version::Http10, &[("Connection", value)]);
            assert!(client_allows_keep_alive(&r), "Connection: {value}");
        }
    }

    #[test]
    fn unrelated_connection_tokens_change_nothing() {
        let r = request(Version::Http11, &[("Connection", "Upgrade")]);
        assert!(client_allows_keep_alive(&r));
        let r = request(Version::Http10, &[("Connection", "Upgrade")]);
        assert!(!client_allows_keep_alive(&r));
    }

    #[test]
    fn several_connection_headers_are_all_considered() {
        let r = request(
            Version::Http11,
            &[("Connection", "keep-alive"), ("connection", "close")],
        );
        assert!(!client_allows_keep_alive(&r));
    }

    // ---------- shutting down ----------

    #[tokio::test]
    async fn an_idle_connection_closes_at_once_when_shutdown_starts() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let (tx, mut stop) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let config = Config::default();
        let mut buffer = Vec::new();
        let started = Instant::now();
        let outcome = super::read_request(
            &mut server,
            &mut buffer,
            &config,
            Duration::from_secs(30),
            &mut stop,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Incoming::Finished));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_request_in_progress_is_finished_even_during_shutdown() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (tx, mut stop) = watch::channel(false);

        // Half a request arrives first...
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();

        // ...then shutdown starts, and only afterwards the request is completed.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let _ = tx.send(true);
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(b"\r\n").await.unwrap();
        });

        let config = Config::default();
        let mut buffer = Vec::new();
        let request = expect_request(
            super::read_request(
                &mut server,
                &mut buffer,
                &config,
                Duration::from_secs(5),
                &mut stop,
            )
            .await
            .unwrap(),
        );
        assert_eq!(request.target, "/health");
    }

    #[tokio::test]
    async fn bytes_already_received_are_still_served_during_shutdown() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let (tx, mut stop) = watch::channel(false);
        tx.send(true).unwrap();

        // A whole request was already waiting in the buffer.
        let config = Config::default();
        let mut buffer = b"GET /queued HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let request = expect_request(
            super::read_request(
                &mut server,
                &mut buffer,
                &config,
                Duration::from_secs(5),
                &mut stop,
            )
            .await
            .unwrap(),
        );
        assert_eq!(request.target, "/queued");
    }

    #[tokio::test]
    async fn a_dropped_shutdown_sender_does_not_close_connections() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (tx, mut stop) = watch::channel(false);
        drop(tx);

        client
            .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let config = Config::default();
        let mut buffer = Vec::new();
        let request = expect_request(
            super::read_request(
                &mut server,
                &mut buffer,
                &config,
                Duration::from_secs(5),
                &mut stop,
            )
            .await
            .unwrap(),
        );
        assert_eq!(request.target, "/ok");
    }
}
