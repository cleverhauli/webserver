//! Graceful shutdown, tested with a real server.

mod common;

use common::{TestServer, parse_responses, read_until_closed};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn an_idle_server_shuts_down_at_once_and_stops_listening() {
    let server = TestServer::start("shutdown-idle").await;
    let addr = server.addr;

    let started = Instant::now();
    server.shutdown().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));

    // The port is closed now: nobody can connect any more.
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn a_request_in_progress_finishes_during_shutdown() {
    let server = TestServer::start("shutdown-busy").await;
    let addr = server.addr;

    // Half a request is on its way when the shutdown starts...
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let shutdown = tokio::spawn(server.shutdown());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ...and the rest of it arrives afterwards.
    stream.write_all(b"\r\n").await.unwrap();
    let data = read_until_closed(&mut stream).await;

    // It still gets a full answer, and is told the connection is closing.
    let responses = parse_responses(&data);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].status, 200);
    assert_eq!(responses[0].text(), r#"{"status":"ok"}"#);
    assert_eq!(responses[0].header("connection"), Some("close"));

    // And once it is done, the server finishes shutting down.
    assert!(shutdown.await.unwrap().is_ok());
}
