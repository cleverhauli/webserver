//! Hardening: clients that misbehave in ways that cost the server something.

mod common;

use common::{TestServer, get, parse_responses, raw_exchange, read_until_closed};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn a_rejection_reaches_a_client_that_keeps_sending() {
    let server = TestServer::start_with("lingering-close", |config| {
        config.max_body_bytes = 10;
    })
    .await;

    // The client announces a 100,000-byte body, which is refused at once...
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    // ...but, like a real client, it keeps sending the body regardless.
    let chunk = [b'x'; 1000];
    for _ in 0..100 {
        if stream.write_all(&chunk).await.is_err() {
            break;
        }
    }

    // Without a lingering close, the server's hang-up can turn into a reset
    // that destroys the answer. With it, the answer arrives.
    let data = read_until_closed(&mut stream).await;
    let responses = parse_responses(&data);
    assert_eq!(responses.first().map(|r| r.status), Some(413));
}

#[tokio::test]
async fn one_address_cannot_hold_every_connection() {
    let server = TestServer::start_with("per-address-limit", |config| {
        config.max_connections_per_ip = 2;
    })
    .await;

    // Two silent connections use up this address's allowance.
    let first = TcpStream::connect(server.addr).await.unwrap();
    let second = TcpStream::connect(server.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let data = raw_exchange(server.addr, b"").await;
    let responses = parse_responses(&data);
    assert_eq!(responses[0].status, 503);
    assert_eq!(responses[0].header("retry-after"), Some("5"));

    // Giving the places back restores normal service.
    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(get(server.addr, "/health").await.status, 200);
}

#[tokio::test]
async fn a_limit_of_zero_means_unlimited() {
    let server = TestServer::start_with("per-address-unlimited", |config| {
        config.max_connections_per_ip = 0;
    })
    .await;

    let mut holders = Vec::new();
    for _ in 0..20 {
        holders.push(TcpStream::connect(server.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(get(server.addr, "/health").await.status, 200);
    assert_eq!(holders.len(), 20);
}
