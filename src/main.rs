mod config;

use config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = match Config::load("config.toml") {
        Ok(config) => config,
        Err(message) => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    };

    let address = config.address();
    let listener = TcpListener::bind(&address).await?;
    println!("Listening on http://{address}");

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    println!("Received {n} bytes");

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
