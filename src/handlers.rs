use crate::http::request::Request;
use crate::http::response::Response;

/// The home page.
pub fn index(_request: &Request) -> Response {
    Response::html(
        200,
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>My Rust Web Server</title></head>
<body>
  <h1>It works!</h1>
  <p>This page is served by a web server written from scratch in Rust.</p>
  <ul>
    <li><a href="/health">/health</a></li>
    <li><a href="/about">/about</a></li>
    <li><a href="/echo">/echo</a></li>
  </ul>
</body>
</html>
"#,
    )
}

/// Used by monitoring tools to check the server is alive.
pub fn health(_request: &Request) -> Response {
    Response::json(200, r#"{"status":"ok"}"#)
}

pub fn about(_request: &Request) -> Response {
    Response::text(
        200,
        "A small web server written in Rust, built step by step.\n",
    )
}

/// Shows back what the server understood from the request.
pub fn echo(request: &Request) -> Response {
    let mut text = format!(
        "Method: {:?}\nPath: {}\nVersion: {:?}\n\nHeaders:\n",
        request.method, request.target, request.version
    );
    for (name, value) in &request.headers {
        text.push_str(&format!("  {name}: {value}\n"));
    }
    text.push_str(&format!(
        "\nBody ({} bytes):\n{}\n",
        request.body.len(),
        String::from_utf8_lossy(&request.body)
    ));
    Response::text(200, text)
}
