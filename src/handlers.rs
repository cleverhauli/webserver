use crate::http::request::Request;
use crate::http::response::Response;

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
