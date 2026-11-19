//! Tests with a real HTTP client library: do ordinary clients understand us?

mod common;

use common::TestServer;

/// A client that does NOT follow redirects, so tests can see them.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn pages_and_files_are_served() {
    let server = TestServer::start("pages").await;
    let client = client();

    let home = client.get(server.url("/")).send().await.unwrap();
    assert_eq!(home.status().as_u16(), 200);
    assert_eq!(home.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(home.text().await.unwrap(), "<h1>home</h1>");

    let css = client.get(server.url("/style.css")).send().await.unwrap();
    assert_eq!(css.status().as_u16(), 200);
    assert_eq!(css.headers()["content-type"], "text/css; charset=utf-8");

    let health = client.get(server.url("/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    assert_eq!(health.headers()["content-type"], "application/json");
    assert_eq!(health.text().await.unwrap(), r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn unknown_paths_get_404() {
    let server = TestServer::start("not-found").await;
    let response = client()
        .get(server.url("/nothing-here"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn folders_redirect_to_a_trailing_slash() {
    let server = TestServer::start("redirect").await;

    let response = client().get(server.url("/docs")).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 301);
    assert_eq!(response.headers()["location"], "/docs/");

    // A normal client follows the redirect and ends up on the docs page.
    let followed = reqwest::get(server.url("/docs")).await.unwrap();
    assert_eq!(followed.status().as_u16(), 200);
    assert_eq!(followed.text().await.unwrap(), "<h1>docs</h1>");
}

#[tokio::test]
async fn unchanged_files_get_304() {
    let server = TestServer::start("etag").await;
    let client = client();

    let first = client.get(server.url("/style.css")).send().await.unwrap();
    assert_eq!(first.status().as_u16(), 200);
    let etag = first.headers()["etag"].to_str().unwrap().to_string();

    let second = client
        .get(server.url("/style.css"))
        .header("If-None-Match", etag.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 304);
    assert!(second.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn byte_ranges_get_206() {
    let server = TestServer::start("range").await;

    let response = client()
        .get(server.url("/digits.txt"))
        .header("Range", "bytes=2-5")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 206);
    assert_eq!(response.headers()["content-range"], "bytes 2-5/10");
    assert_eq!(response.text().await.unwrap(), "2345");
}

#[tokio::test]
async fn head_requests_have_headers_but_no_body() {
    let server = TestServer::start("head").await;

    let response = client().head(server.url("/")).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["content-length"], "13");
    assert!(response.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn post_bodies_reach_the_echo_page() {
    let server = TestServer::start("post").await;

    let response = client()
        .post(server.url("/echo"))
        .body("hello=world")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.text().await.unwrap();
    assert!(text.contains("Body (11 bytes):\nhello=world"), "{text}");
}

#[tokio::test]
async fn large_files_are_streamed_correctly() {
    let server = TestServer::start("big").await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(server.site.root.join("big.bin"), &data).unwrap();
    let client = client();

    let whole = client.get(server.url("/big.bin")).send().await.unwrap();
    assert_eq!(whole.status().as_u16(), 200);
    assert_eq!(whole.headers()["content-length"], "300000");
    let body = whole.bytes().await.unwrap();
    assert_eq!(&body[..], &data[..]);

    let part = client
        .get(server.url("/big.bin"))
        .header("Range", "bytes=150000-150099")
        .send()
        .await
        .unwrap();
    assert_eq!(part.status().as_u16(), 206);
    let body = part.bytes().await.unwrap();
    assert_eq!(&body[..], &data[150_000..150_100]);
}

#[tokio::test]
async fn many_clients_at_once_all_get_answers() {
    let server = TestServer::start("concurrent").await;
    let client = client();

    let mut tasks = Vec::new();
    for _ in 0..20 {
        let client = client.clone();
        let url = server.url("/health");
        tasks.push(tokio::spawn(async move {
            for _ in 0..10 {
                let response = client.get(&url).send().await.unwrap();
                assert_eq!(response.status().as_u16(), 200);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}
