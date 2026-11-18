use crate::http::request::{Method, Request};
use crate::http::response::Response;

/// A handler is a function that takes a request and returns a response.
pub type Handler = fn(&Request) -> Response;

struct Route {
    method: Method,
    path: String,
    handler: Handler,
}

/// Matches requests to handlers.
#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    /// Register a handler for a method and an exact path.
    pub fn add(mut self, method: Method, path: &str, handler: Handler) -> Router {
        self.routes.push(Route {
            method,
            path: path.to_string(),
            handler,
        });
        self
    }

    /// True if any route has this path, whatever the method.
    pub fn knows_path(&self, request: &Request) -> bool {
        let path = path_only(&request.target);
        self.routes.iter().any(|route| route.path == path)
    }

    /// Find the right handler, or build a 404 / 405 response.
    pub fn handle(&self, request: &Request) -> Response {
        let path = path_only(&request.target);
        let mut allowed: Vec<&str> = Vec::new();

        for route in &self.routes {
            if route.path != path {
                continue;
            }

            // HEAD is answered by the GET handler (the body is dropped later).
            let method_matches = route.method == request.method
                || (request.method == Method::Head && route.method == Method::Get);
            if method_matches {
                return (route.handler)(request);
            }

            // Remember which methods this path does support.
            let name = route.method.as_str();
            if !allowed.contains(&name) {
                allowed.push(name);
            }
            if route.method == Method::Get && !allowed.contains(&"HEAD") {
                allowed.push("HEAD");
            }
        }

        if allowed.is_empty() {
            Response::text(404, "404 Not Found\n")
        } else {
            Response::text(405, "405 Method Not Allowed\n").header("Allow", &allowed.join(", "))
        }
    }
}

/// "/hello?name=x" becomes "/hello".
fn path_only(target: &str) -> &str {
    target.split('?').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Version;

    fn request(method: Method, target: &str) -> Request {
        Request {
            method,
            target: target.to_string(),
            version: Version::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn ok(_: &Request) -> Response {
        Response::text(200, "ok")
    }

    fn created(_: &Request) -> Response {
        Response::text(201, "created")
    }

    fn router() -> Router {
        Router::default()
            .add(Method::Get, "/health", ok)
            .add(Method::Get, "/echo", ok)
            .add(Method::Post, "/echo", created)
    }

    fn allow_header(response: &Response) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(name, _)| name == "Allow")
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn exact_match_reaches_the_handler() {
        let response = router().handle(&request(Method::Get, "/health"));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn query_strings_are_ignored() {
        let response = router().handle(&request(Method::Get, "/health?x=1&y=2"));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn unknown_paths_get_404() {
        let response = router().handle(&request(Method::Get, "/nope"));
        assert_eq!(response.status, 404);
    }

    #[test]
    fn paths_must_match_exactly() {
        for target in ["/health/", "/Health", "/healthx", "/"] {
            let response = router().handle(&request(Method::Get, target));
            assert_eq!(response.status, 404, "{target} should not match");
        }
    }

    #[test]
    fn wrong_method_gets_405_with_allow_header() {
        let response = router().handle(&request(Method::Delete, "/health"));
        assert_eq!(response.status, 405);
        assert_eq!(allow_header(&response).as_deref(), Some("GET, HEAD"));
    }

    #[test]
    fn allow_lists_every_method_for_the_path() {
        let response = router().handle(&request(Method::Delete, "/echo"));
        assert_eq!(response.status, 405);
        assert_eq!(allow_header(&response).as_deref(), Some("GET, HEAD, POST"));
    }

    #[test]
    fn head_uses_the_get_handler() {
        let response = router().handle(&request(Method::Head, "/health"));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn the_right_handler_is_chosen_per_method() {
        let get = router().handle(&request(Method::Get, "/echo"));
        let post = router().handle(&request(Method::Post, "/echo"));
        assert_eq!(get.status, 200);
        assert_eq!(post.status, 201);
    }

    #[test]
    fn head_on_a_post_only_path_is_405() {
        let router = Router::default().add(Method::Post, "/submit", created);
        let response = router.handle(&request(Method::Head, "/submit"));
        assert_eq!(response.status, 405);
    }

    #[test]
    fn knows_registered_paths() {
        assert!(router().knows_path(&request(Method::Get, "/health")));
        assert!(router().knows_path(&request(Method::Delete, "/health?x=1")));
    }

    #[test]
    fn does_not_know_other_paths() {
        assert!(!router().knows_path(&request(Method::Get, "/style.css")));
        assert!(!router().knows_path(&request(Method::Get, "/")));
    }
}
