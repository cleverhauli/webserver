/// The standard text that goes with a status code, like 404 -> "Not Found".
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        401 => "Unauthorized",
        406 => "Not Acceptable",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        304 => "Not Modified",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        416 => "Range Not Satisfiable",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_have_names() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(404), "Not Found");
        assert_eq!(reason_phrase(405), "Method Not Allowed");
    }

    #[test]
    fn unknown_codes_do_not_crash() {
        assert_eq!(reason_phrase(999), "Unknown");
    }

    #[test]
    fn common_application_statuses_have_names() {
        assert_eq!(reason_phrase(401), "Unauthorized");
        assert_eq!(reason_phrase(409), "Conflict");
        assert_eq!(reason_phrase(429), "Too Many Requests");
    }
}
