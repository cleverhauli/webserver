/// The kind of action the client wants.
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Other(String),
}

impl Method {
    pub fn parse(text: &str) -> Method {
        match text {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            "PATCH" => Method::Patch,
            other => Method::Other(other.to_string()),
        }
    }

    /// The method as it appears on the wire, like "GET".
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
            Method::Other(name) => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Version {
    Http10,
    Http11,
}

/// A fully parsed HTTP request (headers only, for now).
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub version: Version,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Look up a header by name. Header names are case-insensitive in HTTP,
    /// so "Host", "host" and "HOST" all match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}
