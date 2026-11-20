//! A small HTTP/1.1 web server.
//!
//! The program in `main.rs` is a thin wrapper around this library. Keeping
//! the real code here is what lets tests start real servers.

pub mod compression;
pub mod config;
pub mod connection;
pub mod handlers;
pub mod http;
pub mod net_util;
pub mod proxy;
pub mod redirect;
pub mod router;
pub mod server;
pub mod static_files;
pub mod tls;
