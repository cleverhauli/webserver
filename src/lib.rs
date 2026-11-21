//! A small HTTP/1.1 web server.
//!
//! The program in `main.rs` is a thin wrapper around this library. Keeping
//! the real code here is what lets tests start real servers.

// Code that handles network input must never panic. These lints make the
// compiler enforce that. Tests are exempt, because a panic IS how a test fails.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod compression;
pub mod config;
pub mod connection;
pub mod handlers;
pub mod http;
pub mod ip_limit;
pub mod logging;
pub mod metrics;
pub mod net_util;
pub mod proxy;
pub mod redirect;
pub mod router;
pub mod server;
pub mod static_files;
pub mod status;
pub mod tls;
