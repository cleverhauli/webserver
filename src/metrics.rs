//! Counters that show how the server is doing. They are plain atomic
//! numbers, so counting costs almost nothing and never blocks a request.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct Metrics {
    started: Instant,
    connections_accepted: AtomicU64,
    connections_refused: AtomicU64,
    requests_served: AtomicU64,
    requests_rejected: AtomicU64,
    requests_timed_out: AtomicU64,
    requests_proxied: AtomicU64,
    /// Responses by status class: 1xx, 2xx, 3xx, 4xx, 5xx.
    responses_by_class: [AtomicU64; 5],
    bytes_sent: AtomicU64,
    tls_handshake_failures: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new()
    }
}

impl Metrics {
    pub fn new() -> Metrics {
        Metrics {
            started: Instant::now(),
            connections_accepted: AtomicU64::new(0),
            connections_refused: AtomicU64::new(0),
            requests_served: AtomicU64::new(0),
            requests_rejected: AtomicU64::new(0),
            requests_timed_out: AtomicU64::new(0),
            requests_proxied: AtomicU64::new(0),
            responses_by_class: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes_sent: AtomicU64::new(0),
            tls_handshake_failures: AtomicU64::new(0),
        }
    }

    fn add(counter: &AtomicU64, amount: u64) {
        counter.fetch_add(amount, Ordering::Relaxed);
    }

    /// A TCP connection was accepted.
    pub fn connection_accepted(&self) {
        Self::add(&self.connections_accepted, 1);
    }

    /// A connection was turned away because the server was full.
    pub fn connection_refused(&self) {
        Self::add(&self.connections_refused, 1);
    }

    /// A request was understood and answered with this status.
    pub fn request_served(&self, status: u16, body_bytes: u64, proxied: bool) {
        Self::add(&self.requests_served, 1);
        if (100..=599).contains(&status) {
            let class = usize::from(status / 100 - 1);
            Self::add(&self.responses_by_class[class], 1);
        }
        Self::add(&self.bytes_sent, body_bytes);
        if proxied {
            Self::add(&self.requests_proxied, 1);
        }
    }

    /// A request was malformed or too large and never reached the router.
    pub fn request_rejected(&self) {
        Self::add(&self.requests_rejected, 1);
    }

    /// A client was too slow sending its request (408).
    pub fn request_timed_out(&self) {
        Self::add(&self.requests_timed_out, 1);
    }

    /// A TLS handshake failed or timed out.
    pub fn tls_handshake_failed(&self) {
        Self::add(&self.tls_handshake_failures, 1);
    }

    /// A copy of every number at this moment.
    pub fn snapshot(&self, active_connections: usize) -> Snapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Snapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            connections_accepted: load(&self.connections_accepted),
            connections_refused: load(&self.connections_refused),
            connections_active: u64::try_from(active_connections).unwrap_or(u64::MAX),
            requests_served: load(&self.requests_served),
            requests_rejected: load(&self.requests_rejected),
            requests_timed_out: load(&self.requests_timed_out),
            requests_proxied: load(&self.requests_proxied),
            responses: std::array::from_fn(|i| load(&self.responses_by_class[i])),
            bytes_sent: load(&self.bytes_sent),
            tls_handshake_failures: load(&self.tls_handshake_failures),
        }
    }
}

/// The numbers at one moment, ready to show.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub uptime_seconds: u64,
    pub connections_accepted: u64,
    pub connections_refused: u64,
    pub connections_active: u64,
    pub requests_served: u64,
    pub requests_rejected: u64,
    pub requests_timed_out: u64,
    pub requests_proxied: u64,
    pub responses: [u64; 5],
    pub bytes_sent: u64,
    pub tls_handshake_failures: u64,
}

impl Snapshot {
    /// Compact JSON. Every key is fixed and every value is a number, so
    /// nothing here ever needs escaping.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"uptime_seconds\":{},\"connections\":{{\"accepted\":{},\"refused\":{},\"active\":{}}},\"requests\":{{\"served\":{},\"rejected\":{},\"timed_out\":{},\"proxied\":{}}},\"responses\":{{\"1xx\":{},\"2xx\":{},\"3xx\":{},\"4xx\":{},\"5xx\":{}}},\"bytes_sent\":{},\"tls_handshake_failures\":{}}}",
            self.uptime_seconds,
            self.connections_accepted,
            self.connections_refused,
            self.connections_active,
            self.requests_served,
            self.requests_rejected,
            self.requests_timed_out,
            self.requests_proxied,
            self.responses[0],
            self.responses[1],
            self.responses[2],
            self.responses[3],
            self.responses[4],
            self.bytes_sent,
            self.tls_handshake_failures,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_server_has_counted_nothing() {
        let snapshot = Metrics::new().snapshot(0);
        assert_eq!(snapshot.requests_served, 0);
        assert_eq!(snapshot.responses, [0; 5]);
        assert_eq!(snapshot.bytes_sent, 0);
        assert_eq!(snapshot.connections_accepted, 0);
    }

    #[test]
    fn responses_are_counted_by_status_class() {
        let metrics = Metrics::new();
        for status in [200, 204, 301, 304, 404, 404, 500, 503] {
            metrics.request_served(status, 10, false);
        }
        let snapshot = metrics.snapshot(0);
        assert_eq!(snapshot.responses, [0, 2, 2, 2, 2]);
        assert_eq!(snapshot.requests_served, 8);
        assert_eq!(snapshot.bytes_sent, 80);
    }

    #[test]
    fn odd_statuses_are_counted_as_served_but_not_classified() {
        let metrics = Metrics::new();
        metrics.request_served(99, 0, false);
        metrics.request_served(999, 0, false);
        let snapshot = metrics.snapshot(0);
        assert_eq!(snapshot.requests_served, 2);
        assert_eq!(snapshot.responses, [0; 5]);
    }

    #[test]
    fn the_other_counters_work() {
        let metrics = Metrics::new();
        metrics.connection_accepted();
        metrics.connection_accepted();
        metrics.connection_refused();
        metrics.request_rejected();
        metrics.request_timed_out();
        metrics.tls_handshake_failed();
        metrics.request_served(200, 0, true);

        let snapshot = metrics.snapshot(3);
        assert_eq!(snapshot.connections_accepted, 2);
        assert_eq!(snapshot.connections_refused, 1);
        assert_eq!(snapshot.connections_active, 3);
        assert_eq!(snapshot.requests_rejected, 1);
        assert_eq!(snapshot.requests_timed_out, 1);
        assert_eq!(snapshot.tls_handshake_failures, 1);
        assert_eq!(snapshot.requests_proxied, 1);
    }

    #[test]
    fn json_has_a_fixed_shape() {
        let snapshot = Snapshot {
            uptime_seconds: 7,
            connections_accepted: 5,
            connections_refused: 1,
            connections_active: 2,
            requests_served: 9,
            requests_rejected: 3,
            requests_timed_out: 4,
            requests_proxied: 6,
            responses: [1, 2, 3, 4, 5],
            bytes_sent: 1234,
            tls_handshake_failures: 8,
        };
        assert_eq!(
            snapshot.to_json(),
            r#"{"uptime_seconds":7,"connections":{"accepted":5,"refused":1,"active":2},"requests":{"served":9,"rejected":3,"timed_out":4,"proxied":6},"responses":{"1xx":1,"2xx":2,"3xx":3,"4xx":4,"5xx":5},"bytes_sent":1234,"tls_handshake_failures":8}"#
        );
    }

    #[test]
    fn counting_from_many_threads_loses_nothing() {
        let metrics = Metrics::new();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        metrics.request_served(200, 1, false);
                    }
                });
            }
        });
        let snapshot = metrics.snapshot(0);
        assert_eq!(snapshot.requests_served, 8000);
        assert_eq!(snapshot.responses[1], 8000);
        assert_eq!(snapshot.bytes_sent, 8000);
    }

    #[test]
    fn uptime_starts_near_zero() {
        assert!(Metrics::new().snapshot(0).uptime_seconds < 5);
    }
}
