//! Limiting how many connections one client address may hold at once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

/// Counts the open connections of every address.
pub struct IpLimiter {
    /// The most connections one address may hold. 0 means "no limit".
    max_per_ip: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

/// A place held by one connection. Dropping it gives the place back.
pub struct IpGuard {
    limiter: Option<Arc<IpLimiter>>,
    ip: IpAddr,
}

impl IpLimiter {
    pub fn new(max_per_ip: usize) -> Arc<IpLimiter> {
        Arc::new(IpLimiter {
            max_per_ip,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// Take a place for this address, or `None` if it already holds its maximum.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        // "::ffff:1.2.3.4" and "1.2.3.4" are the same client.
        let ip = ip.to_canonical();

        if self.max_per_ip == 0 {
            return Some(IpGuard { limiter: None, ip });
        }

        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(IpGuard {
            limiter: Some(Arc::clone(self)),
            ip,
        })
    }

    /// How many connections this address holds right now.
    pub fn holding(&self, ip: IpAddr) -> usize {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts.get(&ip.to_canonical()).copied().unwrap_or(0)
    }

    /// How many addresses are being tracked. Addresses with no open
    /// connection are forgotten, so this cannot grow without bound.
    pub fn tracked_addresses(&self) -> usize {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts.len()
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let Some(limiter) = &self.limiter else {
            return;
        };
        let mut counts = limiter
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now_unused = match counts.get_mut(&self.ip) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if now_unused {
            counts.remove(&self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn places_up_to_the_limit_are_given_and_no_more() {
        let limiter = IpLimiter::new(3);
        let held: Vec<_> = (0..3)
            .map(|_| limiter.try_acquire(ip("1.2.3.4")).unwrap())
            .collect();
        assert_eq!(held.len(), 3);
        assert!(limiter.try_acquire(ip("1.2.3.4")).is_none());
        assert_eq!(limiter.holding(ip("1.2.3.4")), 3);
    }

    #[test]
    fn a_released_place_can_be_taken_again() {
        let limiter = IpLimiter::new(1);
        let first = limiter.try_acquire(ip("1.2.3.4")).unwrap();
        assert!(limiter.try_acquire(ip("1.2.3.4")).is_none());
        drop(first);
        assert!(limiter.try_acquire(ip("1.2.3.4")).is_some());
    }

    #[test]
    fn addresses_are_counted_separately() {
        let limiter = IpLimiter::new(1);
        let _a = limiter.try_acquire(ip("1.1.1.1")).unwrap();
        assert!(limiter.try_acquire(ip("2.2.2.2")).is_some());
        assert!(limiter.try_acquire(ip("2001:db8::1")).is_some());
        assert!(limiter.try_acquire(ip("1.1.1.1")).is_none());
    }

    #[test]
    fn zero_means_no_limit() {
        let limiter = IpLimiter::new(0);
        let held: Vec<_> = (0..1000)
            .map(|_| limiter.try_acquire(ip("1.2.3.4")))
            .collect();
        assert!(held.iter().all(|guard| guard.is_some()));
        assert_eq!(limiter.tracked_addresses(), 0);
    }

    #[test]
    fn one_client_in_two_notations_is_still_one_client() {
        let limiter = IpLimiter::new(1);
        let _held = limiter.try_acquire(ip("1.2.3.4")).unwrap();
        assert!(limiter.try_acquire(ip("::ffff:1.2.3.4")).is_none());
        assert_eq!(limiter.holding(ip("::ffff:1.2.3.4")), 1);
    }

    #[test]
    fn finished_addresses_are_forgotten() {
        let limiter = IpLimiter::new(5);
        let guards: Vec<_> = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
            .iter()
            .map(|text| limiter.try_acquire(ip(text)).unwrap())
            .collect();
        assert_eq!(limiter.tracked_addresses(), 3);
        drop(guards);
        assert_eq!(limiter.tracked_addresses(), 0);
    }

    #[test]
    fn many_threads_never_get_more_than_the_limit() {
        let limiter = IpLimiter::new(5);
        let results: Vec<Option<IpGuard>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| limiter.try_acquire(ip("9.9.9.9"))))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(results.iter().flatten().count(), 5);
        drop(results);
        assert_eq!(limiter.holding(ip("9.9.9.9")), 0);
    }
}
