//! Connection management utilities for WiseGate.
//!
//! This module provides utilities for managing connections, including:
//! - Connection limiting with semaphores
//! - Active connection tracking
//! - Graceful shutdown support

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Tracks active connections for graceful shutdown.
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    active: Arc<AtomicUsize>,
}

impl ConnectionTracker {
    /// Create a new connection tracker.
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Increment active connection count.
    pub fn increment(&self) {
        self.active.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement active connection count.
    pub fn decrement(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Get current active connection count.
    pub fn count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Wait for all connections to finish with timeout.
    /// Returns true if all connections finished, false if timeout reached.
    pub async fn wait_for_shutdown(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();

        while self.count() > 0 {
            if start.elapsed() >= timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        true
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for connection limiting.
#[derive(Debug, Clone)]
pub struct ConnectionLimiter {
    semaphore: Option<Arc<Semaphore>>,
    max_connections: usize,
}

impl ConnectionLimiter {
    /// Create a new connection limiter.
    /// If max_connections is 0, no limit is enforced.
    pub fn new(max_connections: usize) -> Self {
        let semaphore = if max_connections > 0 {
            Some(Arc::new(Semaphore::new(max_connections)))
        } else {
            None
        };

        Self {
            semaphore,
            max_connections,
        }
    }

    /// Check if connection limiting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.semaphore.is_some()
    }

    /// Get the maximum number of connections (0 means unlimited).
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Try to acquire a connection permit.
    /// Returns None if no limit is configured.
    /// Returns Some(permit) if acquired, or None if at capacity.
    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.semaphore
            .as_ref()
            .and_then(|sem| sem.clone().try_acquire_owned().ok())
    }

    /// Check if we're at capacity (only meaningful if limiting is enabled).
    pub fn at_capacity(&self) -> bool {
        self.semaphore
            .as_ref()
            .is_some_and(|sem| sem.available_permits() == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // ConnectionTracker tests
    // ===========================================

    #[test]
    fn test_connection_tracker_new() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_connection_tracker_increment() {
        let tracker = ConnectionTracker::new();
        tracker.increment();
        assert_eq!(tracker.count(), 1);
        tracker.increment();
        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn test_connection_tracker_decrement() {
        let tracker = ConnectionTracker::new();
        tracker.increment();
        tracker.increment();
        tracker.decrement();
        assert_eq!(tracker.count(), 1);
    }

    #[test]
    fn test_connection_tracker_clone_shares_state() {
        let tracker1 = ConnectionTracker::new();
        let tracker2 = tracker1.clone();

        tracker1.increment();
        assert_eq!(tracker2.count(), 1);

        tracker2.increment();
        assert_eq!(tracker1.count(), 2);
    }

    #[tokio::test]
    async fn test_connection_tracker_wait_for_shutdown_immediate() {
        let tracker = ConnectionTracker::new();
        let result = tracker.wait_for_shutdown(Duration::from_millis(100)).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_connection_tracker_wait_for_shutdown_with_connections() {
        let tracker = ConnectionTracker::new();
        tracker.increment();

        let tracker_clone = tracker.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tracker_clone.decrement();
        });

        let result = tracker.wait_for_shutdown(Duration::from_millis(200)).await;
        assert!(result);
        assert_eq!(tracker.count(), 0);
    }

    #[tokio::test]
    async fn test_connection_tracker_wait_for_shutdown_timeout() {
        let tracker = ConnectionTracker::new();
        tracker.increment();

        let result = tracker.wait_for_shutdown(Duration::from_millis(50)).await;
        assert!(!result);
        assert_eq!(tracker.count(), 1);
    }

    // ===========================================
    // ConnectionLimiter tests
    // ===========================================

    #[test]
    fn test_connection_limiter_unlimited() {
        let limiter = ConnectionLimiter::new(0);
        assert!(!limiter.is_enabled());
        assert_eq!(limiter.max_connections(), 0);
        assert!(!limiter.at_capacity());
    }

    #[test]
    fn test_connection_limiter_with_limit() {
        let limiter = ConnectionLimiter::new(10);
        assert!(limiter.is_enabled());
        assert_eq!(limiter.max_connections(), 10);
        assert!(!limiter.at_capacity());
    }

    #[test]
    fn test_connection_limiter_try_acquire_unlimited() {
        let limiter = ConnectionLimiter::new(0);
        // Should return None when unlimited (no semaphore)
        assert!(limiter.try_acquire().is_none());
    }

    #[test]
    fn test_connection_limiter_try_acquire_with_limit() {
        let limiter = ConnectionLimiter::new(2);

        let permit1 = limiter.try_acquire();
        assert!(permit1.is_some());

        let permit2 = limiter.try_acquire();
        assert!(permit2.is_some());

        // At capacity now
        assert!(limiter.at_capacity());

        let permit3 = limiter.try_acquire();
        assert!(permit3.is_none());
    }

    #[test]
    fn test_connection_limiter_permit_release() {
        let limiter = ConnectionLimiter::new(1);

        let permit = limiter.try_acquire();
        assert!(permit.is_some());
        assert!(limiter.at_capacity());

        // Drop permit to release
        drop(permit);

        // Should be able to acquire again
        assert!(!limiter.at_capacity());
        let permit2 = limiter.try_acquire();
        assert!(permit2.is_some());
    }

    #[test]
    fn test_connection_limiter_default_unlimited() {
        let limiter = ConnectionLimiter::new(0);
        assert!(!limiter.is_enabled());
    }
}
