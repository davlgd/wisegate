//! Test utilities for WiseGate.
//!
//! This module provides shared test configuration types used across unit tests.
//! It is only compiled when running tests (`#[cfg(test)]`).

use crate::auth::Credentials;
use crate::types::{
    AuthenticationProvider, ConnectionProvider, FilteringProvider, ProxyConfig, ProxyProvider,
    RateLimitCleanupConfig, RateLimitConfig, RateLimitingProvider,
};
use std::time::Duration;

/// Shared test configuration for unit tests.
///
/// This struct implements all configuration traits with sensible defaults
/// and builder methods for customization.
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub rate_limit: RateLimitConfig,
    pub cleanup: RateLimitCleanupConfig,
    pub proxy: ProxyConfig,
    pub allowed_proxy_ips: Option<Vec<String>>,
    pub blocked_ips: Vec<String>,
    pub blocked_methods: Vec<String>,
    pub blocked_patterns: Vec<String>,
    pub max_connections: usize,
    pub auth_credentials: Credentials,
    pub auth_realm: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig {
                max_requests: 100,
                window_duration: Duration::from_secs(60),
            },
            cleanup: RateLimitCleanupConfig {
                threshold: 10_000,
                interval: Duration::from_secs(60),
            },
            proxy: ProxyConfig {
                timeout: Duration::from_secs(30),
                max_body_size: 100 * 1024 * 1024,
            },
            allowed_proxy_ips: None,
            blocked_ips: vec![],
            blocked_methods: vec![],
            blocked_patterns: vec![],
            max_connections: 10_000,
            auth_credentials: Credentials::new(),
            auth_realm: "TestRealm".to_string(),
        }
    }
}

impl TestConfig {
    /// Create a new test configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive configuration (no proxy allowlist).
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Create a strict configuration with allowed proxy IPs.
    pub fn strict(allowed_proxies: Vec<&str>) -> Self {
        Self {
            allowed_proxy_ips: Some(allowed_proxies.into_iter().map(String::from).collect()),
            ..Self::default()
        }
    }

    /// Configure rate limiting.
    pub fn with_rate_limit(mut self, max_requests: u32, window_secs: u64) -> Self {
        self.rate_limit = RateLimitConfig {
            max_requests,
            window_duration: Duration::from_secs(window_secs),
        };
        self
    }

    /// Configure cleanup threshold.
    pub fn with_cleanup(mut self, threshold: usize) -> Self {
        self.cleanup.threshold = threshold;
        self
    }

    /// Configure blocked IPs.
    pub fn with_blocked_ips(mut self, ips: Vec<&str>) -> Self {
        self.blocked_ips = ips.into_iter().map(String::from).collect();
        self
    }

    /// Configure blocked HTTP methods.
    pub fn with_blocked_methods(mut self, methods: Vec<&str>) -> Self {
        self.blocked_methods = methods.into_iter().map(String::from).collect();
        self
    }

    /// Configure blocked URL patterns.
    pub fn with_blocked_patterns(mut self, patterns: Vec<&str>) -> Self {
        self.blocked_patterns = patterns.into_iter().map(String::from).collect();
        self
    }

    /// Configure authentication credentials.
    pub fn with_auth_credentials(mut self, credentials: Credentials) -> Self {
        self.auth_credentials = credentials;
        self
    }

    /// Configure authentication realm.
    pub fn with_auth_realm(mut self, realm: &str) -> Self {
        self.auth_realm = realm.to_string();
        self
    }
}

impl RateLimitingProvider for TestConfig {
    fn rate_limit_config(&self) -> &RateLimitConfig {
        &self.rate_limit
    }

    fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
        &self.cleanup
    }
}

impl ProxyProvider for TestConfig {
    fn proxy_config(&self) -> &ProxyConfig {
        &self.proxy
    }

    fn allowed_proxy_ips(&self) -> Option<&[String]> {
        self.allowed_proxy_ips.as_deref()
    }
}

impl FilteringProvider for TestConfig {
    fn blocked_ips(&self) -> &[String] {
        &self.blocked_ips
    }

    fn blocked_methods(&self) -> &[String] {
        &self.blocked_methods
    }

    fn blocked_patterns(&self) -> &[String] {
        &self.blocked_patterns
    }
}

impl ConnectionProvider for TestConfig {
    fn max_connections(&self) -> usize {
        self.max_connections
    }
}

impl AuthenticationProvider for TestConfig {
    fn auth_credentials(&self) -> &Credentials {
        &self.auth_credentials
    }

    fn auth_realm(&self) -> &str {
        &self.auth_realm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TestConfig::new();
        assert_eq!(config.rate_limit.max_requests, 100);
        assert_eq!(config.rate_limit.window_duration, Duration::from_secs(60));
        assert!(config.allowed_proxy_ips.is_none());
        assert!(config.blocked_ips.is_empty());
    }

    #[test]
    fn test_strict_config() {
        let config = TestConfig::strict(vec!["192.168.1.1", "10.0.0.1"]);
        assert!(config.allowed_proxy_ips.is_some());
        assert_eq!(config.allowed_proxy_ips.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_builder_methods() {
        let config = TestConfig::new()
            .with_rate_limit(50, 30)
            .with_blocked_ips(vec!["1.2.3.4"])
            .with_blocked_methods(vec!["TRACE"])
            .with_blocked_patterns(vec![".env"]);

        assert_eq!(config.rate_limit.max_requests, 50);
        assert_eq!(config.blocked_ips, vec!["1.2.3.4"]);
        assert_eq!(config.blocked_methods, vec!["TRACE"]);
        assert_eq!(config.blocked_patterns, vec![".env"]);
    }
}
