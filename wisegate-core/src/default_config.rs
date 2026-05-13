//! Ready-to-use configuration for library consumers.
//!
//! [`DefaultConfig`] implements every configuration trait
//! ([`RateLimitingProvider`], [`ProxyProvider`], [`FilteringProvider`],
//! [`ConnectionProvider`], [`AuthenticationProvider`]) with the same defaults
//! the CLI uses. Tweak its public fields to customize behaviour without
//! defining a fresh struct or implementing each trait by hand.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use std::time::Duration;
//! use wisegate_core::{DefaultConfig, RateLimiter};
//!
//! let mut config = DefaultConfig::default();
//! config.rate_limit.max_requests = 200;
//! config.rate_limit.window_duration = Duration::from_secs(30);
//! config.blocked_methods = vec!["TRACE".into(), "CONNECT".into()];
//!
//! let _limiter = RateLimiter::new();
//! let _shared_config = Arc::new(config);
//! ```

use crate::auth::Credentials;
use crate::defaults;
use crate::types::{
    AuthenticationProvider, ConnectionProvider, FilteringProvider, ProxyConfig, ProxyProvider,
    RateLimitCleanupConfig, RateLimitConfig, RateLimitingProvider,
};

/// Configuration backed by plain fields — pre-populated with WiseGate's defaults.
///
/// Use this when you want to drop wisegate-core into an application without
/// designing your own configuration plumbing. Mutate the fields directly,
/// then pass the struct (often wrapped in an `Arc`) to
/// [`request_handler::handle_request`](crate::request_handler::handle_request).
#[derive(Debug, Clone)]
pub struct DefaultConfig {
    /// Rate limit policy applied per client IP.
    pub rate_limit: RateLimitConfig,
    /// Rate limiter housekeeping policy.
    pub cleanup: RateLimitCleanupConfig,
    /// Upstream proxy behaviour (timeout, body size cap).
    pub proxy: ProxyConfig,
    /// Trusted proxy IPs. `Some` activates strict mode; `None` is permissive.
    pub allowed_proxy_ips: Option<Vec<String>>,
    /// Client IPs that should be rejected with 403.
    pub blocked_ips: Vec<String>,
    /// HTTP methods that should be rejected with 405.
    pub blocked_methods: Vec<String>,
    /// URL substrings that should be rejected with 404.
    pub blocked_patterns: Vec<String>,
    /// Hard cap on concurrent connections; `0` disables the limit.
    pub max_connections: usize,
    /// Basic Auth credential set (empty disables Basic Auth).
    pub auth_credentials: Credentials,
    /// Realm advertised in `WWW-Authenticate`.
    pub auth_realm: String,
    /// Bearer token (`None` or empty disables bearer auth).
    pub bearer_token: Option<String>,
    /// Forward the `Authorization` header to the upstream after wisegate auth.
    pub forward_authorization_header: bool,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig {
                max_requests: defaults::RATE_LIMIT_REQUESTS,
                window_duration: defaults::RATE_LIMIT_WINDOW,
            },
            cleanup: RateLimitCleanupConfig {
                threshold: defaults::RATE_LIMIT_CLEANUP_THRESHOLD,
                interval: defaults::RATE_LIMIT_CLEANUP_INTERVAL,
            },
            proxy: ProxyConfig {
                timeout: defaults::PROXY_TIMEOUT,
                max_body_size: defaults::MAX_BODY_SIZE,
            },
            allowed_proxy_ips: None,
            blocked_ips: Vec::new(),
            blocked_methods: Vec::new(),
            blocked_patterns: Vec::new(),
            max_connections: defaults::MAX_CONNECTIONS,
            auth_credentials: Credentials::new(),
            auth_realm: defaults::AUTH_REALM.to_string(),
            bearer_token: None,
            forward_authorization_header: false,
        }
    }
}

impl RateLimitingProvider for DefaultConfig {
    fn rate_limit_config(&self) -> &RateLimitConfig {
        &self.rate_limit
    }
    fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
        &self.cleanup
    }
}

impl ProxyProvider for DefaultConfig {
    fn proxy_config(&self) -> &ProxyConfig {
        &self.proxy
    }
    fn allowed_proxy_ips(&self) -> Option<&[String]> {
        self.allowed_proxy_ips.as_deref()
    }
}

impl FilteringProvider for DefaultConfig {
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

impl ConnectionProvider for DefaultConfig {
    fn max_connections(&self) -> usize {
        self.max_connections
    }
}

impl AuthenticationProvider for DefaultConfig {
    fn auth_credentials(&self) -> &Credentials {
        &self.auth_credentials
    }
    fn auth_realm(&self) -> &str {
        &self.auth_realm
    }
    fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }
    fn forward_authorization_header(&self) -> bool {
        self.forward_authorization_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConfigProvider;

    fn assert_is_config_provider<T: ConfigProvider>(_: &T) {}

    #[test]
    fn default_config_implements_config_provider() {
        let config = DefaultConfig::default();
        assert_is_config_provider(&config);
    }

    #[test]
    fn default_values_match_cli_defaults() {
        let config = DefaultConfig::default();
        assert_eq!(
            config.rate_limit.max_requests,
            defaults::RATE_LIMIT_REQUESTS
        );
        assert_eq!(config.max_connections, defaults::MAX_CONNECTIONS);
        assert!(config.allowed_proxy_ips.is_none());
        assert!(!config.forward_authorization_header);
    }
}
