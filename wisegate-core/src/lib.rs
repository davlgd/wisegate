//! WiseGate Core - Reusable reverse proxy components
//!
//! This crate provides the core functionality for building reverse proxies with:
//! - Rate limiting with sliding window algorithm
//! - IP filtering and blocking
//! - HTTP method and URL pattern filtering
//! - Trusted proxy validation (RFC 7239 compliant)
//!
//! # Overview
//!
//! `wisegate-core` is designed to be framework-agnostic and can be integrated
//! into any Rust application. Configuration is provided via the [`ConfigProvider`]
//! trait, allowing flexible configuration from any source.
//!
//! # Example
//!
//! ```rust,no_run
//! use wisegate_core::{
//!     RateLimitingProvider, ProxyProvider, FilteringProvider, ConnectionProvider,
//!     RateLimiter, RateLimitConfig, RateLimitCleanupConfig, ProxyConfig,
//! };
//! use std::time::Duration;
//!
//! // Implement your own configuration provider using composable traits
//! struct MyConfig;
//!
//! impl RateLimitingProvider for MyConfig {
//!     fn rate_limit_config(&self) -> &RateLimitConfig {
//!         static CONFIG: RateLimitConfig = RateLimitConfig {
//!             max_requests: 100,
//!             window_duration: Duration::from_secs(60),
//!         };
//!         &CONFIG
//!     }
//!
//!     fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
//!         static CONFIG: RateLimitCleanupConfig = RateLimitCleanupConfig {
//!             threshold: 10_000,
//!             interval: Duration::from_secs(60),
//!         };
//!         &CONFIG
//!     }
//! }
//!
//! impl ProxyProvider for MyConfig {
//!     fn proxy_config(&self) -> &ProxyConfig {
//!         static CONFIG: ProxyConfig = ProxyConfig {
//!             timeout: Duration::from_secs(30),
//!             max_body_size: 100 * 1024 * 1024,
//!         };
//!         &CONFIG
//!     }
//!
//!     fn allowed_proxy_ips(&self) -> Option<&[String]> { None }
//! }
//!
//! impl FilteringProvider for MyConfig {
//!     fn blocked_ips(&self) -> &[String] { &[] }
//!     fn blocked_methods(&self) -> &[String] { &[] }
//!     fn blocked_patterns(&self) -> &[String] { &[] }
//! }
//!
//! impl ConnectionProvider for MyConfig {
//!     fn max_connections(&self) -> usize { 10_000 }
//! }
//!
//! // Create a rate limiter
//! let limiter = RateLimiter::new();
//! ```
//!
//! # Modules
//!
//! - [`types`] - Core types and the [`ConfigProvider`] trait
//! - [`error`] - Error types and result aliases
//! - [`headers`] - HTTP header constants
//! - [`ip_filter`] - IP validation, extraction, and filtering
//! - [`rate_limiter`] - Rate limiting implementation
//! - [`request_handler`] - HTTP request processing and forwarding

#![forbid(unsafe_code)]

pub mod error;
pub mod headers;
pub mod ip_filter;
pub mod rate_limiter;
pub mod request_handler;
#[cfg(test)]
pub mod test_utils;
pub mod types;

// Re-export commonly used items at crate root
pub use error::{Result, WiseGateError};
pub use types::{
    // Aggregated configuration trait
    ConfigProvider,
    // Composable configuration traits
    ConnectionProvider,
    FilteringProvider,
    // Configuration structs
    ProxyConfig,
    ProxyProvider,
    RateLimitCleanupConfig,
    RateLimitConfig,
    // Rate limiting types
    RateLimitEntry,
    RateLimiter,
    RateLimitingProvider,
};
