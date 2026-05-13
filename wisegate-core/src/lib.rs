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
//! # Quick start
//!
//! [`DefaultConfig`] pre-implements every configuration trait, so a minimal
//! setup needs no boilerplate. Mutate its public fields to customize behaviour:
//!
//! ```
//! use std::time::Duration;
//! use wisegate_core::{DefaultConfig, RateLimiter};
//!
//! let mut config = DefaultConfig::default();
//! config.rate_limit.max_requests = 200;
//! config.rate_limit.window_duration = Duration::from_secs(30);
//! config.blocked_methods = vec!["TRACE".into(), "CONNECT".into()];
//!
//! let _limiter = RateLimiter::new();
//! ```
//!
//! When you need finer control, implement the composable traits directly
//! ([`RateLimitingProvider`], [`ProxyProvider`], [`FilteringProvider`],
//! [`ConnectionProvider`], [`AuthenticationProvider`]). See [`types`] for
//! a worked example of bespoke implementations.
//!
//! # Wiring it into hyper
//!
//! [`request_handler::handle_request`] is async and expects a Tokio runtime —
//! call it from inside `#[tokio::main]` or any other Tokio executor. It takes
//! an `Arc<C: ConfigProvider>` so the same configuration can be cloned cheaply
//! across spawned tasks.
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

pub mod auth;
pub mod default_config;
pub mod defaults;
pub mod error;
pub mod headers;
pub mod ip_filter;
pub mod rate_limiter;
pub mod request_handler;
#[cfg(test)]
pub mod test_utils;
pub mod types;

// Re-export commonly used items at crate root
pub use auth::{Credential, Credentials, check_basic_auth, check_bearer_token};
pub use default_config::DefaultConfig;
pub use error::WiseGateError;
pub use types::{
    // Composable configuration traits
    AuthenticationProvider,
    // Aggregated configuration trait
    ConfigProvider,
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
