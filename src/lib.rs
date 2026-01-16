//! WiseGate - A wise guardian for your network gates
//!
//! An efficient, secure reverse proxy with built-in rate limiting and IP filtering.
//!
//! # Overview
//!
//! WiseGate is a high-performance reverse proxy written in Rust that provides:
//! - Rate limiting with sliding window algorithm
//! - IP filtering and blocking
//! - HTTP method and URL pattern filtering
//! - Trusted proxy validation (RFC 7239 compliant)
//! - Structured logging with JSON support
//!
//! # Example
//!
//! ```rust,no_run
//! use wisegate::{config, RateLimiter};
//!
//! // Get configuration from environment
//! let rate_config = config::get_rate_limit_config();
//! let proxy_config = config::get_proxy_config();
//!
//! // Create a rate limiter
//! let limiter = RateLimiter::new();
//! ```
//!
//! # Modules
//!
//! - [`config`] - Configuration management from environment variables
//! - [`env_vars`] - Environment variable constants
//! - [`server`] - Server utilities and startup info
//! - [`args`] - Command line argument parsing
//!
//! # Re-exports from wisegate-core
//!
//! Core functionality is provided by the `wisegate-core` crate:
//! - [`ip_filter`] - IP validation, extraction, and filtering
//! - [`rate_limiter`] - Rate limiting implementation
//! - [`request_handler`] - HTTP request processing and forwarding

#![forbid(unsafe_code)]

pub mod args;
pub mod config;
pub mod connection;
pub mod env_vars;
pub mod server;

// Re-export wisegate-core modules
pub use wisegate_core::ip_filter;
pub use wisegate_core::rate_limiter;
pub use wisegate_core::request_handler;
pub use wisegate_core::types;

// Re-export commonly used items at crate root
pub use config::{
    EnvVarConfig, get_allowed_proxy_ips, get_blocked_ips, get_blocked_methods,
    get_blocked_patterns, get_max_connections, get_proxy_config, get_rate_limit_cleanup_config,
    get_rate_limit_config,
};
pub use wisegate_core::{
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
