//! Error types for WiseGate.
//!
//! This module provides a unified error type for all WiseGate operations,
//! enabling better error handling and propagation throughout the codebase.

use thiserror::Error;

/// Result type alias for WiseGate operations.
pub type Result<T> = std::result::Result<T, WiseGateError>;

/// Unified error type for WiseGate operations.
///
/// This enum covers all error cases that can occur during request processing,
/// configuration, and proxying operations.
///
/// # Example
///
/// ```
/// use wisegate_core::error::{WiseGateError, Result};
///
/// fn validate_ip(ip: &str) -> Result<()> {
///     if ip.is_empty() {
///         return Err(WiseGateError::InvalidIp("IP address cannot be empty".into()));
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum WiseGateError {
    /// Invalid IP address format or value.
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    /// Configuration error (missing or invalid values).
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Error during request proxying.
    #[error("Proxy error: {0}")]
    ProxyError(String),

    /// Rate limit exceeded for a client.
    #[error("Rate limit exceeded for IP: {0}")]
    RateLimitExceeded(String),

    /// Request blocked by IP filter.
    #[error("IP blocked: {0}")]
    IpBlocked(String),

    /// Request blocked by URL pattern filter.
    #[error("URL pattern blocked: {0}")]
    PatternBlocked(String),

    /// Request blocked by HTTP method filter.
    #[error("HTTP method blocked: {0}")]
    MethodBlocked(String),

    /// Upstream connection failed.
    #[error("Upstream connection failed: {0}")]
    UpstreamConnectionFailed(String),

    /// Upstream request timed out.
    #[error("Upstream timeout: {0}")]
    UpstreamTimeout(String),

    /// Request body too large.
    #[error("Request body too large: {size} bytes (max: {max} bytes)")]
    BodyTooLarge {
        /// Actual body size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Failed to read request or response body.
    #[error("Body read error: {0}")]
    BodyReadError(String),

    /// HTTP client error (from reqwest).
    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] reqwest::Error),

    /// Invalid HTTP header value.
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
}

impl WiseGateError {
    /// Returns the appropriate HTTP status code for this error.
    ///
    /// # Returns
    ///
    /// The HTTP status code that should be returned to the client.
    pub fn status_code(&self) -> hyper::StatusCode {
        use hyper::StatusCode;

        match self {
            Self::InvalidIp(_) => StatusCode::BAD_REQUEST,
            Self::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ProxyError(_) => StatusCode::BAD_GATEWAY,
            Self::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::IpBlocked(_) => StatusCode::FORBIDDEN,
            Self::PatternBlocked(_) => StatusCode::NOT_FOUND,
            Self::MethodBlocked(_) => StatusCode::METHOD_NOT_ALLOWED,
            Self::UpstreamConnectionFailed(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyReadError(_) => StatusCode::BAD_REQUEST,
            Self::HttpClientError(_) => StatusCode::BAD_GATEWAY,
            Self::InvalidHeader(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Returns a user-friendly error message suitable for HTTP responses.
    ///
    /// This method returns a sanitized message that doesn't expose
    /// internal details to clients.
    pub fn user_message(&self) -> &str {
        match self {
            Self::InvalidIp(_) => "Invalid request",
            Self::ConfigError(_) => "Internal server error",
            Self::ProxyError(_) => "Bad gateway",
            Self::RateLimitExceeded(_) => "Rate limit exceeded",
            Self::IpBlocked(_) => "Access denied",
            Self::PatternBlocked(_) => "Not found",
            Self::MethodBlocked(_) => "Method not allowed",
            Self::UpstreamConnectionFailed(_) => "Service unavailable",
            Self::UpstreamTimeout(_) => "Gateway timeout",
            Self::BodyTooLarge { .. } => "Request body too large",
            Self::BodyReadError(_) => "Bad request",
            Self::HttpClientError(_) => "Bad gateway",
            Self::InvalidHeader(_) => "Bad request",
        }
    }

    /// Returns true if this error should be logged at error level.
    ///
    /// Some errors (like rate limiting) are expected and should only
    /// be logged at debug/info level.
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            Self::ConfigError(_)
                | Self::ProxyError(_)
                | Self::UpstreamConnectionFailed(_)
                | Self::UpstreamTimeout(_)
                | Self::HttpClientError(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    #[test]
    fn test_error_display() {
        let err = WiseGateError::InvalidIp("192.168.1.999".into());
        assert_eq!(err.to_string(), "Invalid IP address: 192.168.1.999");

        let err = WiseGateError::RateLimitExceeded("10.0.0.1".into());
        assert_eq!(err.to_string(), "Rate limit exceeded for IP: 10.0.0.1");

        let err = WiseGateError::BodyTooLarge {
            size: 200,
            max: 100,
        };
        assert_eq!(
            err.to_string(),
            "Request body too large: 200 bytes (max: 100 bytes)"
        );
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(
            WiseGateError::InvalidIp("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WiseGateError::RateLimitExceeded("".into()).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            WiseGateError::IpBlocked("".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            WiseGateError::PatternBlocked("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            WiseGateError::MethodBlocked("".into()).status_code(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            WiseGateError::UpstreamTimeout("".into()).status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            WiseGateError::BodyTooLarge { size: 0, max: 0 }.status_code(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn test_user_messages() {
        assert_eq!(
            WiseGateError::ConfigError("secret".into()).user_message(),
            "Internal server error"
        );
        assert_eq!(
            WiseGateError::IpBlocked("10.0.0.1".into()).user_message(),
            "Access denied"
        );
    }

    #[test]
    fn test_is_server_error() {
        assert!(WiseGateError::ConfigError("".into()).is_server_error());
        assert!(WiseGateError::UpstreamConnectionFailed("".into()).is_server_error());
        assert!(WiseGateError::UpstreamTimeout("".into()).is_server_error());

        assert!(!WiseGateError::RateLimitExceeded("".into()).is_server_error());
        assert!(!WiseGateError::IpBlocked("".into()).is_server_error());
        assert!(!WiseGateError::MethodBlocked("".into()).is_server_error());
    }
}
