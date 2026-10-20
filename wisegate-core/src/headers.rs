//! HTTP header constants for WiseGate.
//!
//! This module centralizes all HTTP header names used throughout the codebase,
//! avoiding magic strings and ensuring consistency.

/// X-Forwarded-For header - contains the originating client IP.
pub const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// X-Real-IP header - injected by WiseGate for upstream services.
pub const X_REAL_IP: &str = "x-real-ip";

/// Forwarded header (RFC 7239) - standardized proxy header.
pub const FORWARDED: &str = "forwarded";

/// Authorization header (for Basic Auth).
pub const AUTHORIZATION: &str = "authorization";

/// WWW-Authenticate header (for 401 responses).
pub const WWW_AUTHENTICATE: &str = "www-authenticate";

/// Content-Type header.
pub const CONTENT_TYPE: &str = "content-type";

/// Host header.
pub const HOST: &str = "host";

/// Content-Length header.
pub const CONTENT_LENGTH: &str = "content-length";

/// Connection header (hop-by-hop).
pub const CONNECTION: &str = "connection";

/// Keep-Alive header (hop-by-hop).
pub const KEEP_ALIVE: &str = "keep-alive";

/// Proxy-Authenticate header (hop-by-hop).
pub const PROXY_AUTHENTICATE: &str = "proxy-authenticate";

/// Proxy-Authorization header (hop-by-hop).
pub const PROXY_AUTHORIZATION: &str = "proxy-authorization";

/// TE header (hop-by-hop).
pub const TE: &str = "te";

/// Trailer header (hop-by-hop, RFC 9110 section 7.6.1).
pub const TRAILER: &str = "trailer";

/// Former, misspelled name of [`TRAILER`]. `trailers` is a `TE` token, not a
/// header field, so matching it never removed the `Trailer` header.
#[deprecated(since = "0.13.0", note = "use `TRAILER`; the header is `Trailer`")]
pub const TRAILERS: &str = "trailers";

/// Transfer-Encoding header (hop-by-hop).
pub const TRANSFER_ENCODING: &str = "transfer-encoding";

/// Upgrade header (hop-by-hop).
pub const UPGRADE: &str = "upgrade";

/// List of all hop-by-hop headers that should not be forwarded.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    CONNECTION,
    KEEP_ALIVE,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
];

/// Check if a header is a hop-by-hop header that shouldn't be forwarded.
///
/// Comparison is case-insensitive (ASCII), avoiding allocations from `to_lowercase()`.
///
/// # Arguments
///
/// * `header_name` - The header name to check.
///
/// # Returns
///
/// `true` if the header is a hop-by-hop header, `false` otherwise.
///
/// # Example
///
/// ```
/// use wisegate_core::headers::is_hop_by_hop;
///
/// assert!(is_hop_by_hop("connection"));
/// assert!(is_hop_by_hop("Transfer-Encoding"));
/// assert!(!is_hop_by_hop("content-type"));
/// ```
pub fn is_hop_by_hop(header_name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(header_name))
}

/// Returns the header names listed in the `Connection` header(s), lowercased.
///
/// RFC 9110 section 7.6.1: a proxy must remove every field named in
/// `Connection` before forwarding the message, in addition to the fixed
/// hop-by-hop list.
///
/// # Example
///
/// ```
/// use wisegate_core::headers::connection_nominated;
///
/// let mut headers = hyper::HeaderMap::new();
/// headers.insert("connection", "keep-alive, X-Secret".parse().unwrap());
/// assert_eq!(connection_nominated(&headers), vec!["keep-alive", "x-secret"]);
/// ```
pub fn connection_nominated(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Returns `true` if a header must not be forwarded: either a fixed
/// hop-by-hop header or one nominated by `Connection` (see
/// [`connection_nominated`]).
pub fn is_hop_by_hop_for(header_name: &str, nominated: &[String]) -> bool {
    is_hop_by_hop(header_name)
        || nominated
            .iter()
            .any(|token| token.eq_ignore_ascii_case(header_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop(CONNECTION));
        assert!(is_hop_by_hop(KEEP_ALIVE));
        assert!(is_hop_by_hop(PROXY_AUTHENTICATE));
        assert!(is_hop_by_hop(PROXY_AUTHORIZATION));
        assert!(is_hop_by_hop(TE));
        assert!(is_hop_by_hop(TRAILER));
        assert!(is_hop_by_hop("Trailer"));
        assert!(is_hop_by_hop(TRANSFER_ENCODING));
        assert!(is_hop_by_hop(UPGRADE));
    }

    #[test]
    fn test_connection_nominated_reads_every_field() {
        let mut headers = hyper::HeaderMap::new();
        headers.append(CONNECTION, "close, X-Secret".parse().unwrap());
        headers.append(CONNECTION, " x-other ,,".parse().unwrap());
        assert_eq!(
            connection_nominated(&headers),
            vec!["close", "x-secret", "x-other"]
        );
    }

    #[test]
    fn test_is_hop_by_hop_for_nominated_headers() {
        let nominated = vec!["x-secret".to_string()];
        assert!(is_hop_by_hop_for("X-Secret", &nominated));
        assert!(is_hop_by_hop_for(UPGRADE, &nominated));
        assert!(!is_hop_by_hop_for("x-public", &nominated));
    }

    #[test]
    fn test_not_hop_by_hop_headers() {
        assert!(!is_hop_by_hop(CONTENT_TYPE));
        assert!(!is_hop_by_hop(HOST));
        assert!(!is_hop_by_hop(CONTENT_LENGTH));
        assert!(!is_hop_by_hop(X_FORWARDED_FOR));
        assert!(!is_hop_by_hop(X_REAL_IP));
        assert!(!is_hop_by_hop(FORWARDED));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("accept"));
    }

    #[test]
    fn test_header_constants_lowercase() {
        // All header constants should be lowercase for consistent matching
        assert_eq!(X_FORWARDED_FOR, X_FORWARDED_FOR.to_lowercase());
        assert_eq!(X_REAL_IP, X_REAL_IP.to_lowercase());
        assert_eq!(FORWARDED, FORWARDED.to_lowercase());
        assert_eq!(CONTENT_TYPE, CONTENT_TYPE.to_lowercase());
        assert_eq!(HOST, HOST.to_lowercase());
        assert_eq!(CONTENT_LENGTH, CONTENT_LENGTH.to_lowercase());
    }
}
