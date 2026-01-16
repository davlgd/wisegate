//! IP filtering and validation for WiseGate.
//!
//! This module handles:
//! - Extraction of real client IPs from proxy headers
//! - Validation of trusted proxy IPs
//! - IP blocking/filtering
//! - RFC 7239 compliant Forwarded header parsing
//!
//! # Security Model
//!
//! WiseGate operates in two modes:
//!
//! ## Strict Mode (proxy allowlist configured)
//! - Requires both `x-forwarded-for` and `forwarded` headers
//! - Validates proxy IP from `by=` field against allowlist
//! - Extracts client IP from header chain
//!
//! ## Permissive Mode (no proxy allowlist)
//! - Attempts to extract client IP from available headers
//! - Falls back gracefully if headers are missing
//!
//! # Example
//!
//! ```ignore
//! use wisegate_core::ip_filter;
//! use hyper::HeaderMap;
//!
//! let headers = HeaderMap::new();
//! if let Some(client_ip) = ip_filter::extract_and_validate_real_ip(&headers, &config) {
//!     if ip_filter::is_ip_blocked(&client_ip, &config) {
//!         // Reject request
//!     }
//! }
//! ```

use crate::types::ConfigProvider;

/// Checks if an IP address is in the blocked list.
///
/// # Arguments
///
/// * `ip` - The IP address to check
/// * `config` - Configuration provider for blocked IPs list
///
/// # Returns
///
/// `true` if the IP is blocked, `false` otherwise
///
/// # Example
///
/// ```ignore
/// use wisegate_core::ip_filter::is_ip_blocked;
///
/// let blocked = is_ip_blocked("192.168.1.1", &config);
/// ```
pub fn is_ip_blocked(ip: &str, config: &impl ConfigProvider) -> bool {
    config
        .blocked_ips()
        .iter()
        .any(|blocked_ip| blocked_ip == ip)
}

/// Extracts and validates the real client IP from request headers.
///
/// This function implements WiseGate's security model:
///
/// 1. **Strict mode** (proxy allowlist configured):
///    - Requires both `x-forwarded-for` and `forwarded` headers
///    - Validates proxy IP from `by=` field against allowlist
///    - Extracts client IP from the last entry in `x-forwarded-for`
///
/// 2. **Permissive mode** (no proxy allowlist):
///    - Attempts to extract client IP from available headers
///    - Returns `None` if no valid IP can be extracted
///
/// # Arguments
///
/// * `headers` - HTTP request headers
/// * `config` - Configuration provider for allowed proxy IPs
///
/// # Returns
///
/// - `Some(String)` - The validated client IP address
/// - `None` - If validation fails or no IP can be extracted
///
/// # Example
///
/// ```ignore
/// use wisegate_core::ip_filter::extract_and_validate_real_ip;
///
/// let client_ip = extract_and_validate_real_ip(&request.headers(), &config);
/// ```
pub fn extract_and_validate_real_ip(
    headers: &hyper::HeaderMap,
    config: &impl ConfigProvider,
) -> Option<String> {
    let allowed_proxy_ips = config.allowed_proxy_ips();
    let has_proxy_allowlist = allowed_proxy_ips.is_some();

    if has_proxy_allowlist {
        // Strict mode: require both headers and validate proxy IP
        let xff = headers.get("x-forwarded-for")?.to_str().ok()?;
        let forwarded = headers.get("forwarded")?.to_str().ok()?;
        let proxy_ip = extract_proxy_ip_from_forwarded(forwarded)?;

        if !is_proxy_ip_allowed(&proxy_ip, allowed_proxy_ips) {
            return None;
        }

        extract_client_ip_from_xff(xff)
    } else {
        // Permissive mode: try to extract client IP from available headers
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
            // If we have x-forwarded-for, try to extract client IP from it
            if let Some(client_ip) = extract_client_ip_from_xff(xff) {
                return Some(client_ip);
            }
        }

        if let Some(forwarded) = headers.get("forwarded").and_then(|h| h.to_str().ok()) {
            // If we have forwarded header, try to extract client IP
            if let Some(client_ip) = extract_client_ip_from_forwarded(forwarded) {
                return Some(client_ip);
            }
        }

        // If no headers are available or contain valid IPs, we'll return None
        // This will cause the request handler to use a default behavior
        None
    }
}

/// Extract proxy IP from forwarded header 'by=' field (RFC 7239 compliant)
/// Format: Forwarded: for=client;by=proxy, for=client2;by=proxy2
/// Elements are separated by ',' and parameters within an element by ';'
fn extract_proxy_ip_from_forwarded(forwarded: &str) -> Option<String> {
    // RFC 7239: elements separated by ',', parameters by ';'
    // We want the 'by=' parameter from the last element (closest proxy)
    forwarded
        .split(',')
        .next_back()
        .and_then(|element| {
            element
                .split(';')
                .find_map(|param| param.trim().strip_prefix("by="))
        })
        .and_then(extract_ip_from_node_identifier)
}

/// Check if proxy IP is in the allowed list
/// If no allowed proxy IPs are configured, allows any proxy IP (returns true)
fn is_proxy_ip_allowed(proxy_ip: &str, allowed_proxy_ips: Option<&[String]>) -> bool {
    match allowed_proxy_ips {
        Some(allowed_ips) => allowed_ips.iter().any(|ip| ip == proxy_ip),
        None => true, // If no allowlist is configured, allow any proxy IP
    }
}

/// Extract client IP from x-forwarded-for header (last valid IP)
/// The last IP in the chain should be the real client IP
fn extract_client_ip_from_xff(xff: &str) -> Option<String> {
    xff.split(',')
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .rfind(|ip| is_valid_ip_format(ip))
        .map(|ip| ip.to_string())
}

/// Extract client IP from forwarded header 'for=' field (RFC 7239 compliant)
/// Format: Forwarded: for=client;by=proxy, for=client2;by=proxy2
/// Handles node identifiers: IP, "IP:port", "[IPv6]", "[IPv6]:port", "unknown", "secret"
fn extract_client_ip_from_forwarded(forwarded: &str) -> Option<String> {
    // RFC 7239: elements separated by ',', parameters by ';'
    // We want the 'for=' parameter from the first element (original client)
    forwarded
        .split(',')
        .next()
        .and_then(|element| {
            element
                .split(';')
                .find_map(|param| param.trim().strip_prefix("for="))
        })
        .and_then(extract_ip_from_node_identifier)
        .filter(|ip| is_valid_ip_format(ip))
}

/// Extract IP address from RFC 7239 node identifier
/// Handles formats: IP, "IP:port", "[IPv6]", "[IPv6]:port", quoted values
fn extract_ip_from_node_identifier(value: &str) -> Option<String> {
    let value = value.trim();

    // Remove surrounding quotes if present (RFC 7239 allows quoted strings)
    let value = value.trim_matches('"');

    // Skip special tokens
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }

    // Handle bracketed IPv6 addresses: [IPv6] or [IPv6]:port
    if value.starts_with('[') {
        if let Some(bracket_end) = value.find(']') {
            let ipv6 = &value[1..bracket_end];
            if is_valid_ip_format(ipv6) {
                return Some(ipv6.to_string());
            }
        }
        return None;
    }

    // Handle IPv4 with optional port: IP or IP:port
    // Count colons to distinguish IPv4:port from IPv6
    let colon_count = value.chars().filter(|&c| c == ':').count();

    if colon_count == 1 {
        // IPv4 with port: "192.168.1.1:8080"
        if let Some(colon_pos) = value.find(':') {
            let ip = &value[..colon_pos];
            if is_valid_ip_format(ip) {
                return Some(ip.to_string());
            }
        }
        return None;
    }

    // Plain IPv4 or unbracketed IPv6
    if is_valid_ip_format(value) {
        return Some(value.to_string());
    }

    None
}

/// Validates IP address format using std::net::IpAddr parsing
/// Supports both IPv4 and IPv6 addresses, including bracketed IPv6 (e.g., [::1])
fn is_valid_ip_format(ip: &str) -> bool {
    use std::net::IpAddr;

    if ip.is_empty() {
        return false;
    }

    // Handle bracketed IPv6 addresses (e.g., [::1])
    let ip_to_parse = ip.trim_start_matches('[').trim_end_matches(']');

    ip_to_parse.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyConfig, RateLimitCleanupConfig, RateLimitConfig};
    use std::time::Duration;

    /// Test configuration for unit tests
    struct TestConfig {
        allowed_proxy_ips: Option<Vec<String>>,
        blocked_ips: Vec<String>,
    }

    impl TestConfig {
        fn permissive() -> Self {
            Self {
                allowed_proxy_ips: None,
                blocked_ips: vec![],
            }
        }

        fn strict(allowed_proxies: Vec<&str>) -> Self {
            Self {
                allowed_proxy_ips: Some(allowed_proxies.into_iter().map(String::from).collect()),
                blocked_ips: vec![],
            }
        }

        fn with_blocked_ips(blocked: Vec<&str>) -> Self {
            Self {
                allowed_proxy_ips: None,
                blocked_ips: blocked.into_iter().map(String::from).collect(),
            }
        }
    }

    impl ConfigProvider for TestConfig {
        fn rate_limit_config(&self) -> &RateLimitConfig {
            static CONFIG: RateLimitConfig = RateLimitConfig {
                max_requests: 100,
                window_duration: Duration::from_secs(60),
            };
            &CONFIG
        }

        fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
            static CONFIG: RateLimitCleanupConfig = RateLimitCleanupConfig {
                threshold: 10_000,
                interval: Duration::from_secs(60),
            };
            &CONFIG
        }

        fn proxy_config(&self) -> &ProxyConfig {
            static CONFIG: ProxyConfig = ProxyConfig {
                timeout: Duration::from_secs(30),
                max_body_size: 100 * 1024 * 1024,
            };
            &CONFIG
        }

        fn allowed_proxy_ips(&self) -> Option<&[String]> {
            self.allowed_proxy_ips.as_deref()
        }

        fn blocked_ips(&self) -> &[String] {
            &self.blocked_ips
        }

        fn blocked_methods(&self) -> &[String] {
            &[]
        }

        fn blocked_patterns(&self) -> &[String] {
            &[]
        }

        fn max_connections(&self) -> usize {
            10_000
        }
    }

    // ===========================================
    // is_ip_blocked tests
    // ===========================================

    #[test]
    fn test_is_ip_blocked_when_blocked() {
        let config = TestConfig::with_blocked_ips(vec!["192.168.1.100", "10.0.0.1"]);
        assert!(is_ip_blocked("192.168.1.100", &config));
        assert!(is_ip_blocked("10.0.0.1", &config));
    }

    #[test]
    fn test_is_ip_blocked_when_not_blocked() {
        let config = TestConfig::with_blocked_ips(vec!["192.168.1.100"]);
        assert!(!is_ip_blocked("192.168.1.101", &config));
        assert!(!is_ip_blocked("10.0.0.1", &config));
    }

    #[test]
    fn test_is_ip_blocked_empty_list() {
        let config = TestConfig::permissive();
        assert!(!is_ip_blocked("192.168.1.1", &config));
    }

    #[test]
    fn test_is_ip_blocked_ipv6() {
        let config = TestConfig::with_blocked_ips(vec!["::1", "2001:db8::1"]);
        assert!(is_ip_blocked("::1", &config));
        assert!(is_ip_blocked("2001:db8::1", &config));
        assert!(!is_ip_blocked("2001:db8::2", &config));
    }

    // ===========================================
    // is_valid_ip_format tests
    // ===========================================

    #[test]
    fn test_is_valid_ip_format_ipv4() {
        assert!(is_valid_ip_format("192.168.1.1"));
        assert!(is_valid_ip_format("10.0.0.1"));
        assert!(is_valid_ip_format("127.0.0.1"));
        assert!(is_valid_ip_format("0.0.0.0"));
        assert!(is_valid_ip_format("255.255.255.255"));
    }

    #[test]
    fn test_is_valid_ip_format_ipv4_invalid() {
        assert!(!is_valid_ip_format("256.1.1.1"));
        assert!(!is_valid_ip_format("192.168.1"));
        assert!(!is_valid_ip_format("192.168.1.1.1"));
        assert!(!is_valid_ip_format("abc.def.ghi.jkl"));
        assert!(!is_valid_ip_format("192.168.1.1:8080")); // Port not allowed
    }

    #[test]
    fn test_is_valid_ip_format_ipv6() {
        assert!(is_valid_ip_format("::1"));
        assert!(is_valid_ip_format("2001:db8::1"));
        assert!(is_valid_ip_format("fe80::1"));
        assert!(is_valid_ip_format("::ffff:192.168.1.1"));
        assert!(is_valid_ip_format(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ));
    }

    #[test]
    fn test_is_valid_ip_format_ipv6_bracketed() {
        assert!(is_valid_ip_format("[::1]"));
        assert!(is_valid_ip_format("[2001:db8::1]"));
    }

    #[test]
    fn test_is_valid_ip_format_empty() {
        assert!(!is_valid_ip_format(""));
    }

    #[test]
    fn test_is_valid_ip_format_garbage() {
        assert!(!is_valid_ip_format("not-an-ip"));
        assert!(!is_valid_ip_format("unknown"));
        assert!(!is_valid_ip_format("_secret"));
    }

    // ===========================================
    // extract_ip_from_node_identifier tests
    // ===========================================

    #[test]
    fn test_extract_ip_from_node_identifier_plain_ipv4() {
        assert_eq!(
            extract_ip_from_node_identifier("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_ipv4_with_port() {
        assert_eq!(
            extract_ip_from_node_identifier("192.168.1.1:8080"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_plain_ipv6() {
        assert_eq!(
            extract_ip_from_node_identifier("::1"),
            Some("::1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("2001:db8::1"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_bracketed_ipv6() {
        assert_eq!(
            extract_ip_from_node_identifier("[::1]"),
            Some("::1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("[2001:db8::1]"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_bracketed_ipv6_with_port() {
        assert_eq!(
            extract_ip_from_node_identifier("[::1]:8080"),
            Some("::1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("[2001:db8::1]:443"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_quoted() {
        assert_eq!(
            extract_ip_from_node_identifier("\"192.168.1.1\""),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("\"[::1]:8080\""),
            Some("::1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_node_identifier_unknown() {
        assert_eq!(extract_ip_from_node_identifier("unknown"), None);
        assert_eq!(extract_ip_from_node_identifier("UNKNOWN"), None);
    }

    #[test]
    fn test_extract_ip_from_node_identifier_obfuscated() {
        // RFC 7239: obfuscated identifiers start with '_'
        assert_eq!(extract_ip_from_node_identifier("_secret"), None);
        assert_eq!(extract_ip_from_node_identifier("_hidden123"), None);
    }

    #[test]
    fn test_extract_ip_from_node_identifier_with_whitespace() {
        assert_eq!(
            extract_ip_from_node_identifier("  192.168.1.1  "),
            Some("192.168.1.1".to_string())
        );
    }

    // ===========================================
    // extract_client_ip_from_xff tests
    // ===========================================

    #[test]
    fn test_extract_client_ip_from_xff_single() {
        assert_eq!(
            extract_client_ip_from_xff("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_xff_chain() {
        // Last valid IP should be returned
        assert_eq!(
            extract_client_ip_from_xff("10.0.0.1, 172.16.0.1, 192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_xff_with_whitespace() {
        assert_eq!(
            extract_client_ip_from_xff("  10.0.0.1 ,  192.168.1.1  "),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_xff_empty() {
        assert_eq!(extract_client_ip_from_xff(""), None);
    }

    #[test]
    fn test_extract_client_ip_from_xff_invalid_only() {
        assert_eq!(extract_client_ip_from_xff("invalid, also-invalid"), None);
    }

    #[test]
    fn test_extract_client_ip_from_xff_ipv6() {
        assert_eq!(extract_client_ip_from_xff("::1"), Some("::1".to_string()));
        assert_eq!(
            extract_client_ip_from_xff("10.0.0.1, 2001:db8::1"),
            Some("2001:db8::1".to_string())
        );
    }

    // ===========================================
    // extract_proxy_ip_from_forwarded tests
    // ===========================================

    #[test]
    fn test_extract_proxy_ip_from_forwarded_simple() {
        assert_eq!(
            extract_proxy_ip_from_forwarded("for=client;by=10.0.0.1"),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_proxy_ip_from_forwarded_multiple_elements() {
        // Should get 'by=' from the LAST element (closest proxy)
        assert_eq!(
            extract_proxy_ip_from_forwarded("for=c1;by=10.0.0.1, for=c2;by=192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_proxy_ip_from_forwarded_no_by() {
        assert_eq!(extract_proxy_ip_from_forwarded("for=192.168.1.1"), None);
    }

    #[test]
    fn test_extract_proxy_ip_from_forwarded_ipv6() {
        assert_eq!(
            extract_proxy_ip_from_forwarded("for=client;by=\"[::1]\""),
            Some("::1".to_string())
        );
    }

    // ===========================================
    // extract_client_ip_from_forwarded tests
    // ===========================================

    #[test]
    fn test_extract_client_ip_from_forwarded_simple() {
        assert_eq!(
            extract_client_ip_from_forwarded("for=192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_forwarded_with_by() {
        assert_eq!(
            extract_client_ip_from_forwarded("for=192.168.1.1;by=10.0.0.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_forwarded_multiple_elements() {
        // Should get 'for=' from the FIRST element (original client)
        assert_eq!(
            extract_client_ip_from_forwarded("for=192.168.1.1;by=p1, for=10.0.0.1;by=p2"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_forwarded_ipv6() {
        assert_eq!(
            extract_client_ip_from_forwarded("for=\"[2001:db8::1]\""),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_forwarded_unknown() {
        assert_eq!(extract_client_ip_from_forwarded("for=unknown"), None);
    }

    // ===========================================
    // is_proxy_ip_allowed tests
    // ===========================================

    #[test]
    fn test_is_proxy_ip_allowed_in_list() {
        let allowed = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        assert!(is_proxy_ip_allowed("10.0.0.1", Some(&allowed)));
        assert!(is_proxy_ip_allowed("10.0.0.2", Some(&allowed)));
    }

    #[test]
    fn test_is_proxy_ip_allowed_not_in_list() {
        let allowed = vec!["10.0.0.1".to_string()];
        assert!(!is_proxy_ip_allowed("10.0.0.2", Some(&allowed)));
    }

    #[test]
    fn test_is_proxy_ip_allowed_no_list() {
        // When no allowlist is configured, any proxy IP is allowed
        assert!(is_proxy_ip_allowed("any.ip.address", None));
    }

    // ===========================================
    // extract_and_validate_real_ip tests (integration)
    // ===========================================

    #[test]
    fn test_extract_and_validate_real_ip_permissive_with_xff() {
        let config = TestConfig::permissive();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_with_forwarded() {
        let config = TestConfig::permissive();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("forwarded", "for=192.168.1.100".parse().unwrap());

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_xff_priority() {
        let config = TestConfig::permissive();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
        headers.insert("forwarded", "for=10.0.0.1".parse().unwrap());

        // XFF should be checked first
        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_no_headers() {
        let config = TestConfig::permissive();
        let headers = hyper::HeaderMap::new();

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_valid() {
        let config = TestConfig::strict(vec!["10.0.0.1"]);
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
        headers.insert(
            "forwarded",
            "for=192.168.1.100;by=10.0.0.1".parse().unwrap(),
        );

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_proxy_not_allowed() {
        let config = TestConfig::strict(vec!["10.0.0.1"]);
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
        headers.insert(
            "forwarded",
            "for=192.168.1.100;by=10.0.0.2".parse().unwrap(),
        ); // Wrong proxy

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_missing_xff() {
        let config = TestConfig::strict(vec!["10.0.0.1"]);
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=192.168.1.100;by=10.0.0.1".parse().unwrap(),
        );
        // Missing x-forwarded-for

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_missing_forwarded() {
        let config = TestConfig::strict(vec!["10.0.0.1"]);
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
        // Missing forwarded

        let result = extract_and_validate_real_ip(&headers, &config);
        assert_eq!(result, None);
    }
}
