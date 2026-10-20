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
//! - Requires the TCP peer to be an allowlisted proxy
//! - Reads the last `forwarded` element, the one that proxy appended
//! - Validates its `by=` against the allowlist and takes the client IP from its `for=`
//!
//! ## Permissive Mode (no proxy allowlist)
//! - Attempts to extract client IP from available headers
//! - Falls back gracefully if headers are missing
//!
//! ⚠️ Permissive mode trusts client-supplied `X-Forwarded-For`/`Forwarded`
//! headers verbatim. An attacker who can reach wisegate directly can spoof
//! their apparent IP by forging these headers. Use permissive mode only when
//! wisegate sits behind another reverse proxy that strips or normalises them,
//! or when IP attribution is not a security boundary.
//!
//! # Example
//!
//! ```ignore
//! use wisegate_core::ip_filter;
//! use hyper::HeaderMap;
//!
//! let headers = HeaderMap::new();
//! if let Some(client_ip) = ip_filter::extract_and_validate_real_ip(&headers, peer_ip, &config) {
//!     if ip_filter::is_ip_blocked(&client_ip, &config) {
//!         // Reject request
//!     }
//! }
//! ```

use std::net::IpAddr;

use crate::headers;
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
        .any(|blocked_ip| ips_match(blocked_ip, ip))
}

/// Returns true when `a` and `b` denote the same IP address, comparing on
/// canonical form so non-canonical IPv6 spellings in config still match.
/// Falls back to byte equality when either side fails to parse.
fn ips_match(a: &str, b: &str) -> bool {
    match (parse_canonical_ip(a), parse_canonical_ip(b)) {
        (Some(ca), Some(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Extracts and validates the real client IP from request headers.
///
/// This function implements WiseGate's security model:
///
/// 1. **Strict mode** (proxy allowlist configured):
///    - The TCP peer (`peer_ip`) must be in the allowlist, or be a loopback
///      address when [`crate::ProxyProvider::trust_loopback_proxy`] is enabled
///    - Only the last element of the `forwarded` header is used: it is the one
///      appended by the trusted proxy. Its `by=` must be in the allowlist and
///      its `for=` is the client IP. No fallback to earlier elements.
///    - All `forwarded` header fields are read, in order, so a client cannot
///      hide the proxy's element behind a field of its own
///    - `x-forwarded-for` is not used
///
/// 2. **Permissive mode** (no proxy allowlist):
///    - Attempts to extract client IP from available headers
///    - Returns `None` if no valid IP can be extracted
///
/// # Arguments
///
/// * `headers` - HTTP request headers
/// * `peer_ip` - IP address of the TCP peer that sent the request
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
/// let client_ip = extract_and_validate_real_ip(&request.headers(), peer_addr.ip(), &config);
/// ```
pub fn extract_and_validate_real_ip(
    headers: &hyper::HeaderMap,
    peer_ip: IpAddr,
    config: &impl ConfigProvider,
) -> Option<String> {
    match config.allowed_proxy_ips() {
        Some(allowed_proxy_ips) => extract_from_trusted_proxy(
            headers,
            peer_ip,
            allowed_proxy_ips,
            config.trust_loopback_proxy(),
        ),
        None => extract_permissive(headers),
    }
}

/// Strict mode: trust only what the allowlisted proxy appended itself.
fn extract_from_trusted_proxy(
    headers: &hyper::HeaderMap,
    peer_ip: IpAddr,
    allowed_proxy_ips: &[String],
    trust_loopback_proxy: bool,
) -> Option<String> {
    let peer_ip = peer_ip.to_canonical();
    let peer_trusted = (trust_loopback_proxy && peer_ip.is_loopback())
        || is_proxy_ip_allowed(&peer_ip.to_string(), Some(allowed_proxy_ips));
    if !peer_trusted {
        return None;
    }

    let forwarded = joined_header_values(headers, headers::FORWARDED)?;
    let proxy_ip = extract_proxy_ip_from_forwarded(&forwarded)?;
    if !is_proxy_ip_allowed(&proxy_ip, Some(allowed_proxy_ips)) {
        return None;
    }

    extract_client_ip_from_last_forwarded(&forwarded)
}

/// Permissive mode: best-effort extraction from client-controlled headers.
fn extract_permissive(headers: &hyper::HeaderMap) -> Option<String> {
    if let Some(xff) = joined_header_values(headers, headers::X_FORWARDED_FOR)
        && let Some(client_ip) = extract_client_ip_from_xff(&xff)
    {
        return Some(client_ip);
    }

    joined_header_values(headers, headers::FORWARDED)
        .and_then(|forwarded| extract_client_ip_from_forwarded(&forwarded))
}

/// Joins every field of a header with `,`, in order, as RFC 9110 allows for
/// list-based fields. Proxies such as Sōzu append to the last field only, so
/// reading just the first one would return a client-controlled value.
/// Returns `None` if the header is absent or a field is not visible ASCII.
fn joined_header_values(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter().peekable();
    values.peek()?;
    values
        .map(|value| value.to_str().ok())
        .collect::<Option<Vec<_>>>()
        .map(|fields| fields.join(","))
}

/// Returns the value of a Forwarded parameter in one element.
///
/// Parameter names are case-insensitive (RFC 7239, section 4). Fails closed:
/// returns `None` if any parameter of the element is malformed (no `=`, empty
/// name, unbalanced or embedded quotes) or if `name` appears more than once,
/// so an ambiguous element can never yield an identity.
fn forwarded_param<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    let mut found = None;
    for param in element.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, value) = param.split_once('=')?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() || !is_valid_forwarded_value(value) {
            return None;
        }
        if key.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// A Forwarded value is either a token-like string without quotes or a single
/// quoted string with no quote or backslash inside it.
fn is_valid_forwarded_value(value: &str) -> bool {
    match value.strip_prefix('"') {
        Some(rest) => rest
            .strip_suffix('"')
            .is_some_and(|inner| !inner.contains(['"', '\\'])),
        None => !value.is_empty() && !value.contains(['"', '\\']),
    }
}

/// Last element of a Forwarded header: the one added by the closest proxy.
///
/// This deliberately supports a subset of RFC 7239: the element is whatever
/// follows the last `,`, so a proxy whose own element contains a comma inside
/// a quoted extension is not supported (the element then fails validation
/// and the request is rejected). A full tokenizer would let an unterminated
/// quote in a client-supplied earlier element swallow the proxy's element.
fn last_forwarded_element(forwarded: &str) -> &str {
    forwarded.rsplit(',').next().unwrap_or(forwarded)
}

/// Extract proxy IP from forwarded header 'by=' field (RFC 7239 compliant)
/// Format: Forwarded: for=client;by=proxy, for=client2;by=proxy2
/// Elements are separated by ',' and parameters within an element by ';'
fn extract_proxy_ip_from_forwarded(forwarded: &str) -> Option<String> {
    // We want the 'by=' parameter from the last element (closest proxy)
    forwarded_param(last_forwarded_element(forwarded), "by")
        .and_then(extract_ip_from_node_identifier)
}

/// Extract client IP from the 'for=' field of the last Forwarded element,
/// the one written by the closest proxy alongside its own 'by='.
fn extract_client_ip_from_last_forwarded(forwarded: &str) -> Option<String> {
    forwarded_param(last_forwarded_element(forwarded), "for")
        .and_then(extract_ip_from_node_identifier)
}

/// Check if proxy IP is in the allowed list
/// If no allowed proxy IPs are configured, allows any proxy IP (returns true).
/// Comparison is done on canonical form so non-canonical IPv6 spellings in
/// config still match (`2001:0db8::1` vs `2001:db8::1`).
fn is_proxy_ip_allowed(proxy_ip: &str, allowed_proxy_ips: Option<&[String]>) -> bool {
    match allowed_proxy_ips {
        Some(allowed_ips) => allowed_ips.iter().any(|ip| ips_match(ip, proxy_ip)),
        None => true, // If no allowlist is configured, allow any proxy IP
    }
}

/// Extract client IP from x-forwarded-for header (last valid IP)
/// The last IP in the chain should be the real client IP
fn extract_client_ip_from_xff(xff: &str) -> Option<String> {
    xff.split(',')
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
        .rev()
        .find_map(parse_canonical_ip)
}

/// Extract client IP from forwarded header 'for=' field (RFC 7239 compliant)
/// Format: Forwarded: for=client;by=proxy, for=client2;by=proxy2
/// Handles node identifiers: IP, "IP:port", "[IPv6]", "[IPv6]:port", "unknown", "secret"
fn extract_client_ip_from_forwarded(forwarded: &str) -> Option<String> {
    // We want the 'for=' parameter from the first element (original client)
    forwarded
        .split(',')
        .next()
        .and_then(|element| forwarded_param(element, "for"))
        .and_then(extract_ip_from_node_identifier)
}

/// Extract IP address from RFC 7239 node identifier
/// Handles formats: IP, "IP:port", "[IPv6]", "[IPv6]:port", quoted values.
/// The whole value must parse: a port must be a valid u16 or an obfuscated
/// `_token`, and nothing may follow the address or port.
fn extract_ip_from_node_identifier(value: &str) -> Option<String> {
    let value = value.trim();

    // Remove one pair of surrounding quotes (RFC 7239 allows quoted strings)
    let value = match value.strip_prefix('"') {
        Some(rest) => rest.strip_suffix('"')?,
        None => value,
    };
    if value.contains('"') {
        return None;
    }

    // Skip special tokens
    if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }

    // Handle bracketed IPv6 addresses: [IPv6] or [IPv6]:port
    if let Some(rest) = value.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        if !after.is_empty() && !after.strip_prefix(':').is_some_and(is_valid_node_port) {
            return None;
        }
        return ip
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .and_then(|_| parse_canonical_ip(ip));
    }

    // Handle IPv4 with optional port: IP or IP:port
    // Count colons to distinguish IPv4:port from IPv6
    if value.matches(':').count() == 1 {
        // IPv4 with port: "192.168.1.1:8080"
        let (ip, port) = value.split_once(':')?;
        if !is_valid_node_port(port) {
            return None;
        }
        return ip
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .and_then(|_| parse_canonical_ip(ip));
    }

    // Plain IPv4 or unbracketed IPv6: parsed as-is, no bracket trimming
    value
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_canonical().to_string())
}

/// RFC 7239 node-port: a decimal port number or an obfuscated `_token`.
fn is_valid_node_port(port: &str) -> bool {
    match port.strip_prefix('_') {
        Some(obfuscated) => {
            !obfuscated.is_empty()
                && obfuscated
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }
        None => {
            port.len() <= 5
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        }
    }
}

/// Parses an IP address and returns its canonical string form.
///
/// Two equivalent IPv6 representations (e.g. `2001:db8::1` and
/// `2001:0db8:0000:0000:0000:0000:0000:0001`) produce the same canonical
/// string (RFC 5952), and IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`)
/// collapse to their IPv4 form. This prevents bypassing per-IP rate limiting
/// or blocklists by alternating address formats.
fn parse_canonical_ip(ip: &str) -> Option<String> {
    if ip.is_empty() {
        return None;
    }

    // Handle bracketed IPv6 addresses (e.g., [::1])
    let ip_to_parse = ip.trim_start_matches('[').trim_end_matches(']');

    ip_to_parse
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_canonical().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestConfig;

    // ===========================================
    // is_ip_blocked tests
    // ===========================================

    #[test]
    fn test_is_ip_blocked_when_blocked() {
        let config = TestConfig::new().with_blocked_ips(vec!["192.168.1.100", "10.0.0.1"]);
        assert!(is_ip_blocked("192.168.1.100", &config));
        assert!(is_ip_blocked("10.0.0.1", &config));
    }

    #[test]
    fn test_is_ip_blocked_when_not_blocked() {
        let config = TestConfig::new().with_blocked_ips(vec!["192.168.1.100"]);
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
        let config = TestConfig::new().with_blocked_ips(vec!["::1", "2001:db8::1"]);
        assert!(is_ip_blocked("::1", &config));
        assert!(is_ip_blocked("2001:db8::1", &config));
        assert!(!is_ip_blocked("2001:db8::2", &config));
    }

    #[test]
    fn test_is_ip_blocked_matches_non_canonical_config() {
        // Operator typed the IPv6 in full form in config; runtime sees canonical form.
        let config =
            TestConfig::new().with_blocked_ips(vec!["2001:0db8:0000:0000:0000:0000:0000:0001"]);
        assert!(is_ip_blocked("2001:db8::1", &config));
    }

    #[test]
    fn test_is_proxy_ip_allowed_matches_non_canonical_config() {
        let allowed = vec!["2001:0db8:0000:0000:0000:0000:0000:0001".to_string()];
        assert!(is_proxy_ip_allowed("2001:db8::1", Some(&allowed)));
        assert!(!is_proxy_ip_allowed("2001:db8::2", Some(&allowed)));
    }

    // ===========================================
    // parse_canonical_ip tests
    // ===========================================

    #[test]
    fn test_parse_canonical_ip_ipv4() {
        assert_eq!(
            parse_canonical_ip("192.168.1.1").as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(parse_canonical_ip("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(
            parse_canonical_ip("127.0.0.1").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(parse_canonical_ip("0.0.0.0").as_deref(), Some("0.0.0.0"));
        assert_eq!(
            parse_canonical_ip("255.255.255.255").as_deref(),
            Some("255.255.255.255")
        );
    }

    #[test]
    fn test_parse_canonical_ip_ipv4_invalid() {
        assert!(parse_canonical_ip("256.1.1.1").is_none());
        assert!(parse_canonical_ip("192.168.1").is_none());
        assert!(parse_canonical_ip("192.168.1.1.1").is_none());
        assert!(parse_canonical_ip("abc.def.ghi.jkl").is_none());
        assert!(parse_canonical_ip("192.168.1.1:8080").is_none()); // Port not allowed
    }

    #[test]
    fn test_parse_canonical_ip_ipv6() {
        assert_eq!(parse_canonical_ip("::1").as_deref(), Some("::1"));
        assert_eq!(
            parse_canonical_ip("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_canonical_ip("fe80::1").as_deref(), Some("fe80::1"));
        // RFC 5952 canonical form: zero compression collapses long forms.
        assert_eq!(
            parse_canonical_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334").as_deref(),
            Some("2001:db8:85a3::8a2e:370:7334"),
        );
    }

    #[test]
    fn test_parse_canonical_ip_ipv6_bracketed() {
        assert_eq!(parse_canonical_ip("[::1]").as_deref(), Some("::1"));
        assert_eq!(
            parse_canonical_ip("[2001:db8::1]").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn test_parse_canonical_ip_empty() {
        assert!(parse_canonical_ip("").is_none());
    }

    #[test]
    fn test_parse_canonical_ip_garbage() {
        assert!(parse_canonical_ip("not-an-ip").is_none());
        assert!(parse_canonical_ip("unknown").is_none());
        assert!(parse_canonical_ip("_secret").is_none());
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
    fn test_extract_canonicalizes_ipv6_forms() {
        // RFC 5952: zero-compressed form is canonical, so an attacker cannot
        // bypass per-IP rate limiting by sending the same address spelled out.
        assert_eq!(
            extract_client_ip_from_xff("2001:0db8:0000:0000:0000:0000:0000:0001"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(
            extract_client_ip_from_xff("2001:db8::1"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("[2001:0db8:0000:0000:0000:0000:0000:0001]:8080"),
            Some("2001:db8::1".to_string())
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

    const PROXY: &str = "10.0.0.1";

    fn peer(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    fn headers_from(fields: &[(&'static str, &str)]) -> hyper::HeaderMap {
        let mut headers = hyper::HeaderMap::new();
        for (name, value) in fields {
            headers.append(*name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_with_xff() {
        let config = TestConfig::permissive();
        let headers = headers_from(&[("x-forwarded-for", "192.168.1.100")]);

        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.1"), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_with_forwarded() {
        let config = TestConfig::permissive();
        let headers = headers_from(&[("forwarded", "for=192.168.1.100")]);

        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.1"), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_xff_priority() {
        let config = TestConfig::permissive();
        let headers = headers_from(&[
            ("x-forwarded-for", "192.168.1.100"),
            ("forwarded", "for=10.0.0.1"),
        ]);

        // XFF should be checked first
        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.1"), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_reads_every_xff_field() {
        let config = TestConfig::permissive();
        let headers = headers_from(&[
            ("x-forwarded-for", "198.51.100.7"),
            ("x-forwarded-for", "198.51.100.8, 192.168.1.100"),
        ]);

        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.1"), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_permissive_no_headers() {
        let config = TestConfig::permissive();
        let headers = hyper::HeaderMap::new();

        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.1"), &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_valid() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.1")]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_sozu_format() {
        // Header as appended by Sōzu on Clever Cloud: quoted for= with port
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[(
            "forwarded",
            "proto=https;for=\"192.168.1.100:57676\";by=10.0.0.1",
        )]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_param_names_case_insensitive() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("forwarded", "For=192.168.1.100;BY=10.0.0.1")]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_by_may_differ_from_peer() {
        // Design choice: peer and by= must both be allowlisted, not equal. A
        // multi-homed load balancer may connect from another address than
        // the one it announces in by=.
        let config = TestConfig::strict(vec![PROXY, "10.0.0.2"]);
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.2")]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_proxy_not_allowed() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.2")]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_rejects_untrusted_peer() {
        // A client reaching wisegate directly forges the proxy's by=
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[
            ("x-forwarded-for", "198.51.100.7"),
            ("forwarded", "for=198.51.100.7;by=10.0.0.1"),
        ]);

        let result = extract_and_validate_real_ip(&headers, peer("203.0.113.66"), &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_ipv4_mapped_peer() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.1")]);

        let result = extract_and_validate_real_ip(&headers, peer("::ffff:10.0.0.1"), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_loopback_peer_needs_opt_in() {
        let mut config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.1")]);

        assert_eq!(
            extract_and_validate_real_ip(&headers, peer("127.0.0.1"), &config),
            None
        );

        config.trust_loopback_proxy = true;
        assert_eq!(
            extract_and_validate_real_ip(&headers, peer("127.0.0.1"), &config),
            Some("192.168.1.100".to_string())
        );
        assert_eq!(
            extract_and_validate_real_ip(&headers, peer("::1"), &config),
            Some("192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_loopback_still_checks_by() {
        let mut config = TestConfig::strict(vec![PROXY]);
        config.trust_loopback_proxy = true;
        let headers = headers_from(&[("forwarded", "for=192.168.1.100;by=10.0.0.2")]);

        let result = extract_and_validate_real_ip(&headers, peer("127.0.0.1"), &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_ignores_xff() {
        // The client IP comes from the proxy's Forwarded element, never XFF
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[
            ("x-forwarded-for", "198.51.100.7"),
            ("forwarded", "for=192.168.1.100;by=10.0.0.1"),
        ]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_duplicate_forwarded_fields() {
        // Sōzu appends to the last field; a client-supplied first field
        // carrying an allowlisted by= must not be picked up.
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[
            ("forwarded", "for=198.51.100.9;by=10.0.0.1"),
            (
                "forwarded",
                "for=198.51.100.10, for=192.168.1.100;by=10.0.0.1",
            ),
        ]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_client_prefix_ignored() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[(
            "forwarded",
            "for=198.51.100.9;by=10.0.0.1, for=192.168.1.100;by=10.0.0.1",
        )]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_no_fallback_on_invalid_for() {
        // An unusable for= in the proxy's element must not fall back to an
        // earlier, client-controlled element.
        let config = TestConfig::strict(vec![PROXY]);
        for last in [
            "for=unknown;by=10.0.0.1",
            "for=_hidden;by=10.0.0.1",
            "by=10.0.0.1",
        ] {
            let value = format!("for=198.51.100.9;by=10.0.0.1, {last}");
            let headers = headers_from(&[("forwarded", value.as_str())]);
            assert_eq!(
                extract_and_validate_real_ip(&headers, peer(PROXY), &config),
                None,
                "{value}"
            );
        }
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_missing_forwarded() {
        let config = TestConfig::strict(vec![PROXY]);
        let headers = headers_from(&[("x-forwarded-for", "192.168.1.100")]);

        let result = extract_and_validate_real_ip(&headers, peer(PROXY), &config);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_and_validate_real_ip_strict_rejects_ambiguous_elements() {
        // Separators hidden in a quoted extension, duplicated parameters and
        // malformed node identifiers must fail closed, never yield a client IP.
        let config = TestConfig::strict(vec![PROXY]);
        for value in [
            "for=198.51.100.7;by=10.0.0.1;ext=\"x;for=203.0.113.66\"",
            "for=198.51.100.7;by=10.0.0.1;ext=\"x,for=203.0.113.66;by=10.0.0.1\"",
            "for=198.51.100.7;for=203.0.113.66;by=10.0.0.1",
            "for=198.51.100.7;by=10.0.0.1;by=10.0.0.1",
            "for=\"198.51.100.7;by=10.0.0.1",
            "for=198.51.100.7:garbage;by=10.0.0.1",
            "for=198.51.100.7:65536;by=10.0.0.1",
            "for=\"[2001:db8::1]garbage\";by=10.0.0.1",
            "for=\"[198.51.100.7]\";by=10.0.0.1",
            "for=198.51.100.7;by=10.0.0.1;novalue",
            "for=198.51.100.7];by=10.0.0.1",
            "for=2001:db8::1]];by=10.0.0.1",
        ] {
            let headers = headers_from(&[("forwarded", value)]);
            assert_eq!(
                extract_and_validate_real_ip(&headers, peer(PROXY), &config),
                None,
                "{value}"
            );
        }
    }

    #[test]
    fn test_extract_ip_from_node_identifier_ports() {
        assert_eq!(
            extract_ip_from_node_identifier("\"192.0.2.1:65535\""),
            Some("192.0.2.1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("\"192.0.2.1:_proxy-1\""),
            Some("192.0.2.1".to_string())
        );
        assert_eq!(
            extract_ip_from_node_identifier("\"[2001:db8::1]:_x\""),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(extract_ip_from_node_identifier("\"192.0.2.1:\""), None);
        assert_eq!(extract_ip_from_node_identifier("\"192.0.2.1:_\""), None);
        assert_eq!(extract_ip_from_node_identifier("\"\"192.0.2.1\"\""), None);
    }

    #[test]
    fn test_parse_canonical_ip_collapses_ipv4_mapped() {
        assert_eq!(
            parse_canonical_ip("::ffff:192.0.2.1"),
            Some("192.0.2.1".to_string())
        );
    }

    #[test]
    fn test_is_ip_blocked_matches_ipv4_mapped_form() {
        let config = TestConfig {
            blocked_ips: vec!["192.0.2.1".to_string()],
            ..TestConfig::permissive()
        };
        assert!(is_ip_blocked("::ffff:192.0.2.1", &config));
    }
}
