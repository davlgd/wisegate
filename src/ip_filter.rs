use crate::config;

/// Check if an IP address is in the blocked list
pub fn is_ip_blocked(ip: &str) -> bool {
    let blocked_ips = config::get_blocked_ips();
    blocked_ips.iter().any(|blocked_ip| blocked_ip == ip)
}

/// This function implements the security model:
/// 1. If proxy allowlist is configured: requires both x-forwarded-for and forwarded headers
/// 2. If no proxy allowlist: attempts to extract client IP from available headers
/// 3. Validates that the proxy IP (from 'by=' field) is in allowlist (if configured)
/// 4. Extracts the real client IP (last valid IP in x-forwarded-for chain)
/// 5. Validates the real client IP is not blocked
/// 6. Returns the real client IP if all checks pass, otherwise None
pub fn extract_and_validate_real_ip(headers: &hyper::HeaderMap) -> Option<String> {
    let has_proxy_allowlist = config::get_allowed_proxy_ips().is_some();

    if has_proxy_allowlist {
        // Strict mode: require both headers and validate proxy IP
        let xff = headers.get("x-forwarded-for")?.to_str().ok()?;
        let forwarded = headers.get("forwarded")?.to_str().ok()?;
        let proxy_ip = extract_proxy_ip_from_forwarded(forwarded)?;

        if !is_proxy_ip_allowed(&proxy_ip) {
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
        .last()
        .and_then(|element| {
            element
                .split(';')
                .find_map(|param| param.trim().strip_prefix("by="))
        })
        .and_then(|value| extract_ip_from_node_identifier(value))
}

/// Check if proxy IP is in the allowed list
/// If no allowed proxy IPs are configured, allows any proxy IP (returns true)
fn is_proxy_ip_allowed(proxy_ip: &str) -> bool {
    match config::get_allowed_proxy_ips() {
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
        .filter(|ip| is_valid_ip_format(ip))
        .next_back() // Get last element efficiently (O(1) vs last()'s O(n))
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
        .and_then(|value| extract_ip_from_node_identifier(value))
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
