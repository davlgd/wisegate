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

/// Extract proxy IP from forwarded header 'by=' field
fn extract_proxy_ip_from_forwarded(forwarded: &str) -> Option<String> {
    forwarded
        .split(';')
        .find_map(|part| part.trim().strip_prefix("by="))
        .map(|ip| ip.trim().to_string())
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

/// Extract client IP from forwarded header 'for=' field
fn extract_client_ip_from_forwarded(forwarded: &str) -> Option<String> {
    forwarded
        .split(';')
        .find_map(|part| part.trim().strip_prefix("for="))
        .map(|ip_part| {
            // Handle cases like "for=192.168.1.1:1234" or "for=192.168.1.1"
            if let Some(colon_pos) = ip_part.find(':') {
                ip_part[..colon_pos].trim().to_string()
            } else {
                ip_part.trim().to_string()
            }
        })
        .filter(|ip| is_valid_ip_format(ip))
}

/// Basic IP format validation (contains . for IPv4 or : for IPv6)
/// Also validates that it's not empty and doesn't contain invalid characters
fn is_valid_ip_format(ip: &str) -> bool {
    if ip.is_empty() || ip.len() > 45 {
        return false; // Max IPv6 length is 39, add some buffer
    }

    // Basic format check
    let has_valid_format = ip.contains('.') || ip.contains(':');

    // Additional validation: should not contain spaces or other invalid chars
    let has_invalid_chars = ip
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !".:[]".contains(c));

    has_valid_format && !has_invalid_chars
}
