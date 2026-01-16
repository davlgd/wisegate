use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::convert::Infallible;

use crate::config;
use crate::types::RateLimiter;
use crate::{ip_filter, rate_limiter};

/// HTTP request handler with streaming support and improved error handling
pub async fn handle_request(
    req: Request<Incoming>,
    forward_port: u16,
    limiter: RateLimiter,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let proxy_config = config::get_proxy_config();

    // Extract and validate real client IP
    let real_client_ip = match ip_filter::extract_and_validate_real_ip(req.headers()) {
        Some(ip) => ip,
        None => {
            // In permissive mode (no allowlist configured), we couldn't extract IP from headers
            // Use placeholder IP and continue with non-IP-based security features only
            if config::get_allowed_proxy_ips().is_none() {
                "unknown".to_string()
            } else {
                // If allowlist is configured but validation failed, reject the request
                return Ok(create_error_response(
                    StatusCode::FORBIDDEN,
                    "Invalid request: missing or invalid proxy headers",
                ));
            }
        }
    };

    // Check if IP is blocked (skip if IP is unknown)
    if real_client_ip != "unknown" && ip_filter::is_ip_blocked(&real_client_ip) {
        return Ok(create_error_response(
            StatusCode::FORBIDDEN,
            "IP address is blocked",
        ));
    }

    // Check for blocked URL patterns
    let request_path = req.uri().path();
    if is_url_pattern_blocked(request_path) {
        return Ok(create_error_response(StatusCode::NOT_FOUND, "Not Found"));
    }

    // Check for blocked HTTP methods
    let request_method = req.method().as_str();
    if is_method_blocked(request_method) {
        return Ok(create_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP method not allowed",
        ));
    }

    // Apply rate limiting (skip if IP is unknown)
    if real_client_ip != "unknown" && !rate_limiter::check_rate_limit(&limiter, &real_client_ip) {
        return Ok(create_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        ));
    }

    // Add X-Real-IP header for upstream service (only if we have a real IP)
    let mut req = req;
    if real_client_ip != "unknown" {
        if let Ok(header_value) = real_client_ip.parse() {
            req.headers_mut().insert("x-real-ip", header_value);
        }
    }

    // Forward the request
    forward_request(req, forward_port, &proxy_config).await
}

/// Forward request to upstream service
async fn forward_request(
    req: Request<Incoming>,
    port: u16,
    proxy_config: &crate::types::ProxyConfig,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(bytes) => {
            let collected_bytes = bytes.to_bytes();

            // Check body size limit
            if proxy_config.max_body_size > 0 && collected_bytes.len() > proxy_config.max_body_size
            {
                return Ok(create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large",
                ));
            }

            collected_bytes
        }
        Err(_) => {
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body",
            ));
        }
    };

    forward_with_reqwest(parts, body_bytes, port, proxy_config).await
}

/// Shared forwarding logic using reqwest with timeout support
async fn forward_with_reqwest(
    parts: hyper::http::request::Parts,
    body_bytes: bytes::Bytes,
    port: u16,
    proxy_config: &crate::types::ProxyConfig,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    // Construct destination URI
    let destination_uri = format!(
        "http://localhost:{}{}",
        port,
        parts.uri.path_and_query().map_or("", |pq| pq.as_str())
    );

    // Create reqwest client with timeout configuration
    let client = reqwest::Client::builder()
        .timeout(proxy_config.timeout)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // Build the request with method support for all HTTP verbs
    let mut req_builder = match parts.method.as_str() {
        "GET" => client.get(&destination_uri),
        "POST" => client.post(&destination_uri),
        "PUT" => client.put(&destination_uri),
        "DELETE" => client.delete(&destination_uri),
        "HEAD" => client.head(&destination_uri),
        "PATCH" => client.patch(&destination_uri),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &destination_uri),
        method => {
            // Try to parse custom methods
            match reqwest::Method::from_bytes(method.as_bytes()) {
                Ok(custom_method) => client.request(custom_method, &destination_uri),
                Err(_) => {
                    return Ok(create_error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "HTTP method not supported",
                    ));
                }
            }
        }
    };

    // Add headers (excluding host and content-length)
    for (name, value) in parts.headers.iter() {
        if name != "host" && name != "content-length" {
            if let Ok(header_value) = value.to_str() {
                req_builder = req_builder.header(name.as_str(), header_value);
            }
        }
    }

    // Add body if not empty
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    // Send request
    match req_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();

            match response.bytes().await {
                Ok(body_bytes) => {
                    let mut hyper_response = Response::builder()
                        .status(status.as_u16())
                        .body(Full::new(body_bytes))
                        .unwrap();

                    // Copy response headers (skip hop-by-hop headers)
                    for (name, value) in headers.iter() {
                        let header_name = name.as_str().to_lowercase();
                        // Skip hop-by-hop headers that shouldn't be forwarded
                        if !is_hop_by_hop_header(&header_name) {
                            if let (Ok(hyper_name), Ok(hyper_value)) = (
                                hyper::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                                hyper::header::HeaderValue::from_bytes(value.as_bytes()),
                            ) {
                                hyper_response.headers_mut().insert(hyper_name, hyper_value);
                            }
                        }
                    }

                    Ok(hyper_response)
                }
                Err(_) => Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to read response body",
                )),
            }
        }
        Err(err) => {
            // More specific error handling
            if err.is_timeout() {
                Ok(create_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream service timeout",
                ))
            } else if err.is_connect() {
                Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Could not connect to upstream service",
                ))
            } else {
                Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream service error",
                ))
            }
        }
    }
}

/// Create standardized error responses
pub fn create_error_response(status: StatusCode, message: &str) -> Response<Full<bytes::Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(bytes::Bytes::from(message.to_string())))
        .unwrap()
}

/// Check if URL path contains any blocked patterns
/// Decodes URL-encoded characters to prevent bypass via encoding (e.g., .ph%70 for .php)
fn is_url_pattern_blocked(path: &str) -> bool {
    let blocked_patterns = config::get_blocked_patterns();
    if blocked_patterns.is_empty() {
        return false;
    }

    // Decode URL-encoded path to prevent bypass attacks
    let decoded_path = url_decode(path);

    // Check against both original and decoded path
    blocked_patterns.iter().any(|pattern| {
        path.contains(pattern) || decoded_path.contains(pattern)
    })
}

/// Decode URL-encoded string (percent-encoding)
/// Handles common bypass attempts like %2e for '.', %70 for 'p', etc.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // If decoding failed, keep original characters
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

/// Check if HTTP method is blocked
fn is_method_blocked(method: &str) -> bool {
    let blocked_methods = config::get_blocked_methods();
    blocked_methods
        .iter()
        .any(|blocked_method| blocked_method == &method.to_uppercase())
}

/// Check if a header is a hop-by-hop header that shouldn't be forwarded
fn is_hop_by_hop_header(header_name: &str) -> bool {
    matches!(
        header_name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}
