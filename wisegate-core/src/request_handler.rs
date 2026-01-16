//! HTTP request handling and proxying.
//!
//! This module contains the core request handling logic for the reverse proxy,
//! including IP validation, rate limiting, URL pattern blocking, and request forwarding.
//!
//! # Architecture
//!
//! The request handling flow:
//! 1. Extract and validate client IP from proxy headers
//! 2. Check if IP is blocked
//! 3. Check for blocked URL patterns
//! 4. Check for blocked HTTP methods
//! 5. Apply rate limiting
//! 6. Forward request to upstream service
//!
//! # Connection Pooling
//!
//! The module accepts a shared [`reqwest::Client`] for HTTP connection pooling,
//! which should be configured by the caller with appropriate timeouts.

use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::convert::Infallible;
use std::sync::Arc;

use crate::types::{ConfigProvider, RateLimiter};
use crate::{ip_filter, rate_limiter};

/// Handles an incoming HTTP request through the proxy pipeline.
///
/// This is the main entry point for request processing. It performs:
/// - Client IP extraction and validation from proxy headers
/// - IP blocking checks
/// - URL pattern blocking (e.g., `.php`, `.env` files)
/// - HTTP method blocking (e.g., `PUT`, `DELETE`)
/// - Rate limiting per client IP
/// - Request forwarding to the upstream service
///
/// # Arguments
///
/// * `req` - The incoming HTTP request
/// * `forward_host` - The upstream host to forward requests to
/// * `forward_port` - The upstream port to forward requests to
/// * `limiter` - The shared rate limiter instance
/// * `config` - Configuration provider for all settings
/// * `http_client` - HTTP client for forwarding requests (with connection pooling)
///
/// # Returns
///
/// Always returns `Ok` with either:
/// - A successful proxied response from upstream
/// - An error response (403, 404, 405, 429, 502, etc.)
///
/// # Security
///
/// In strict mode (when proxy allowlist is configured), requests
/// without valid proxy headers are rejected with 403 Forbidden.
pub async fn handle_request<C: ConfigProvider>(
    req: Request<Incoming>,
    forward_host: String,
    forward_port: u16,
    limiter: RateLimiter,
    config: Arc<C>,
    http_client: reqwest::Client,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    // Extract and validate real client IP
    let real_client_ip =
        match ip_filter::extract_and_validate_real_ip(req.headers(), config.as_ref()) {
            Some(ip) => ip,
            None => {
                // In permissive mode (no allowlist configured), we couldn't extract IP from headers
                // Use placeholder IP and continue with non-IP-based security features only
                if config.allowed_proxy_ips().is_none() {
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
    if real_client_ip != "unknown" && ip_filter::is_ip_blocked(&real_client_ip, config.as_ref()) {
        return Ok(create_error_response(
            StatusCode::FORBIDDEN,
            "IP address is blocked",
        ));
    }

    // Check for blocked URL patterns
    let request_path = req.uri().path();
    if is_url_pattern_blocked(request_path, config.as_ref()) {
        return Ok(create_error_response(StatusCode::NOT_FOUND, "Not Found"));
    }

    // Check for blocked HTTP methods
    let request_method = req.method().as_str();
    if is_method_blocked(request_method, config.as_ref()) {
        return Ok(create_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP method not allowed",
        ));
    }

    // Apply rate limiting (skip if IP is unknown)
    if real_client_ip != "unknown"
        && !rate_limiter::check_rate_limit(&limiter, &real_client_ip, config.as_ref()).await
    {
        return Ok(create_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        ));
    }

    // Add X-Real-IP header for upstream service (only if we have a real IP)
    let mut req = req;
    if real_client_ip != "unknown"
        && let Ok(header_value) = real_client_ip.parse()
    {
        req.headers_mut().insert("x-real-ip", header_value);
    }

    // Forward the request
    forward_request(
        req,
        &forward_host,
        forward_port,
        config.as_ref(),
        &http_client,
    )
    .await
}

/// Forward request to upstream service
async fn forward_request(
    req: Request<Incoming>,
    host: &str,
    port: u16,
    config: &impl ConfigProvider,
    http_client: &reqwest::Client,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let proxy_config = config.proxy_config();
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

    forward_with_reqwest(parts, body_bytes, host, port, http_client).await
}

/// Shared forwarding logic using reqwest with connection pooling
async fn forward_with_reqwest(
    parts: hyper::http::request::Parts,
    body_bytes: bytes::Bytes,
    host: &str,
    port: u16,
    client: &reqwest::Client,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    // Construct destination URI
    let destination_uri = format!(
        "http://{}:{}{}",
        host,
        port,
        parts.uri.path_and_query().map_or("", |pq| pq.as_str())
    );

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
        if name != "host"
            && name != "content-length"
            && let Ok(header_value) = value.to_str()
        {
            req_builder = req_builder.header(name.as_str(), header_value);
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
                    let mut hyper_response = match Response::builder()
                        .status(status.as_u16())
                        .body(Full::new(body_bytes))
                    {
                        Ok(resp) => resp,
                        Err(_) => {
                            return Ok(create_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to build response",
                            ));
                        }
                    };

                    // Copy response headers (skip hop-by-hop headers)
                    for (name, value) in headers.iter() {
                        let header_name = name.as_str().to_lowercase();
                        // Skip hop-by-hop headers that shouldn't be forwarded
                        if !is_hop_by_hop_header(&header_name)
                            && let (Ok(hyper_name), Ok(hyper_value)) = (
                                hyper::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                                hyper::header::HeaderValue::from_bytes(value.as_bytes()),
                            )
                        {
                            hyper_response.headers_mut().insert(hyper_name, hyper_value);
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

/// Creates a standardized error response.
///
/// Builds an HTTP response with the given status code and plain text message.
/// Falls back to a minimal 500 response if building fails (should never happen
/// with valid StatusCode).
///
/// # Arguments
///
/// * `status` - The HTTP status code for the response
/// * `message` - The plain text error message body
///
/// # Returns
///
/// An HTTP response with `content-type: text/plain` header.
///
/// # Example
///
/// ```
/// use wisegate_core::request_handler::create_error_response;
/// use hyper::StatusCode;
///
/// let response = create_error_response(StatusCode::NOT_FOUND, "Resource not found");
/// assert_eq!(response.status(), StatusCode::NOT_FOUND);
/// ```
pub fn create_error_response(status: StatusCode, message: &str) -> Response<Full<bytes::Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(bytes::Bytes::from(message.to_string())))
        .unwrap_or_else(|_| {
            // Fallback response if builder fails (extremely unlikely)
            Response::new(Full::new(bytes::Bytes::from("Internal Server Error")))
        })
}

/// Check if URL path contains any blocked patterns
/// Decodes URL-encoded characters to prevent bypass via encoding (e.g., .ph%70 for .php)
fn is_url_pattern_blocked(path: &str, config: &impl ConfigProvider) -> bool {
    let blocked_patterns = config.blocked_patterns();
    if blocked_patterns.is_empty() {
        return false;
    }

    // Decode URL-encoded path to prevent bypass attacks
    let decoded_path = url_decode(path);

    // Check against both original and decoded path
    blocked_patterns
        .iter()
        .any(|pattern| path.contains(pattern) || decoded_path.contains(pattern))
}

/// Decode URL-encoded string (percent-encoding)
/// Handles common bypass attempts like %2e for '.', %70 for 'p', etc.
/// Properly handles multi-byte UTF-8 sequences.
fn url_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
            {
                bytes.push(byte);
                continue;
            }
            // If decoding failed, keep original characters
            bytes.extend_from_slice(b"%");
            bytes.extend_from_slice(hex.as_bytes());
        } else {
            // Regular character - encode as UTF-8 bytes
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    // Convert bytes to string, replacing invalid UTF-8 with replacement character
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Check if HTTP method is blocked
fn is_method_blocked(method: &str, config: &impl ConfigProvider) -> bool {
    let blocked_methods = config.blocked_methods();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ConnectionProvider, FilteringProvider, ProxyConfig, ProxyProvider, RateLimitCleanupConfig,
        RateLimitConfig, RateLimitingProvider,
    };
    use http_body_util::BodyExt;
    use std::time::Duration;

    /// Test configuration for unit tests
    struct TestConfig {
        blocked_methods: Vec<String>,
        blocked_patterns: Vec<String>,
    }

    impl TestConfig {
        fn new() -> Self {
            Self {
                blocked_methods: vec![],
                blocked_patterns: vec![],
            }
        }

        fn with_blocked_methods(mut self, methods: Vec<&str>) -> Self {
            self.blocked_methods = methods.into_iter().map(String::from).collect();
            self
        }

        fn with_blocked_patterns(mut self, patterns: Vec<&str>) -> Self {
            self.blocked_patterns = patterns.into_iter().map(String::from).collect();
            self
        }
    }

    impl RateLimitingProvider for TestConfig {
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
    }

    impl ProxyProvider for TestConfig {
        fn proxy_config(&self) -> &ProxyConfig {
            static CONFIG: ProxyConfig = ProxyConfig {
                timeout: Duration::from_secs(30),
                max_body_size: 100 * 1024 * 1024,
            };
            &CONFIG
        }

        fn allowed_proxy_ips(&self) -> Option<&[String]> {
            None
        }
    }

    impl FilteringProvider for TestConfig {
        fn blocked_ips(&self) -> &[String] {
            &[]
        }

        fn blocked_methods(&self) -> &[String] {
            &self.blocked_methods
        }

        fn blocked_patterns(&self) -> &[String] {
            &self.blocked_patterns
        }
    }

    impl ConnectionProvider for TestConfig {
        fn max_connections(&self) -> usize {
            10_000
        }
    }

    // ===========================================
    // url_decode tests
    // ===========================================

    #[test]
    fn test_url_decode_no_encoding() {
        assert_eq!(url_decode("/path/to/file"), "/path/to/file");
        assert_eq!(url_decode("hello"), "hello");
        assert_eq!(url_decode(""), "");
    }

    #[test]
    fn test_url_decode_simple_encoding() {
        assert_eq!(url_decode("%20"), " ");
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("%2F"), "/");
    }

    #[test]
    fn test_url_decode_dot_encoding() {
        // Common bypass attempts
        assert_eq!(url_decode("%2e"), ".");
        assert_eq!(url_decode("%2E"), ".");
        assert_eq!(url_decode(".%2ephp"), "..php");
    }

    #[test]
    fn test_url_decode_php_bypass() {
        // Attacker tries to bypass .php blocking
        assert_eq!(url_decode(".ph%70"), ".php");
        assert_eq!(url_decode("%2ephp"), ".php");
        assert_eq!(url_decode(".%70%68%70"), ".php");
    }

    #[test]
    fn test_url_decode_env_bypass() {
        // Attacker tries to bypass .env blocking
        assert_eq!(url_decode(".%65nv"), ".env");
        assert_eq!(url_decode("%2eenv"), ".env");
        assert_eq!(url_decode("%2e%65%6e%76"), ".env");
    }

    #[test]
    fn test_url_decode_multiple_encodings() {
        assert_eq!(url_decode("%2F%2e%2e%2Fetc%2Fpasswd"), "/../etc/passwd");
    }

    #[test]
    fn test_url_decode_invalid_hex() {
        // Invalid hex should be preserved
        assert_eq!(url_decode("%GG"), "%GG");
        assert_eq!(url_decode("%"), "%");
        assert_eq!(url_decode("%2"), "%2");
        assert_eq!(url_decode("%ZZ"), "%ZZ");
    }

    #[test]
    fn test_url_decode_mixed_content() {
        assert_eq!(url_decode("path%2Fto%2Ffile.txt"), "path/to/file.txt");
        assert_eq!(url_decode("hello%20%26%20world"), "hello & world");
    }

    #[test]
    fn test_url_decode_unicode() {
        // UTF-8 encoded characters
        assert_eq!(url_decode("%C3%A9"), "é"); // é in UTF-8
        assert_eq!(url_decode("caf%C3%A9"), "café");
    }

    // ===========================================
    // is_url_pattern_blocked tests
    // ===========================================

    #[test]
    fn test_url_pattern_blocked_simple() {
        let config = TestConfig::new().with_blocked_patterns(vec![".php", ".env"]);

        assert!(is_url_pattern_blocked("/file.php", &config));
        assert!(is_url_pattern_blocked("/.env", &config));
        assert!(is_url_pattern_blocked("/path/to/file.php", &config));
    }

    #[test]
    fn test_url_pattern_not_blocked() {
        let config = TestConfig::new().with_blocked_patterns(vec![".php", ".env"]);

        assert!(!is_url_pattern_blocked("/file.html", &config));
        assert!(!is_url_pattern_blocked("/path/to/file.js", &config));
        assert!(!is_url_pattern_blocked("/", &config));
    }

    #[test]
    fn test_url_pattern_blocked_empty_patterns() {
        let config = TestConfig::new();

        assert!(!is_url_pattern_blocked("/file.php", &config));
        assert!(!is_url_pattern_blocked("/.env", &config));
    }

    #[test]
    fn test_url_pattern_blocked_bypass_attempt() {
        let config = TestConfig::new().with_blocked_patterns(vec![".php", ".env", "admin"]);

        // URL-encoded bypass attempts should still be blocked
        assert!(is_url_pattern_blocked("/.ph%70", &config)); // .php
        assert!(is_url_pattern_blocked("/%2eenv", &config)); // .env
        assert!(is_url_pattern_blocked("/adm%69n", &config)); // admin
    }

    #[test]
    fn test_url_pattern_blocked_double_encoding_attempt() {
        let config = TestConfig::new().with_blocked_patterns(vec![".php"]);

        // Single encoding should be caught
        assert!(is_url_pattern_blocked("/.ph%70", &config));
    }

    #[test]
    fn test_url_pattern_blocked_case_sensitive() {
        let config = TestConfig::new().with_blocked_patterns(vec![".PHP"]);

        // Pattern matching is case-sensitive
        assert!(is_url_pattern_blocked("/file.PHP", &config));
        assert!(!is_url_pattern_blocked("/file.php", &config)); // Different case
    }

    #[test]
    fn test_url_pattern_blocked_partial_match() {
        let config = TestConfig::new().with_blocked_patterns(vec!["admin"]);

        assert!(is_url_pattern_blocked("/admin/panel", &config));
        assert!(is_url_pattern_blocked("/path/admin", &config));
        assert!(is_url_pattern_blocked("/administrator", &config)); // Contains "admin"
    }

    // ===========================================
    // is_method_blocked tests
    // ===========================================

    #[test]
    fn test_method_blocked() {
        let config = TestConfig::new().with_blocked_methods(vec!["TRACE", "CONNECT"]);

        assert!(is_method_blocked("TRACE", &config));
        assert!(is_method_blocked("CONNECT", &config));
    }

    #[test]
    fn test_method_not_blocked() {
        let config = TestConfig::new().with_blocked_methods(vec!["TRACE", "CONNECT"]);

        assert!(!is_method_blocked("GET", &config));
        assert!(!is_method_blocked("POST", &config));
        assert!(!is_method_blocked("PUT", &config));
        assert!(!is_method_blocked("DELETE", &config));
    }

    #[test]
    fn test_method_blocked_empty_list() {
        let config = TestConfig::new();

        assert!(!is_method_blocked("TRACE", &config));
        assert!(!is_method_blocked("GET", &config));
    }

    #[test]
    fn test_method_blocked_case_insensitive() {
        let config = TestConfig::new().with_blocked_methods(vec!["TRACE"]);

        assert!(is_method_blocked("TRACE", &config));
        assert!(is_method_blocked("trace", &config));
        assert!(is_method_blocked("Trace", &config));
    }

    // ===========================================
    // is_hop_by_hop_header tests
    // ===========================================

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("proxy-authenticate"));
        assert!(is_hop_by_hop_header("proxy-authorization"));
        assert!(is_hop_by_hop_header("te"));
        assert!(is_hop_by_hop_header("trailers"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(is_hop_by_hop_header("upgrade"));
    }

    #[test]
    fn test_not_hop_by_hop_headers() {
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("accept"));
        assert!(!is_hop_by_hop_header("authorization"));
        assert!(!is_hop_by_hop_header("x-custom-header"));
        assert!(!is_hop_by_hop_header("host"));
    }

    // ===========================================
    // create_error_response tests
    // ===========================================

    #[test]
    fn test_create_error_response_status() {
        let response = create_error_response(StatusCode::NOT_FOUND, "Not Found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = create_error_response(StatusCode::FORBIDDEN, "Forbidden");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = create_error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limited");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_create_error_response_content_type() {
        let response = create_error_response(StatusCode::NOT_FOUND, "Not Found");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn test_create_error_response_body() {
        let response = create_error_response(StatusCode::NOT_FOUND, "Resource not found");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Resource not found");
    }

    #[tokio::test]
    async fn test_create_error_response_empty_message() {
        let response = create_error_response(StatusCode::NO_CONTENT, "");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "");
    }
}
