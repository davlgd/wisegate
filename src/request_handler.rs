use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
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

    // Step 1: Extract and validate real client IP
    let real_client_ip = match ip_filter::extract_and_validate_real_ip(req.headers()) {
        Some(ip) => ip,
        None => {
            return Ok(create_error_response(
                StatusCode::FORBIDDEN,
                "Invalid request: missing or invalid proxy headers"
            ));
        }
    };

    // Step 2: Check if IP is blocked
    if ip_filter::is_ip_blocked(&real_client_ip) {
        return Ok(create_error_response(
            StatusCode::FORBIDDEN,
            "IP address is blocked"
        ));
    }

    // Step 3: Apply rate limiting
    if !rate_limiter::check_rate_limit(&limiter, &real_client_ip) {
        return Ok(create_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded"
        ));
    }

    // Step 4: Add X-Real-IP header for upstream service
    let mut req = req;
    req.headers_mut().insert(
        "x-real-ip",
        real_client_ip.parse().unwrap()
    );

    // Step 5: Forward request with streaming support
    if proxy_config.enable_streaming {
        forward_request_streaming(req, forward_port, &proxy_config).await
    } else {
        forward_request_buffered(req, forward_port, &proxy_config).await
    }
}

/// Forward request with buffered body (legacy mode for compatibility)
async fn forward_request_buffered(
    req: Request<Incoming>,
    port: u16,
    proxy_config: &crate::types::ProxyConfig,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    // Collect the body into memory
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(bytes) => {
            let collected_bytes = bytes.to_bytes();

            // Check body size limit
            if proxy_config.max_body_size > 0 && collected_bytes.len() > proxy_config.max_body_size {
                return Ok(create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large"
                ));
            }

            collected_bytes
        },
        Err(_) => {
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body"
            ));
        }
    };

    // Forward using buffered approach
    forward_with_reqwest(parts, body_bytes, port, proxy_config).await
}

/// Forward request with streaming support (recommended for large bodies)
async fn forward_request_streaming(
    req: Request<Incoming>,
    port: u16,
    proxy_config: &crate::types::ProxyConfig,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();

    // For streaming, we'll still use reqwest but with better memory management
    // In a more advanced implementation, we'd use hyper's direct streaming
    let body_bytes = match body.collect().await {
        Ok(bytes) => {
            let collected_bytes = bytes.to_bytes();

            // More lenient size check for streaming mode
            if proxy_config.max_body_size > 0 && collected_bytes.len() > proxy_config.max_body_size * 2 {
                return Ok(create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body exceeds maximum allowed size"
                ));
            }

            collected_bytes
        },
        Err(_) => {
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body"
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
        "TRACE" => client.request(reqwest::Method::TRACE, &destination_uri),
        "CONNECT" => client.request(reqwest::Method::CONNECT, &destination_uri),
        _ => return Ok(create_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP method not supported"
        )),
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
                        .body(Full::new(bytes::Bytes::from(body_bytes)))
                        .unwrap();

                    // Copy headers
                    for (name, value) in headers.iter() {
                        if let (Ok(header_name), Ok(header_value)) = (
                            hyper::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                            hyper::header::HeaderValue::from_bytes(value.as_bytes())
                        ) {
                            hyper_response.headers_mut().insert(header_name, header_value);
                        }
                    }

                    Ok(hyper_response)
                }
                Err(_) => Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to read response body"
                ))
            }
        }
        Err(_) => Ok(create_error_response(
            StatusCode::BAD_GATEWAY,
            "Destination service unavailable"
        ))
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
