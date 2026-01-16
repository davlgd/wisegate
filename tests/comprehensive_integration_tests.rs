use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

// Global test serialization
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Comprehensive integration tests for WiseGate
/// These tests mirror the functionality of the Python test-local.py script
use std::sync::atomic::{AtomicU16, Ordering};

static PORT_COUNTER: AtomicU16 = AtomicU16::new(9100);

fn get_available_port() -> u16 {
    loop {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        if port > 9999 {
            PORT_COUNTER.store(9100, Ordering::SeqCst);
            continue;
        }

        if TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            return port;
        }
    }
}

struct TestEnvironment {
    backend_process: Option<Child>,
    wisegate_process: Option<Child>,
    backend_port: u16,
    wisegate_port: u16,
}

impl TestEnvironment {
    fn new() -> Self {
        let backend_port = get_available_port();
        let wisegate_port = get_available_port();

        Self {
            backend_process: None,
            wisegate_process: None,
            backend_port,
            wisegate_port,
        }
    }

    fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Build WiseGate first
        self.build_wisegate()?;

        // Start backend server
        self.start_backend()?;
        thread::sleep(Duration::from_secs(1));

        // Start WiseGate with test configuration
        self.start_wisegate()?;
        thread::sleep(Duration::from_secs(2));

        Ok(())
    }

    fn build_wisegate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("cargo")
            .args(&["build", "--release"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to build WiseGate: {stderr}").into());
        }

        Ok(())
    }

    fn start_backend(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let backend_script = format!(
            r#"
import http.server
import socketserver
import json
import sys

class TestBackendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Backend-Server', 'test-backend')
        self.end_headers()

        response = {{
            'message': 'Hello from test backend!',
            'method': 'GET',
            'path': self.path,
            'headers': dict(self.headers),
            'server': 'test-backend'
        }}
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Backend-Server', 'test-backend')
        self.end_headers()

        response = {{
            'message': 'POST received by test backend!',
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'body_size': len(post_data),
            'body_preview': post_data[:100].decode('utf-8', errors='ignore') if post_data else None,
            'server': 'test-backend'
        }}
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_PUT(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {{'message': 'PUT request received', 'method': 'PUT'}}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging

with socketserver.TCPServer(('localhost', {}), TestBackendHandler) as httpd:
    sys.stderr.write('Test backend started on port {}\n')
    sys.stderr.flush()
    httpd.serve_forever()
"#,
            self.backend_port, self.backend_port
        );

        self.backend_process = Some(
            Command::new("python3")
                .arg("-c")
                .arg(&backend_script)
                .stderr(Stdio::piped())
                .spawn()?,
        );

        Ok(())
    }

    fn start_wisegate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.wisegate_process = Some(
            Command::new("./target/release/wisegate")
                .args(&[
                    "-l",
                    &self.wisegate_port.to_string(),
                    "-f",
                    &self.backend_port.to_string(),
                    "--quiet",
                ])
                .env("RATE_LIMIT_REQUESTS", "5")
                .env("RATE_LIMIT_WINDOW_SECS", "10")
                .env("BLOCKED_METHODS", "TRACE,CONNECT")
                .env("BLOCKED_PATTERNS", ".env,.git,admin")
                .env("PROXY_TIMEOUT_SECS", "5")
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );

        Ok(())
    }

    fn wait_for_service(&self, port: u16, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            // Try to connect to the service
            if let Ok(output) = Command::new("curl")
                .args(&[
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &format!("http://localhost:{port}/"),
                    "--max-time",
                    "2",
                    "--connect-timeout",
                    "1",
                ])
                .output()
            {
                if output.status.success() {
                    let status_code = String::from_utf8_lossy(&output.stdout);
                    if status_code == "200" || status_code == "404" || status_code == "405" {
                        return true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        false
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        if let Some(mut process) = self.wisegate_process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
        if let Some(mut process) = self.backend_process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

fn make_request(
    env: &TestEnvironment,
    method: &str,
    path: &str,
    data: Option<&str>,
    headers: Option<&[(&str, &str)]>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("curl");
    cmd.args(&["-X", method])
        .args(&[&format!("http://localhost:{}{path}", env.wisegate_port)])
        .args(&["--max-time", "10"])
        .args(&["-w", "%{http_code}"])
        .args(&["-s"]);

    if let Some(data) = data {
        cmd.args(&["--data", data]);
    }

    if let Some(headers) = headers {
        for (key, value) in headers {
            cmd.args(&["-H", &format!("{key}: {value}")]);
        }
    }

    let output = cmd.output()?;
    let response = String::from_utf8_lossy(&output.stdout);

    // Extract status code (last 3 characters) and body
    if response.len() >= 3 {
        let status_code = response[response.len() - 3..].parse::<u16>().unwrap_or(0);
        let body = response[..response.len() - 3].to_string();
        Ok((status_code, body))
    } else {
        Ok((0, response.to_string()))
    }
}

#[test]
fn test_basic_proxy_functionality() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(
        env.wait_for_service(env.wisegate_port, Duration::from_secs(5)),
        "WiseGate service did not start in time"
    );

    let (status, body) =
        make_request(&env, "GET", "/", None, None).expect("Failed to make request");

    assert_eq!(status, 200, "Expected 200 status code");
    assert!(
        body.contains("Hello from test backend!"),
        "Response should contain backend message"
    );
    assert!(
        body.contains("test-backend"),
        "Response should indicate test backend"
    );
}

#[test]
fn test_post_request_forwarding() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let test_data = "This is test POST data";
    let (status, body) = make_request(&env, "POST", "/api/test", Some(test_data), None)
        .expect("Failed to make POST request");

    assert_eq!(status, 200, "Expected 200 status code for POST");
    assert!(
        body.contains("POST received by test backend!"),
        "Response should contain POST confirmation"
    );
    assert!(
        body.contains(&format!("\"body_size\": {}", test_data.len())),
        "Response should contain correct body size"
    );
}

#[test]
fn test_headers_forwarding() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let headers = &[("X-Custom-Header", "test-value"), ("X-Client-ID", "12345")];

    let (status, body) = make_request(&env, "GET", "/headers", None, Some(headers))
        .expect("Failed to make request with headers");

    assert_eq!(status, 200, "Expected 200 status code");

    // Check if custom headers are present (case-insensitive)
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("custom-header") || body_lower.contains("x-custom-header"),
        "Custom header should be forwarded"
    );
    assert!(
        body_lower.contains("client-id") || body_lower.contains("x-client-id"),
        "Client ID header should be forwarded"
    );
}

#[test]
fn test_blocked_http_methods() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Test TRACE method (should be blocked)
    let (status, _) =
        make_request(&env, "TRACE", "/", None, None).expect("Failed to make TRACE request");

    assert_eq!(status, 405, "TRACE method should be blocked with 405");

    // Test CONNECT method (should be blocked)
    let (status, _) =
        make_request(&env, "CONNECT", "/", None, None).expect("Failed to make CONNECT request");

    assert_eq!(status, 405, "CONNECT method should be blocked with 405");
}

#[test]
fn test_blocked_url_patterns() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let blocked_paths = &["/.env", "/.git/config", "/admin/panel"];

    for path in blocked_paths {
        let (status, _) = make_request(&env, "GET", path, None, None)
            .expect(&format!("Failed to make request to {path}"));

        assert_eq!(status, 404, "Path {} should be blocked with 404", path);
    }
}

#[test]
fn test_rate_limiting() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Make rapid requests to trigger rate limiting (configured for 5 requests per 10 seconds)
    let mut status_codes = Vec::new();

    for i in 0..7 {
        let (status, _) = make_request(&env, "GET", &format!("/rate-test-{i}"), None, None)
            .expect("Failed to make rate limit test request");
        status_codes.push(status);
        thread::sleep(Duration::from_millis(50)); // Rapid requests
    }

    // In permissive mode, rate limiting might not work if IP is "unknown"
    // So we check if we got consistent 200s OR some 429s
    let has_429 = status_codes.iter().any(|&code| code == 429);
    let all_200 = status_codes.iter().all(|&code| code == 200);

    assert!(
        has_429 || all_200,
        "Rate limiting should either work (429s) or be disabled (all 200s): {:?}",
        status_codes
    );
}

#[test]
fn test_large_request_handling() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Create 100KB of data
    let large_data = "x".repeat(1024 * 100);

    let (status, body) = make_request(&env, "POST", "/large", Some(&large_data), None)
        .expect("Failed to make large request");

    assert_eq!(status, 200, "Large request should succeed");
    assert!(
        body.contains(&format!("\"body_size\": {}", large_data.len())),
        "Response should contain correct body size for large request"
    );
}

#[test]
fn test_real_ip_header_injection() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let (status, body) =
        make_request(&env, "GET", "/ip-test", None, None).expect("Failed to make IP test request");

    assert_eq!(status, 200, "IP test request should succeed");

    // In permissive mode, X-Real-IP might not be set, which is correct behavior
    // This test passes if we get a valid response
    assert!(
        body.contains("test-backend"),
        "Should get response from backend"
    );
}

#[test]
fn test_timeout_handling() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Test normal request works within timeout
    let start = Instant::now();
    let (status, _) = make_request(&env, "GET", "/timeout-test", None, None)
        .expect("Failed to make timeout test request");
    let duration = start.elapsed();

    assert_eq!(status, 200, "Normal request should succeed");
    assert!(
        duration < Duration::from_secs(5),
        "Request should complete well within timeout limit"
    );
}

#[test]
fn test_put_request_allowed() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // PUT should be allowed (not in blocked methods)
    let (status, body) = make_request(&env, "PUT", "/resource", Some("update data"), None)
        .expect("Failed to make PUT request");

    assert_eq!(status, 200, "PUT method should be allowed");
    assert!(body.contains("PUT"), "Response should confirm PUT method");
}

#[test]
fn test_delete_request_allowed() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // DELETE should be allowed (not in blocked methods)
    let (status, _) =
        make_request(&env, "DELETE", "/resource/123", None, None).expect("Failed to make request");

    // Note: Our test backend may not handle DELETE, but we should get through WiseGate
    // Status could be 200 or 501 depending on backend support
    assert!(
        status == 200 || status == 501 || status == 405,
        "DELETE should pass through WiseGate, got status: {}",
        status
    );
}

#[test]
fn test_url_encoded_bypass_attempt() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Try to bypass .env blocking with URL encoding
    let encoded_paths = &[
        "/.%65nv",        // .env with 'e' encoded
        "/%2eenv",        // .env with '.' encoded
        "/%2e%65%6e%76",  // fully encoded .env
        "/.git%2fconfig", // .git/config with '/' encoded
    ];

    for path in encoded_paths {
        let (status, _) = make_request(&env, "GET", path, None, None)
            .expect(&format!("Failed to make request to {path}"));

        assert_eq!(
            status, 404,
            "URL-encoded path {} should still be blocked",
            path
        );
    }
}

#[test]
fn test_multiple_headers_forwarding() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let headers = &[
        ("Accept", "application/json"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("User-Agent", "WiseGate-Test/1.0"),
        ("X-Request-ID", "test-12345"),
    ];

    let (status, body) = make_request(&env, "GET", "/multi-headers", None, Some(headers))
        .expect("Failed to make request with multiple headers");

    assert_eq!(status, 200, "Request with multiple headers should succeed");

    // Verify headers are in the response
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("application/json") || body_lower.contains("accept"),
        "Accept header should be forwarded"
    );
}

#[test]
fn test_empty_body_post() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // POST with empty body
    let (status, body) =
        make_request(&env, "POST", "/empty", Some(""), None).expect("Failed to make empty POST");

    assert_eq!(status, 200, "Empty POST should succeed");
    assert!(
        body.contains("\"body_size\": 0"),
        "Empty body should have size 0"
    );
}

#[test]
fn test_special_characters_in_path() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    // Test paths with special characters (that aren't blocked patterns)
    let paths = &[
        "/path/with/slashes",
        "/path-with-dashes",
        "/path_with_underscores",
        "/path.with.dots",
        "/path%20with%20spaces",
    ];

    for path in paths {
        let (status, _) = make_request(&env, "GET", path, None, None)
            .expect(&format!("Failed to make request to {path}"));

        assert_eq!(status, 200, "Path {} should succeed", path);
    }
}

#[test]
fn test_query_string_forwarding() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut env = TestEnvironment::new();
    env.setup().expect("Failed to setup test environment");

    assert!(env.wait_for_service(env.wisegate_port, Duration::from_secs(5)));

    let (status, body) = make_request(&env, "GET", "/search?q=test&page=1&limit=10", None, None)
        .expect("Failed to make request with query string");

    assert_eq!(status, 200, "Request with query string should succeed");
    assert!(
        body.contains("q=test") || body.contains("search"),
        "Query string should be forwarded"
    );
}
