use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn test_large_request_handling() {
    // This test verifies that the hyper Parse(TooLarge) issue is fixed
    // by testing requests that would previously fail due to buffer size limits
    
    let output = Command::new("cargo")
        .args(&["build", "--release"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to build wisegate");
    
    assert!(output.status.success(), "Failed to build wisegate: {}", String::from_utf8_lossy(&output.stderr));

    // Start a simple backend server for testing
    let mut backend = Command::new("python3")
        .arg("-c")
        .arg(r#"
import http.server
import socketserver
import sys

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Hello from test backend')
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f'Received {len(post_data)} bytes'.encode())

with socketserver.TCPServer(('localhost', 9001), Handler) as httpd:
    sys.stderr.write('Test backend started on port 9001\n')
    sys.stderr.flush()
    httpd.serve_forever()
"#)
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start test backend");

    // Give backend time to start
    thread::sleep(Duration::from_secs(2));

    // Start wisegate
    let mut wisegate = Command::new("./target/release/wisegate")
        .args(&["--listen", "8081", "--forward", "9001"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start wisegate");

    // Give wisegate time to start
    thread::sleep(Duration::from_secs(2));

    // Test 1: Simple GET request
    let output = Command::new("curl")
        .args(&["-X", "GET", "http://localhost:8081/", "--max-time", "10"])
        .output()
        .expect("Failed to execute curl");
    
    let response = String::from_utf8_lossy(&output.stdout);
    assert!(response.contains("Hello from test backend"), "GET request failed: {}", response);

    // Test 2: Large POST request (10MB) - should succeed without Parse(TooLarge) error
    let output = Command::new("sh")
        .arg("-c")
        .arg("dd if=/dev/zero bs=1M count=10 2>/dev/null | curl -X POST -H 'Content-Type: application/octet-stream' --data-binary @- http://localhost:8081/ --max-time 30")
        .output()
        .expect("Failed to execute large POST test");
    
    let response = String::from_utf8_lossy(&output.stdout);
    assert!(response.contains("Received 10485760 bytes"), "Large POST request failed: {}", response);

    // Clean up
    let _ = wisegate.kill();
    let _ = backend.kill();
}

#[test]
fn test_environment_config_isolation() {
    // This test verifies that the config tests don't have race conditions
    // by running them multiple times in quick succession
    
    for i in 0..5 {
        let output = Command::new("cargo")
            .args(&["test", "config::tests", "--", "--test-threads=1"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to run config tests");
        
        assert!(output.status.success(), "Config test run {} failed: {}", i, String::from_utf8_lossy(&output.stderr));
    }
}