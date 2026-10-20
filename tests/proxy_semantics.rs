//! Header and redirect semantics against the real binary. Run with:
//! cargo test --release --test proxy_semantics -- --ignored --test-threads=1

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// Minimal upstream: answers each request according to its path and sends the
/// raw request head it received back to the test.
struct Backend {
    port: u16,
    requests: Receiver<String>,
}

impl Backend {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, requests) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let tx = tx.clone();
                thread::spawn(move || serve(stream, &tx));
            }
        });
        Self { port, requests }
    }

    fn next_request(&self) -> String {
        self.requests
            .recv_timeout(Duration::from_secs(5))
            .expect("backend received no request")
            .to_ascii_lowercase()
    }
}

fn serve(stream: TcpStream, tx: &mpsc::Sender<String>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
    let _ = tx.send(head);
    let response: &[u8] = match path.as_str() {
        "/cookies" => {
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        }
        "/nominated" => {
            b"HTTP/1.1 200 OK\r\nConnection: close, X-Internal\r\nX-Internal: leak\r\nContent-Length: 2\r\n\r\nok"
        }
        "/redirect" => {
            b"HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        _ => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    };
    let mut stream = stream;
    let _ = stream.write_all(response);
}

struct Proxy {
    child: Child,
    port: u16,
}

impl Proxy {
    fn start(backend: &Backend, extra_env: &[(&str, &str)]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut command = Command::new(env!("CARGO_BIN_EXE_wisegate"));
        command
            .env_clear()
            .envs(extra_env.iter().copied())
            .args([
                "--bind",
                "127.0.0.1",
                "--listen",
                &port.to_string(),
                "--forward",
                &backend.port.to_string(),
                "--quiet",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut proxy = Self {
            child: command.spawn().unwrap(),
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return proxy;
            }
            assert!(proxy.child.try_wait().unwrap().is_none(), "proxy exited");
            assert!(Instant::now() < deadline, "proxy did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Sends a raw request head and returns the full response, lowercased.
    fn send(&self, path: &str, extra_headers: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}Connection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.to_ascii_lowercase()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn repeated_response_headers_are_all_forwarded() {
    let backend = Backend::start();
    let proxy = Proxy::start(&backend, &[]);
    let response = proxy.send("/cookies", "");
    assert!(response.contains("set-cookie: a=1\r\n"), "{response}");
    assert!(response.contains("set-cookie: b=2\r\n"), "{response}");
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn connection_nominated_request_headers_are_dropped() {
    let backend = Backend::start();
    let proxy = Proxy::start(&backend, &[]);
    proxy.send(
        "/",
        "Connection: X-Secret\r\nX-Secret: s3cr3t\r\nTrailer: X-Checksum\r\nX-Kept: yes\r\n",
    );
    let request = backend.next_request();
    assert!(!request.contains("x-secret"), "{request}");
    assert!(!request.contains("trailer:"), "{request}");
    assert!(request.contains("x-kept: yes\r\n"), "{request}");
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn connection_nominated_response_headers_are_dropped() {
    let backend = Backend::start();
    let proxy = Proxy::start(&backend, &[]);
    let response = proxy.send("/nominated", "");
    assert!(response.starts_with("http/1.1 200"), "{response}");
    assert!(!response.contains("x-internal"), "{response}");
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn real_ip_survives_connection_nomination() {
    // A client nominating X-Real-IP must not strip wisegate's own value,
    // nor get its forged one through.
    let backend = Backend::start();
    let proxy = Proxy::start(&backend, &[]);
    proxy.send(
        "/",
        "X-Forwarded-For: 198.51.100.7\r\nConnection: X-Real-IP\r\nX-Real-IP: 203.0.113.66\r\n",
    );
    let request = backend.next_request();
    assert!(request.contains("x-real-ip: 198.51.100.7\r\n"), "{request}");
    assert!(!request.contains("203.0.113.66"), "{request}");
}
