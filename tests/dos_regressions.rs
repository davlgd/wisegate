//! Socket regressions against the real binary. Run with:
//! cargo test --release --test dos_regressions -- --ignored --test-threads=1

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    port: u16,
    // Reserve the upstream port without accepting requests. Tests that should
    // fail before forwarding never need an upstream service.
    _backend: TcpListener,
}

impl Proxy {
    fn start(extra_env: &[(&str, &str)]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = backend.local_addr().unwrap().port();
        drop(listener);
        let mut command = Command::new(env!("CARGO_BIN_EXE_wisegate"));
        command
            .env_clear()
            .env("PROXY_TIMEOUT_SECS", "1")
            .envs(extra_env.iter().copied())
            .args([
                "--bind",
                "127.0.0.1",
                "--listen",
                &port.to_string(),
                "--forward",
                &upstream_port.to_string(),
                "--quiet",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut proxy = Self {
            child: command.spawn().unwrap(),
            port,
            _backend: backend,
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

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn request(&self, auth: &str) -> u16 {
        let mut stream = self.connect();
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 198.51.100.7\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        status(&mut stream)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn status(stream: &mut TcpStream) -> u16 {
    let mut response = Vec::new();
    let mut byte = [0; 1];
    while !response.ends_with(b"\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "missing status line");
        response.push(byte[0]);
        assert!(response.len() < 1024);
    }
    String::from_utf8(response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn chunked_body_is_rejected_before_the_terminating_chunk() {
    let proxy = Proxy::start(&[("MAX_BODY_SIZE_MB", "1")]);
    let mut stream = proxy.connect();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    let body = vec![b'x'; 1024 * 1024];
    write!(stream, "{:x}\r\n", body.len()).unwrap();
    stream.write_all(&body).unwrap();
    stream.write_all(b"\r\n1\r\nx\r\n").unwrap();
    // Deliberately leave the request unfinished.
    assert_eq!(status(&mut stream), 413);
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn unfinished_client_body_has_its_own_deadline() {
    let proxy = Proxy::start(&[
        ("CLIENT_BODY_TIMEOUT_SECS", "1"),
        ("PROXY_TIMEOUT_SECS", "60"),
    ]);
    let mut stream = proxy.connect();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
        .unwrap();
    assert_eq!(status(&mut stream), 408);
    let mut remaining = String::new();
    stream.read_to_string(&mut remaining).unwrap();
    assert!(remaining.to_ascii_lowercase().contains("connection: close"));
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn unfinished_client_headers_release_the_connection() {
    let proxy = Proxy::start(&[("CLIENT_HEADER_TIMEOUT_SECS", "1")]);
    let mut stream = proxy.connect();
    stream.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
    let mut response = Vec::new();
    // A socket read timeout is a failure: hyper must close the connection.
    stream.read_to_end(&mut response).unwrap();
    assert!(response.is_empty() || String::from_utf8_lossy(&response).starts_with("HTTP/1.1 408"));
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn rejected_credentials_consume_the_ip_quota() {
    let proxy = Proxy::start(&[
        ("CC_HTTP_BASIC_AUTH", "admin:secret"),
        ("RATE_LIMIT_REQUESTS", "2"),
    ]);
    assert_eq!(proxy.request("Basic YWRtaW46d3Jvbmc="), 401);
    assert_eq!(proxy.request("Basic YWRtaW46d3Jvbmc="), 401);
    assert_eq!(proxy.request("Basic YWRtaW46d3Jvbmc="), 429);
}

#[test]
#[ignore = "starts the real binary and binds loopback sockets"]
fn valid_credentials_are_charged_only_once() {
    let proxy = Proxy::start(&[
        ("CC_HTTP_BASIC_AUTH", "admin:secret"),
        ("RATE_LIMIT_REQUESTS", "2"),
    ]);
    // The reserved backend deliberately does not respond. Passing authentication
    // therefore results in upstream timeout, not a 401 or an early 429.
    assert_eq!(proxy.request("Basic YWRtaW46c2VjcmV0"), 504);
    assert_eq!(proxy.request("Basic YWRtaW46c2VjcmV0"), 504);
    assert_eq!(proxy.request("Basic YWRtaW46c2VjcmV0"), 429);
}
