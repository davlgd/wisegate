# 🛡️ WiseGate

*"You shall not pass!"* - A wise guardian for your network gates.

An efficient, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

WiseGate is an HTTP/1.1 proxy meant to sit in front of a local service, behind a TLS-terminating load balancer: it does not terminate TLS, and it buffers request and response bodies instead of streaming them.

## ✨ Features

- **🚀 Efficient & Compact**: ~2-3 MB native binary
- **📊 Rate Limiting**: Per-IP sliding window algorithm
- **🚫 IP Filtering**: Block client IPs, trust only allowlisted proxies in strict mode
- **⚔️ HTTP Method Filtering**: Block specific methods (PUT, DELETE, etc.)
- **🛡️ URL Pattern Blocking**: Block requests matching patterns (.php, .yaml, etc.)
- **🔑 Basic Authentication**: RFC 7617 HTTP Basic Auth with multiple hash formats
- **🎫 Bearer Token**: RFC 6750 Bearer Token authentication
- **🌐 Real IP Extraction**: From `Forwarded` and `X-Forwarded-For` headers
- **📝 Structured Logging**: Human-readable or JSON format
- **🔄 Graceful Shutdown**: Drain connections on SIGINT/SIGTERM (up to 30 s)
- **🔒 Resource Limits**: Connection cap, body size limit, client read deadlines

## 🚀 Quick Start

```bash
# Install
cargo install wisegate

# Run (permissive mode)
wisegate --listen 8080 --forward 9000

# Run (strict mode: only accept requests relayed by these proxies)
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"
wisegate -l 8080 -f 9000
```

## ⚙️ CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--listen` | `-l` | `8080` | Port to listen on |
| `--forward` | `-f` | `9000` | Port to forward to |
| `--bind` | `-b` | `0.0.0.0` | IP address to listen on, also used to reach the upstream |
| `--verbose` | `-v` | | Debug logging (ignored when `RUST_LOG` is set) |
| `--quiet` | `-q` | | Errors only (ignored when `RUST_LOG` is set) |
| `--json-logs` | | | JSON log format |

WiseGate forwards to `http://<bind>:<forward>`: the upstream is a local plain-HTTP service on the same address, not an arbitrary host or HTTPS URL.

## 🔧 Configuration

Proxy policies are configured through environment variables; ports, bind address and logging use the CLI flags above. Values are cached on first use: restart WiseGate to apply changes.

| Variable | Default | Description |
|----------|---------|-------------|
| `CC_REVERSE_PROXY_IPS` | - | Comma-separated trusted proxy IPs; a non-empty value enables strict mode |
| `TRUSTED_PROXY_IPS_VAR` | - | Name of another variable to read the proxy IPs from when `CC_REVERSE_PROXY_IPS` is empty (allowed names: `TRUSTED_PROXY_IPS`, `REVERSE_PROXY_IPS`, `PROXY_ALLOWLIST`, `ALLOWED_PROXY_IPS`, `PROXY_IPS`) |
| `TRUST_LOOPBACK_PROXY` | `false` | In strict mode, also trust a loopback TCP peer (another local middleware in front of WiseGate, e.g. a Clever Cloud Request Flow chain) |
| `BLOCKED_IPS` | - | Comma-separated client IPs to reject with 403 (exact addresses, no CIDR ranges) |
| `BLOCKED_METHODS` | - | Comma-separated HTTP methods to reject with 405 |
| `BLOCKED_PATTERNS` | - | Comma-separated substrings of the URL path to reject with 404 (case-insensitive, also matched after percent-decoding; not regexes, query string not checked) |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window and client IP (positive) |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Window duration in seconds (positive) |
| `RATE_LIMIT_CLEANUP_THRESHOLD` | `10000` | Number of tracked IPs above which stale entries are purged; not a memory cap (0 = never purge) |
| `RATE_LIMIT_CLEANUP_INTERVAL_SECS` | `60` | Min interval between cleanups in seconds |
| `PROXY_TIMEOUT_SECS` | `30` | Upstream request timeout (positive) |
| `CLIENT_HEADER_TIMEOUT_SECS` | `30` | Total time to receive client request headers; must be positive |
| `CLIENT_BODY_TIMEOUT_SECS` | `30` | Total time to receive the client body; must be positive |
| `MAX_BODY_SIZE_MB` | `100` | Max request body size in MiB (0 = unlimited) |
| `MAX_CONNECTIONS` | `10000` | Max concurrent connections (0 = unlimited) |
| `CC_HTTP_BASIC_AUTH` | - | Basic auth credentials (username:password) |
| `CC_HTTP_BASIC_AUTH_1`, `_2`, … | - | Additional credentials, numbered from 1 without gaps |
| `CC_HTTP_BASIC_AUTH_REALM` | `WiseGate` | Authentication realm |
| `CC_BEARER_TOKEN` | - | Bearer token for API authentication |
| `CC_FORWARD_AUTH_HEADER` | `false` | Forward the `Authorization` header upstream after WiseGate authenticated the request (otherwise it is stripped; without WiseGate auth it is always forwarded) |

Boolean variables accept `1`, `true`, `yes` or `on` (case-insensitive); any other value means `false`. Unparsable numbers fall back to the variable's default. Setting `RATE_LIMIT_REQUESTS` or `RATE_LIMIT_WINDOW_SECS` to `0` resets both to their defaults; `PROXY_TIMEOUT_SECS=0` likewise resets both the upstream timeout and `MAX_BODY_SIZE_MB`.

### ⏱️ Limits and Timeouts

- **Client deadlines** are independent of the upstream timeout. Incomplete headers close the connection when `CLIENT_HEADER_TIMEOUT_SECS` expires; an incomplete body gets `408 Request Timeout` and the connection is closed. Zero or invalid values fall back to 30 seconds. Raise `CLIENT_BODY_TIMEOUT_SECS` for large or slow uploads.
- **Body size** is enforced while reading, including chunked requests without `Content-Length`: the request is rejected with `413` as soon as it exceeds the limit. `MAX_BODY_SIZE_MB=0` disables the size limit but keeps the body deadline.
- **Rate limiting** is per client IP and is checked before authentication, so rejected credentials consume the quota too; a successful request is charged once. Requests rejected earlier (blocked IP, pattern or method) are not counted.
- **Password checks** run outside the async executor, at most four at a time per process; extra concurrent checks get `503` immediately instead of queuing. Each well-formed Basic Auth attempt checks all configured credentials.
- **Connections** beyond `MAX_CONNECTIONS` are closed right after being accepted.

### 📋 Example Configuration

```bash
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"
export BLOCKED_IPS="203.0.113.42"
export BLOCKED_METHODS="PUT,DELETE,PATCH"
export BLOCKED_PATTERNS=".php,.yaml,wp-login"
export RATE_LIMIT_REQUESTS=100
export MAX_CONNECTIONS=5000

wisegate -l 8080 -f 9000
```

## 🔐 Security Modes

### Strict Mode (proxy allowlist configured)

Enabled when `CC_REVERSE_PROXY_IPS` is non-empty, or when `TRUSTED_PROXY_IPS_VAR` names an allowed variable that is non-empty (e.g. `TRUSTED_PROXY_IPS_VAR=TRUSTED_PROXY_IPS` and `TRUSTED_PROXY_IPS=10.0.0.1`).

- ✅ Requires the TCP peer to be an allowlisted proxy (or a local middleware with `TRUST_LOOPBACK_PROXY`)
- ✅ Reads only the last `Forwarded` element, the one appended by that proxy: its `by=` must be allowlisted, its `for=` is the client IP
- ✅ Ignores `X-Forwarded-For` and any element a client added before the proxy's own
- ✅ Rejects malformed identities in that element (unbalanced quotes, parameter names that are not tokens, duplicate `for`/`by`, invalid ports); complex quoted extensions are not supported
- ✅ Full IP filtering and rate limiting
- ✅ Injects `X-Real-IP` header

Requests that fail these checks are rejected with `400 Bad Request`. The trusted proxy must append a `Forwarded` element with both `for=` and `by=` (as Sōzu does on Clever Cloud). Both the TCP peer (unless it is a loopback peer trusted with `TRUST_LOOPBACK_PROXY`) and `by=` must be in the allowlist; they do not have to be the same address, so multi-homed load balancers keep working.

### Permissive Mode (no proxy IPs)

- ✅ Best-effort IP extraction from headers: `X-Forwarded-For` first (rightmost valid IP), then the first `Forwarded` element
- ✅ Method and pattern filtering still active
- ✅ IP blocklist, rate limiting and `X-Real-IP` when an IP could be extracted

Without a valid IP in these headers, the request goes through with no IP blocklist, no rate limiting and no `X-Real-IP`: WiseGate never falls back to the TCP peer address.

> ⚠️ Permissive mode trusts client-supplied `X-Forwarded-For` / `Forwarded` headers verbatim. An attacker who can reach WiseGate directly can spoof their apparent IP by forging them. Use permissive mode only when WiseGate sits behind another reverse proxy that strips or normalises these headers, or when IP attribution is not a security boundary.

In both modes, make sure the upstream service is only reachable through WiseGate: anything that can reach it directly bypasses every check.

## 🔐 Authentication

WiseGate supports two authentication methods that can be used independently or together.

### Basic Authentication (RFC 7617)

```bash
# Plain text (not recommended for production)
export CC_HTTP_BASIC_AUTH="admin:secret"

# bcrypt (recommended)
export CC_HTTP_BASIC_AUTH="admin:\$2y\$05\$..."

# APR1 MD5 (htpasswd -m)
export CC_HTTP_BASIC_AUTH="admin:\$apr1\$..."

# SHA1 (htpasswd -s)
export CC_HTTP_BASIC_AUTH="admin:{SHA}..."

# Multiple users
export CC_HTTP_BASIC_AUTH="admin:admin123"
export CC_HTTP_BASIC_AUTH_1="user1:pass1"
export CC_HTTP_BASIC_AUTH_2="user2:pass2"

# Custom realm
export CC_HTTP_BASIC_AUTH_REALM="My Protected Area"
```

Generate password hashes with `htpasswd`:
```bash
htpasswd -nbB user password  # bcrypt
htpasswd -nbm user password  # APR1 MD5
htpasswd -nbs user password  # SHA1
```

### Bearer Token (RFC 6750)

```bash
# Set bearer token
export CC_BEARER_TOKEN="my-secret-api-key"

# Use with curl
curl -H "Authorization: Bearer my-secret-api-key" http://localhost:8080/api
```

### Combined Authentication

When both Basic Auth and Bearer Token are configured, either method is accepted (OR, not AND):

```bash
# Configure both methods
export CC_HTTP_BASIC_AUTH="admin:secret"
export CC_BEARER_TOKEN="my-api-key"

# Both of these will work:
curl -u admin:secret http://localhost:8080/
curl -H "Authorization: Bearer my-api-key" http://localhost:8080/
```

Once WiseGate has authenticated a request, the `Authorization` header is stripped before forwarding, unless `CC_FORWARD_AUTH_HEADER=true`.

## 🔍 Request Flow

```
Client → Load Balancer → 🧙‍♂️ WiseGate → Your Service
                              │
                              ├─ 🔒 Check connection limit, header read deadline
                              ├─ 🔍 Validate proxy (strict mode) + extract client IP
                              ├─ 🚫 Check IP blocklist
                              ├─ 🗺️ Check URL patterns
                              ├─ ⚔️ Check HTTP method
                              ├─ ⏱️ Apply rate limiting
                              ├─ 🔑 Verify authentication (if enabled)
                              ├─ 📏 Read body (size limit, body deadline)
                              └─ 📋 Forward with X-Real-IP (when an IP is known)
```

## 📝 Logging

```bash
# Human-readable (default)
wisegate -l 8080 -f 9000

# JSON format (for log aggregation)
wisegate -l 8080 -f 9000 --json-logs

# Debug level
wisegate -l 8080 -f 9000 -v

# Via RUST_LOG (takes precedence over -v and -q)
RUST_LOG=debug wisegate -l 8080 -f 9000
```

## 📦 Using as a Library

WiseGate's core functionality is available as a separate crate `wisegate-core` for integration into your own projects:

```toml
[dependencies]
wisegate-core = "0.13"
```

The fastest path is `DefaultConfig` — it implements every configuration trait and exposes plain public fields you can tweak (inside an async function):

```rust
use std::sync::Arc;
use std::time::Duration;
use wisegate_core::{DefaultConfig, RateLimiter, ip_filter, rate_limiter};

let mut config = DefaultConfig::default();
config.rate_limit.max_requests = 200;
config.rate_limit.window_duration = Duration::from_secs(30);
config.blocked_methods = vec!["TRACE".into(), "CONNECT".into()];

let limiter = RateLimiter::new();
let config = Arc::new(config);

// Helpers used inside the pipeline are also available directly
let _blocked = ip_filter::is_ip_blocked("192.168.1.1", &*config);
let _allowed = rate_limiter::check_rate_limit(&limiter, "192.168.1.1", &*config).await;
```

When you need finer control, implement the composable traits yourself (`RateLimitingProvider`, `ProxyProvider`, `FilteringProvider`, `ConnectionProvider`, `AuthenticationProvider`). The blanket impl turns any type that implements all five into a `ConfigProvider` — see the [`wisegate_core::types` rustdoc](https://docs.rs/wisegate-core) for a worked example.

To proxy real HTTP traffic, serve `request_handler::handle_request` from a hyper server inside a Tokio runtime. This complete example needs these dependencies:

```toml
[dependencies]
wisegate-core = "0.13"
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
reqwest = { version = "0.13", default-features = false }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

```rust
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use wisegate_core::{DefaultConfig, RateLimiter, request_handler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(DefaultConfig::default());
    let limiter = RateLimiter::new();
    let upstream_host: Arc<str> = Arc::from("127.0.0.1");
    let upstream_port = 9000;

    // handle_request relays 3xx responses and does not apply the upstream
    // timeout itself: disable redirects and set the timeout on the client.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.proxy.timeout)
        .build()?;

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let (config, limiter) = (config.clone(), limiter.clone());
        let (host, client) = (upstream_host.clone(), http_client.clone());
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                request_handler::handle_request(
                    req,
                    peer_addr, // TCP peer, checked against the allowlist in strict mode
                    host.clone(),
                    upstream_port,
                    limiter.clone(),
                    config.clone(),
                    client.clone(),
                )
            });
            // Header deadlines and connection limits belong to the server loop
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
```

This minimal server omits connection limiting and graceful shutdown, which `handle_request` does not enforce. `DefaultConfig` does not read environment variables: the `CC_*` and other variables above only configure the `wisegate` binary.

## 🛠️ Development

```bash
cargo build                                     # Debug build
cargo build --release                           # Release build
cargo test --workspace                          # Unit and integration tests (binary + core)
cargo test -p wisegate-core                     # Core library only
cargo test --workspace --release -- --ignored --test-threads=1  # End-to-end tests (Linux; need python3 and curl)
cargo clippy --workspace --all-targets -- -D warnings           # Linting
cargo doc --workspace --no-deps                 # Generate docs
```

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE).

---

**Made with ❤️ and ancient wisdom ⚡ for the Open Source Community**

*"All we have to decide is what to do with the traffic that is given to us."*
