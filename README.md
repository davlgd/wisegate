# 🛡️ WiseGate

*"You shall not pass!"* - A wise guardian for your network gates.

An efficient, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

## ✨ Features

- **🚀 Efficient & Compact**: ~2.5MB binary, statically compiled
- **📊 Rate Limiting**: Per-IP sliding window algorithm
- **🚫 IP Filtering**: Block malicious IPs, validate proxy headers
- **⚔️ HTTP Method Filtering**: Block specific methods (PUT, DELETE, etc.)
- **🛡️ URL Pattern Blocking**: Block requests matching patterns (.php, .yaml, etc.)
- **🔑 Basic Authentication**: RFC 7617 HTTP Basic Auth with multiple hash formats
- **🎫 Bearer Token**: RFC 6750 Bearer Token authentication
- **🌐 Real IP Extraction**: RFC 7239 compliant header parsing
- **📝 Structured Logging**: Human-readable or JSON format
- **🔄 Graceful Shutdown**: Drain connections on SIGINT/SIGTERM
- **🔒 Connection Limiting**: Prevent resource exhaustion

## 🚀 Quick Start

```bash
# Install
cargo install wisegate

# Run (permissive mode)
wisegate --listen 8080 --forward 9000

# Run (strict mode with proxy validation)
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"
wisegate -l 8080 -f 9000
```

## ⚙️ CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--listen` | `-l` | `8080` | Port to listen on |
| `--forward` | `-f` | `9000` | Port to forward to |
| `--bind` | `-b` | `0.0.0.0` | Bind address |
| `--verbose` | `-v` | | Debug logging |
| `--quiet` | `-q` | | Errors only |
| `--json-logs` | | | JSON log format |

## 🔧 Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CC_REVERSE_PROXY_IPS` | - | Trusted proxy IPs (enables strict mode) |
| `TRUSTED_PROXY_IPS_VAR` | - | Alternative variable name for proxy IPs (whitelisted: `TRUSTED_PROXY_IPS`, `REVERSE_PROXY_IPS`, `PROXY_ALLOWLIST`, `ALLOWED_PROXY_IPS`, `PROXY_IPS`) |
| `BLOCKED_IPS` | - | Blocked client IPs |
| `BLOCKED_METHODS` | - | Blocked HTTP methods (returns 405) |
| `BLOCKED_PATTERNS` | - | Blocked URL patterns (returns 404) |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Window duration in seconds |
| `RATE_LIMIT_CLEANUP_THRESHOLD` | `10000` | Entries before auto-cleanup (0 = disabled) |
| `RATE_LIMIT_CLEANUP_INTERVAL_SECS` | `60` | Min interval between cleanups in seconds |
| `PROXY_TIMEOUT_SECS` | `30` | Upstream request timeout |
| `MAX_BODY_SIZE_MB` | `100` | Max body size (0 = unlimited) |
| `MAX_CONNECTIONS` | `10000` | Max concurrent connections (0 = unlimited) |
| `CC_HTTP_BASIC_AUTH` | - | Basic auth credentials (username:password) |
| `CC_HTTP_BASIC_AUTH_N` | - | Additional credentials (_1, _2, etc.) |
| `CC_HTTP_BASIC_AUTH_REALM` | `WiseGate` | Authentication realm |
| `CC_BEARER_TOKEN` | - | Bearer token for API authentication |

### 📋 Example Configuration

```bash
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"
export BLOCKED_IPS="malicious.ip.here"
export BLOCKED_METHODS="PUT,DELETE,PATCH"
export BLOCKED_PATTERNS=".php,.yaml,wp-login"
export RATE_LIMIT_REQUESTS=100
export MAX_CONNECTIONS=5000

wisegate -l 8080 -f 9000
```

## 🔐 Security Modes

### Strict Mode (CC_REVERSE_PROXY_IPS set)

- ✅ Validates `x-forwarded-for` and `forwarded` headers
- ✅ Authenticates proxy IPs against allowlist
- ✅ Full IP filtering and rate limiting
- ✅ Injects `X-Real-IP` header

### Permissive Mode (no proxy IPs)

- ✅ Best-effort IP extraction from headers
- ✅ Method and pattern filtering still active
- ✅ Rate limiting when IP is available

> ⚠️ Permissive mode trusts client-supplied `X-Forwarded-For` / `Forwarded` headers verbatim. An attacker who can reach WiseGate directly can spoof their apparent IP by forging them. Use permissive mode only when WiseGate sits behind another reverse proxy that strips or normalises these headers, or when IP attribution is not a security boundary.

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

When both Basic Auth and Bearer Token are configured, either method will be accepted:

```bash
# Configure both methods
export CC_HTTP_BASIC_AUTH="admin:secret"
export CC_BEARER_TOKEN="my-api-key"

# Both of these will work:
curl -u admin:secret http://localhost:8080/
curl -H "Authorization: Bearer my-api-key" http://localhost:8080/
```

## 🔍 Request Flow

```
Client → Load Balancer → 🧙‍♂️ WiseGate → Your Service
                              │
                              ├─ 🔒 Check connection limit
                              ├─ 🔍 Validate proxy headers + Extract client IP
                              ├─ 🚫 Check IP blocklist
                              ├─ 🗺️ Check URL patterns
                              ├─ ⚔️ Check HTTP method
                              ├─ 🔑 Verify Authentication (if enabled)
                              ├─ ⏱️ Apply rate limiting
                              └─ 📋 Forward with X-Real-IP
```

## 📝 Logging

```bash
# Human-readable (default)
wisegate -l 8080 -f 9000

# JSON format (for log aggregation)
wisegate -l 8080 -f 9000 --json-logs

# Debug level
wisegate -l 8080 -f 9000 -v

# Via RUST_LOG
RUST_LOG=debug wisegate -l 8080 -f 9000
```

## 📦 Using as a Library

WiseGate's core functionality is available as a separate crate `wisegate-core` for integration into your own projects:

```toml
[dependencies]
wisegate-core = "0.12"
```

The fastest path is `DefaultConfig` — it implements every configuration trait and exposes plain public fields you can tweak:

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

To proxy real HTTP traffic, call `request_handler::handle_request` from inside a Tokio runtime with a shared `reqwest::Client`:

```rust
use std::sync::Arc;
use wisegate_core::{DefaultConfig, RateLimiter, request_handler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(DefaultConfig::default());
    let limiter = RateLimiter::new();
    let http_client = reqwest::Client::new();
    // Use `request_handler::handle_request(req, ...)` inside your hyper service.
    Ok(())
}
```

## 🛠️ Development

```bash
cargo build                  # Debug build
cargo build --release        # Release build
cargo test                   # Run all tests
cargo test -p wisegate-core  # Test core library only
cargo clippy                 # Linting
cargo doc --no-deps          # Generate docs
```

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE).

---

**Made with ❤️ and ancient wisdom ⚡ for the Open Source Community**

*"All we have to decide is what to do with the traffic that is given to us."*
