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
                              ├─ 🔍 Validate proxy headers (strict)
                              ├─ ⚔️ Check HTTP method
                              ├─ 🗺️ Check URL patterns
                              ├─ 👁️ Extract client IP
                              ├─ 🚫 Check IP blocklist
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
wisegate-core = "0.10"
```

```rust
use wisegate_core::{
    RateLimitingProvider, ProxyProvider, FilteringProvider,
    ConnectionProvider, AuthenticationProvider, Credentials,
    RateLimiter, RateLimitConfig, RateLimitCleanupConfig, ProxyConfig,
    request_handler, ip_filter, rate_limiter,
};
use std::sync::Arc;
use std::time::Duration;

// Implement composable configuration traits
struct MyConfig { credentials: Credentials }

impl RateLimitingProvider for MyConfig {
    fn rate_limit_config(&self) -> &RateLimitConfig {
        static C: RateLimitConfig = RateLimitConfig {
            max_requests: 100, window_duration: Duration::from_secs(60),
        };
        &C
    }
    fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
        static C: RateLimitCleanupConfig = RateLimitCleanupConfig {
            threshold: 10_000, interval: Duration::from_secs(60),
        };
        &C
    }
}
impl ProxyProvider for MyConfig {
    fn proxy_config(&self) -> &ProxyConfig {
        static C: ProxyConfig = ProxyConfig {
            timeout: Duration::from_secs(30), max_body_size: 100 * 1024 * 1024,
        };
        &C
    }
    fn allowed_proxy_ips(&self) -> Option<&[String]> { None }
}
impl FilteringProvider for MyConfig {
    fn blocked_ips(&self) -> &[String] { &[] }
    fn blocked_methods(&self) -> &[String] { &[] }
    fn blocked_patterns(&self) -> &[String] { &[] }
}
impl ConnectionProvider for MyConfig {
    fn max_connections(&self) -> usize { 10_000 }
}
impl AuthenticationProvider for MyConfig {
    fn auth_credentials(&self) -> &Credentials { &self.credentials }
    fn auth_realm(&self) -> &str { "MyApp" }
    fn bearer_token(&self) -> Option<&str> { None }
}

// Use the components
let limiter = RateLimiter::new();
let config = Arc::new(MyConfig { credentials: Credentials::new() });

// Individual components
let is_blocked = ip_filter::is_ip_blocked("192.168.1.1", &*config);
let allowed = rate_limiter::check_rate_limit(&limiter, "192.168.1.1", &*config).await;
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
