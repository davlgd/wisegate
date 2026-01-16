# 🛡️ WiseGate

*"You shall not pass!"* - A wise guardian for your network gates.

An efficient, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

## ✨ Features

- **🚀 Efficient & Compact**: ~2.5MB binary, statically compiled
- **📊 Rate Limiting**: Per-IP sliding window algorithm
- **🚫 IP Filtering**: Block malicious IPs, validate proxy headers
- **⚔️ HTTP Method Filtering**: Block specific methods (PUT, DELETE, etc.)
- **🛡️ URL Pattern Blocking**: Block requests matching patterns (.php, .yaml, etc.)
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
| `TRUSTED_PROXY_IPS_VAR` | - | Alternative variable name for proxy IPs |
| `BLOCKED_IPS` | - | Blocked client IPs |
| `BLOCKED_METHODS` | - | Blocked HTTP methods (returns 405) |
| `BLOCKED_PATTERNS` | - | Blocked URL patterns (returns 404) |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Window duration in seconds |
| `PROXY_TIMEOUT_SECS` | `30` | Upstream request timeout |
| `MAX_BODY_SIZE_MB` | `100` | Max body size (0 = unlimited) |
| `MAX_CONNECTIONS` | `10000` | Max concurrent connections (0 = unlimited) |

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
wisegate-core = "0.7"
```

```rust
use wisegate_core::{ConfigProvider, RateLimiter, request_handler};
use std::sync::Arc;

// Implement your own configuration
struct MyConfig { /* ... */ }
impl ConfigProvider for MyConfig { /* ... */ }

let limiter = RateLimiter::new();
let config = Arc::new(MyConfig::new());
let http_client = reqwest::Client::new();

// Use in your request handler
let response = request_handler::handle_request(
    req, host, port, limiter, config, http_client
).await;
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
