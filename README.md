# 🛡️ WiseGate

A high-performance, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

## ✨ Features

- **🚀 Ultra-Fast**: ~2MB binary (1 MB after upx)
- **🔒 Secure**: Validates load balancer headers and enforces proxy IP allowlists
- **📊 Rate Limiting**: Per-IP rate limiting with configurable sliding windows
- **🚫 IP Filtering**: Block malicious IPs with environment-based configuration
- **🚫 HTTP Method Filtering**: Block specific HTTP methods (GET, POST, PUT, etc.)
- **🛡️ URL Pattern Blocking**: Block requests containing specific patterns (e.g., `.ext`, `/path/to/block`)
- **🌐 Real IP Extraction**: Correctly extracts client IPs from `x-forwarded-for` and `forwarded` headers
- **⚙️ Zero Dependencies**: Statically compiled binary with no external runtime requirements

## 🎯 Use Cases

- **API Gateway**: Rate limiting and IP filtering for REST APIs
- **DDoS Protection**: Basic protection against IP-based attacks
- **Microservices Security**: Add security layer to existing services without code changes
- **Load Balancer Backend**: Perfect for services behind a load balancers like Clever Cloud's [Sōzu](https://sozu.io)

## 🚀 Quick Start

### Installation

#### Install via Cargo (Recommended)

```bash
cargo install wisegate
```

#### Download Binary

```bash
# Adapt the URL for your platform
wget https://github.com/davlgd/wisegate/releases/latest/download/wisegate-linux-x64
chmod +x wisegate-linux-x64
sudo mv wisegate-linux-x64 /usr/local/bin/wisegate
```

#### Build from Source

```bash
git clone https://github.com/davlgd/wisegate.git
cd wisegate
cargo build --release
sudo cp target/release/wisegate /usr/local/bin/
```

### Basic Usage

```bash
# Optional: Set allowed proxy IPs (enables strict IP validation)
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"

# Start the proxy
wisegate --listen 8080 --forward 9000
```

Your service is now protected! Requests will be forwarded from port 8080 to port 9000 with added security.

### CLI Options

WiseGate supports several command-line options for different use cases:

- `--listen` / `-l`: Port to listen on for incoming requests
- `--forward` / `-f`: Port to forward requests to
- `--verbose` / `-v`: Show detailed configuration and startup information
- `--quiet` / `-q`: Minimal output mode (conflicts with verbose)
- `--help` / `-h`: Show help information

The `--verbose` mode shows detailed configuration including environment variables, while `--quiet` mode only displays essential startup information - perfect for production deployments.

## ⚙️ Configuration

All configuration is done via environment variables:

### Proxy Security Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `CC_REVERSE_PROXY_IPS` | *(Optional)* Comma-separated list of allowed proxy/load balancer IPs. When set, enables strict header validation. | `"192.168.1.1,10.0.0.1"` |
| `TRUSTED_PROXY_IPS_VAR` | *(Optional)* Name of alternative environment variable to use instead of `CC_REVERSE_PROXY_IPS` | `"MY_COMPANY_PROXY_IPS"` |

**Note**: When neither `CC_REVERSE_PROXY_IPS` nor an alternative variable is configured, WiseGate runs in permissive mode where proxy IP validation is disabled. This allows requests without proper reverse proxy headers but maintains other security features.

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCKED_IPS` | _(none)_ | Comma-separated list of blocked client IPs |
| `BLOCKED_METHODS` | _(none)_ | Comma-separated list of blocked HTTP methods (returns 405) |
| `BLOCKED_PATTERNS` | _(none)_ | Comma-separated list of URL patterns to block (returns 404) |
| `RATE_LIMIT_REQUESTS` | `100` | Maximum requests per time window |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Time window in seconds for rate limiting |
| `PROXY_TIMEOUT_SECS` | `30` | Timeout for upstream requests in seconds |
| `MAX_BODY_SIZE_MB` | `100` | Maximum request body size in MB (0 = unlimited) |

### Configuration Examples

#### Strict Mode

```bash
# Proxy IP validation and full security features
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1,172.16.0.1"
export BLOCKED_IPS="192.168.1.200,malicious.ip.here"
export BLOCKED_METHODS="PUT,DELETE,PATCH"
export BLOCKED_PATTERNS=".yaml,.php,matomo"
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW_SECS=60

wisegate -l 8080 -f 9000
```

#### Custom Alternative Variable

```bash
# Use custom environment variable name for proxy IPs
export TRUSTED_PROXY_IPS_VAR="MY_PROXY_IPS"
export MY_PROXY_IPS="192.168.1.100,10.0.0.1"
export BLOCKED_METHODS="PUT,DELETE,PATCH"

wisegate -l 8080 -f 9000
```

#### Permissive Mode (Basic Security)

```bash
# No proxy IP validation - only method and pattern filtering
export BLOCKED_METHODS="PUT,DELETE,PATCH"
export BLOCKED_PATTERNS=".yaml,.php,matomo"

wisegate -l 8080 -f 9000
```

## 🔍 How It Works

### Security Model

WiseGate operates in two modes depending on configuration:

**All modes provide:**
- **HTTP Method Filtering**: Blocks requests using blacklisted HTTP methods (returns 405)
- **URL Pattern Filtering**: Blocks URLs containing configured patterns (returns 404)

#### Permissive Mode (when no proxy IPs are configured)

Additionally provides:

- **Best-Effort IP Extraction**: Attempts to extract client IP from available headers
- **Limited IP Features**: IP filtering and rate limiting are disabled when client IP cannot be determined
- **Conditional Header Injection**: Adds `X-Real-IP` header only when client IP is available

#### Strict Mode (when proxy IPs are configured)

Additionally provides:

- **Header Validation**: Requires both `x-forwarded-for` and `forwarded` headers
- **Proxy Authentication**: Validates the proxy IP (from `by=` field) against allow list
- **Real IP Extraction**: Extracts actual client IP from forwarded headers
- **IP Filtering**: Blocks requests from blacklisted IPs
- **Rate Limiting**: Applies per-IP rate limiting with sliding windows
- **Header Injection**: Adds `X-Real-IP` header for upstream services

### Request Flow

```
Client → Load Balancer → WiseGate → Your Service
                               ↓
                        ✅ Validate headers (strict mode)
                        ✅ Check Trusted Proxy IPs allowlist (strict mode)
                        ✅ Check HTTP methods
                        ✅ Check URL patterns
                        ✅ Extract real client IP (if detected)
                        ✅ Check IP blocklist (if IP is detected)
                        ✅ Apply rate limiting (if IP is detected)
                        ✅ Add X-Real-IP header (if IP is detected)
```

### Example Headers

**Incoming request:**
```http
x-forwarded-for: client.ip, proxy.ip, 203.0.113.1
forwarded: for=203.0.113.1:45678;by=192.168.1.100;proto=https
```

**Forwarded request:**
```http
x-forwarded-for: client.ip, proxy.ip, 203.0.113.1
forwarded: for=203.0.113.1:45678;by=192.168.1.100;proto=https
x-real-ip: 203.0.113.1
```

## ⚡ Performance Features

### Request Timeouts
- **Configurable**: Set custom timeouts with `PROXY_TIMEOUT_SECS`
- **Default**: 30 seconds timeout for upstream requests
- **Reliability**: Prevents hanging connections

### Body Size Limits
- **Flexible**: Configure maximum request body size
- **Protection**: Prevents memory exhaustion from large uploads
- **Configurable**: Set `MAX_BODY_SIZE_MB=0` for unlimited size

## 🤝 Contributing

Contributions are welcome!

- **Issues**: [GitHub Issues](https://github.com/davlgd/wisegate/issues)
- **Discussions**: [GitHub Discussions](https://github.com/davlgd/wisegate/discussions)

### Development Setup

1. Install Rust
2. Clone the repository
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Building

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release

# Cross-compilation for different targets
cargo build --release --target x86_64-unknown-linux-musl
```

### Testing

```bash
# Run tests
cargo test

# Integration testing (Strict Mode)
export CC_REVERSE_PROXY_IPS="127.0.0.1"
./target/release/wisegate -l 8080 -f 9000 &
curl -H "x-forwarded-for: 203.0.113.1" \
     -H "forwarded: by=127.0.0.1" \
     http://localhost:8080/

# Integration testing (Permissive Mode)
unset CC_REVERSE_PROXY_IPS
./target/release/wisegate -l 8081 -f 9001 &
curl http://localhost:8081/
```

## 📁 Project Structure

The project follows Rust best practices with a modular architecture for maintainability and clarity:

```
src/
├── main.rs              # Entry point and server logic
├── args.rs              # Command line argument parsing
├── types.rs             # Common types and type aliases
├── env_vars.rs          # Environment variable constants
├── config.rs            # Configuration management
├── ip_filter.rs         # IP validation and filtering logic
├── rate_limiter.rs      # Rate limiting implementation
├── request_handler.rs   # HTTP request processing
└── server.rs            # Server utilities and startup info
```

### Module Responsibilities

- **`main.rs`**: Application entry point, server setup, and connection handling
- **`args.rs`**: CLI argument definitions using Clap
- **`types.rs`**: Shared type definitions (RateLimitConfig, RateLimiter)
- **`env_vars.rs`**: Centralized environment variable names
- **`config.rs`**: Environment variable parsing and configuration loading
- **`ip_filter.rs`**: IP validation, header parsing, and blocking logic
- **`rate_limiter.rs`**: Sliding window rate limiting implementation
- **`request_handler.rs`**: HTTP request/response processing and forwarding
- **`server.rs`**: Startup banner and server utility functions

This modular structure ensures each component has a single responsibility, making the codebase easy to understand, test, and maintain.

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- Built with [Hyper](https://hyper.rs/) for HTTP handling
- [Tokio](https://tokio.rs/) for async runtime
- [Clap](https://clap.rs/) for CLI parsing
- [Reqwest](https://docs.rs/reqwest/) for HTTP client functionality
- Inspired by the need for a lightweight, simple, secure proxy

---

**Made with ❤️ and ⚡ for the Open Source Community**
