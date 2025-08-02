# 🛡️  Clever GateKeeper

A high-performance, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

## ✨ Features

- **🚀 Ultra-Fast**: ~3MB binary (550 KB after upx), ~2MB RAM usage
- **🔒 Secure**: Validates load balancer headers and enforces proxy IP allowlists
- **📊 Rate Limiting**: Per-IP rate limiting with configurable sliding windows
- **🚫 IP Filtering**: Block malicious IPs with environment-based configuration
- **🛡️ URL Pattern Blocking**: Block requests containing specific patterns (e.g., `.php`, `.yaml`)
- **🌐 Real IP Extraction**: Correctly extracts client IPs from `x-forwarded-for` and `forwarded` headers
- **⚙️ Zero Dependencies**: Statically compiled binary with no external runtime requirements

## 🎯 Use Cases

- **Load Balancer Backend**: Perfect for services behind a load balancers like Clever Cloud's [Sōzu](https://sozu.io)
- **API Gateway**: Rate limiting and IP filtering for REST APIs
- **Microservices Security**: Add security layer to existing services without code changes
- **DDoS Protection**: Basic protection against IP-based attacks

## 🚀 Quick Start

### Installation

#### Download Binary (Recommended)
```bash
# Download latest release
wget https://github.com/davlgd/clever-gatekeeper/releases/latest/download/clever-gatekeeper-linux-x64
chmod +x clever-gatekeeper-linux-x64
sudo mv clever-gatekeeper-linux-x64 /usr/local/bin/clever-gatekeeper
```

#### Build from Source
```bash
git clone https://github.com/davlgd/clever-gatekeeper.git
cd clever-gatekeeper
cargo build --release
sudo cp target/release/clever-gatekeeper /usr/local/bin/
```

### Basic Usage

```bash
# Set allowed proxy IPs (required, native in Clever Cloud's applications)
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1"

# Start the proxy
clever-gatekeeper --listen 8080 --forward 9000
```

Your service is now protected! Requests will be forwarded from port 8080 to port 3000 with added security.

## ⚙️  Configuration

All configuration is done via environment variables:

### Required Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `CC_REVERSE_PROXY_IPS` | Comma-separated list of allowed proxy/load balancer IPs | `"192.168.1.1,10.0.0.1"` |

### Optional Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCKED_IPS` | _(none)_ | Comma-separated list of blocked client IPs |
| `BLOCKED_PATTERNS` | _(none)_ | Comma-separated list of URL patterns to block (returns 404) |
| `RATE_LIMIT_REQUESTS` | `100` | Maximum requests per time window |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Time window in seconds for rate limiting |
| `PROXY_TIMEOUT_SECS` | `30` | Timeout for upstream requests in seconds |
| `MAX_BODY_SIZE_MB` | `100` | Maximum request body size in MB (0 = unlimited) |
| `ENABLE_STREAMING` | `true` | Enable streaming mode for better memory usage |

### Complete Example

```bash
# Security configuration
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1,172.16.0.1"
export BLOCKED_IPS="192.168.1.200,malicious.ip.here"
export BLOCKED_PATTERNS=".yaml,.php,matomo"

# Rate limiting (100 requests per minute per IP)
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW_SECS=60

# Proxy performance tuning
export PROXY_TIMEOUT_SECS=30
export MAX_BODY_SIZE_MB=100
export ENABLE_STREAMING=true

# Start proxy
clever-gatekeeper --listen 8080 --forward 3000
```

## 🔍 How It Works

### Security Model

1. **Header Validation**: Requires both `x-forwarded-for` and `forwarded` headers
2. **Proxy Authentication**: Validates the proxy IP (from `by=` field) against allowlist
3. **Real IP Extraction**: Extracts actual client IP from forwarded headers
4. **IP Filtering**: Blocks requests from blacklisted IPs
5. **URL Pattern Filtering**: Blocks URLs containing configured patterns (returns 404)
6. **Rate Limiting**: Applies per-IP rate limiting with sliding windows
7. **Header Injection**: Adds `X-Real-IP` header for upstream services

### Request Flow

```
Client → Load Balancer → Clever GateKeeper → Your Service
                               ↓
                        ✅ Validate headers
                        ✅ Check IP allowlist
                        ✅ Check URL patterns
                        ✅ Apply rate limiting
                        ✅ Add X-Real-IP header
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

### Streaming Support
- **Automatic**: Enabled by default for better memory usage
- **Configurable**: Set `ENABLE_STREAMING=false` for legacy buffered mode
- **Memory Efficient**: Handles large files without loading entirely into RAM

### Request Timeouts
- **Configurable**: Set custom timeouts with `PROXY_TIMEOUT_SECS`
- **Default**: 30 seconds timeout for upstream requests
- **Reliability**: Prevents hanging connections

### Body Size Limits
- **Flexible**: Configure maximum request body size
- **Protection**: Prevents memory exhaustion from large uploads
- **Streaming Mode**: More lenient limits when streaming is enabled

## 🔧 Development

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

# Integration testing
export CC_REVERSE_PROXY_IPS="127.0.0.1"
./target/release/clever-gatekeeper --listen 8080 --forward 3000 &
curl -H "x-forwarded-for: 203.0.113.1" \
     -H "forwarded: by=127.0.0.1" \
     http://localhost:8080/
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Install Rust
2. Clone the repository
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/davlgd/clever-gatekeeper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/davlgd/clever-gatekeeper/discussions)

## 🏆 Acknowledgments

- Built with [Hyper](https://hyper.rs/) for HTTP handling
- [Tokio](https://tokio.rs/) for async runtime
- [Clap](https://clap.rs/) for CLI parsing
- [Reqwest](https://docs.rs/reqwest/) for HTTP client functionality
- Inspired by the need for a lightweight, simple, secure proxy

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

---

**Made with ❤️ and ⚡ for the Open Source Community**
