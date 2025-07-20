# 🛡️  Clever GateKeeper

A high-performance, secure reverse proxy written in Rust with built-in rate limiting and IP filtering capabilities.

## ✨ Features

- **🚀 Ultra-Fast**: ~3MB binary (550 KB after upx), ~2MB RAM usage
- **🔒 Secure**: Validates load balancer headers and enforces proxy IP allowlists
- **📊 Rate Limiting**: Per-IP rate limiting with configurable sliding windows
- **🚫 IP Filtering**: Block malicious IPs with environment-based configuration
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
| `RATE_LIMIT_REQUESTS` | `100` | Maximum requests per time window |
| `RATE_LIMIT_WINDOW_SECS` | `60` | Time window in seconds for rate limiting |

### Complete Example

```bash
# Security configuration
export CC_REVERSE_PROXY_IPS="192.168.1.100,10.0.0.1,172.16.0.1"
export BLOCKED_IPS="192.168.1.200,malicious.ip.here"

# Rate limiting (100 requests per minute per IP)
export RATE_LIMIT_REQUESTS=100
export RATE_LIMIT_WINDOW_SECS=60

# Start proxy
clever-gatekeeper --listen 8080 --forward 3000
```

## 🔍 How It Works

### Security Model

1. **Header Validation**: Requires both `x-forwarded-for` and `forwarded` headers
2. **Proxy Authentication**: Validates the proxy IP (from `by=` field) against allowlist
3. **Real IP Extraction**: Extracts actual client IP from forwarded headers
4. **IP Filtering**: Blocks requests from blacklisted IPs
5. **Rate Limiting**: Applies per-IP rate limiting with sliding windows
6. **Header Injection**: Adds `X-Real-IP` header for upstream services

### Request Flow

```
Client → Load Balancer → Clever GateKeeper → Your Service
                               ↓
                        ✅ Validate headers
                        ✅ Check IP allowlist
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
- Inspired by the need for a lightweight, simple, secure proxy

---

**Made with ❤️ and ⚡ for the Open Source Community**
