# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-01-17

### Added
- **wisegate-core crate**: Extracted reusable library for embedding in other projects
- **ConfigProvider trait**: Dependency injection for configuration, enabling library reuse
- **EnvVarConfig**: Default implementation reading from environment variables
- **WiseGateError**: Custom error type with HTTP status mapping and user-friendly messages
- **HTTP header constants**: Centralized in `headers.rs` with `is_hop_by_hop()` helper
- **ConnectionTracker**: Track active connections for graceful shutdown
- **ConnectionLimiter**: Semaphore-based connection limiting with permit management
- **Shared TestConfig**: Centralized test configuration in `test_utils.rs` module
- **Comprehensive unit tests**: 220 tests covering all modules

### Refactored
- **Workspace structure**: Split into `wisegate` (CLI) and `wisegate-core` (library)
- **ip_filter**: Accepts `ConfigProvider` instead of global config
- **rate_limiter**: Accepts `ConfigProvider` instead of global config
- **request_handler**: Accepts `ConfigProvider` and HTTP client, uses centralized `headers::is_hop_by_hop()`
- **main.rs**: Uses `ConnectionTracker` and `ConnectionLimiter` for cleaner connection management

### Removed
- **test-local.py**: Removed redundant Python test script (replaced by Rust integration tests)
- **Duplicated TestConfig**: Consolidated into shared `test_utils.rs` module
- **Duplicated is_hop_by_hop**: Now uses centralized function from `headers.rs`

---

## [0.7.2] - 2026-01-16

### Added
- **ConfigProvider trait**: Dependency injection for configuration, enabling library reuse
- **EnvVarConfig**: Default implementation reading from environment variables

### Refactored
- **ip_filter**: Accepts `ConfigProvider` instead of global config
- **rate_limiter**: Accepts `ConfigProvider` instead of global config
- **request_handler**: Accepts `ConfigProvider` instead of global config
- **main**: Uses `EnvVarConfig` for dependency injection

---

## [0.7.1] - 2026-01-16

### Refactored
- **NewType RateLimiter**: Replaced type alias with proper struct for better encapsulation
- **RateLimitEntry struct**: Named fields instead of tuple for clearer code
- **StartupConfig**: Decoupled `server.rs` from CLI `Args` struct
- **IP validation**: `validate()` now returns parsed `IpAddr` to avoid double parsing

---

## [0.7.0] - 2026-01-16

### Added
- **Structured logging**: `tracing` with JSON support (`--json-logs`)
- **Graceful shutdown**: SIGINT/SIGTERM handling with 30s connection drain
- **Connection limiting**: `MAX_CONNECTIONS` env var with semaphore-based limiting
- **HTTP connection pooling**: Reusable client with 32 connections per host
- **Configuration caching**: `once_cell::Lazy` for zero-overhead config access
- **Library structure**: Extracted `lib.rs` for better testability and reuse
- **Complete rustdoc**: All public functions documented with examples
- **Default ports**: `--listen` defaults to 8080, `--forward` defaults to 9000

### Enhanced
- **Performance**: `opt-level = 3` (2x faster than `"z"`, +0.8MB)
- **Dependencies**: Updated to latest versions (tokio 1.49, reqwest 0.13, clap 4.5.54)
- **Documentation**: Simplified README

---

## [0.6.1] - 2025-08-03

### Enhanced
- **Docs**: Updated texts
- **Testing**: Added scripts & tools

---

## [0.6.0] - 2025-08-03

### Added
- CLI short flags support (`-l`, `-f`, `-v`, `-q`)
- `--verbose` mode for detailed configuration display with environment variables
- `--quiet` mode for minimal output (perfect for production)
- Improved build workflow with caching
- CI workflow with automated testing
- Custom HTTP method handling

### Enhanced
- **Security**: Better hop-by-hop header filtering in proxy responses
- **Performance**: More efficient IP extraction with `next_back()` optimization
- **Configuration**: Centralized default values and improved validation
- **Error handling**: Replaced panic-prone `unwrap()` calls with graceful error handling
- **User experience**: Clear configuration display showing proxy mode (strict vs permissive)
- **Code quality**: Enhanced type safety and better separation of concerns

### Removed
- `ENABLE_STREAMING` experiment
- Duplicate request forwarding logic

## [0.5.0] - 2025-08-03

### Added
- `TRUSTED_PROXY_IPS_VAR` environment variable for custom proxy IP variable names
- Permissive mode when no proxy allow list is configured
- Initial integration tests

## [0.4.0] - 2025-08-02

### Added
- `BLOCKED_METHODS` environment variable for HTTP method filtering
- `BLOCKED_PATTERNS` environment variable for URL pattern blocking
- Apache 2.0 license

## Enhanced
- Updated dependencies and code organization

### Changed
- Project renamed to WiseGate

## [0.3.0] - 2025-07-21

### Added
- Streaming experiment
- Timeouts, max body size

## Enhanced
- Build workflow with upx, Apple Silicon
- Imports reordered for clarity

## [0.2.0] - 2025-07-21

### Enhanced
- Modular code architecture with better separation of concerns

## [0.1.0] - 2025-07-20

### Added
- Initial release
- Basic reverse proxy functionality
- Rate limiting with configurable sliding windows
- IP filtering and validation
- Proxy header validation (strict mode)
- Environment-based configuration
- Rust-based high-performance implementation
