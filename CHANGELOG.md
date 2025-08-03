# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
