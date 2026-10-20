# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.0] - 2026-10-20

### Security
- **Strict-mode IP spoofing through the load balancer**: wisegate only read the first `X-Forwarded-For` and `Forwarded` header fields, while Sōzu (Clever Cloud) appends to the last one. A client sending two `X-Forwarded-For` fields chose the IP wisegate attributed to it, bypassing the IP blocklist and the rate limiter. Strict mode now reads every `Forwarded` field and trusts only the last element, the one appended by the proxy: its `by=` must be allowlisted and the client IP comes from its `for=`, with no fallback to earlier elements. `X-Forwarded-For` is no longer used in strict mode.
- **Strict-mode IP spoofing by direct clients**: the proxy allowlist was matched against the client-supplied `by=` only. The TCP peer must now itself be an allowlisted proxy (or a loopback peer, only when `TRUST_LOOPBACK_PROXY` is enabled).
- **Malformed `Forwarded` elements**: in the identity-bearing element, unbalanced quotes, parameter names that are not tokens, duplicated `for`/`by` parameters, separators hidden in quoted extensions, invalid ports and stray brackets are rejected instead of yielding an identity. wisegate validates the `for`/`by` identities of the proxy's element and rejects ambiguous quoting; complex quoted extensions are not supported. IPv4-mapped IPv6 addresses are normalised to IPv4 for blocklists, allowlists and rate limiting.
- **Unbounded chunked bodies**: `MAX_BODY_SIZE_MB` was only checked after the whole body was buffered when no `Content-Length` was sent. The limit is now enforced while reading, and the connection is closed on rejection.
- **Slow clients holding connections**: request headers and bodies now have read deadlines (`CLIENT_HEADER_TIMEOUT_SECS`, `CLIENT_BODY_TIMEOUT_SECS`, 30 s by default); an incomplete body gets `408 Request Timeout`.
- **Password-check CPU exhaustion**: rate limiting now applies before authentication, so failed attempts consume the per-IP quota, and Basic Auth hash checks run off the async executor with a bounded concurrency (`503` when saturated).
- **Redirects followed upstream**: the upstream client followed up to 10 redirects, serving targets that never went through wisegate's filters (e.g. a `302` to a blocked path). 3xx responses are now relayed to the client.
- **Hop-by-hop headers**: headers named in `Connection` are now dropped in both directions as RFC 9110 requires, `Trailer` is filtered (the list had `trailers`), and `X-Real-IP` is added after this cleanup so a client cannot nominate it away.

### Added
- **`TRUST_LOOPBACK_PROXY`** env var (and `ProxyProvider::trust_loopback_proxy()`): in strict mode, also trust a loopback TCP peer, for chains where another local middleware runs in front of wisegate (e.g. Clever Cloud Request Flow `varnish,custom`). The `by=` must still be allowlisted.
- **`CLIENT_HEADER_TIMEOUT_SECS`** and **`CLIENT_BODY_TIMEOUT_SECS`** env vars (and `ProxyProvider::client_body_timeout()`).
- **`headers::connection_nominated()`** and **`headers::is_hop_by_hop_for()`** helpers, and the `headers::TRAILER` constant.

### Changed
- **Breaking (library)**: `request_handler::handle_request` takes the TCP peer address (`SocketAddr`) as its second argument, and `ip_filter::extract_and_validate_real_ip` takes the peer IP. Library users must also build their `reqwest::Client` with `redirect::Policy::none()`.
- **Breaking (behaviour)**: strict mode no longer requires nor reads `X-Forwarded-For`; it requires a `Forwarded` element with both `for=` and `by=` from an allowlisted peer, or from an explicitly trusted loopback peer.
- **Repeated response headers** such as `Set-Cookie` are all forwarded; only the last one was kept.
- The binary exits if the upstream HTTP client cannot be built, instead of silently falling back to a default client.

### Deprecated
- `headers::TRAILERS`: use `headers::TRAILER`.

---

## [0.12.0] - 2026-05-13

### Security
- **X-Real-IP spoofing**: Strip any client-supplied `X-Real-IP` header before processing so the upstream only ever sees the value wisegate computed.
- **Authorization leakage**: When wisegate has performed authentication, the `Authorization` header is now stripped before forwarding. Opt back in with `CC_FORWARD_AUTH_HEADER=true` (or `AuthenticationProvider::forward_authorization_header()` in the library) when the upstream genuinely needs the credentials.
- **IPv6 rate-limit bypass**: Extracted IPs are canonicalised (RFC 5952), so `2001:0db8::1` and `2001:db8::1` now key the same rate-limit bucket. Blocked/allowed IP lists are also matched on canonical form, so non-canonical IPv6 spellings in config still apply.

### Added
- **`wisegate_core::DefaultConfig`**: ready-to-use struct implementing every configuration trait with the same defaults as the CLI, so library users can drop wisegate-core in without trait boilerplate.
- **Startup warnings**: warn when `CC_REVERSE_PROXY_IPS` contains the bind sentinel `0.0.0.0`, and when wisegate listens on `0.0.0.0` with no auth and no IP blocklist (a common open-proxy misconfiguration).
- **Full env-var reference in `--help`**: every recognised variable is now listed, grouped by purpose (proxy security / filtering / rate limiting / authentication / proxy behaviour).
- **`CC_FORWARD_AUTH_HEADER`** env var to opt into upstream Authorization forwarding.

### Changed
- **Library example**: README and `wisegate-core` crate docs now showcase the `DefaultConfig` path instead of the 5-trait implementation snippet.
- **`ConnectionTracker::track()`**: returns `impl Drop` instead of the concrete `ConnectionGuard`; binary callers only ever depended on the drop side anyway.
- **Doc**: `request_handler::handle_request` rustdoc now spells out the Tokio runtime requirement, the permissive-mode header-trust caveat, and that strict mode requires both `X-Forwarded-For` and `Forwarded` headers (the `by=` field is what gets matched against the proxy allowlist).

### Refactored
- **`ip_filter`**: deduplicated the canonical-IP equality path into a private `ips_match` helper and dropped the dead `is_valid_ip_format` wrapper.

---

## [0.11.0] - 2026-02-19

### Added
- **Sliding window log algorithm**: True sliding window rate limiting replacing the fixed window approach

### Fixed
- **Content-Length pre-check**: Check body size before buffering to prevent memory exhaustion
- **Hop-by-hop header filtering**: Filter on request path per RFC 7230
- **URL pattern bypass**: Case-insensitive URL pattern blocking to prevent bypass
- **Bearer token prefix**: Case-insensitive `Bearer` prefix per RFC 6750
- **WWW-Authenticate header**: Sanitize realm value to prevent header injection
- **Credential masking**: Mask auth credentials and tokens in verbose log output

### Performance
- **Zero-copy body forwarding**: Pass `Bytes` directly to reqwest body instead of `to_vec()`
- **Hop-by-hop comparison**: Case-insensitive comparison without allocation
- **Method/pattern filtering**: Reduce allocations in method and URL pattern filtering
- **url_decode**: Byte-based iteration avoiding String allocation per hex pair
- **Blocked patterns**: Pre-normalize to lowercase at config load time
- **forward_host**: Use `Arc<str>` to avoid per-connection `String::clone`

### Refactored
- **RateLimiter**: Unified state into single `Mutex`, encapsulated internals, moved cleanup state per-instance
- **Client IP**: Replace sentinel string with `Option<String>`
- **ConnectionGuard**: RAII guard with saturating decrement
- **Config caching**: Replace `once_cell::Lazy` with `std::sync::LazyLock`
- **ConfigProvider**: Use trait consistently instead of standalone getters
- **Header constants**: Use constants instead of magic strings in IP filter and request handler
- **Test infrastructure**: Merge `AuthTestEnvironment` into `TestEnvironment` with builder pattern
- **Error types**: Remove unused error variants
- **Defaults**: Remove redundant constant aliases, use defaults module directly
- **Method matching**: Simplify HTTP method matching in request forwarding
- **Rate limiter locking**: Eliminate nested locking in cleanup path
- **Dead code cleanup**: Remove unused `Result` type alias, builder methods, and consolidate redundant tests
- **Clippy warnings**: Fix `collapsible_if`, `expect_fun_call`, and `manual_contains` in integration tests

### Documentation
- Fix request flow order in README to match implementation
- Fix library examples, document `TRUSTED_PROXY_IPS_VAR` whitelist
- Remove unsupported CIDR notation from proxy IPs example

---

## [0.10.0] - 2026-01-17

### Added
- **Authentication integration tests**: 9 new tests covering Basic Auth, Bearer Token, and combined authentication scenarios
- **defaults module**: Centralized default configuration values in `wisegate-core/src/defaults.rs` (DRY principle)

### Changed
- **request_handler**: Now uses `WiseGateError` for consistent error handling throughout the pipeline
- **test_utils**: Uses centralized defaults module for configuration values

---

## [0.9.0] - 2026-01-17

### Added
- **HTTP Basic Authentication** (RFC 7617): Protect your endpoints with username/password
  - Support for multiple password formats: plain text, bcrypt, APR1 MD5, SHA1
  - Constant-time comparison to prevent timing attacks
  - Multiple users via `CC_HTTP_BASIC_AUTH_N` environment variables
  - Configurable realm via `CC_HTTP_BASIC_AUTH_REALM`
- **Bearer Token Authentication** (RFC 6750): API key authentication
  - Simple token-based authentication via `CC_BEARER_TOKEN`
  - Constant-time comparison to prevent timing attacks
  - Can be used alone or combined with Basic Auth (either method accepted)
- **auth module**: New `wisegate-core/src/auth/` module with:
  - `Credentials` struct for credential storage
  - `hash::verify()` for multi-format password verification
  - `hash::constant_time_eq()` for secure comparison
  - `check_basic_auth()` for request authentication
  - `check_bearer_token()` for bearer token verification
- **AuthenticationProvider trait**: Configuration trait for authentication settings
  - `bearer_token()` method for bearer token access
  - `is_basic_auth_enabled()` and `is_bearer_auth_enabled()` helpers
- **New environment variables**: `CC_HTTP_BASIC_AUTH`, `CC_HTTP_BASIC_AUTH_N`, `CC_HTTP_BASIC_AUTH_REALM`, `CC_BEARER_TOKEN`
- **New error types**: `AuthenticationRequired`, `InvalidCredentials`
- **New headers**: `AUTHORIZATION`, `WWW_AUTHENTICATE` constants
- **51 new tests**: Comprehensive coverage for auth module

### Changed
- Request pipeline now includes authentication check after method blocking, before rate limiting
- `ConfigProvider` trait now requires `AuthenticationProvider` implementation
- Startup info displays authentication status (Basic Auth and Bearer Token)

---

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

[0.13.0]: https://github.com/davlgd/wisegate/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/davlgd/wisegate/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/davlgd/wisegate/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/davlgd/wisegate/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/davlgd/wisegate/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/davlgd/wisegate/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/davlgd/wisegate/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/davlgd/wisegate/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/davlgd/wisegate/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/davlgd/wisegate/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/davlgd/wisegate/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/davlgd/wisegate/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/davlgd/wisegate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/davlgd/wisegate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/davlgd/wisegate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/davlgd/wisegate/releases/tag/v0.1.0
