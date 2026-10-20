# WiseGate threat model

WiseGate is an HTTP/1.1 reverse proxy written in Rust (hyper 1 server, reqwest towards the upstream). It sits in front of one local plain-HTTP service, behind a TLS-terminating load balancer, and buffers request and response bodies. Each accepted TCP connection is subject to the connection limit and a header read deadline; each request then goes through client IP extraction (and proxy validation in strict mode), IP blocklist, URL path pattern blocklist, HTTP method blocklist, per-IP rate limiting, authentication (HTTP Basic and/or Bearer, either one accepted), body read with size limit and deadline, then forwarding, with `X-Real-IP` added when a client IP is known. It ships as a binary (`wisegate`, in `src/`) and as a library (`wisegate-core`, in `wisegate-core/src/`).

## Where untrusted input enters

Every byte received from a client is untrusted: request line, path and query, method, all headers (including `X-Forwarded-For`, `Forwarded`, `Authorization`, `Connection`, `Content-Length`, `Transfer-Encoding`) and the body, sized or chunked, sent at any pace.

The upstream service belongs to the operator and is trusted, but its responses may carry client-influenced data (reflected content, redirects, repeated `Set-Cookie`, large bodies). WiseGate relays 3xx responses instead of following them; mishandling of such responses by WiseGate itself is in scope.

Configuration comes from CLI flags and environment variables (`src/config.rs`, `src/env_vars.rs`) and is trusted. A finding that needs control of the configuration is out of scope, unless WiseGate mishandles a value a careful operator would legitimately set (an htpasswd hash format, a non-canonical IPv6 address, an empty or zero value) in a way that weakens security.

## Deployment assumptions and modes

- **Strict mode** (non-empty `CC_REVERSE_PROXY_IPS`, or an allowed variable named by `TRUSTED_PROXY_IPS_VAR`): the TCP peer must be in the allowlist, or a loopback address when `TRUST_LOOPBACK_PROXY` is enabled. Every `Forwarded` field is read in order, and only the last element, the one appended by the trusted proxy, is used: its `by=` must be allowlisted and its `for=` is the client IP, with no fallback to earlier elements. `X-Forwarded-For` is ignored. Failures get `400`. Anything that makes WiseGate attribute a client-chosen IP in strict mode, or bypass the IP blocklist or rate limiter, is a vulnerability.
- **Permissive mode** (no allowlist): client-supplied `X-Forwarded-For` / `Forwarded` are trusted verbatim, as documented. IP spoofing in permissive mode is expected and out of scope. Without a valid IP in these headers, only the IP-based checks are skipped (IP blocklist, rate limiting, `X-Real-IP`); method, path, authentication, size and deadline checks still apply. This is documented behaviour.
- The trusted proxy (Sōzu on Clever Cloud) appends `proto=https;for="ip:port";by=ip` to the last `Forwarded` field. WiseGate supports this subset of RFC 7239: the element is whatever follows the last comma, its parameter names must be tokens, quotes must be balanced, `for`/`by` must appear once and be valid nodes. Complex quoted extensions containing commas are unsupported by design (a full tokenizer would let an unterminated quote in a client-supplied earlier element swallow the proxy's element). For attacks through a trusted proxy, show how client-controlled input survives its append or normalisation; direct clients bypassing the strict TCP-peer check are also in scope.
- WiseGate does not terminate TLS and speaks HTTP/1.1 only; the upstream must only be reachable through WiseGate.
- Library use: `request_handler::handle_request` relies on the `reqwest::Client` it is given (redirects disabled, timeout set) and on the embedding server for the connection limit, header deadline and shutdown. Environment variables only configure the `wisegate` binary; `DefaultConfig` does not read them. An embedding that ignores these documented requirements is not a WiseGate vulnerability.

## Components that matter most

1. `wisegate-core/src/ip_filter.rs`: peer validation, `Forwarded` / `X-Forwarded-For` parsing, IP canonicalisation (including IPv4-mapped IPv6), blocklist matching.
2. `wisegate-core/src/auth/`: Basic and Bearer checks, constant-time comparison, bcrypt / APR1-MD5 / `{SHA}` / plain-text verification, bounded blocking pool for password checks.
3. `wisegate-core/src/request_handler.rs`: the pipeline order, URL pattern matching (with percent-decoding), method filter, body limit and deadline, header forwarding (`Host` and `Content-Length` rebuilt for the upstream; `Authorization` removed only when WiseGate authentication is enabled and `CC_FORWARD_AUTH_HEADER` is not enabled; hop-by-hop and `Connection`-nominated headers dropped; `X-Real-IP` added after this cleanup), response relay.
4. `wisegate-core/src/headers.rs`, `wisegate-core/src/rate_limiter.rs`, `src/connection.rs` and `src/main.rs`: hop-by-hop rules, sliding-window limiter and cleanup, connection limit, hyper server timers, graceful shutdown.

`src/args.rs` and `src/server.rs` (startup logging) matter less, but leaking a password or token in logs is in scope.

## How to exercise it

The checkout and build artifacts are in `/src`. All of these work offline:

```sh
cd /src
cargo test --locked --workspace                                        # unit and doc tests
cargo build --locked --release                                         # target/release/wisegate
cargo test --locked --workspace --release -- --ignored --test-threads=1  # end-to-end tests
```

`tests/proxy_semantics.rs` and `tests/dos_regressions.rs` start the release binary against a raw-socket backend on loopback; they are the best template for a reproducer. `tests/comprehensive_integration_tests.rs` uses a Python backend and `curl`. `wisegate-core/src/test_utils.rs` is `cfg(test)`: use it from unit tests inside the crate, or implement the configuration traits (or use `DefaultConfig`) from outside.

To run strict mode by hand, make loopback the trusted proxy and send the element it would append:

```sh
python3 -m http.server 9000 --bind 127.0.0.1 &
CC_REVERSE_PROXY_IPS=127.0.0.1 CC_HTTP_BASIC_AUTH='admin:secret' \
  ./target/release/wisegate --bind 127.0.0.1 --listen 8080 --forward 9000 -v &
curl -u admin:secret -H 'Forwarded: for=198.51.100.7;by=127.0.0.1' http://127.0.0.1:8080/
```

Without that `Forwarded` element the request gets `400`, which is expected.

## How I rate severity

Rate by demonstrated impact and realistic prerequisites, not by mechanism. The levels below are indicative and assume the security boundary is actually crossed.

- **Critical**: remote code execution; disclosure of configured credentials or tokens to clients; unauthenticated access to the upstream with critical demonstrated impact.
- **High**: unauthenticated access to the upstream when Basic or Bearer auth is enabled; request smuggling or desynchronisation with a demonstrated security effect; memory-safety bugs (the binary forbids `unsafe`, so most likely through a dependency misuse).
- **Medium to high, by demonstrated impact**: in strict mode, a client choosing the IP WiseGate attributes to it, or bypassing the IP blocklist or rate limiter (higher when the upstream relies on `X-Real-IP` for access control); `Authorization` forwarded to the upstream when it should be stripped.
- **Medium**: denial of service that bypasses a configured limit (`MAX_BODY_SIZE_MB`, client deadlines, `MAX_CONNECTIONS`, the password-check pool) or that a small input amplifies, including a remotely triggered panic (the release profile aborts the whole process); bypass of the URL pattern or method blocklists, which are defence in depth rather than access control. Raise to high when the impact is systemic and demonstrated.
- **Low**: resource use that only scales linearly with traffic the operator allowed (limits set to 0, very high thresholds); misleading log entries; error messages that reveal nothing sensitive. A timing claim needs a statistically credible remote oracle and a concrete security impact; a timing difference alone is not enough.

## Anything to leave alone

- IP spoofing in permissive mode, and IP-based checks being skipped for permissive requests without a valid IP header (both documented).
- The weakness of the plain-text, `{SHA}` and APR1-MD5 formats themselves (supported for htpasswd compatibility; the README recommends bcrypt). Bugs in how WiseGate verifies them are in scope.
- Lack of TLS, HTTP/2, WebSocket or streaming support.
- Load balancer behaviour WiseGate cannot observe, e.g. a proxy that drops `Connection` but forwards the fields it nominated.
- Vulnerabilities in dependencies unless WiseGate's use of them creates the issue; name the responsible component precisely.
- `quick-test.sh` and the workflows in `.github/`.

## Reports

Include the affected commit, the mode and environment variables, the exact request bytes, expected and observed behaviour, and a reproducer, ideally a test in the style of `tests/proxy_semantics.rs` or a unit test in the affected module, with a minimal patch addressing the root cause. Group variants of the same root cause in one report.
