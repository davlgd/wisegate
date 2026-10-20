# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this file with the repository as the build context. Network access is only
# available during this build, so every dependency the tests need is fetched here.
FROM rust:1-trixie

ENV DEBIAN_FRONTEND=noninteractive
# python3 runs the backend and curl the client in the older end-to-end tests.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN cargo fetch --locked

# Everything after this point works offline. RUSTFLAGS stays set so later builds reuse these artifacts.
ENV CARGO_NET_OFFLINE=true \
    RUSTFLAGS="-C force-frame-pointers=yes"

# Debug build of every target (binary, library, tests) with full debug info.
RUN cargo build --locked --workspace --all-targets

# Release binary at /src/target/release/wisegate, used by the integration tests in tests/.
RUN cargo build --locked --release

# Run the suites so the image is known to work, without letting a failure abort the build.
RUN cargo test --locked --workspace || echo "WARNING: unit tests reported failures"
RUN cargo test --locked --workspace --release -- --ignored --test-threads=1 \
    || echo "WARNING: integration tests reported failures"
