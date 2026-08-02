# Routa

A high-performance HTTP/1.1 & HTTP/2 proxy, load balancer, and cache server with native WebSocket support, written in Rust.

> **Status: active development, pre-v1.** Core proxy, load balancing, caching, and middleware are stable and fully test-covered on the epoll backend. The `io_uring` backend is functional for the base server but not yet wired into the proxy path — see [Roadmap](#roadmap).

## Features

- **Dual event-loop backends** — runs on either `epoll` (default, production-ready) or `io_uring` (experimental, see status above), selected at compile time
- **HTTP/1.1 and HTTP/2** — full HTTP/2 implementation including HPACK header compression
- **WebSocket support**
- **Reverse proxy & load balancing** — with outlier detection for automatically routing around unhealthy upstreams
- **In-memory response caching**
- **Middleware pipeline** — authentication, rate limiting, CORS, compression, access control (ACL/CIDR), request logging, metrics
- **TLS termination**

## Conformance & Testing

Correctness is validated against industry-standard conformance suites, not just internal tests:

- **[h1spec](https://github.com/summerwind/h1spec)** — full pass
- **[h2spec](https://github.com/summerwind/h2spec)** — full pass
- **[Autobahn Testsuite](https://github.com/crossbario/autobahn-testsuite)** (WebSocket) — full pass

All three suites pass in full on both the `epoll` and `io_uring` backends. On top of this, the codebase has 600+ hand-written unit tests covering the parsers, protocol state machines, middleware, and load balancer — independently cross-checked against the conformance suites above rather than written to match them.

## Roadmap

- [ ] `io_uring` backend support in the proxy path (currently base-server only)
- [ ] HTTP/3
- [ ] WebTransport

## Getting Started

Build and run with the default (`epoll`) backend:

```bash
cargo build --release
./target/release/routa examples/routa.conf
```

**Experimental `io_uring` backend** (not yet recommended for the proxy path):

```bash
cargo build --release --features io_uring
./target/release/routa examples/routa.conf
```

See [`examples/routa.conf`](examples/routa.conf) for a full configuration to start from.

## Architecture

- `src/core/event_loop/` — `epoll` (`mio_backend.rs`) and `io_uring` (`uring_backend.rs`) event-loop implementations behind a shared interface
- `src/http/` — HTTP/1.1, HTTP/2 (with HPACK), WebSocket, and static file/cache handling, all implemented from scratch and optimized for performance
- `src/lb/` — load balancing and upstream health/outlier detection
- `src/http/middleware/` — pluggable middleware pipeline (auth, rate limiting, CORS, compression, ACL, logging, metrics)

## License

Licensed under the [Apache License 2.0](LICENSE).
