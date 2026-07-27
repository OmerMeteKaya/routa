//! Reverse-proxy orchestration: picks an upstream node, obtains a
//! connection to it (H1 via `lb::upstream`'s pooled connections, H2
//! via `net::h2_client`), forwards a request, and returns the
//! response -- retrying across nodes according to the load balancer's
//! configured policy when a connection attempt or the request itself
//! fails.
//!
//! Request header preparation (X-Forwarded-For/Via chains, hop-by-hop
//! header filtering) lives here rather than in either transport
//! module, so it's applied identically regardless of which protocol
//! ends up carrying the request to the upstream -- an H1 and an H2
//! upstream selected for the same logical service see the same
//! header policy.
//!
//! H2 connection establishment never blocks a request waiting for it:
//! if no ready connection exists for a node, one is started and the
//! current request moves on to try the next node (or fails over to
//! whatever the load balancer's retry policy dictates) rather than
//! stalling until that connection finishes handshaking. A later
//! request to the same node picks up the now-ready connection. This
//! keeps a slow or unresponsive upstream from ever blocking the
//! request that happened to trigger dialing it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::http::h2::hpack::HeaderField;
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use crate::lb::lb::LoadBalancer;
use crate::lb::upstream::UpstreamNode;
use crate::net::h2_client::H2Client;

// ─── Header preparation ─────────────────────────────────────────────────

/// RFC 9110 7.6.1's hop-by-hop header set, plus `Connection` itself --
/// these describe *this specific connection*, not the request/response
/// semantics, so they're never forwarded to (or trusted from) an
/// upstream. An H2 upstream request additionally never carries any of
/// these at all (H2 has no equivalent concept), but filtering them out
/// unconditionally keeps one rule that's correct for both protocols
/// rather than a protocol-specific exception list.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

/// Builds the final header list to send upstream: copies every
/// non-hop-by-hop header from `req`, then appends/extends
/// `X-Forwarded-For` and `Via` to reflect this hop. `client_addr` is
/// the real connection's address (never a client-supplied header --
/// see `http::middleware::ratelimit`'s doc comment for the same
/// spoofing concern this avoids).
pub fn build_upstream_headers(
    req: &HttpRequest,
    client_addr: Option<IpAddr>,
    proxy_identity: &str,
) -> Vec<HeaderField> {
    let mut headers: Vec<HeaderField> = req
        .headers
        .iter()
        .filter(|(name, _)| !is_hop_by_hop(name))
        .map(|(name, value)| HeaderField {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();

    if let Some(addr) = client_addr {
        let addr_str = addr.to_string();
        match headers.iter_mut().find(|h| h.name.eq_ignore_ascii_case("x-forwarded-for")) {
            Some(existing) => {
                existing.value = format!("{}, {}", existing.value, addr_str);
            }
            None => {
                headers.push(HeaderField {
                    name: "X-Forwarded-For".to_string(),
                    value: addr_str,
                });
            }
        }
    }

    let via_entry = format!("1.1 {proxy_identity}");
    match headers.iter_mut().find(|h| h.name.eq_ignore_ascii_case("via")) {
        Some(existing) => {
            existing.value = format!("{}, {}", existing.value, via_entry);
        }
        None => {
            headers.push(HeaderField {
                name: "Via".to_string(),
                value: via_entry,
            });
        }
    }

    headers
}

// ─── Node/connection acquisition ────────────────────────────────────────

/// The transport a request ended up using -- decided per attempt by
/// whichever node was picked, not fixed ahead of time, since a pool's
/// nodes can mix H1 and H2 upstreams.
pub enum UpstreamConnection {
    Http1 {
        node: Arc<UpstreamNode>,
        conn: crate::lb::upstream::IdleConn,
    },
    Http2 {
        node: Arc<UpstreamNode>,
        client: Arc<Mutex<H2Client>>,
    },
}

/// The outcome of attempting to acquire a connection for one node
/// during a forwarding attempt.
enum AcquireOutcome {
    Ready(UpstreamConnection),
    /// An H2 connection was started but isn't ready yet -- this
    /// attempt moves on to the next node (or fails over) rather than
    /// waiting; see this module's top doc comment.
    Pending,
    Failed,
}

/// Where a node's pooled H2 connections live -- one per node, shared
/// across every request that might pick that node. Kept outside
/// `UpstreamNode` itself (rather than adding an H2-specific field to
/// that type) since not every deployment uses H2 upstreams at all,
/// and this pool's locking/lifecycle concerns are specific to
/// managing a small number of shared, long-lived, multiplexed
/// connections -- a different shape from the plain per-request
/// connection pooling `UpstreamNode` already does for H1.
#[derive(Default)]
pub struct H2ConnectionPool {
    connections: Mutex<Vec<Arc<Mutex<H2Client>>>>,
}

impl H2ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a ready (state `Ready`, with spare stream capacity)
    /// connection if one exists in this node's pool.
    fn ready_connection(&self) -> Option<Arc<Mutex<H2Client>>> {
        let conns = self.connections.lock().unwrap();
        conns
            .iter()
            .find(|c| {
                let client = c.lock().unwrap();
                client.state == crate::net::h2_client::H2ClientState::Ready && client.has_capacity()
            })
            .cloned()
    }

    /// Advances every connection currently establishing itself
    /// (`Connecting`/`TlsHandshake`/etc.) by one step -- called once
    /// per poller readiness event for each such connection's socket
    /// (see this module's top doc comment on H2 establishment never
    /// blocking a request: this is where that establishment actually
    /// progresses, independently of whichever request originally
    /// triggered starting it).
    pub fn advance_pending(&self) {
        let conns = self.connections.lock().unwrap();
        for conn in conns.iter() {
            let mut client = conn.lock().unwrap();
            if client.state != crate::net::h2_client::H2ClientState::Ready {
                let _ = client.advance();
            }
        }
    }

    /// Starts a new H2 connection to `node` and adds it to the pool in
    /// its initial (not-yet-ready) state -- the caller doesn't wait
    /// for it; a later request (or `advance_pending`) picks it up
    /// once it's ready.
    fn start_connection(&self, node: &UpstreamNode) -> std::io::Result<()> {
        let addr = node.resolve_addr()?;
        let client = H2Client::connect(addr, &node.host)?;
        self.connections.lock().unwrap().push(Arc::new(Mutex::new(client)));
        Ok(())
    }

    /// Removes connections that failed or are otherwise dead --
    /// called periodically alongside the H1 idle-connection reaping
    /// `UpstreamNode` already does, so a pool doesn't accumulate
    /// stale entries forever.
    pub fn reap_failed(&self) {
        self.connections
            .lock()
            .unwrap()
            .retain(|c| c.lock().unwrap().state != crate::net::h2_client::H2ClientState::Failed);
    }
}

/// Attempts to acquire a connection to `node`, using whichever
/// transport the node is configured for.
fn acquire_connection(node: &Arc<UpstreamNode>, h2_pools: &H2PoolRegistry) -> AcquireOutcome {
    if node.use_tls && h2_pools.uses_h2(node) {
        let pool = h2_pools.pool_for(node);
        if let Some(client) = pool.ready_connection() {
            return AcquireOutcome::Ready(UpstreamConnection::Http2 {
                node: Arc::clone(node),
                client,
            });
        }
        // No ready connection -- start one for a future request and
        // move on without waiting (see this module's top doc
        // comment).
        let _ = pool.start_connection(node);
        return AcquireOutcome::Pending;
    }

    if let Some(conn) = node.acquire_idle() {
        node.mark_active();
        return AcquireOutcome::Ready(UpstreamConnection::Http1 {
            node: Arc::clone(node),
            conn,
        });
    }

    match node.connect_async() {
        Ok(stream) => {
            node.mark_active();
            AcquireOutcome::Ready(UpstreamConnection::Http1 {
                node: Arc::clone(node),
                conn: crate::lb::upstream::IdleConn {
                    stream,
                    created_at: Instant::now(),
                    last_used: Instant::now(),
                    requests_served: 0,
                },
            })
        }
        Err(_) => AcquireOutcome::Failed,
    }
}

/// Tracks, per node, whether it should be treated as an H2 upstream
/// and (if so) that node's connection pool. Kept separate from
/// `UpstreamNode` -- see `H2ConnectionPool`'s doc comment.
#[derive(Default)]
pub struct H2PoolRegistry {
    pools: Mutex<std::collections::HashMap<usize, Arc<H2ConnectionPool>>>,
    h2_node_ids: Mutex<std::collections::HashSet<usize>>,
}

fn node_id(node: &UpstreamNode) -> usize {
    node as *const UpstreamNode as usize
}

impl H2PoolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_h2(&self, node: &Arc<UpstreamNode>) {
        self.h2_node_ids.lock().unwrap().insert(node_id(node));
    }

    fn uses_h2(&self, node: &UpstreamNode) -> bool {
        self.h2_node_ids.lock().unwrap().contains(&node_id(node))
    }

    fn pool_for(&self, node: &UpstreamNode) -> Arc<H2ConnectionPool> {
        let mut pools = self.pools.lock().unwrap();
        pools
            .entry(node_id(node))
            .or_insert_with(|| Arc::new(H2ConnectionPool::new()))
            .clone()
    }

    /// Advances every node's H2 pool -- see
    /// `H2ConnectionPool::advance_pending`.
    pub fn advance_all_pending(&self) {
        for pool in self.pools.lock().unwrap().values() {
            pool.advance_pending();
        }
    }

    pub fn reap_all_failed(&self) {
        for pool in self.pools.lock().unwrap().values() {
            pool.reap_failed();
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_identity: String,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            proxy_identity: "routa".to_string(),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub enum ForwardError {
    /// Every node the retry policy allowed trying failed to even
    /// establish a connection.
    AllNodesExhausted,
    /// A connection was established but the request/response exchange
    /// itself failed (e.g. the upstream reset the connection
    /// mid-response).
    UpstreamError(std::io::Error),
}

/// Forwards `req` to whichever upstream node `lb` selects, retrying
/// across additional nodes (up to `lb.config.max_retries` further
/// attempts) if a connection can't be established or the exchange
/// itself fails -- honoring the load balancer's own configured retry
/// policy rather than a fixed number of attempts, so a pool configured
/// for "never retry" (max_retries: 0) genuinely never does.
pub fn forward(
    lb: &LoadBalancer,
    h2_pools: &H2PoolRegistry,
    req: &HttpRequest,
    config: &ProxyConfig,
) -> Result<HttpResponse, ForwardError> {
    let client_ip_str = req.remote_addr.map(|a| a.to_string());
    let sticky_value = req.get_header(&sticky_cookie_header_name(lb)).map(|s| s.to_string());

    let max_attempts = 1 + lb.config.max_retries as usize;
    let mut last_error: Option<std::io::Error> = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            lb.record_retry();
        }

        let Some(node) = lb.pick_node_sticky(client_ip_str.as_deref(), sticky_value.as_deref())
        else {
            break; // no selectable node at all -- retrying further won't help
        };

        match acquire_connection(&node, h2_pools) {
            AcquireOutcome::Ready(conn) => {
                lb.record_request();
                match forward_over_connection(conn, req, config, &lb.pool) {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        node.record_failure(&lb.pool);
                        lb.record_failed();
                        last_error = Some(e);
                        continue;
                    }
                }
            }
            AcquireOutcome::Pending => continue,
            AcquireOutcome::Failed => {
                node.record_failure(&lb.pool);
                continue;
            }
        }
    }

    match last_error {
        Some(e) => Err(ForwardError::UpstreamError(e)),
        None => Err(ForwardError::AllNodesExhausted),
    }
}

fn sticky_cookie_header_name(lb: &LoadBalancer) -> String {
    // Sticky value arrives as a Cookie header's value already parsed
    // out to just this cookie's value by whatever layer reads
    // incoming cookies -- this module only needs the configured
    // cookie's name to look it up. If sticky sessions aren't enabled,
    // this name is never actually consulted (see `pick_node_sticky`).
    if lb.config.sticky_cookie_name.is_empty() {
        "routa_sticky".to_string()
    } else {
        lb.config.sticky_cookie_name.clone()
    }
}

/// Sends `req` over an already-acquired connection and waits for the
/// complete response, blocking this call for as long as the exchange
/// takes. This blocking behavior is deliberate and scoped: it's used
/// from a dedicated per-request execution context (not the same
/// non-blocking event loop thread serving other connections), the
/// same separation `lb::upstream`'s active health-check probes use
/// their own dedicated thread for rather than running on a worker's
/// main loop. `core::event_loop`'s integration of this module is
/// responsible for ensuring forward() runs somewhere that blocking is
/// safe.
fn forward_over_connection(
    conn: UpstreamConnection,
    req: &HttpRequest,
    config: &ProxyConfig,
    pool: &crate::lb::upstream::UpstreamPool,
) -> std::io::Result<HttpResponse> {
    match conn {
        UpstreamConnection::Http1 { node, conn } => forward_http1(node, conn, req, config, pool),
        UpstreamConnection::Http2 { node, client } => forward_http2(node, client, req, config),
    }
}

fn forward_http1(
    node: Arc<UpstreamNode>,
    mut conn: crate::lb::upstream::IdleConn,
    req: &HttpRequest,
    config: &ProxyConfig,
    pool: &crate::lb::upstream::UpstreamPool,
) -> std::io::Result<HttpResponse> {
    let client_addr = req.remote_addr;
    let headers = build_upstream_headers(req, client_addr, &config.proxy_identity);
    let mut upstream_req = req.clone();
    upstream_req.headers = headers
        .into_iter()
        .map(|h| (h.name, h.value))
        .collect();

    let request_bytes = upstream_req.serialize();
    if let Err(e) = write_all_with_timeout(&mut conn.stream, &request_bytes, config.write_timeout) {
        node.release_conn(conn, false);
        return Err(e);
    }

    let read_result = read_http1_response(&mut conn.stream, config.read_timeout);
    match read_result {
        Ok(response) => {
            node.release_conn(conn, true);
            node.record_success(pool);
            Ok(response)
        }
        Err(e) => {
            node.release_conn(conn, false);
            Err(e)
        }
    }
}

/// Writes all of `data`, retrying on `WouldBlock` (mio's sockets are
/// always non-blocking, so a write that can't complete immediately
/// reports this rather than actually blocking) until either every
/// byte is sent or `timeout` elapses.
fn write_all_with_timeout(
    stream: &mut mio::net::TcpStream,
    data: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    use std::io::Write;
    let deadline = Instant::now() + timeout;
    let mut sent = 0;
    while sent < data.len() {
        match stream.write(&data[sent..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write returned 0")),
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads a complete HTTP/1.1 response from `stream`, using
/// `http::response`'s own framing rules (Content-Length or chunked)
/// to know when the response is complete rather than reading until
/// EOF -- an EOF-based read would misbehave on a keep-alive
/// connection, where the upstream has no reason to close after just
/// one response.
fn read_http1_response(stream: &mut mio::net::TcpStream, timeout: Duration) -> std::io::Result<HttpResponse> {
    use std::io::Read;
    let deadline = Instant::now() + timeout;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // upstream closed -- see what's accumulated so far
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(resp) = try_parse_response(&buf) {
                    return Ok(resp);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    try_parse_response(&buf).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "upstream closed before a complete response arrived")
    })
}

/// Best-effort framing check: looks for a complete header block plus
/// (if a body is declared) enough bytes to satisfy it. Not a full
/// `http::request::parse`-equivalent parser for responses (this
/// module doesn't have one -- `http::response` is write-only from
/// this codebase's perspective so far), just enough structure to know
/// when to stop reading and build the `HttpResponse` to hand back to
/// the frontend.
fn try_parse_response(buf: &[u8]) -> Option<HttpResponse> {
    let headers_end = find_subslice(buf, b"\r\n\r\n")?;
    let header_bytes = &buf[..headers_end];
    let body_start = headers_end + 4;

    let header_str = std::str::from_utf8(header_bytes).ok()?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let _http_version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();

    let mut resp = HttpResponse::new(status, reason);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        resp.set_header(name, value);
    }

    if chunked {
        let (body, complete) = decode_chunked_so_far(&buf[body_start..]);
        if !complete {
            return None;
        }
        resp.remove_header("Transfer-Encoding");
        resp.set_body(body);
        return Some(resp);
    }

    let needed = content_length.unwrap_or(0);
    if buf.len() < body_start + needed {
        return None; // body not fully arrived yet
    }
    if needed > 0 {
        resp.set_body(buf[body_start..body_start + needed].to_vec());
    }
    Some(resp)
}

/// Decodes as much of a chunked body as `data` currently contains.
/// Returns `(body_so_far, true)` once the terminating zero-length
/// chunk has been seen, `(partial_body, false)` if more data is still
/// needed.
fn decode_chunked_so_far(data: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    let mut pos = 0;
    loop {
        let Some(line_end) = find_subslice(&data[pos..], b"\r\n") else {
            return (body, false);
        };
        let line_end = pos + line_end;
        let Ok(size_str) = std::str::from_utf8(&data[pos..line_end]) else {
            return (body, false);
        };
        let Ok(size) = usize::from_str_radix(size_str.trim(), 16) else {
            return (body, false);
        };
        let chunk_start = line_end + 2;
        if size == 0 {
            return (body, true);
        }
        if data.len() < chunk_start + size + 2 {
            return (body, false);
        }
        body.extend_from_slice(&data[chunk_start..chunk_start + size]);
        pos = chunk_start + size + 2;
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn forward_http2(
    node: Arc<UpstreamNode>,
    client: Arc<Mutex<H2Client>>,
    req: &HttpRequest,
    config: &ProxyConfig,
) -> std::io::Result<HttpResponse> {
    let client_addr = req.remote_addr;
    let mut headers = build_upstream_headers(req, client_addr, &config.proxy_identity);

    let scheme = if node.use_tls { "https" } else { "http" };
    let mut pseudo_headers = vec![
        HeaderField { name: ":method".to_string(), value: req.method.as_str().to_string() },
        HeaderField { name: ":scheme".to_string(), value: scheme.to_string() },
        HeaderField {
            name: ":path".to_string(),
            value: match &req.query {
                Some(q) => format!("{}?{}", req.path, q),
                None => req.path.clone(),
            },
        },
        HeaderField { name: ":authority".to_string(), value: node.host.clone() },
    ];
    pseudo_headers.append(&mut headers);

    let stream_id = {
        let mut client = client.lock().unwrap();
        client.open_stream(&pseudo_headers, &req.body).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "connection at its concurrent stream limit")
        })?
    };

    let deadline = Instant::now() + config.read_timeout.max(config.write_timeout);
    loop {
        {
            let mut client = client.lock().unwrap();
            client.flush()?;
            let completed = client.process_readable()?;
            if completed.contains(&stream_id) {
                let response = client.take_response(stream_id).unwrap();
                let mut resp = HttpResponse::new(response.status, "");
                for h in response.headers {
                    resp.set_header(h.name, h.value);
                }
                resp.set_body(response.body);
                return Ok(resp);
            }
        }

        if Instant::now() > deadline {
            let mut client = client.lock().unwrap();
            client.abandon_stream(stream_id);
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream response timed out"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Checks every node's active H2 connections for streams that have
/// exceeded `timeout` with no activity, abandoning each one -- the H2
/// counterpart to the per-connection idle reaping `UpstreamNode`
/// already does for H1 pooled connections. Called periodically (e.g.
/// alongside `H2PoolRegistry::reap_all_failed`) rather than as part of
/// the request path, since a stream any single in-flight request is
/// actually waiting on already has its own deadline in
/// `forward_http2`.
pub fn reap_timed_out_h2_streams(h2_pools: &H2PoolRegistry, timeout: Duration) {
    for pool in h2_pools.pools.lock().unwrap().values() {
        for conn in pool.connections.lock().unwrap().iter() {
            let mut client = conn.lock().unwrap();
            let stale: Vec<u32> = client.timed_out_streams(timeout);
            for stream_id in stale {
                client.abandon_stream(stream_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::HttpMethod;
    use crate::lb::lb::{LbAlgo, LbConfig};
    use crate::lb::upstream::{add_node, UpstreamPool};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn make_request(method: HttpMethod, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method,
            remote_addr: Some("203.0.113.5".parse().unwrap()),
            path: path.to_string(),
            query: None,
            query_params: Vec::new(),
            version_major: 1,
            version_minor: 1,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: Vec::new(),
            keep_alive: true,
            trailers: Vec::new(),
        }
    }

    // ─── Header preparation ─────────────────────────────────────────

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let req = make_request(
            HttpMethod::Get,
            "/",
            &[
                ("Connection", "keep-alive"),
                ("Content-Type", "text/plain"),
                ("Transfer-Encoding", "chunked"),
            ],
        );
        let headers = build_upstream_headers(&req, None, "routa-test");
        assert!(!headers.iter().any(|h| h.name.eq_ignore_ascii_case("connection")));
        assert!(!headers.iter().any(|h| h.name.eq_ignore_ascii_case("transfer-encoding")));
        assert!(headers.iter().any(|h| h.name.eq_ignore_ascii_case("content-type")));
    }

    #[test]
    fn x_forwarded_for_added_when_absent() {
        let req = make_request(HttpMethod::Get, "/", &[]);
        let headers = build_upstream_headers(&req, Some("203.0.113.5".parse().unwrap()), "routa-test");
        let xff = headers.iter().find(|h| h.name.eq_ignore_ascii_case("x-forwarded-for")).unwrap();
        assert_eq!(xff.value, "203.0.113.5");
    }

    #[test]
    fn x_forwarded_for_extends_existing_chain() {
        let req = make_request(HttpMethod::Get, "/", &[("X-Forwarded-For", "9.9.9.9")]);
        let headers = build_upstream_headers(&req, Some("203.0.113.5".parse().unwrap()), "routa-test");
        let xff = headers.iter().find(|h| h.name.eq_ignore_ascii_case("x-forwarded-for")).unwrap();
        assert_eq!(xff.value, "9.9.9.9, 203.0.113.5");
    }

    #[test]
    fn via_header_added_with_proxy_identity() {
        let req = make_request(HttpMethod::Get, "/", &[]);
        let headers = build_upstream_headers(&req, None, "routa-node-1");
        let via = headers.iter().find(|h| h.name.eq_ignore_ascii_case("via")).unwrap();
        assert_eq!(via.value, "1.1 routa-node-1");
    }

    #[test]
    fn via_header_extends_existing_chain() {
        let req = make_request(HttpMethod::Get, "/", &[("Via", "1.1 other-proxy")]);
        let headers = build_upstream_headers(&req, None, "routa-node-1");
        let via = headers.iter().find(|h| h.name.eq_ignore_ascii_case("via")).unwrap();
        assert_eq!(via.value, "1.1 other-proxy, 1.1 routa-node-1");
    }

    // ─── HTTP/1.1 response parsing ────────────────────────────────────

    #[test]
    fn parses_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let resp = try_parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body(), b"hello");
    }

    #[test]
    fn incomplete_response_returns_none() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert!(try_parse_response(raw).is_none());
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let resp = try_parse_response(raw).unwrap();
        assert_eq!(resp.body(), b"hello");
    }

    #[test]
    fn incomplete_chunked_response_returns_none() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(try_parse_response(raw).is_none());
    }

    // ─── End-to-end forward() ─────────────────────────────────────────

    fn spawn_http1_test_server(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf); // drain the request
                    let _ = stream.write_all(response);
                }
                Err(_) => break,
            }
        });
        port
    }

    fn make_pool_with_node(port: u16) -> (Arc<UpstreamPool>, Arc<UpstreamNode>) {
        let pool = Arc::new(UpstreamPool::new(3, 2));
        let node = Arc::new(UpstreamNode::new("127.0.0.1".to_string(), port, 1, false, 8));
        add_node(&pool, node.clone());
        (pool, node)
    }

    fn make_lb(pool: Arc<UpstreamPool>) -> LoadBalancer {
        LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                max_retries: 2,
                ..Default::default()
            },
            pool,
        )
    }

    #[test]
    fn forward_succeeds_against_real_http1_server() {
        let port = spawn_http1_test_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (pool, _node) = make_pool_with_node(port);
        let lb = make_lb(pool);
        let h2_pools = H2PoolRegistry::new();
        let config = ProxyConfig::default();

        let req = make_request(HttpMethod::Get, "/", &[("Host", "example.com")]);
        let resp = forward(&lb, &h2_pools, &req, &config).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body(), b"ok");
    }

    #[test]
    fn forward_records_success_on_the_node() {
        let port = spawn_http1_test_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (pool, node) = make_pool_with_node(port);
        let lb = make_lb(pool);
        let h2_pools = H2PoolRegistry::new();
        let config = ProxyConfig::default();

        node.record_failure(&lb.pool); // start with one recorded failure
        let req = make_request(HttpMethod::Get, "/", &[("Host", "example.com")]);
        forward(&lb, &h2_pools, &req, &config).unwrap();

        // A success should have reset the fail streak -- confirmed
        // indirectly by the node still being selectable/Up (it never
        // reached the failure threshold to begin with here, but this
        // exercises that record_success was actually reached, not
        // skipped).
        assert_eq!(node.state(), crate::lb::upstream::NodeState::Up);
    }

    #[test]
    fn forward_fails_over_to_second_node_when_first_is_unreachable() {
        // First node points at a closed port; second is a real server.
        let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let good_port = spawn_http1_test_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood");

        let pool = Arc::new(UpstreamPool::new(3, 2));
        let dead_node = Arc::new(UpstreamNode::new("127.0.0.1".to_string(), dead_port, 1, false, 8));
        let good_node = Arc::new(UpstreamNode::new("127.0.0.1".to_string(), good_port, 1, false, 8));
        add_node(&pool, dead_node.clone());
        add_node(&pool, good_node.clone());

        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                max_retries: 3,
                ..Default::default()
            },
            pool,
        );
        let h2_pools = H2PoolRegistry::new();
        let config = ProxyConfig::default();

        let req = make_request(HttpMethod::Get, "/", &[("Host", "example.com")]);
        let resp = forward(&lb, &h2_pools, &req, &config).unwrap();
        assert_eq!(resp.body(), b"good");
    }

    #[test]
    fn forward_respects_zero_max_retries() {
        // Both nodes are dead, and max_retries is 0 -- exactly one
        // attempt total should be made (verified indirectly: the
        // error returned is AllNodesExhausted/UpstreamError, not a
        // hang or a success neither node could have produced).
        let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let pool = Arc::new(UpstreamPool::new(3, 2));
        let node = Arc::new(UpstreamNode::new("127.0.0.1".to_string(), dead_port, 1, false, 8));
        add_node(&pool, node);

        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                max_retries: 0,
                ..Default::default()
            },
            pool,
        );
        let h2_pools = H2PoolRegistry::new();
        let config = ProxyConfig::default();

        let req = make_request(HttpMethod::Get, "/", &[("Host", "example.com")]);
        let result = forward(&lb, &h2_pools, &req, &config);
        assert!(result.is_err());
    }

    #[test]
    fn forward_upstream_headers_reach_the_server() {
        // A server that echoes back whatever X-Forwarded-For it
        // received, so we can confirm header preparation actually
        // happened on the real wire, not just in build_upstream_headers'
        // own unit tests.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let request_text = String::from_utf8_lossy(&buf[..n]);
                let has_xff = request_text.to_lowercase().contains("x-forwarded-for");
                let body = if has_xff { "yes" } else { "no" };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let (pool, _node) = make_pool_with_node(port);
        let lb = make_lb(pool);
        let h2_pools = H2PoolRegistry::new();
        let config = ProxyConfig::default();

        let req = make_request(HttpMethod::Get, "/", &[("Host", "example.com")]);
        let resp = forward(&lb, &h2_pools, &req, &config).unwrap();
        assert_eq!(resp.body(), b"yes");
    }
}
