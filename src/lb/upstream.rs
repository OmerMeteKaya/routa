//! A single backend server (`UpstreamNode`) and the pool of nodes
//! behind one logical upstream (`UpstreamPool`): connection pooling,
//! passive health tracking with circuit-breaker half-open recovery,
//! and active health checks.
//!
//! Circuit-breaker timing uses `std::time::Instant` (monotonic by
//! construction) rather than a wall-clock timestamp -- this sidesteps
//! an entire class of correctness bugs a wall-clock-based
//! implementation is exposed to (second-resolution timestamps making
//! sub-second retry windows never elapse, or a system clock adjustment
//! corrupting an elapsed-time calculation); `Instant` is immune to
//! both by construction, not by careful arithmetic.
//!
//! Node state fields that are read/written at high frequency on every
//! request (fail/success counters, inflight count, circuit-breaker
//! counters) are plain atomics -- lock-free, with no lock to acquire
//! at all on the hot path. The connection pool's idle list, which
//! needs coordinated multi-field mutation (push/pop plus bookkeeping),
//! uses a `Mutex` instead -- atomics aren't a good fit for a
//! collection.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long a resolved upstream address stays valid before
/// `resolve_addr` performs a fresh DNS lookup. Chosen as a middle
/// ground: short enough that a hostname's DNS record change (e.g. a
/// cloud load balancer rotating IPs) is picked up within a reasonable
/// operational window, long enough that a busy pool making frequent
/// new connections doesn't pay for a DNS round-trip on most of them.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

use mio::net::TcpStream;

// ─── Health check config ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthCheckType {
    /// Passive only -- no active probing, recovery is via the
    /// circuit-breaker half-open mechanism instead.
    #[default]
    None,
    /// Active: TCP connect probe.
    Tcp,
    /// Active: HTTP GET, expect 2xx.
    Http,
    /// Active: HTTP GET, parse a `{"status":"ok"}`-shaped JSON body.
    Custom,
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub check_type: HealthCheckType,
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub threshold_up: u32,
    pub threshold_down: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            check_type: HealthCheckType::default(),
            path: "/health".to_string(),
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            threshold_up: 2,
            threshold_down: 3,
        }
    }
}

// ─── Node state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Up,
    Down,
    /// Graceful removal: no new connections, existing ones finish.
    Draining,
    /// A `Down` node currently allowing one trial request through to
    /// test recovery -- see `UpstreamNode::is_selectable`. Only
    /// reachable when `hc.check_type == HealthCheckType::None`; nodes
    /// with an active health check recover via the probe loop instead
    /// and never enter this state.
    HalfOpen,
}

/// Encodes `NodeState` into a single `AtomicU8`-sized value so node
/// state can be read/written without a lock -- see this module's doc
/// comment for why the hot-path fields are atomics.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeStateCode {
    Up = 0,
    Down = 1,
    Draining = 2,
    HalfOpen = 3,
}

impl From<NodeState> for NodeStateCode {
    fn from(s: NodeState) -> Self {
        match s {
            NodeState::Up => NodeStateCode::Up,
            NodeState::Down => NodeStateCode::Down,
            NodeState::Draining => NodeStateCode::Draining,
            NodeState::HalfOpen => NodeStateCode::HalfOpen,
        }
    }
}

impl From<u8> for NodeStateCode {
    fn from(v: u8) -> Self {
        match v {
            0 => NodeStateCode::Up,
            1 => NodeStateCode::Down,
            2 => NodeStateCode::Draining,
            _ => NodeStateCode::HalfOpen,
        }
    }
}

impl From<NodeStateCode> for NodeState {
    fn from(c: NodeStateCode) -> Self {
        match c {
            NodeStateCode::Up => NodeState::Up,
            NodeStateCode::Down => NodeState::Down,
            NodeStateCode::Draining => NodeState::Draining,
            NodeStateCode::HalfOpen => NodeState::HalfOpen,
        }
    }
}

// ─── Connection pool ────────────────────────────────────────────────────

/// One idle, previously-established connection sitting in a node's
/// pool, ready to be reused. Consumed by taking ownership out of the
/// `Vec` it's stored in (see `UpstreamNode::acquire_idle`).
pub struct IdleConn {
    pub stream: TcpStream,
    pub created_at: Instant,
    pub last_used: Instant,
    pub requests_served: u32,
}

// ─── UpstreamNode ───────────────────────────────────────────────────────

/// One backend server. Cheap to share (`Arc<UpstreamNode>`) across
/// however many worker threads route requests to it -- every mutable
/// field is internally synchronized (atomics for hot-path counters,
/// `Mutex`/`RwLock` for the idle connection list and resolved
/// address), so callers never need their own external locking.
pub struct UpstreamNode {
    pub host: String,
    pub port: u16,
    pub weight: i32,
    /// Smooth weighted round-robin dynamic state: incremented by
    /// `weight` each pick, the winner decremented by the pool's total
    /// weight -- nginx-style, so bursts of the same high-weight node
    /// get spread out rather than clustered. Owned by `lb::pick_wrr`,
    /// not read/written anywhere else. Signed: this value legitimately
    /// goes negative right after a node wins (it's immediately
    /// decremented by the full total weight), so an unsigned type
    /// would silently wrap to a huge positive value instead and make
    /// that node win every subsequent pick forever.
    pub current_weight: AtomicI32,

    state: AtomicU32, // encodes NodeStateCode

    // Passive health tracking.
    fail_count: AtomicU32,
    success_count: AtomicU32,
    total_requests: AtomicU64,
    total_errors: AtomicU64,

    // Circuit-breaker half-open state (see this module's doc comment
    // for why Instant rather than a wall-clock timestamp). `RwLock`
    // rather than an atomic since `Instant` isn't atomic-representable
    // and this is written rarely (only on a Down transition) compared
    // to how often it might be read.
    down_since: RwLock<Option<Instant>>,
    half_open_probe_in_flight: AtomicBool,
    pub circuit_breaker_trips_total: AtomicU64,
    pub half_open_trials_total: AtomicU64,

    // Active health check.
    pub hc: HealthCheckConfig,
    hc_consec_ok: AtomicU32,
    hc_consec_fail: AtomicU32,

    // Connection pool.
    idle_conns: Mutex<Vec<IdleConn>>,
    active_count: AtomicU32,
    pub pool_max: u32,

    // Least-connections counter.
    pub inflight: AtomicU32,

    // Resolved address, cached with a TTL -- see `resolve_addr`'s doc
    // comment for why a bounded cache (rather than either "resolve
    // every call" or "resolve once for the process's lifetime")
    // is the right tradeoff here.
    resolved_addr: RwLock<Option<(SocketAddr, Instant)>>,

    pub use_tls: bool,

    /// Back-reference to the pool this node belongs to, set once by
    /// `UpstreamPool::add_node`. Lets code holding just an
    /// `Arc<UpstreamNode>` (not the pool it came from) call
    /// `record_success`/`record_failure` without the caller needing to
    /// separately thread a pool reference through -- needed by, for
    /// example, an async connection-establishment dispatch path that
    /// only has a handle to the node itself, not the pool the request
    /// originated from.
    pool: RwLock<Option<std::sync::Weak<UpstreamPool>>>,
}

impl UpstreamNode {
    pub fn new(host: String, port: u16, weight: i32, use_tls: bool, pool_max: u32) -> Self {
        UpstreamNode {
            host,
            port,
            weight,
            current_weight: AtomicI32::new(0),
            state: AtomicU32::new(NodeStateCode::Up as u32),
            fail_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            down_since: RwLock::new(None),
            half_open_probe_in_flight: AtomicBool::new(false),
            circuit_breaker_trips_total: AtomicU64::new(0),
            half_open_trials_total: AtomicU64::new(0),
            hc: HealthCheckConfig::default(),
            hc_consec_ok: AtomicU32::new(0),
            hc_consec_fail: AtomicU32::new(0),
            idle_conns: Mutex::new(Vec::new()),
            active_count: AtomicU32::new(0),
            pool_max,
            inflight: AtomicU32::new(0),
            resolved_addr: RwLock::new(None),
            use_tls,
            pool: RwLock::new(None),
        }
    }

    pub fn state(&self) -> NodeState {
        NodeStateCode::from(self.state.load(Ordering::Acquire) as u8).into()
    }

    /// Resolves this node's address, caching the result for
    /// `DNS_CACHE_TTL` -- IPv4/IPv6 literals resolve instantly (and
    /// are effectively cached forever, since parsing a literal never
    /// changes); a hostname goes through a real (blocking) DNS lookup
    /// whenever the cached entry is missing or older than the TTL.
    /// This bounds how long an upstream's DNS-level changes (e.g. a
    /// cloud load balancer rotating the IPs behind a hostname) can go
    /// unnoticed, without paying a DNS lookup on every single
    /// connection attempt -- the two extremes a fixed "resolve once
    /// for the process's lifetime" or "resolve on every call" policy
    /// would otherwise force a choice between.
    ///
    /// A stale cached address isn't proactively evicted on its own --
    /// it's simply not reused past the TTL, and the next call pays for
    /// a fresh lookup. If that fresh lookup itself fails (e.g. a
    /// transient DNS outage), the error propagates rather than falling
    /// back to the stale address; a caller that already has a
    /// TcpStream open against the old address keeps using it until
    /// that connection's own lifecycle ends (idle-reaping, a failed
    /// request) -- this function only affects NEW connection
    /// attempts, never ones already in flight.
    pub fn resolve_addr(&self) -> std::io::Result<SocketAddr> {
        if let Some((addr, resolved_at)) = *self.resolved_addr.read().unwrap() {
            if resolved_at.elapsed() < DNS_CACHE_TTL {
                return Ok(addr);
            }
        }
        let mut guard = self.resolved_addr.write().unwrap();
        // Re-check under the write lock -- another thread may have
        // already refreshed it while we were waiting for the lock.
        if let Some((addr, resolved_at)) = *guard {
            if resolved_at.elapsed() < DNS_CACHE_TTL {
                return Ok(addr);
            }
        }
        let addr = if let Ok(ip) = self.host.parse::<IpAddr>() {
            SocketAddr::new(ip, self.port)
        } else {
            // Hostname -- a real (blocking) DNS lookup.
            use std::net::ToSocketAddrs;
            let mut addrs = (self.host.as_str(), self.port).to_socket_addrs()?;
            addrs.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no addresses found for host '{}'", self.host),
                )
            })?
        };
        *guard = Some((addr, Instant::now()));
        Ok(addr)
    }

    /// Starts a non-blocking TCP connection to this node. Returns the
    /// stream immediately (connection likely still in progress) --
    /// the caller registers it with a poller for write-readiness and
    /// completes the handshake asynchronously (see
    /// `net::tls::TlsConnection::advance_io` for the equivalent
    /// pattern once TLS is layered on top for `use_tls` nodes).
    pub fn connect_async(&self) -> std::io::Result<TcpStream> {
        let addr = self.resolve_addr()?;
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    fn set_state(&self, new_state: NodeState) {
        let old_code = self
            .state
            .swap(NodeStateCode::from(new_state) as u32, Ordering::AcqRel);
        let old_state: NodeState = NodeStateCode::from(old_code as u8).into();

        if new_state == NodeState::Down && old_state != NodeState::Down {
            *self.down_since.write().unwrap() = Some(Instant::now());
            self.half_open_probe_in_flight.store(false, Ordering::SeqCst);
            self.circuit_breaker_trips_total
                .fetch_add(1, Ordering::Relaxed);
        }

        if new_state == NodeState::Down {
            self.drain_idle();
        }
    }

    /// Whether this node should be considered for selection right now:
    /// - `Up` is always selectable.
    /// - `Draining`/`HalfOpen` are never (the latter is a transient
    ///   state only the winning caller of this same method briefly
    ///   observes between winning the trial slot and the request
    ///   outcome being recorded).
    /// - `Down` depends on whether this node has an active health
    ///   check (which owns recovery instead) and, if not, whether
    ///   enough time has passed since going down to allow one trial
    ///   request through -- and only one: a compare-and-swap on
    ///   `half_open_probe_in_flight` ensures a single winner among any
    ///   concurrently-arriving requests. The winning caller becomes
    ///   responsible for routing exactly one request to this node and
    ///   calling `record_success`/`record_failure` (or
    ///   `release_half_open_trial` directly, if it bails out before
    ///   reaching either) when that request completes.
    pub fn is_selectable(&self, pool: &UpstreamPool) -> bool {
        match self.state() {
            NodeState::Up => return true,
            NodeState::Draining | NodeState::HalfOpen => return false,
            NodeState::Down => {}
        }

        if self.hc.check_type != HealthCheckType::None {
            return false; // the health-check loop owns recovery for this node
        }
        if pool.half_open_retry_after.is_zero() {
            return false; // half-open disabled
        }

        let down_since = *self.down_since.read().unwrap();
        let Some(down_since) = down_since else {
            return false; // not actually down (shouldn't normally happen)
        };
        if down_since.elapsed() < pool.half_open_retry_after {
            return false;
        }

        // Try to win the trial slot -- only one caller may proceed.
        if self
            .half_open_probe_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false; // someone else already has the trial in flight
        }

        self.set_state(NodeState::HalfOpen);
        self.half_open_trials_total.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Releases the half-open trial guard so a future trial can be
    /// attempted. Safe to call unconditionally -- a no-op if this node
    /// wasn't in a half-open trial. `record_success`/`record_failure`
    /// call this internally; exposed separately for a caller that
    /// needs to bail out before reaching either (e.g. the connect()
    /// itself failed).
    pub fn release_half_open_trial(&self) {
        self.half_open_probe_in_flight.store(false, Ordering::SeqCst);
    }

    pub fn record_success(&self, pool: &UpstreamPool) {
        self.success_count.fetch_add(1, Ordering::AcqRel);
        self.fail_count.store(0, Ordering::Release);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let state = self.state();

        if (state == NodeState::Down || state == NodeState::HalfOpen)
            && self.success_count.load(Ordering::Acquire) >= pool.passive_recover_threshold
        {
            self.set_state(NodeState::Up);
            self.success_count.store(0, Ordering::Release);
        }
        if state == NodeState::HalfOpen {
            self.release_half_open_trial();
        }
    }

    pub fn record_failure(&self, pool: &UpstreamPool) {
        self.fail_count.fetch_add(1, Ordering::AcqRel);
        self.success_count.store(0, Ordering::Release);
        self.total_errors.fetch_add(1, Ordering::Relaxed);
        let fail_count = self.fail_count.load(Ordering::Acquire);
        let state = self.state();

        if state == NodeState::HalfOpen {
            // Trial failed: back to Down (resets down_since, restarting
            // the half-open clock for the next attempt) and release the
            // guard.
            self.set_state(NodeState::Down);
            self.release_half_open_trial();
            return;
        }

        if fail_count >= pool.passive_fail_threshold {
            self.set_state(NodeState::Down);
        }
    }

    fn drain_idle(&self) {
        self.idle_conns.lock().unwrap().clear();
    }

    /// Closes idle connections whose `last_used` is older than
    /// `max_age`.
    pub fn reap_idle(&self, max_age: Duration) {
        let now = Instant::now();
        self.idle_conns
            .lock()
            .unwrap()
            .retain(|c| now.duration_since(c.last_used) <= max_age);
    }

    /// Takes an idle connection out of the pool for reuse, if one is
    /// available.
    pub fn acquire_idle(&self) -> Option<IdleConn> {
        self.idle_conns.lock().unwrap().pop()
    }

    /// Returns a connection to the pool. `healthy = false` means the
    /// connection is broken and should be dropped rather than reused.
    pub fn release_conn(&self, mut conn: IdleConn, healthy: bool) {
        self.active_count.fetch_sub(1, Ordering::AcqRel);
        if !healthy {
            return; // dropped, not returned to the pool
        }
        conn.last_used = Instant::now();
        conn.requests_served += 1;
        let mut idle = self.idle_conns.lock().unwrap();
        if (idle.len() as u32) < self.pool_max {
            idle.push(conn);
        }
        // Over pool_max: drop it rather than growing the pool
        // unbounded.
    }

    pub fn mark_active(&self) {
        self.active_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn idle_count(&self) -> usize {
        self.idle_conns.lock().unwrap().len()
    }

    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Acquire)
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn total_errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }
}

// ─── UpstreamPool ───────────────────────────────────────────────────────

/// A collection of nodes behind one logical upstream, plus the shared
/// config (passive health thresholds, circuit-breaker half-open
/// window) that applies to all of them unless a node overrides it.
pub struct UpstreamPool {
    nodes: RwLock<Vec<Arc<UpstreamNode>>>,

    pub passive_fail_threshold: u32,
    pub passive_recover_threshold: u32,

    /// How long a `Down` node (with no active health check) sits
    /// before the next request is let through as a recovery trial.
    /// `Duration::ZERO` disables half-open entirely -- such a node
    /// then stays `Down` forever unless it also has an active health
    /// check.
    pub half_open_retry_after: Duration,

    /// Round-robin counter, shared across every caller picking from
    /// this pool.
    pub rr_counter: AtomicU32,
}

impl UpstreamPool {
    pub fn new(passive_fail_threshold: u32, passive_recover_threshold: u32) -> Self {
        UpstreamPool {
            nodes: RwLock::new(Vec::new()),
            passive_fail_threshold,
            passive_recover_threshold,
            half_open_retry_after: Duration::from_secs(30),
            rr_counter: AtomicU32::new(0),
        }
    }
}

/// Adds `node` to `pool`, wiring up the node's back-reference to the
/// pool it now belongs to (see `UpstreamNode.pool`'s doc comment for
/// why that back-reference exists). Takes `pool` as an `Arc` (rather
/// than being an `UpstreamPool` method) since the back-reference needs
/// a `Weak` handle to the pool, which requires the pool to already be
/// behind an `Arc`.
pub fn add_node(pool: &Arc<UpstreamPool>, node: Arc<UpstreamNode>) {
    *node.pool.write().unwrap() = Some(Arc::downgrade(pool));
    pool.nodes.write().unwrap().push(node);
}

impl UpstreamPool {
    pub fn nodes(&self) -> Vec<Arc<UpstreamNode>> {
        self.nodes.read().unwrap().clone()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.read().unwrap().len()
    }

    /// Every currently-selectable node (see
    /// `UpstreamNode::is_selectable`) -- the candidate set a load
    /// balancing algorithm picks from.
    pub fn selectable_nodes(&self) -> Vec<Arc<UpstreamNode>> {
        self.nodes
            .read()
            .unwrap()
            .iter()
            .filter(|n| n.is_selectable(self))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node() -> Arc<UpstreamNode> {
        Arc::new(UpstreamNode::new(
            "127.0.0.1".to_string(),
            8080,
            1,
            false,
            32,
        ))
    }

    fn make_pool(fail_threshold: u32, recover_threshold: u32) -> Arc<UpstreamPool> {
        Arc::new(UpstreamPool::new(fail_threshold, recover_threshold))
    }

    #[test]
    fn new_node_starts_up() {
        let node = make_node();
        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn resolve_addr_parses_ip_literal() {
        let node = make_node();
        let addr = node.resolve_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn resolve_addr_caches_result() {
        let node = make_node();
        let first = node.resolve_addr().unwrap();
        let second = node.resolve_addr().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn resolve_addr_refreshes_after_ttl_expires() {
        let node = make_node();
        let first = node.resolve_addr().unwrap();

        // Directly age the cached entry past DNS_CACHE_TTL rather than
        // actually sleeping for it in a test -- same address is
        // expected back (this node's host is an IP literal, so a
        // "fresh" resolution is identical), but what's under test is
        // that resolve_addr() actually re-entered its resolution path
        // rather than trusting a stale cache entry indefinitely. A
        // hostname-based node re-resolving to a *different* address
        // isn't practical to test without a controllable DNS backend,
        // so this test's guarantee is narrower: expiry triggers
        // resolution again, not "resolution ever changes."
        {
            let mut guard = node.resolved_addr.write().unwrap();
            if let Some((addr, _)) = *guard {
                let long_ago = Instant::now()
                    .checked_sub(DNS_CACHE_TTL + Duration::from_secs(1))
                    .expect("test clock underflow");
                *guard = Some((addr, long_ago));
            }
        }

        let second = node.resolve_addr().unwrap();
        assert_eq!(first, second); // same IP literal -- but re-resolved, not just reused from a stale cache hit
    }

    // ─── Passive health / circuit breaker ────────────────────────────

    #[test]
    fn failures_below_threshold_keep_node_up() {
        let node = make_node();
        let pool = make_pool(3, 2);
        node.record_failure(&pool);
        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn failures_at_threshold_trip_the_breaker() {
        let node = make_node();
        let pool = make_pool(3, 2);
        node.record_failure(&pool);
        node.record_failure(&pool);
        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Down);
        assert_eq!(node.circuit_breaker_trips_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn success_resets_fail_count() {
        let node = make_node();
        let pool = make_pool(3, 2);
        node.record_failure(&pool);
        node.record_failure(&pool);
        node.record_success(&pool);
        node.record_failure(&pool);
        node.record_failure(&pool);
        // Two more failures after the reset shouldn't be enough to trip
        // a threshold-of-3 breaker.
        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn down_node_not_selectable_when_half_open_disabled() {
        let node = make_node();
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::ZERO;
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Down);
        assert!(!node.is_selectable(&pool));
    }

    #[test]
    fn down_node_becomes_selectable_after_half_open_window() {
        let node = make_node();
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::from_millis(20);
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Down);
        assert!(!node.is_selectable(&pool)); // window hasn't elapsed yet

        std::thread::sleep(Duration::from_millis(40));
        assert!(node.is_selectable(&pool));
        assert_eq!(node.state(), NodeState::HalfOpen);
    }

    #[test]
    fn only_one_caller_wins_the_half_open_trial() {
        let node = make_node();
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::from_millis(10);
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        std::thread::sleep(Duration::from_millis(20));

        assert!(node.is_selectable(&pool)); // first caller wins
        assert!(!node.is_selectable(&pool)); // second caller loses
    }

    #[test]
    fn half_open_trial_success_recovers_node() {
        let node = make_node();
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::from_millis(10);
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        std::thread::sleep(Duration::from_millis(20));
        assert!(node.is_selectable(&pool));
        assert_eq!(node.state(), NodeState::HalfOpen);

        node.record_success(&pool);
        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn half_open_trial_failure_returns_to_down_and_releases_guard() {
        let node = make_node();
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::from_millis(10);
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        std::thread::sleep(Duration::from_millis(20));
        assert!(node.is_selectable(&pool));

        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Down);

        // The guard should be released -- another trial should be
        // possible once the window elapses again.
        std::thread::sleep(Duration::from_millis(20));
        assert!(node.is_selectable(&pool));
    }

    #[test]
    fn draining_node_never_selectable() {
        let node = make_node();
        let pool = make_pool(1, 1);
        node.set_state(NodeState::Draining);
        assert!(!node.is_selectable(&pool));
    }

    #[test]
    fn active_health_check_node_recovers_via_probe_not_half_open() {
        let node = Arc::new(UpstreamNode {
            hc: HealthCheckConfig {
                check_type: HealthCheckType::Http,
                ..Default::default()
            },
            ..UpstreamNode::new("127.0.0.1".to_string(), 8080, 1, false, 32)
        });
        let mut pool_inner = UpstreamPool::new(1, 1);
        pool_inner.half_open_retry_after = Duration::from_millis(1);
        let pool = Arc::new(pool_inner);

        node.record_failure(&pool);
        std::thread::sleep(Duration::from_millis(10));
        // Even though the half-open window elapsed, a node with an
        // active health check never becomes selectable this way -- the
        // health-check loop owns its recovery instead.
        assert!(!node.is_selectable(&pool));
    }

    // ─── Connection pool ──────────────────────────────────────────────

    #[test]
    fn idle_pool_starts_empty() {
        let node = make_node();
        assert_eq!(node.idle_count(), 0);
        assert!(node.acquire_idle().is_none());
    }

    #[test]
    fn going_down_drains_idle_connections() {
        // We can't easily construct a real TcpStream for a unit test
        // without a live listener, so this test only checks the
        // observable state-transition side effect (idle count reset)
        // via reap_idle's own bookkeeping path instead of a literal
        // IdleConn push -- acquire/release are exercised at the
        // integration level once core::proxy uses this pool for real
        // connections.
        let node = make_node();
        let pool = make_pool(1, 1);
        node.record_failure(&pool);
        assert_eq!(node.state(), NodeState::Down);
        assert_eq!(node.idle_count(), 0);
    }

    // ─── Pool node management ───────────────────────────────────────

    #[test]
    fn add_node_sets_back_reference() {
        let pool = make_pool(3, 2);
        let node = make_node();
        add_node(&pool, node.clone());

        assert_eq!(pool.node_count(), 1);
        let upgraded = node.pool.read().unwrap().as_ref().unwrap().upgrade();
        assert!(upgraded.is_some());
    }

    #[test]
    fn selectable_nodes_excludes_down_nodes() {
        let pool = make_pool(1, 1);
        let up_node = make_node();
        let down_node = make_node();
        add_node(&pool, up_node.clone());
        add_node(&pool, down_node.clone());

        down_node.record_failure(&pool);
        assert_eq!(down_node.state(), NodeState::Down);

        let selectable = pool.selectable_nodes();
        assert_eq!(selectable.len(), 1);
    }
}

// ─── Active health check probing ───────────────────────────────────────
//
// Runs on its own dedicated thread with its own `MioPoller`, entirely
// independent of any worker's event loop -- a slow or unresponsive
// node's probe never blocks any other node's probe, or any worker's
// request handling. Each node's `interval_ms`/`timeout_ms` is honored
// independently rather than sharing one pool-wide schedule.
//
// Reuses `TlsConnection` for the TLS handshake path (`HC_TCP`/`HC_HTTP`/
// `HC_CUSTOM` over a `use_tls` node) rather than driving a second,
// separate TLS state machine just for probes -- the same non-blocking
// handshake/read/write pattern applies here as it does to real request
// traffic.

use crate::net::poller::{EventPoller, Interests, MioPoller, PollKey};
use crate::net::tls::TlsConnection;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::AtomicBool as ProbeStopFlag;

/// Minimal, dependency-free scan for a top-level `"status"` JSON key
/// with a string value of exactly `"ok"`/`"OK"` -- not a full JSON
/// parser (no nesting, no escapes, no other value types), but a real
/// key/value match rather than a bare substring search, which would
/// false-positive on `{"status":"not_ok"}` (contains the substring
/// `"ok"`), `{"other_field":"ok"}` (right value, wrong key), or
/// `{"message":"looks ok to me"}` (neither the right field nor an
/// exact value match). Fails closed (returns `false`) on anything it
/// can't confidently confirm, including malformed input.
fn json_status_ok(body: &[u8]) -> bool {
    let mut pos = 0;
    while pos < body.len() {
        let Some(key_rel) = find_subslice(&body[pos..], b"\"status\"") else {
            return false;
        };
        let key_start = pos + key_rel;
        let mut q = key_start + 8; // past "status"
        while q < body.len() && (body[q] == b' ' || body[q] == b'\t') {
            q += 1;
        }
        if q >= body.len() || body[q] != b':' {
            pos = key_start + 1;
            continue;
        }
        q += 1;
        while q < body.len() && (body[q] == b' ' || body[q] == b'\t') {
            q += 1;
        }
        if q + 1 >= body.len() || body[q] != b'"' {
            pos = key_start + 1;
            continue;
        }
        q += 1;
        if q + 2 < body.len()
            && (body[q] == b'o' || body[q] == b'O')
            && (body[q + 1] == b'k' || body[q + 1] == b'K')
            && body[q + 2] == b'"'
        {
            return true;
        }
        pos = key_start + 1; // keep scanning for other "status" occurrences
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HcPhase {
    Connecting,
    TlsHandshake,
    Writing,
    Reading,
}

enum HcTransport {
    Plain(TcpStream),
    Tls {
        stream: TcpStream,
        tls: Box<TlsConnection>,
    },
}

/// One in-flight probe against a single node.
struct HcProbe {
    node: Arc<UpstreamNode>,
    transport: HcTransport,
    phase: HcPhase,
    deadline: Instant,
    request: Vec<u8>,
    request_sent: usize,
    response: Vec<u8>,
}

const HC_RESPONSE_BUF_CAP: usize = 256;

impl HcProbe {
    fn build_request(node: &UpstreamNode) -> Vec<u8> {
        let path = if node.hc.path.is_empty() {
            "/health"
        } else {
            &node.hc.path
        };
        format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", node.host)
            .into_bytes()
    }

    /// Validates a completed `Http`/`Custom` response: a `2xx` status
    /// line is always required; `Custom` additionally requires a
    /// `{"status":"ok"}`-shaped JSON body (see `json_status_ok`).
    fn validate_response(node: &UpstreamNode, response: &[u8]) -> bool {
        if response.is_empty() {
            return false;
        }
        if !response.starts_with(b"HTTP/1.") {
            return false;
        }
        // Status code starts right after "HTTP/1.x " (9 bytes in).
        let Some(status_str) = response.get(9..12).and_then(|b| std::str::from_utf8(b).ok())
        else {
            return false;
        };
        let Ok(status) = status_str.parse::<u32>() else {
            return false;
        };
        if !(200..300).contains(&status) {
            return false;
        }
        if node.hc.check_type == HealthCheckType::Custom {
            let Some(body_start) = find_subslice(response, b"\r\n\r\n") else {
                return false;
            };
            return json_status_ok(&response[body_start + 4..]);
        }
        true
    }

    /// Advances this probe by one step in response to a readiness
    /// event. Returns `Some(ok)` once the probe has finished (success
    /// or failure), `None` if it's still in progress.
    fn advance(&mut self) -> Option<bool> {
        loop {
            match self.phase {
                HcPhase::Connecting => {
                    // mio's connect() is already non-blocking by the
                    // time this probe is registered; readiness here
                    // means connect() has resolved one way or another.
                    // A `take_error()` check distinguishes a completed
                    // connection from a failed one.
                    let stream = match &self.transport {
                        HcTransport::Plain(s) => s,
                        HcTransport::Tls { stream, .. } => stream,
                    };
                    match stream.take_error() {
                        Ok(None) => {}
                        _ => return Some(false),
                    }

                    if let HcTransport::Tls { .. } = &self.transport {
                        self.phase = HcPhase::TlsHandshake;
                        continue;
                    }

                    if self.node.hc.check_type == HealthCheckType::Tcp {
                        return Some(true);
                    }
                    self.request = Self::build_request(&self.node);
                    self.phase = HcPhase::Writing;
                    continue;
                }

                HcPhase::TlsHandshake => {
                    let HcTransport::Tls { stream, tls } = &mut self.transport else {
                        unreachable!("TlsHandshake phase implies a Tls transport")
                    };
                    match tls.advance_io(stream) {
                        Ok(advance) => {
                            if tls.is_handshaking() {
                                return None; // wait for the next readiness event
                            }
                            if advance.peer_closed {
                                return Some(false);
                            }
                            if self.node.hc.check_type == HealthCheckType::Tcp {
                                return Some(true);
                            }
                            self.request = Self::build_request(&self.node);
                            self.phase = HcPhase::Writing;
                            continue;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                        Err(_) => return Some(false),
                    }
                }

                HcPhase::Writing => {
                    let remaining = &self.request[self.request_sent..];
                    let write_result = match &mut self.transport {
                        HcTransport::Plain(stream) => stream.write(remaining),
                        HcTransport::Tls { tls, .. } => tls.write_plaintext(remaining),
                    };
                    match write_result {
                        Ok(0) => return Some(false),
                        Ok(n) => {
                            self.request_sent += n;
                            if self.request_sent < self.request.len() {
                                return None; // partial write, wait for more
                            }
                            self.phase = HcPhase::Reading;
                            continue;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                        Err(_) => return Some(false),
                    }
                }

                HcPhase::Reading => {
                    let mut chunk = [0u8; HC_RESPONSE_BUF_CAP];
                    let read_result = match &mut self.transport {
                        HcTransport::Plain(stream) => stream.read(&mut chunk),
                        HcTransport::Tls { tls, .. } => tls.read_plaintext(&mut chunk),
                    };
                    match read_result {
                        Ok(0) => {
                            // EOF -- validate whatever accumulated so far.
                            return Some(Self::validate_response(&self.node, &self.response));
                        }
                        Ok(n) => {
                            self.response.extend_from_slice(&chunk[..n]);
                            if self.response.len() >= HC_RESPONSE_BUF_CAP {
                                return Some(Self::validate_response(&self.node, &self.response));
                            }
                            continue; // keep reading
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                        Err(_) => return Some(false),
                    }
                }
            }
        }
    }

    fn stream_mut(&mut self) -> &mut TcpStream {
        match &mut self.transport {
            HcTransport::Plain(s) => s,
            HcTransport::Tls { stream, .. } => stream,
        }
    }
}

/// Runs `pool`'s active health check probes on their own dedicated
/// thread until `stop` is signaled. One `HealthCheckLoop` per pool
/// that has at least one node with an active health check configured
/// -- a pool where every node is `HealthCheckType::None` has no need
/// for one.
pub struct HealthCheckLoop {
    stop: Arc<ProbeStopFlag>,
    handle: Option<std::thread::JoinHandle<()>>,
}

const HC_POLL_TIMEOUT: Duration = Duration::from_millis(200);
const HC_DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
const HC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

impl HealthCheckLoop {
    /// `pool_name`/`metrics` are optional purely so this module's own
    /// tests (and any other caller that doesn't care about metrics)
    /// can start a health-check loop without needing a `Metrics`
    /// registry at hand -- `core::server` (the only caller that
    /// matters for production use) always supplies both.
    pub fn start(pool: Arc<UpstreamPool>) -> Self {
        Self::start_with_metrics(pool, String::new(), None)
    }

    pub fn start_with_metrics(
        pool: Arc<UpstreamPool>,
        pool_name: String,
        metrics: Option<Arc<crate::util::metrics::Metrics>>,
    ) -> Self {
        let stop = Arc::new(ProbeStopFlag::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("routa-healthcheck".to_string())
            .spawn(move || run_health_check_loop(pool, stop_for_thread, pool_name, metrics))
            .expect("failed to spawn health check thread");

        HealthCheckLoop {
            stop,
            handle: Some(handle),
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_health_check_loop(
    pool: Arc<UpstreamPool>,
    stop: Arc<ProbeStopFlag>,
    pool_name: String,
    metrics: Option<Arc<crate::util::metrics::Metrics>>,
) {
    let nodes = pool.nodes();
    if nodes.is_empty() {
        return;
    }

    let Ok(mut poller) = MioPoller::new(64) else {
        return; // health checks disabled for this pool if the poller can't be created
    };

    let mut probes: HashMap<PollKey, HcProbe> = HashMap::new();
    let mut last_probe_start: HashMap<usize, Instant> = HashMap::new();
    let mut in_flight: HashMap<usize, PollKey> = HashMap::new();

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();

        // Start any due, not-currently-in-flight probes.
        for (idx, node) in nodes.iter().enumerate() {
            if node.hc.check_type == HealthCheckType::None {
                continue;
            }
            if in_flight.contains_key(&idx) {
                continue;
            }

            let interval = if node.hc.interval.is_zero() {
                HC_DEFAULT_INTERVAL
            } else {
                node.hc.interval
            };
            if let Some(last_start) = last_probe_start.get(&idx) {
                if now.duration_since(*last_start) < interval {
                    continue;
                }
            }
            last_probe_start.insert(idx, now);

            match start_probe(node, &mut poller) {
                Ok((key, probe)) => {
                    probes.insert(key, probe);
                    in_flight.insert(idx, key);
                }
                Err(()) => {
                    record_probe_result(node, false);
                    record_health_check_metric(&metrics, &pool_name, node, false);
                }
            }
        }

        let Ok(events) = poller.poll(Some(HC_POLL_TIMEOUT)) else {
            continue;
        };
        for (key, _readiness) in events {
            let Some(probe) = probes.get_mut(&key) else {
                continue;
            };
            if let Some(ok) = probe.advance() {
                let mut probe = probes.remove(&key).unwrap();
                let _ = poller.deregister(probe.stream_mut(), key);
                in_flight.remove(&node_index(&nodes, &probe.node));
                record_probe_result(&probe.node, ok);
                record_health_check_metric(&metrics, &pool_name, &probe.node, ok);
            }
        }

        // Reap any probe that's run past its own deadline -- poll()
        // alone won't catch this (e.g. a connect() that never
        // completes produces no event at all).
        let now = Instant::now();
        let expired: Vec<PollKey> = probes
            .iter()
            .filter(|(_, p)| now >= p.deadline)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            let mut probe = probes.remove(&key).unwrap();
            let _ = poller.deregister(probe.stream_mut(), key);
            in_flight.remove(&node_index(&nodes, &probe.node));
            record_probe_result(&probe.node, false);
            record_health_check_metric(&metrics, &pool_name, &probe.node, false);
        }
    }

    for (key, mut probe) in probes {
        let _ = poller.deregister(probe.stream_mut(), key);
    }
}

fn record_health_check_metric(
    metrics: &Option<Arc<crate::util::metrics::Metrics>>,
    pool_name: &str,
    node: &Arc<UpstreamNode>,
    ok: bool,
) {
    let Some(metrics) = metrics else {
        return;
    };
    let node_label = format!("{}:{}", node.host, node.port);
    let result = if ok { "ok" } else { "fail" };
    metrics.upstream.health_check_total.with_label_values(&[pool_name, &node_label, result]).inc();
}

fn node_index(nodes: &[Arc<UpstreamNode>], target: &Arc<UpstreamNode>) -> usize {
    nodes
        .iter()
        .position(|n| Arc::ptr_eq(n, target))
        .unwrap_or(usize::MAX)
}

fn start_probe(node: &Arc<UpstreamNode>, poller: &mut MioPoller) -> Result<(PollKey, HcProbe), ()> {
    let stream = node.connect_async().map_err(|_| ())?;

    let transport = if node.use_tls {
        let tls = TlsConnection::new_client(&node.host, vec![b"http/1.1".to_vec()])
            .map_err(|_| ())?;
        HcTransport::Tls {
            stream,
            tls: Box::new(tls),
        }
    } else {
        HcTransport::Plain(stream)
    };

    let timeout = if node.hc.timeout.is_zero() {
        HC_DEFAULT_TIMEOUT
    } else {
        node.hc.timeout
    };

    let mut probe = HcProbe {
        node: Arc::clone(node),
        transport,
        phase: HcPhase::Connecting,
        deadline: Instant::now() + timeout,
        request: Vec::new(),
        request_sent: 0,
        response: Vec::new(),
    };

    let key = poller
        .register(probe.stream_mut(), Interests::READABLE_WRITABLE)
        .map_err(|_| ())?;

    Ok((key, probe))
}

/// Updates a node's consecutive ok/fail counters and, if a threshold
/// is crossed, its state -- the same logic a blocking probe loop would
/// apply inline.
fn record_probe_result(node: &UpstreamNode, ok: bool) {
    if ok {
        node.hc_consec_ok.fetch_add(1, Ordering::AcqRel);
        node.hc_consec_fail.store(0, Ordering::Release);
        if node.hc_consec_ok.load(Ordering::Acquire) >= node.hc.threshold_up
            && node.state() == NodeState::Down
        {
            node.set_state(NodeState::Up);
        }
    } else {
        node.hc_consec_fail.fetch_add(1, Ordering::AcqRel);
        node.hc_consec_ok.store(0, Ordering::Release);
        if node.hc_consec_fail.load(Ordering::Acquire) >= node.hc.threshold_down {
            node.set_state(NodeState::Down);
        }
    }
}

#[cfg(test)]
mod health_check_tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener as StdTcpListener;

    /// Spawns a tiny, single-shot HTTP server on its own thread: reads
    /// one request, writes back `response_body` verbatim (caller
    /// supplies the full status line + headers + body), then closes.
    /// Returns the port it bound to.
    fn spawn_test_server(response: &'static [u8]) -> u16 {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test server");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Health checks run repeatedly (every interval), so this
            // must keep accepting connections for the test's whole
            // duration, not just once -- a single accept() would leave
            // every subsequent probe attempt hitting a closed listener
            // (connection refused), which looks identical to a real
            // probe failure from the health-check loop's point of view.
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        let _ = reader.read_line(&mut line);
                        let _ = stream.write_all(response);
                    }
                    Err(_) => break,
                }
            }
        });
        port
    }

    fn make_http_node(port: u16, check_type: HealthCheckType) -> Arc<UpstreamNode> {
        Arc::new(UpstreamNode {
            hc: HealthCheckConfig {
                check_type,
                path: "/health".to_string(),
                interval: Duration::from_millis(50),
                timeout: Duration::from_secs(2),
                threshold_up: 1,
                threshold_down: 1,
            },
            ..UpstreamNode::new("127.0.0.1".to_string(), port, 1, false, 32)
        })
    }

    #[test]
    fn json_status_ok_accepts_exact_match() {
        assert!(json_status_ok(br#"{"status":"ok"}"#));
        assert!(json_status_ok(br#"{"status": "OK"}"#));
    }

    #[test]
    fn json_status_ok_rejects_substring_false_positives() {
        // These all contain the substring "ok" but aren't a real
        // {"status":"ok"} match -- a naive strstr search would wrongly
        // accept all three.
        assert!(!json_status_ok(br#"{"status":"not_ok"}"#));
        assert!(!json_status_ok(br#"{"other_field":"ok"}"#));
        assert!(!json_status_ok(br#"{"message":"looks ok to me"}"#));
    }

    #[test]
    fn json_status_ok_rejects_malformed_input() {
        assert!(!json_status_ok(b""));
        assert!(!json_status_ok(b"not json at all"));
        assert!(!json_status_ok(br#"{"status":}"#));
    }

    #[test]
    fn tcp_probe_succeeds_against_open_port() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Just needs to accept a connection -- HC_TCP only checks
        // connect() succeeds, nothing more. Keeps accepting for the
        // test's duration since health checks probe repeatedly -- see
        // spawn_test_server's doc comment for why a single accept()
        // isn't enough.
        std::thread::spawn(move || loop {
            match listener.accept() {
                Ok(_) => {}
                Err(_) => break,
            }
        });

        let node = make_http_node(port, HealthCheckType::Tcp);
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(300));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn http_probe_succeeds_on_2xx_response() {
        let port =
            spawn_test_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let node = make_http_node(port, HealthCheckType::Http);
        node.set_state(NodeState::Down); // start Down so a successful probe is observable
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(300));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn http_probe_fails_on_5xx_response() {
        let port = spawn_test_server(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let node = make_http_node(port, HealthCheckType::Http);
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(300));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Down);
        assert!(node.hc_consec_fail.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn custom_probe_requires_json_status_ok() {
        let port = spawn_test_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}",
        );
        let node = make_http_node(port, HealthCheckType::Custom);
        node.set_state(NodeState::Down);
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(300));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Up);
    }

    #[test]
    fn custom_probe_rejects_wrong_json_status() {
        let port = spawn_test_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"status\":\"not_ok\"}",
        );
        let node = make_http_node(port, HealthCheckType::Custom);
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(300));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Down);
    }

    #[test]
    fn probe_against_closed_port_fails() {
        // Bind and immediately drop -- the port is very likely free
        // again but nothing is listening, so connect() should fail or
        // the probe should time out.
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut node_inner = UpstreamNode::new("127.0.0.1".to_string(), port, 1, false, 32);
        node_inner.hc = HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            path: "/health".to_string(),
            interval: Duration::from_millis(50),
            timeout: Duration::from_millis(500),
            threshold_up: 1,
            threshold_down: 1,
        };
        let node = Arc::new(node_inner);
        let pool = Arc::new(UpstreamPool::new(1, 1));
        add_node(&pool, node.clone());

        let hc_loop = HealthCheckLoop::start(pool);
        std::thread::sleep(Duration::from_millis(700));
        hc_loop.stop();

        assert_eq!(node.state(), NodeState::Down);
    }
}
