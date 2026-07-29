//! Load-balancing node selection: seven algorithms (round robin,
//! weighted round robin, least-connections, IP hash, random, power of
//! two choices, consistent hash) plus cookie-based sticky session
//! pinning checked ahead of whichever algorithm is configured.
//!
//! Scope is deliberately limited to *selecting* a node -- serializing
//! a request, opening/reusing a connection, and forwarding bytes to
//! whatever was selected are `core::proxy`'s responsibility. Keeping
//! selection and forwarding as separate concerns (rather than one
//! function that does both, which is easy to reach for but ends up
//! mixing "which backend" logic with "how do I talk to it" plumbing)
//! means `core::proxy` can add retry-across-nodes, per-attempt
//! timeouts, and connection-pool integration without this module
//! needing to know anything about any of that.
//!
//! Sticky session pinning identifies a node by a hash of its
//! `host:port` rather than its index in the pool's node list -- an
//! index-based cookie would silently repin a client to the wrong
//! physical node after any config reload that changes node ordering
//! (adding/removing/reordering upstreams), even though nothing about
//! that specific node actually changed.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::lb::upstream::{NodeState, UpstreamPool, UpstreamNode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LbAlgo {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConn,
    IpHash,
    Random,
    /// Power of Two Choices: sample two random nodes, pick whichever
    /// has fewer in-flight requests. Approximates least-connections'
    /// quality with O(1) work instead of scanning every node.
    P2c,
    /// Ketama-style consistent hashing: minimizes how many keys remap
    /// when the node set changes, at the cost of a less perfectly even
    /// distribution than round robin -- the right tradeoff when
    /// upstream-side caching means "same client, same backend" has
    /// real value beyond pure load spreading.
    ConsistentHash,
}

#[derive(Debug, Clone)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct LbConfig {
    pub algo: LbAlgo,

    // Retry policy -- core::proxy consults these to decide whether/how
    // many times to retry a failed request against a different node;
    // this module only stores the policy, it doesn't run any retry
    // loop itself.
    pub max_retries: u32,
    pub retry_on_connect_fail: bool,
    pub retry_on_5xx: bool,

    // Consistent hash tuning.
    pub consistent_hash_vnodes: u32,

    // Cookie-based sticky sessions.
    pub sticky_session_enabled: bool,
    pub sticky_cookie_name: String,

    // Header manipulation policy -- applied on top of routa's own
    // automatic headers (X-Forwarded-For, etc.); core::proxy is what
    // actually applies these when building/receiving upstream
    // requests/responses.
    pub request_header_add: Vec<HeaderRule>,
    pub request_header_remove: Vec<String>,
    pub response_header_add: Vec<HeaderRule>,
    pub response_header_remove: Vec<String>,

    // Pool-scoped ACL, checked in addition to (after) any global ACL a
    // request already passed through the middleware chain -- lets a
    // pool restrict which clients can reach its specific upstreams
    // beyond whatever the server-wide policy already allows.
    pub acl: Option<crate::http::middleware::acl::AclConfig>,
}

// ─── Hashing / randomness helpers ───────────────────────────────────────

fn fnv1a(s: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in s {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

/// A simple xorshift PRNG, process-wide and lock-free (a single
/// atomic, updated with relaxed ordering -- exact fairness under
/// concurrent access isn't required, this only needs to be fast and
/// reasonably well-distributed for load-balancing choices, not
/// cryptographically secure).
static RAND_STATE: AtomicU32 = AtomicU32::new(0x9e3779b9);

fn lb_rand() -> u32 {
    let mut x = RAND_STATE.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    RAND_STATE.store(x, Ordering::Relaxed);
    x
}

// ─── Consistent hash ring ───────────────────────────────────────────────

struct VNode {
    hash: u32,
    node_index: usize,
}

struct HashRing {
    vnodes: Vec<VNode>,
}

const RING_VNODE_MAX: usize = 65536;

impl HashRing {
    /// Builds a ring with `vnodes_per * node.weight` virtual nodes for
    /// each real node (so higher-weight nodes claim proportionally
    /// more of the ring, same as they'd get proportionally more
    /// traffic under a weighted algorithm), each keyed by
    /// `"{host}:{port}#{v}"` and hashed with FNV-1a.
    fn build(nodes: &[Arc<UpstreamNode>], vnodes_per: u32) -> HashRing {
        let mut vnodes = Vec::new();
        for (idx, node) in nodes.iter().enumerate() {
            let per = (vnodes_per as i64 * node.weight as i64).max(1) as u32;
            for v in 0..per {
                if vnodes.len() >= RING_VNODE_MAX {
                    break;
                }
                let key = format!("{}:{}#{v}", node.host, node.port);
                vnodes.push(VNode {
                    hash: fnv1a(key.as_bytes()),
                    node_index: idx,
                });
            }
        }
        vnodes.sort_by_key(|v| v.hash);
        HashRing { vnodes }
    }

    /// Finds the first selectable node at or after `hash` on the ring
    /// (wrapping around), via binary search to the insertion point
    /// followed by a linear walk forward -- the walk is needed because
    /// the nearest vnode's real node might currently be
    /// unselectable (Down/Draining), in which case the next one
    /// around the ring is tried instead.
    fn lookup(&self, nodes: &[Arc<UpstreamNode>], pool: &UpstreamPool, hash: u32) -> Option<Arc<UpstreamNode>> {
        if self.vnodes.is_empty() {
            return None;
        }
        let start = self.vnodes.partition_point(|v| v.hash < hash);
        for i in 0..self.vnodes.len() {
            let idx = (start + i) % self.vnodes.len();
            let node = &nodes[self.vnodes[idx].node_index];
            if node.is_selectable(pool) {
                return Some(Arc::clone(node));
            }
        }
        None
    }
}

// ─── LoadBalancer ───────────────────────────────────────────────────────

pub struct LoadBalancer {
    pub config: LbConfig,
    pub pool: Arc<UpstreamPool>,
    ring: Mutex<Option<HashRing>>,

    // Weighted round robin's running total-weight tiebreak lives on
    // each node's own `current_weight` (see `UpstreamNode`); this lock
    // only serializes concurrent pick_wrr calls so the read-bump-pick-
    // subtract sequence across every node happens atomically as a
    // whole, not per-field.
    wrr_lock: Mutex<()>,

    stat_requests: AtomicU64,
    stat_failed: AtomicU64,
    stat_retries: AtomicU64,
}

impl LoadBalancer {
    pub fn new(config: LbConfig, pool: Arc<UpstreamPool>) -> Self {
        let ring = if config.algo == LbAlgo::ConsistentHash {
            let nodes = pool.nodes();
            let vnodes_per = config.consistent_hash_vnodes.max(1);
            Some(HashRing::build(&nodes, vnodes_per))
        } else {
            None
        };
        LoadBalancer {
            config,
            pool,
            ring: Mutex::new(ring),
            wrr_lock: Mutex::new(()),
            stat_requests: AtomicU64::new(0),
            stat_failed: AtomicU64::new(0),
            stat_retries: AtomicU64::new(0),
        }
    }

    /// Rebuilds the consistent-hash ring after the pool's node set has
    /// changed (nodes added/removed). A no-op for any other algorithm.
    pub fn rebuild_ring(&self) {
        if self.config.algo != LbAlgo::ConsistentHash {
            return;
        }
        let nodes = self.pool.nodes();
        let vnodes_per = self.config.consistent_hash_vnodes.max(1);
        *self.ring.lock().unwrap() = Some(HashRing::build(&nodes, vnodes_per));
    }

    pub fn record_retry(&self) {
        self.stat_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request(&self) {
        self.stat_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failed(&self) {
        self.stat_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> LbStats {
        LbStats {
            requests_total: self.stat_requests.load(Ordering::Relaxed),
            requests_failed: self.stat_failed.load(Ordering::Relaxed),
            retries: self.stat_retries.load(Ordering::Relaxed),
        }
    }

    fn pick_any_selectable(&self, nodes: &[Arc<UpstreamNode>]) -> Option<Arc<UpstreamNode>> {
        nodes
            .iter()
            .find(|n| n.is_selectable(&self.pool))
            .cloned()
    }

    /// Smooth weighted round robin (nginx-style): each Up node's
    /// `current_weight` is bumped by its own `weight` on every pick;
    /// the highest running total wins and is decremented by the total
    /// weight of all Up nodes. This spreads repeated picks of a
    /// high-weight node out evenly rather than clustering them --
    /// e.g. weights {5,1,1} produces a sequence like A A B A C A A
    /// rather than A A A A A B C, even though both have the same 5:1:1
    /// long-run ratio.
    ///
    /// Deliberately restricted to Up nodes only (not the broader
    /// "selectable", which also covers a half-open trial) -- the
    /// weighted math assumes stable pool membership for the length of
    /// this call, which a one-shot half-open trial can't provide. If
    /// no Up node exists at all, a half-open trial is offered as a
    /// dedicated fallback instead.
    fn pick_wrr(&self, nodes: &[Arc<UpstreamNode>]) -> Option<Arc<UpstreamNode>> {
        let _guard = self.wrr_lock.lock().unwrap();

        let mut total_weight: i32 = 0;
        let mut best: Option<(&Arc<UpstreamNode>, i32)> = None;

        for node in nodes {
            if node.state() != NodeState::Up || node.weight <= 0 {
                continue;
            }
            total_weight += node.weight;
            let new_cw = node.current_weight.fetch_add(node.weight, Ordering::AcqRel) + node.weight;
            if best.is_none_or(|(_, cw)| new_cw > cw) {
                best = Some((node, new_cw));
            }
        }

        let Some((winner, _)) = best else {
            return self.pick_any_selectable(nodes); // no Up nodes -- offer a half-open trial
        };

        winner
            .current_weight
            .fetch_sub(total_weight, Ordering::AcqRel);
        Some(Arc::clone(winner))
    }

    /// Power of Two Choices: samples two distinct random Up nodes and
    /// picks whichever has fewer in-flight requests -- approximates
    /// least-connections' quality with O(1) work instead of a full
    /// scan.
    fn pick_p2c(&self, nodes: &[Arc<UpstreamNode>]) -> Option<Arc<UpstreamNode>> {
        if nodes.len() <= 1 {
            return self.pick_any_selectable(nodes);
        }

        let up: Vec<&Arc<UpstreamNode>> =
            nodes.iter().filter(|n| n.state() == NodeState::Up).collect();

        match up.len() {
            0 => self.pick_any_selectable(nodes), // no Up nodes -- offer a half-open trial
            1 => Some(Arc::clone(up[0])),
            len => {
                let a = (lb_rand() as usize) % len;
                let mut b = (lb_rand() as usize) % len;
                while b == a {
                    b = (lb_rand() as usize) % len;
                }
                let inf_a = up[a].inflight.load(Ordering::Relaxed);
                let inf_b = up[b].inflight.load(Ordering::Relaxed);
                Some(Arc::clone(if inf_a <= inf_b { up[a] } else { up[b] }))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LbStats {
    pub requests_total: u64,
    pub requests_failed: u64,
    pub retries: u64,
}

/// A stable identifier for a node, derived from its `host:port` rather
/// than its position in the pool's node list -- see this module's top
/// doc comment for why. Suitable for use as a sticky-session cookie
/// value: it survives a config reload that reorders/adds/removes other
/// nodes, as long as this specific node's host:port is unchanged.
pub fn sticky_id_for_node(node: &UpstreamNode) -> String {
    format!("{:08x}", fnv1a(format!("{}:{}", node.host, node.port).as_bytes()))
}

impl LoadBalancer {
    /// Picks a node using whichever algorithm is configured, ignoring
    /// sticky sessions entirely -- see `pick_node_sticky` for the
    /// sticky-aware entry point callers normally want.
    pub fn pick_node(&self, client_ip: Option<&str>) -> Option<Arc<UpstreamNode>> {
        let nodes = self.pool.nodes();
        if nodes.is_empty() {
            return None;
        }

        match self.config.algo {
            LbAlgo::RoundRobin => {
                let start = self.pool.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                let n = nodes.len();
                (0..n)
                    .map(|i| &nodes[(start + i) % n])
                    .find(|node| node.is_selectable(&self.pool))
                    .cloned()
            }
            LbAlgo::WeightedRoundRobin => self.pick_wrr(&nodes),
            LbAlgo::LeastConn => {
                let best = nodes
                    .iter()
                    .filter(|n| n.state() == NodeState::Up)
                    .min_by_key(|n| n.inflight.load(Ordering::Relaxed));
                match best {
                    Some(n) => Some(Arc::clone(n)),
                    None => self.pick_any_selectable(&nodes), // no Up nodes -- offer a half-open trial
                }
            }
            LbAlgo::IpHash => {
                let Some(ip) = client_ip else {
                    return self.pick_any_selectable(&nodes);
                };
                let h = fnv1a(ip.as_bytes());
                let n = nodes.len();
                (0..n)
                    .map(|i| &nodes[(h as usize + i) % n])
                    .find(|node| node.is_selectable(&self.pool))
                    .cloned()
            }
            LbAlgo::Random => {
                let n = nodes.len();
                let start = (lb_rand() as usize) % n;
                (0..n)
                    .map(|i| &nodes[(start + i) % n])
                    .find(|node| node.is_selectable(&self.pool))
                    .cloned()
            }
            LbAlgo::P2c => self.pick_p2c(&nodes),
            LbAlgo::ConsistentHash => {
                let ring_guard = self.ring.lock().unwrap();
                let Some(ring) = ring_guard.as_ref() else {
                    return self.pick_any_selectable(&nodes);
                };
                let key = client_ip.unwrap_or("default");
                let h = fnv1a(key.as_bytes());
                ring.lookup(&nodes, &self.pool, h)
            }
        }
    }

    /// Sticky-session-aware node selection, checked ahead of whichever
    /// algorithm is configured. `sticky_value` is the raw sticky
    /// cookie value from the client's request, if any (see
    /// `sticky_id_for_node` for how it's generated).
    ///
    /// If sticky sessions are disabled, no cookie was sent, the cookie
    /// doesn't match any current node, or the matched node isn't
    /// currently `Up`, falls through to the normal algorithm --
    /// deliberately without offering a half-open trial for a
    /// sticky-matched Down node specifically: pinning this one client
    /// to a trial slot on every request would either keep hitting a
    /// likely-still-failing node, or silently monopolize the pool's
    /// only half-open trial slot, starving the rest of the pool of any
    /// chance to test recovery at all.
    pub fn pick_node_sticky(
        &self,
        client_ip: Option<&str>,
        sticky_value: Option<&str>,
    ) -> Option<Arc<UpstreamNode>> {
        if self.config.sticky_session_enabled {
            if let Some(value) = sticky_value {
                let nodes = self.pool.nodes();
                let matched = nodes
                    .iter()
                    .find(|n| sticky_id_for_node(n) == value && n.state() == NodeState::Up);
                if let Some(node) = matched {
                    return Some(Arc::clone(node));
                }
                // Stale/invalid cookie, or the matched node isn't Up --
                // fall through to the normal algorithm below, which
                // will pick a live node; the caller re-sets the sticky
                // cookie to whatever gets picked.
            }
        }
        self.pick_node(client_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lb::upstream::{add_node, UpstreamNode, UpstreamPool};

    fn make_node(host: &str, port: u16, weight: i32) -> Arc<UpstreamNode> {
        Arc::new(UpstreamNode::new(host.to_string(), port, weight, false, 32))
    }

    fn make_pool(nodes: Vec<Arc<UpstreamNode>>) -> Arc<UpstreamPool> {
        let pool = Arc::new(UpstreamPool::new(3, 2));
        for node in nodes {
            add_node(&pool, node);
        }
        pool
    }

    fn lb_with_algo(algo: LbAlgo, pool: Arc<UpstreamPool>) -> LoadBalancer {
        LoadBalancer::new(
            LbConfig {
                algo,
                consistent_hash_vnodes: 100,
                ..Default::default()
            },
            pool,
        )
    }

    // ─── Round robin ────────────────────────────────────────────────

    #[test]
    fn round_robin_cycles_through_all_nodes() {
        let nodes = vec![
            make_node("a", 1, 1),
            make_node("b", 2, 1),
            make_node("c", 3, 1),
        ];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::RoundRobin, pool);

        let mut hosts = Vec::new();
        for _ in 0..6 {
            let node = lb.pick_node(None).unwrap();
            hosts.push(node.host.clone());
        }
        // Every node should appear, roughly evenly, over 6 picks with 3 nodes.
        assert_eq!(hosts.iter().filter(|h| *h == "a").count(), 2);
        assert_eq!(hosts.iter().filter(|h| *h == "b").count(), 2);
        assert_eq!(hosts.iter().filter(|h| *h == "c").count(), 2);
    }

    #[test]
    fn round_robin_skips_down_nodes() {
        let down = make_node("down", 1, 1);
        let up = make_node("up", 2, 1);
        let pool = make_pool(vec![down.clone(), up.clone()]);
        let lb = lb_with_algo(LbAlgo::RoundRobin, pool.clone());

        down.record_failure(&pool);
        down.record_failure(&pool);
        down.record_failure(&pool);
        assert_eq!(down.state(), NodeState::Down);

        for _ in 0..5 {
            let node = lb.pick_node(None).unwrap();
            assert_eq!(node.host, "up");
        }
    }

    // ─── Weighted round robin ───────────────────────────────────────

    #[test]
    fn weighted_round_robin_respects_weight_ratio() {
        let nodes = vec![make_node("a", 1, 5), make_node("b", 2, 1), make_node("c", 3, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::WeightedRoundRobin, pool);

        let mut counts = std::collections::HashMap::new();
        for _ in 0..70 {
            let node = lb.pick_node(None).unwrap();
            *counts.entry(node.host.clone()).or_insert(0) += 1;
        }
        // Weights 5:1:1 over 70 picks -> roughly 50:10:10 -- every node
        // must be picked at least once, and "a" (weight 5) should be
        // picked noticeably more often than either weight-1 node.
        let a = *counts.get("a").unwrap_or(&0);
        let b = *counts.get("b").unwrap_or(&0);
        let c = *counts.get("c").unwrap_or(&0);
        assert!(b > 0, "b should be picked at least once, got 0");
        assert!(c > 0, "c should be picked at least once, got 0");
        assert!(a > b, "expected a ({a}) > b ({b})");
        assert!(a > c, "expected a ({a}) > c ({c})");
    }

    // ─── Least connections ──────────────────────────────────────────

    #[test]
    fn least_conn_picks_node_with_fewest_inflight() {
        let busy = make_node("busy", 1, 1);
        let idle = make_node("idle", 2, 1);
        busy.inflight.store(10, Ordering::Relaxed);
        idle.inflight.store(0, Ordering::Relaxed);
        let pool = make_pool(vec![busy, idle]);
        let lb = lb_with_algo(LbAlgo::LeastConn, pool);

        let node = lb.pick_node(None).unwrap();
        assert_eq!(node.host, "idle");
    }

    // ─── IP hash ─────────────────────────────────────────────────────

    #[test]
    fn ip_hash_is_deterministic_for_same_client() {
        let nodes = vec![make_node("a", 1, 1), make_node("b", 2, 1), make_node("c", 3, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::IpHash, pool);

        let first = lb.pick_node(Some("203.0.113.5")).unwrap().host.clone();
        let second = lb.pick_node(Some("203.0.113.5")).unwrap().host.clone();
        assert_eq!(first, second);
    }

    #[test]
    fn ip_hash_falls_back_without_client_ip() {
        let nodes = vec![make_node("a", 1, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::IpHash, pool);
        assert!(lb.pick_node(None).is_some());
    }

    // ─── Random ─────────────────────────────────────────────────────

    #[test]
    fn random_always_picks_a_selectable_node() {
        let nodes = vec![make_node("a", 1, 1), make_node("b", 2, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::Random, pool);
        for _ in 0..20 {
            assert!(lb.pick_node(None).is_some());
        }
    }

    // ─── P2C ────────────────────────────────────────────────────────

    #[test]
    fn p2c_prefers_less_loaded_node_over_many_trials() {
        let busy = make_node("busy", 1, 1);
        let idle = make_node("idle", 2, 1);
        busy.inflight.store(100, Ordering::Relaxed);
        idle.inflight.store(0, Ordering::Relaxed);
        let pool = make_pool(vec![busy, idle]);
        let lb = lb_with_algo(LbAlgo::P2c, pool);

        // With only two nodes, P2C always samples both, so it should
        // deterministically prefer "idle" every time.
        for _ in 0..10 {
            assert_eq!(lb.pick_node(None).unwrap().host, "idle");
        }
    }

    #[test]
    fn p2c_single_node_pool_just_returns_it() {
        let pool = make_pool(vec![make_node("only", 1, 1)]);
        let lb = lb_with_algo(LbAlgo::P2c, pool);
        assert_eq!(lb.pick_node(None).unwrap().host, "only");
    }

    // ─── Consistent hash ─────────────────────────────────────────────

    #[test]
    fn consistent_hash_is_deterministic_for_same_key() {
        let nodes = vec![make_node("a", 1, 1), make_node("b", 2, 1), make_node("c", 3, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::ConsistentHash, pool);

        let first = lb.pick_node(Some("client-1")).unwrap().host.clone();
        let second = lb.pick_node(Some("client-1")).unwrap().host.clone();
        assert_eq!(first, second);
    }

    #[test]
    fn consistent_hash_distributes_across_nodes() {
        let nodes = vec![make_node("a", 1, 1), make_node("b", 2, 1), make_node("c", 3, 1)];
        let pool = make_pool(nodes);
        let lb = lb_with_algo(LbAlgo::ConsistentHash, pool);

        let mut seen = std::collections::HashSet::new();
        for i in 0..50 {
            let key = format!("client-{i}");
            seen.insert(lb.pick_node(Some(&key)).unwrap().host.clone());
        }
        // With enough distinct clients, all three nodes should get
        // picked at least once.
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn consistent_hash_skips_down_nodes() {
        let down = make_node("down", 1, 1);
        let up = make_node("up", 2, 1);
        let pool = make_pool(vec![down.clone(), up.clone()]);
        let lb = lb_with_algo(LbAlgo::ConsistentHash, pool.clone());

        down.record_failure(&pool);
        down.record_failure(&pool);
        down.record_failure(&pool);

        for i in 0..20 {
            let key = format!("client-{i}");
            assert_eq!(lb.pick_node(Some(&key)).unwrap().host, "up");
        }
    }

    // ─── Sticky sessions ─────────────────────────────────────────────

    #[test]
    fn sticky_id_is_stable_for_same_host_port() {
        let node = make_node("api.internal", 8443, 1);
        let id1 = sticky_id_for_node(&node);
        let id2 = sticky_id_for_node(&node);
        assert_eq!(id1, id2);
    }

    #[test]
    fn sticky_id_differs_for_different_nodes() {
        let a = make_node("a.internal", 8443, 1);
        let b = make_node("b.internal", 8443, 1);
        assert_ne!(sticky_id_for_node(&a), sticky_id_for_node(&b));
    }

    #[test]
    fn sticky_session_pins_to_matching_node() {
        let a = make_node("a.internal", 8443, 1);
        let b = make_node("b.internal", 8443, 1);
        let a_id = sticky_id_for_node(&a);
        let pool = make_pool(vec![a, b]);
        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                sticky_session_enabled: true,
                sticky_cookie_name: "routa_sticky".to_string(),
                ..Default::default()
            },
            pool,
        );

        for _ in 0..10 {
            let node = lb.pick_node_sticky(None, Some(&a_id)).unwrap();
            assert_eq!(node.host, "a.internal");
        }
    }

    #[test]
    fn sticky_session_falls_through_on_down_node() {
        let a = make_node("a.internal", 8443, 1);
        let b = make_node("b.internal", 8443, 1);
        let a_id = sticky_id_for_node(&a);
        let pool = make_pool(vec![a.clone(), b]);
        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                sticky_session_enabled: true,
                ..Default::default()
            },
            pool.clone(),
        );

        a.record_failure(&pool);
        a.record_failure(&pool);
        a.record_failure(&pool);
        assert_eq!(a.state(), NodeState::Down);

        // Sticky cookie points at the now-Down node -- should fall
        // through to picking the other (Up) node instead.
        let node = lb.pick_node_sticky(None, Some(&a_id)).unwrap();
        assert_eq!(node.host, "b.internal");
    }

    #[test]
    fn sticky_session_falls_through_on_invalid_cookie() {
        let nodes = vec![make_node("a", 1, 1)];
        let pool = make_pool(nodes);
        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                sticky_session_enabled: true,
                ..Default::default()
            },
            pool,
        );

        let node = lb.pick_node_sticky(None, Some("not-a-real-id"));
        assert!(node.is_some());
    }

    #[test]
    fn sticky_disabled_ignores_cookie() {
        let a = make_node("a.internal", 8443, 1);
        let a_id = sticky_id_for_node(&a);
        let pool = make_pool(vec![a]);
        let lb = LoadBalancer::new(
            LbConfig {
                algo: LbAlgo::RoundRobin,
                sticky_session_enabled: false,
                ..Default::default()
            },
            pool,
        );

        // Even with a "matching" cookie, sticky is disabled so this
        // should just run the normal algorithm -- observable here only
        // as "doesn't panic and still returns a node".
        assert!(lb.pick_node_sticky(None, Some(&a_id)).is_some());
    }

    // ─── Stats ──────────────────────────────────────────────────────

    #[test]
    fn stats_start_at_zero_and_increment() {
        let pool = make_pool(vec![make_node("a", 1, 1)]);
        let lb = lb_with_algo(LbAlgo::RoundRobin, pool);

        assert_eq!(lb.stats().requests_total, 0);
        lb.record_request();
        lb.record_request();
        lb.record_failed();
        lb.record_retry();

        let stats = lb.stats();
        assert_eq!(stats.requests_total, 2);
        assert_eq!(stats.requests_failed, 1);
        assert_eq!(stats.retries, 1);
    }

    // ─── Empty pool ──────────────────────────────────────────────────

    #[test]
    fn empty_pool_returns_none_for_every_algo() {
        for algo in [
            LbAlgo::RoundRobin,
            LbAlgo::WeightedRoundRobin,
            LbAlgo::LeastConn,
            LbAlgo::IpHash,
            LbAlgo::Random,
            LbAlgo::P2c,
            LbAlgo::ConsistentHash,
        ] {
            let pool = make_pool(vec![]);
            let lb = lb_with_algo(algo, pool);
            assert!(lb.pick_node(Some("1.2.3.4")).is_none(), "{algo:?} should return None on an empty pool");
        }
    }
}
