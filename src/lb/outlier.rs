//! Success-rate outlier detection: ejects upstream nodes whose success
//! rate is statistically worse than their peers, complementing the
//! passive circuit breaker in `lb::upstream` (which only reacts to a
//! node's own consecutive failures, with no notion of "worse than the
//! rest of the pool").
//!
//! Modeled on Envoy's success-rate outlier detection: each analysis
//! interval, every node with enough request volume gets a success
//! rate (successes / total); the pool's mean and standard deviation
//! of those rates are computed, and any node whose rate falls more
//! than `stdev_factor` standard deviations below the mean is ejected
//! for a backoff period that grows with repeated ejections. A
//! `max_ejection_percent` cap prevents a pool-wide problem (e.g. every
//! node briefly struggling under a traffic spike) from ejecting the
//! entire pool at once -- if that cap is already reached, further
//! would-be ejections are skipped this interval rather than pushing
//! the pool below its minimum viable capacity.
//!
//! Kept as a separate module from `lb::upstream`'s circuit breaker
//! rather than merged into it: the two answer different questions
//! (this node keeps failing on its own vs. this node is worse than
//! its peers right now) using different mechanisms (consecutive-
//! failure counting vs. interval statistics), and a caller that wants
//! only one of the two shouldn't have to carry the other's state.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::upstream::UpstreamNode;

#[derive(Debug, Clone)]
pub struct OutlierConfig {
    pub enabled: bool,
    /// How often the ejection analysis sweep runs.
    pub interval: Duration,
    /// A node needs at least this many requests in the current
    /// interval to be included in the statistical analysis at all --
    /// below this, there isn't enough signal to draw a conclusion.
    pub min_request_volume: u32,
    /// The pool needs at least this many nodes meeting
    /// `min_request_volume` for mean/stdev to be statistically
    /// meaningful -- comparing "the rest of the pool" against fewer
    /// than a handful of peers is comparing against noise.
    pub min_hosts: usize,
    /// How many standard deviations below the mean a node's success
    /// rate must fall to be ejected. Envoy's own default is 1.9;
    /// expressed here as a plain f64 rather than Envoy's
    /// per-mille-integer convention (1900 = 1.9) since this config
    /// isn't required to match Envoy's wire format, just its
    /// underlying statistics.
    pub stdev_factor: f64,
    /// The base ejection duration -- the actual duration for a node's
    /// Nth ejection is `base_ejection_time * N`, so repeatedly-ejected
    /// nodes are kept out of rotation for progressively longer.
    pub base_ejection_time: Duration,
    /// An upper bound on ejection duration regardless of how many
    /// times a node has been ejected -- without this, a
    /// long-unhealthy node's ejection time would grow unbounded.
    pub max_ejection_time: Duration,
    /// The maximum percentage of a pool's nodes that can be ejected at
    /// once -- see this module's top doc comment for why this exists.
    pub max_ejection_percent: u8,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        OutlierConfig {
            enabled: false,
            interval: Duration::from_secs(10),
            min_request_volume: 100,
            min_hosts: 3, // Envoy's own default is 5; 3 is more realistic for smaller pools this codebase is likely to see
            stdev_factor: 1.9,
            base_ejection_time: Duration::from_secs(30),
            max_ejection_time: Duration::from_secs(300),
            max_ejection_percent: 20,
        }
    }
}

/// Per-node outlier-detection state: the current interval's running
/// request/success counts, plus ejection bookkeeping (how many times
/// this node has been ejected, for the progressive backoff, and when
/// its current ejection -- if any -- ends).
pub struct NodeOutlierStats {
    interval_requests: AtomicU32,
    interval_successes: AtomicU32,
    ejection_count: AtomicU32,
    /// `Some(deadline)` while this node is currently ejected; `None`
    /// otherwise. Checked by `is_ejected` alongside the deadline
    /// itself, so a caller never needs to separately ask "is it
    /// ejected" and "has its ejection expired" -- one check answers
    /// both.
    ejected_until: RwLock<Option<Instant>>,
}

impl Default for NodeOutlierStats {
    fn default() -> Self {
        NodeOutlierStats {
            interval_requests: AtomicU32::new(0),
            interval_successes: AtomicU32::new(0),
            ejection_count: AtomicU32::new(0),
            ejected_until: RwLock::new(None),
        }
    }
}

impl NodeOutlierStats {
    pub fn record_request(&self, success: bool) {
        self.interval_requests.fetch_add(1, Ordering::AcqRel);
        if success {
            self.interval_successes.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// This node's success rate over the current (not-yet-reset)
    /// interval, and how many requests that rate is based on. Returns
    /// `None` if there have been no requests at all this interval
    /// (a 0/0 rate is meaningless, not 0%).
    fn current_interval_rate(&self) -> Option<(f64, u32)> {
        let total = self.interval_requests.load(Ordering::Acquire);
        if total == 0 {
            return None;
        }
        let successes = self.interval_successes.load(Ordering::Acquire);
        Some((f64::from(successes) / f64::from(total), total))
    }

    /// Resets the interval counters to 0, ready for the next analysis
    /// window -- called once per sweep, after this interval's data has
    /// already been used for this sweep's analysis.
    fn reset_interval(&self) {
        self.interval_requests.store(0, Ordering::Release);
        self.interval_successes.store(0, Ordering::Release);
    }

    pub fn is_ejected(&self) -> bool {
        match *self.ejected_until.read().unwrap() {
            Some(deadline) => Instant::now() < deadline,
            None => false,
        }
    }

    /// Ejects this node, computing its actual ejection duration from
    /// `config`'s base/max ejection times and this node's own ejection
    /// history (see `OutlierConfig::base_ejection_time`'s doc comment
    /// for the progressive-backoff formula).
    fn eject(&self, config: &OutlierConfig) {
        let count = self.ejection_count.fetch_add(1, Ordering::AcqRel) + 1;
        let duration = (config.base_ejection_time * count).min(config.max_ejection_time);
        *self.ejected_until.write().unwrap() = Some(Instant::now() + duration);
    }
}

/// One sweep of outlier analysis over every node in `nodes`, using
/// each node's own `NodeOutlierStats` (looked up via `stats_for`,
/// since `UpstreamNode` itself doesn't carry this state -- see this
/// module's top doc comment on keeping the two mechanisms separate).
/// Ejects any node found to be a statistical outlier, subject to
/// `max_ejection_percent`, and resets every analyzed node's interval
/// counters for the next sweep regardless of whether it was ejected.
///
/// Returns the ids (host:port) of nodes ejected this sweep, purely for
/// observability (logging/metrics) -- the actual ejection state lives
/// in each node's own `NodeOutlierStats`.
pub fn run_outlier_sweep(
    nodes: &[Arc<UpstreamNode>],
    stats_for: impl Fn(&Arc<UpstreamNode>) -> Arc<NodeOutlierStats>,
    config: &OutlierConfig,
) -> Vec<String> {
    if !config.enabled {
        return Vec::new();
    }

    // Only nodes with enough request volume this interval are eligible
    // for analysis at all -- both to be a candidate for ejection and
    // to contribute to the pool's mean/stdev (a node with too little
    // traffic to say anything meaningful about shouldn't skew the
    // baseline other nodes are compared against either).
    let candidates: Vec<(&Arc<UpstreamNode>, Arc<NodeOutlierStats>, f64)> = nodes
        .iter()
        .filter_map(|node| {
            let stats = stats_for(node);
            let (rate, volume) = stats.current_interval_rate()?;
            if volume < config.min_request_volume {
                return None;
            }
            Some((node, stats, rate))
        })
        .collect();

    if candidates.len() < config.min_hosts {
        // Not enough statistical signal to compare against -- reset
        // interval counters (this data point is now stale for next
        // sweep) but eject nobody.
        for node in nodes {
            stats_for(node).reset_interval();
        }
        return Vec::new();
    }

    let rates: Vec<f64> = candidates.iter().map(|(_, _, rate)| *rate).collect();
    let mean = rates.iter().sum::<f64>() / rates.len() as f64;
    let variance = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
    let stdev = variance.sqrt();
    let threshold = mean - (stdev * config.stdev_factor);

    let currently_ejected = nodes.iter().filter(|n| stats_for(n).is_ejected()).count();
    let max_ejected = ((nodes.len() as f64) * (f64::from(config.max_ejection_percent) / 100.0)).floor() as usize;
    let mut newly_ejected_slots = max_ejected.saturating_sub(currently_ejected);

    let mut ejected_ids = Vec::new();
    for (node, stats, rate) in &candidates {
        if *rate < threshold && newly_ejected_slots > 0 && !stats.is_ejected() {
            stats.eject(config);
            newly_ejected_slots -= 1;
            ejected_ids.push(format!("{}:{}", node.host, node.port));
        }
    }

    for node in nodes {
        stats_for(node).reset_interval();
    }

    ejected_ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn make_node(host: &str) -> Arc<UpstreamNode> {
        Arc::new(UpstreamNode::new(host.to_string(), 8080, 1, false, 8))
    }

    /// A simple stats registry keyed by node identity, standing in for
    /// wherever a real caller (e.g. `core::proxy`) would keep one
    /// `NodeOutlierStats` per node alongside its `UpstreamPool`.
    struct StatsRegistry {
        by_host: Mutex<HashMap<String, Arc<NodeOutlierStats>>>,
    }

    impl StatsRegistry {
        fn new() -> Self {
            StatsRegistry {
                by_host: Mutex::new(HashMap::new()),
            }
        }

        fn get(&self, node: &Arc<UpstreamNode>) -> Arc<NodeOutlierStats> {
            self.by_host
                .lock()
                .unwrap()
                .entry(node.host.clone())
                .or_insert_with(|| Arc::new(NodeOutlierStats::default()))
                .clone()
        }
    }

    fn record_n_requests(stats: &NodeOutlierStats, total: u32, successes: u32) {
        for i in 0..total {
            stats.record_request(i < successes);
        }
    }

    #[test]
    fn disabled_config_ejects_nobody() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let registry = StatsRegistry::new();
        for node in &nodes {
            record_n_requests(&registry.get(node), 100, 0); // 0% success -- would be ejected if enabled
        }
        let config = OutlierConfig {
            enabled: false,
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert!(ejected.is_empty());
    }

    #[test]
    fn clear_outlier_gets_ejected() {
        // More peers than the minimum, all uniformly healthy, so the
        // pool's own stdev among "normal" nodes stays small -- with
        // only a handful of nodes, one badly-behaving outlier can
        // itself inflate the standard deviation enough to raise its
        // own ejection threshold below its own (still-bad) rate,
        // masking the very problem this test is checking for. More
        // healthy peers keeps that baseline noise low, so the
        // one truly bad node clearly stands out.
        let healthy_hosts = ["a", "b", "c", "d", "e", "f"];
        let mut nodes: Vec<Arc<UpstreamNode>> = healthy_hosts.iter().map(|h| make_node(h)).collect();
        nodes.push(make_node("bad"));

        let registry = StatsRegistry::new();
        for node in &nodes[..healthy_hosts.len()] {
            record_n_requests(&registry.get(node), 200, 200); // 100% success
        }
        record_n_requests(&registry.get(nodes.last().unwrap()), 200, 10); // 5% success -- clearly bad

        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3,
            stdev_factor: 1.9,
            max_ejection_percent: 50,
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert_eq!(ejected, vec!["bad:8080".to_string()]);
        assert!(registry.get(nodes.last().unwrap()).is_ejected());
        assert!(!registry.get(&nodes[0]).is_ejected());
    }

    #[test]
    fn uniformly_healthy_pool_ejects_nobody() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c"), make_node("d")];
        let registry = StatsRegistry::new();
        for node in &nodes {
            record_n_requests(&registry.get(node), 150, 148); // small, uniform noise across all nodes
        }
        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3,
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert!(ejected.is_empty(), "a uniformly-healthy pool should never eject anyone");
    }

    #[test]
    fn insufficient_request_volume_excludes_node_from_analysis() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let registry = StatsRegistry::new();
        record_n_requests(&registry.get(&nodes[0]), 200, 200);
        record_n_requests(&registry.get(&nodes[1]), 200, 200);
        // Below min_request_volume -- shouldn't count toward min_hosts
        // or be a candidate for ejection despite a terrible rate.
        record_n_requests(&registry.get(&nodes[2]), 5, 0);

        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3, // requires 3 qualifying nodes, but only 2 meet min_request_volume
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert!(ejected.is_empty(), "shouldn't eject when too few nodes have enough volume to analyze");
    }

    #[test]
    fn insufficient_host_count_ejects_nobody() {
        let nodes = vec![make_node("a"), make_node("b")]; // only 2 nodes total
        let registry = StatsRegistry::new();
        record_n_requests(&registry.get(&nodes[0]), 200, 200);
        record_n_requests(&registry.get(&nodes[1]), 200, 20);

        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3, // more than the pool's own node count
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert!(ejected.is_empty(), "shouldn't analyze a pool smaller than min_hosts");
    }

    #[test]
    fn max_ejection_percent_caps_how_many_nodes_are_ejected_at_once() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c"), make_node("d"), make_node("e")];
        let registry = StatsRegistry::new();
        // One healthy node, four terrible ones -- without a cap, all
        // four would be flagged as outliers relative to the healthy
        // one's rate.
        record_n_requests(&registry.get(&nodes[0]), 200, 200);
        for node in &nodes[1..] {
            record_n_requests(&registry.get(node), 200, 10);
        }

        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3,
            stdev_factor: 0.5, // permissive threshold so all 4 bad nodes would qualify
            max_ejection_percent: 20, // allows only 1 of 5 nodes (20% of 5 = 1) to be ejected
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert_eq!(ejected.len(), 1, "max_ejection_percent should cap ejections to 1 of 5 nodes");
    }

    #[test]
    fn ejection_time_grows_with_repeated_ejections() {
        let stats = NodeOutlierStats::default();
        let config = OutlierConfig {
            base_ejection_time: Duration::from_secs(10),
            max_ejection_time: Duration::from_secs(1000),
            ..Default::default()
        };

        let before_first = Instant::now();
        stats.eject(&config);
        let first_deadline = stats.ejected_until.read().unwrap().unwrap();
        let first_duration = first_deadline.duration_since(before_first);
        assert!(first_duration >= Duration::from_secs(9) && first_duration <= Duration::from_secs(11));

        let before_second = Instant::now();
        stats.eject(&config);
        let second_deadline = stats.ejected_until.read().unwrap().unwrap();
        let second_duration = second_deadline.duration_since(before_second);
        // Second ejection should be roughly double the first (base_ejection_time * 2).
        assert!(second_duration >= Duration::from_secs(19) && second_duration <= Duration::from_secs(21));
    }

    #[test]
    fn ejection_time_is_capped_at_max_ejection_time() {
        let stats = NodeOutlierStats::default();
        let config = OutlierConfig {
            base_ejection_time: Duration::from_secs(100),
            max_ejection_time: Duration::from_secs(150),
            ..Default::default()
        };
        stats.eject(&config); // would be 100s, under the cap
        stats.eject(&config); // would be 200s, but capped to 150s
        let deadline = stats.ejected_until.read().unwrap().unwrap();
        let duration = deadline.duration_since(Instant::now());
        assert!(duration <= Duration::from_secs(151), "ejection time should be capped at max_ejection_time");
    }

    #[test]
    fn interval_counters_reset_after_a_sweep() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let registry = StatsRegistry::new();
        for node in &nodes {
            record_n_requests(&registry.get(node), 150, 150);
        }
        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3,
            ..Default::default()
        };
        run_outlier_sweep(&nodes, |n| registry.get(n), &config);

        // After the sweep, interval counters should be back to 0 --
        // confirmed indirectly: a node with no new requests this
        // interval has no current_interval_rate() at all.
        assert!(registry.get(&nodes[0]).current_interval_rate().is_none());
    }

    #[test]
    fn is_ejected_becomes_false_after_ejection_expires() {
        let stats = NodeOutlierStats::default();
        let config = OutlierConfig {
            base_ejection_time: Duration::from_millis(1),
            max_ejection_time: Duration::from_millis(10),
            ..Default::default()
        };
        stats.eject(&config);
        assert!(stats.is_ejected());
        std::thread::sleep(Duration::from_millis(20));
        assert!(!stats.is_ejected(), "ejection should have expired by now");
    }

    #[test]
    fn node_with_no_requests_this_interval_is_excluded_from_analysis() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let registry = StatsRegistry::new();
        record_n_requests(&registry.get(&nodes[0]), 200, 200);
        record_n_requests(&registry.get(&nodes[1]), 200, 200);
        // nodes[2] has recorded nothing this interval at all.

        let config = OutlierConfig {
            enabled: true,
            min_request_volume: 100,
            min_hosts: 3,
            ..Default::default()
        };
        let ejected = run_outlier_sweep(&nodes, |n| registry.get(n), &config);
        assert!(ejected.is_empty(), "shouldn't analyze when fewer than min_hosts nodes have any data this interval");
    }
}

/// A background thread that periodically runs `run_outlier_sweep`
/// against every node in a pool, using `UpstreamPool::outlier_stats_for`
/// for each node's stats -- the actual wiring `core::server` uses to
/// turn this module's pure functions into an always-running mechanism.
/// Runs on its own thread/interval, deliberately independent of
/// `HealthCheckLoop`'s own thread and interval: outlier detection's
/// natural analysis window (Envoy's own default is 10s) and active
/// health-check probing's natural interval (often much shorter) are
/// answering different questions on different time scales, and tying
/// them to the same loop would force one to distort the other's
/// timing.
pub struct OutlierSweepLoop {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OutlierSweepLoop {
    /// `pool_name`/`metrics` are optional purely so this module's own
    /// tests (and any other caller that doesn't care about metrics)
    /// can start a sweep loop without a `Metrics` registry at hand --
    /// `core::server` (the only caller that matters for production
    /// use) always supplies both.
    pub fn start(pool: Arc<super::upstream::UpstreamPool>) -> Self {
        Self::start_with_metrics(pool, String::new(), None)
    }

    pub fn start_with_metrics(
        pool: Arc<super::upstream::UpstreamPool>,
        pool_name: String,
        metrics: Option<Arc<crate::util::metrics::Metrics>>,
    ) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("routa-outlier-sweep".to_string())
            .spawn(move || run_sweep_loop(pool, stop_for_thread, pool_name, metrics))
            .expect("failed to spawn outlier sweep thread");

        OutlierSweepLoop {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for OutlierSweepLoop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_sweep_loop(
    pool: Arc<super::upstream::UpstreamPool>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    pool_name: String,
    metrics: Option<Arc<crate::util::metrics::Metrics>>,
) {
    // Kept as this thread's own local state (not shared/static) --
    // each OutlierSweepLoop instance has exactly one thread running
    // this function for exactly one pool, so there's no sharing
    // concern to justify anything more elaborate than a plain local.
    let mut last_run: Option<Instant> = None;

    while !stop.load(Ordering::Acquire) {
        // Sleep in short increments (rather than the full configured
        // interval at once) purely so this thread notices `stop`
        // promptly instead of potentially sleeping through a full
        // analysis interval before it can exit.
        std::thread::sleep(Duration::from_millis(200));
        if stop.load(Ordering::Acquire) {
            break;
        }

        let interval = pool.outlier_config.interval;
        let should_run = match last_run {
            Some(last) => last.elapsed() >= interval,
            None => true,
        };
        if should_run {
            let nodes = pool.nodes();
            let ejected = run_outlier_sweep(&nodes, |n| pool.outlier_stats_for(n), &pool.outlier_config);
            for node_id in &ejected {
                tracing::warn!(node = %node_id, "node ejected by outlier detection");
                if let Some(metrics) = &metrics {
                    metrics.upstream.outlier_ejections_total.with_label_values(&[&pool_name, node_id]).inc();
                }
            }
            last_run = Some(Instant::now());
        }
    }
}

