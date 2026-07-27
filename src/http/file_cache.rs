//! Static-file metadata (and, for small files, content) caching.
//!
//! Two modes, matching the tradeoffs described in each variant's doc
//! comment below: `Local` (each worker keeps a fully independent
//! cache, simplest, no cross-worker coordination) and
//! `SharedMetadata` (path metadata lives in a table shared across
//! workers via `DashMap`, so invalidation is instantly visible
//! everywhere; the mapped file content itself still lives per-worker,
//! since mmap()/munmap() churn -- not the mapped pages themselves,
//! which the kernel page cache already shares across processes -- is
//! the real per-worker cost).
//!
//! Memory-mapped file content is held in `memmap2::Mmap`, whose `Drop`
//! unmaps automatically -- there's no explicit "don't forget to
//! munmap on eviction/generation-mismatch" bookkeeping to get wrong,
//! unlike a raw `mmap()`/`munmap()` pair.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

// ─── Config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// Each worker keeps a fully independent cache. Simplest, but
    /// invalidation only affects the calling worker, and N workers
    /// each redo their own stat()/open()/mmap() for the same file.
    Local,
    /// Path metadata (etag, mtime, size) is shared across all workers
    /// via a lock-protected table; invalidation is instantly visible
    /// everywhere. The mapped file content itself still lives
    /// per-worker.
    #[default]
    SharedMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictionPolicy {
    /// Evicts the least-recently-used entry. Good general default.
    #[default]
    Lru,
    /// Evicts the least-frequently-used entry (frequency decays
    /// periodically so long-idle-but-once-popular entries don't become
    /// permanently unevictable). Better than LRU when some files are
    /// consistently much hotter than others regardless of recency.
    Lfu,
    /// No active ordering, just relies on TTL expiry. Cheapest, least
    /// smart.
    TtlOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevalidationStrategy {
    /// Pure TTL: an entry is valid until `ttl` elapses, no filesystem
    /// check.
    Ttl,
    /// Valid until `ttl` elapses, then one stat() confirms mtime/size
    /// are unchanged before extending validity another `ttl`.
    #[default]
    StatTtl,
    /// Validity is driven entirely by filesystem change notifications
    /// (see `Watch`) -- no TTL ceiling while a watch is active.
    Inotify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Watch {
    #[default]
    None,
    /// Watches cached files for real filesystem change events and
    /// invalidates immediately, via the `notify` crate (inotify on
    /// Linux).
    Inotify,
}

#[derive(Debug, Clone)]
pub struct FileCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl: Duration,
    pub strategy: RevalidationStrategy,
    pub mode: CacheMode,
    pub eviction: EvictionPolicy,
    /// `None` disables negative caching (caching "file not found"
    /// results to avoid re-stat()ing a missing path on every request).
    pub negative_ttl: Option<Duration>,
    /// Files smaller than this are mmap'd and served from memory;
    /// larger files are served via a different path (sendfile, once
    /// `http::static_files` implements it).
    pub mmap_threshold: u64,
}

impl Default for FileCacheConfig {
    fn default() -> Self {
        FileCacheConfig {
            enabled: true,
            max_entries: 1024,
            ttl: Duration::from_secs(5),
            strategy: RevalidationStrategy::default(),
            mode: CacheMode::default(),
            eviction: EvictionPolicy::default(),
            negative_ttl: None,
            mmap_threshold: 64 * 1024,
        }
    }
}

// ─── Cache entry ────────────────────────────────────────────────────────

/// A cached file's metadata plus, for small files, its mapped content.
/// `Mmap`'s `Drop` unmaps automatically when this (and every clone
/// sharing the same `Arc<Mmap>`) is dropped -- see this module's doc
/// comment.
#[derive(Clone)]
pub struct CacheEntry {
    pub resolved_path: PathBuf,
    pub etag: String,
    pub last_modified: String,
    pub mime_type: String,
    pub size: u64,
    pub mtime: SystemTime,
    pub cached_at: Instant,
    /// `true` only for a cached "not found" result -- every other
    /// field except `resolved_path`/`cached_at` is meaningless in that
    /// case.
    pub negative: bool,
    /// Present only when `size < mmap_threshold` and the mapping
    /// succeeded. `Arc` because `SharedMetadata` mode's per-worker
    /// mmap cache and the entry returned to a caller both need to
    /// reference the same mapping without forcing an unmap while
    /// either side still holds it.
    pub mapped: Option<Arc<Mmap>>,
}

impl CacheEntry {
    fn negative(resolved_path: PathBuf) -> Self {
        CacheEntry {
            resolved_path,
            etag: String::new(),
            last_modified: String::new(),
            mime_type: String::new(),
            size: 0,
            mtime: UNIX_EPOCH,
            cached_at: Instant::now(),
            negative: true,
            mapped: None,
        }
    }
}

/// Formats an ETag as `"mtime-size"` in hex, quoted.
pub fn make_etag(mtime: SystemTime, size: u64) -> String {
    let mtime_secs = mtime
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("\"{mtime_secs:x}-{size:x}\"")
}

/// Attempts to mmap `path` if `size` is within `mmap_threshold`.
/// `Ok(None)` (not an error) covers both "too large to map" and "empty
/// file" -- neither is mapped, callers fall back to reading/serving
/// the file another way.
fn try_mmap(path: &Path, size: u64, mmap_threshold: u64) -> std::io::Result<Option<Mmap>> {
    if size == 0 || size >= mmap_threshold {
        return Ok(None);
    }
    let file = std::fs::File::open(path)?;
    // Safety: the file is opened read-only immediately above and
    // nothing else in this process holds it open for writing; the
    // standard caveats of mmap (another process truncating/modifying
    // the file concurrently) apply the same way they would to a raw
    // mmap() call.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(Some(mmap))
}

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

// ─── LOCAL mode ─────────────────────────────────────────────────────────
//
// Each worker owns a fully independent `LocalCache`. No cross-worker
// coordination at all -- simplest possible mode, intended for
// low-traffic/debug use.

use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;

/// Approximate LFU tracking, in the style Redis uses: a per-entry
/// counter that increments on access (with diminishing probability as
/// it grows, so a handful of early hits don't saturate it) and decays
/// globally on a schedule. Eviction picks the entry with the lowest
/// counter among a small random sample rather than scanning the whole
/// cache for a true minimum -- O(1) amortized, no need for an
/// intrusive frequency-bucket linked list (which requires `unsafe` or
/// `Rc<RefCell<>>` to express safely in Rust; approximate LFU gets
/// within noise of the same behavior without either).
struct ApproxLfu<K: Clone + Eq + std::hash::Hash> {
    counters: HashMap<K, u8>,
    puts_since_decay: u32,
}

const LFU_MAX_COUNTER: u8 = 255;
const LFU_DECAY_INTERVAL: u32 = 4096;
const LFU_SAMPLE_SIZE: usize = 5;

impl<K: Clone + Eq + std::hash::Hash> ApproxLfu<K> {
    fn new() -> Self {
        ApproxLfu {
            counters: HashMap::new(),
            puts_since_decay: 0,
        }
    }

    fn record_access(&mut self, key: &K) {
        if let Some(counter) = self.counters.get_mut(key) {
            // Diminishing increment probability, same idea as Redis's
            // LFU: probability of incrementing drops as the counter
            // grows, so hot keys don't all just saturate at the max
            // and become indistinguishable.
            let p = 1.0 / (*counter as f64 * 10.0 + 1.0);
            if *counter < LFU_MAX_COUNTER && fastrand_f64() < p {
                *counter += 1;
            }
        }
    }

    fn insert(&mut self, key: K) {
        self.counters.insert(key, 1);
    }

    fn remove(&mut self, key: &K) {
        self.counters.remove(key);
    }

    /// Picks an eviction candidate: samples a handful of entries and
    /// returns whichever has the lowest counter.
    fn sample_eviction_candidate(&self) -> Option<K> {
        if self.counters.is_empty() {
            return None;
        }
        let mut best: Option<(&K, u8)> = None;
        for (k, &c) in self.counters.iter().take(LFU_SAMPLE_SIZE.max(1)) {
            if best.is_none_or(|(_, bc)| c < bc) {
                best = Some((k, c));
            }
        }
        best.map(|(k, _)| k.clone())
    }

    fn maybe_decay(&mut self) {
        self.puts_since_decay += 1;
        if self.puts_since_decay < LFU_DECAY_INTERVAL {
            return;
        }
        self.puts_since_decay = 0;
        for counter in self.counters.values_mut() {
            *counter /= 2;
        }
    }
}

/// A simple xorshift PRNG seeded from the current time -- avoids
/// pulling in a random-number crate just for LFU's sampling and
/// increment-probability decisions, neither of which need
/// cryptographic quality randomness.
fn fastrand_f64() -> f64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E3779B97F4A7C15)
                | 1, // must be nonzero for xorshift
        );
    }
    STATE.with(|state| {
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        (x >> 11) as f64 / (1u64 << 53) as f64
    })
}

enum LocalOrdering {
    Lru(LruCache<String, ()>),
    Lfu(ApproxLfu<String>),
    /// TTL_ONLY: no active ordering, entries just expire -- a plain
    /// insertion-ordered list is enough to pick *some* eviction victim
    /// (oldest-inserted) when the cache is full, without the
    /// bookkeeping cost LRU/LFU ordering requires for a policy that
    /// doesn't need it.
    TtlOnly(Vec<String>),
}

pub struct LocalCache {
    config: FileCacheConfig,
    entries: HashMap<String, CacheEntry>,
    ordering: LocalOrdering,
}

impl LocalCache {
    pub fn new(config: FileCacheConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_entries.max(1)).unwrap();
        let ordering = match config.eviction {
            EvictionPolicy::Lru => LocalOrdering::Lru(LruCache::new(cap)),
            EvictionPolicy::Lfu => LocalOrdering::Lfu(ApproxLfu::new()),
            EvictionPolicy::TtlOnly => LocalOrdering::TtlOnly(Vec::new()),
        };
        LocalCache {
            config,
            entries: HashMap::new(),
            ordering,
        }
    }

    pub fn get(&mut self, path: &str) -> Option<CacheEntry> {
        let entry = self.entries.get(path)?;
        if !self.is_fresh(entry) {
            self.remove(path);
            return None;
        }
        let entry = entry.clone();

        match &mut self.ordering {
            LocalOrdering::Lru(lru) => {
                lru.promote(path);
            }
            LocalOrdering::Lfu(lfu) => {
                lfu.record_access(&path.to_string());
            }
            LocalOrdering::TtlOnly(_) => {}
        }

        Some(entry)
    }

    fn is_fresh(&self, entry: &CacheEntry) -> bool {
        let now = Instant::now();
        if entry.negative {
            return match self.config.negative_ttl {
                Some(ttl) => now.duration_since(entry.cached_at) < ttl,
                None => false,
            };
        }

        match self.config.strategy {
            RevalidationStrategy::Ttl => now.duration_since(entry.cached_at) < self.config.ttl,
            RevalidationStrategy::StatTtl => {
                if now.duration_since(entry.cached_at) < self.config.ttl {
                    return true;
                }
                // TTL elapsed -- confirm the file hasn't changed before
                // treating it as still fresh.
                matches!(
                    std::fs::metadata(&entry.resolved_path),
                    Ok(meta) if meta.len() == entry.size
                        && meta.modified().ok() == Some(entry.mtime)
                )
            }
            RevalidationStrategy::Inotify => {
                // With an active watch, presence in the map alone means
                // fresh (a watch event removes the entry directly).
                // Without one (Watch::None but this strategy requested
                // anyway), degrade to a generous TTL multiple rather
                // than caching forever.
                now.duration_since(entry.cached_at) < self.config.ttl * 10
            }
        }
    }

    pub fn put(&mut self, path: &str, entry: CacheEntry) {
        if self.entries.len() >= self.config.max_entries && !self.entries.contains_key(path) {
            self.evict_one();
        }

        self.entries.insert(path.to_string(), entry);
        match &mut self.ordering {
            LocalOrdering::Lru(lru) => {
                lru.put(path.to_string(), ());
            }
            LocalOrdering::Lfu(lfu) => {
                lfu.insert(path.to_string());
                lfu.maybe_decay();
            }
            LocalOrdering::TtlOnly(order) => {
                order.retain(|p| p != path);
                order.push(path.to_string());
            }
        }
    }

    pub fn put_negative(&mut self, path: &str, resolved_path: PathBuf) {
        if self.config.negative_ttl.is_none() {
            return;
        }
        self.put(path, CacheEntry::negative(resolved_path));
    }

    pub fn invalidate(&mut self, path: &str) {
        self.remove(path);
    }

    fn remove(&mut self, path: &str) {
        self.entries.remove(path);
        match &mut self.ordering {
            LocalOrdering::Lru(lru) => {
                lru.pop(path);
            }
            LocalOrdering::Lfu(lfu) => {
                lfu.remove(&path.to_string());
            }
            LocalOrdering::TtlOnly(order) => {
                order.retain(|p| p != path);
            }
        }
    }

    fn evict_one(&mut self) {
        let victim = match &mut self.ordering {
            LocalOrdering::Lru(lru) => lru.pop_lru().map(|(k, _)| k),
            LocalOrdering::Lfu(lfu) => lfu.sample_eviction_candidate(),
            LocalOrdering::TtlOnly(order) => {
                if order.is_empty() {
                    None
                } else {
                    Some(order.remove(0))
                }
            }
        };
        if let Some(victim) = victim {
            self.entries.remove(&victim);
            if let LocalOrdering::Lfu(lfu) = &mut self.ordering {
                lfu.remove(&victim);
            }
        }
    }
}

// ─── SHARED_METADATA mode ───────────────────────────────────────────────
//
// Path metadata lives in a `DashMap` shared across every worker.
// Unlike a design that destroys and recreates the metadata entry on
// every put() (which would require a separate persistent
// high-water-mark table just to hand out a "definitely newer than
// before" generation number across that destroy/recreate boundary),
// this keeps the entry in place and increments its generation field
// directly -- invalidate() bumps `generation`. That removes the need
// for a second table and its own lock entirely: the generation a
// worker needs to compare against always lives on the entry itself.
//
// Mapped file content still lives per-worker (see this module's top
// doc comment for why) -- `WorkerMmapCache` tracks each worker's own
// mappings, keyed by path, and re-maps whenever its locally-remembered
// generation falls behind the shared entry's current one.

use dashmap::DashMap;
use std::sync::RwLock;

struct SharedEntry {
    resolved_path: PathBuf,
    etag: String,
    last_modified: String,
    mime_type: String,
    size: u64,
    mtime: SystemTime,
    cached_at: Instant,
    negative: bool,
    generation: u64,
}

pub struct SharedMetadataCache {
    config: FileCacheConfig,
    table: DashMap<String, SharedEntry>,
    /// Approximate insertion/access order for eviction, one per
    /// eviction policy. Kept separate from `table` (rather than
    /// intrusive pointers inside `SharedEntry`) since `DashMap`
    /// already gives safe concurrent access -- a second, simpler
    /// structure for ordering avoids needing any unsafe/intrusive
    /// linkage to keep both in sync under concurrent access.
    order: RwLock<EvictionOrder>,
}

enum EvictionOrder {
    Lru(LruCache<String, ()>),
    Lfu(ApproxLfu<String>),
    TtlOnly(Vec<String>),
}

impl SharedMetadataCache {
    pub fn new(config: FileCacheConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_entries.max(1)).unwrap();
        let order = match config.eviction {
            EvictionPolicy::Lru => EvictionOrder::Lru(LruCache::new(cap)),
            EvictionPolicy::Lfu => EvictionOrder::Lfu(ApproxLfu::new()),
            EvictionPolicy::TtlOnly => EvictionOrder::TtlOnly(Vec::new()),
        };
        SharedMetadataCache {
            config,
            table: DashMap::new(),
            order: RwLock::new(order),
        }
    }

    /// Looks up `path`'s shared metadata (not including any mapped
    /// content -- see `WorkerMmapCache::sync`, which callers combine
    /// this with). Returns the entry's current generation alongside so
    /// the caller can decide whether its own local mapping is stale.
    fn get_metadata(&self, path: &str) -> Option<(SharedMetaSnapshot, u64)> {
        let entry = self.table.get(path)?;
        if !self.is_fresh(&entry) {
            return None;
        }
        let snapshot = SharedMetaSnapshot {
            resolved_path: entry.resolved_path.clone(),
            etag: entry.etag.clone(),
            last_modified: entry.last_modified.clone(),
            mime_type: entry.mime_type.clone(),
            size: entry.size,
            mtime: entry.mtime,
            cached_at: entry.cached_at,
            negative: entry.negative,
        };
        let generation = entry.generation;
        drop(entry);

        self.touch(path);
        Some((snapshot, generation))
    }

    fn is_fresh(&self, entry: &SharedEntry) -> bool {
        let now = Instant::now();
        if entry.negative {
            return match self.config.negative_ttl {
                Some(ttl) => now.duration_since(entry.cached_at) < ttl,
                None => false,
            };
        }
        match self.config.strategy {
            RevalidationStrategy::Ttl => now.duration_since(entry.cached_at) < self.config.ttl,
            // STAT_TTL and INOTIFY both treat "still present in the
            // shared table" as fresh here: doing a stat() under the
            // table's lock would serialize every reader on disk I/O,
            // defeating the point of sharing the table. A background
            // sweep is responsible for actually revalidating STAT_TTL
            // entries and evicting stale ones (see this module's open
            // items).
            RevalidationStrategy::StatTtl | RevalidationStrategy::Inotify => true,
        }
    }

    fn touch(&self, path: &str) {
        let mut order = self.order.write().unwrap();
        match &mut *order {
            EvictionOrder::Lru(lru) => {
                lru.promote(path);
            }
            EvictionOrder::Lfu(lfu) => {
                lfu.record_access(&path.to_string());
            }
            EvictionOrder::TtlOnly(_) => {}
        }
    }

    fn put_metadata(&self, path: &str, snapshot: SharedMetaSnapshot) -> u64 {
        let generation = next_generation();

        if self.table.len() >= self.config.max_entries && !self.table.contains_key(path) {
            self.evict_one();
        }

        self.table.insert(
            path.to_string(),
            SharedEntry {
                resolved_path: snapshot.resolved_path,
                etag: snapshot.etag,
                last_modified: snapshot.last_modified,
                mime_type: snapshot.mime_type,
                size: snapshot.size,
                mtime: snapshot.mtime,
                cached_at: snapshot.cached_at,
                negative: snapshot.negative,
                generation,
            },
        );

        let mut order = self.order.write().unwrap();
        match &mut *order {
            EvictionOrder::Lru(lru) => {
                lru.put(path.to_string(), ());
            }
            EvictionOrder::Lfu(lfu) => {
                lfu.insert(path.to_string());
                lfu.maybe_decay();
            }
            EvictionOrder::TtlOnly(o) => {
                o.retain(|p| p != path);
                o.push(path.to_string());
            }
        }

        generation
    }

    fn evict_one(&self) {
        let victim = {
            let mut order = self.order.write().unwrap();
            match &mut *order {
                EvictionOrder::Lru(lru) => lru.pop_lru().map(|(k, _)| k),
                EvictionOrder::Lfu(lfu) => lfu.sample_eviction_candidate(),
                EvictionOrder::TtlOnly(o) => {
                    if o.is_empty() {
                        None
                    } else {
                        Some(o.remove(0))
                    }
                }
            }
        };
        if let Some(victim) = victim {
            self.table.remove(&victim);
            if let EvictionOrder::Lfu(lfu) = &mut *self.order.write().unwrap() {
                lfu.remove(&victim);
            }
        }
    }

    /// Removes `path`'s entry so a subsequent lookup is a clean miss.
    /// The next `put_metadata` for this path always draws a fresh
    /// generation from the shared, monotonically-increasing counter
    /// (never from whatever the replaced entry had), so there's no
    /// generation to preserve across this removal -- see this module's
    /// top doc comment.
    pub fn invalidate(&self, path: &str) {
        self.table.remove(path);
        let mut order = self.order.write().unwrap();
        match &mut *order {
            EvictionOrder::Lru(lru) => {
                lru.pop(path);
            }
            EvictionOrder::Lfu(lfu) => {
                lfu.remove(&path.to_string());
            }
            EvictionOrder::TtlOnly(o) => {
                o.retain(|p| p != path);
            }
        }
    }
}

struct SharedMetaSnapshot {
    resolved_path: PathBuf,
    etag: String,
    last_modified: String,
    mime_type: String,
    size: u64,
    mtime: SystemTime,
    cached_at: Instant,
    negative: bool,
}

/// A single worker's own mmap mappings for `SharedMetadata` mode,
/// keyed by path. Never touches another worker's mapping -- see this
/// module's top doc comment.
pub struct WorkerMmapCache {
    slots: HashMap<String, (Arc<Mmap>, u64)>, // (mapping, generation it was mapped at)
}

impl WorkerMmapCache {
    pub fn new() -> Self {
        WorkerMmapCache {
            slots: HashMap::new(),
        }
    }

    /// Returns this worker's mapping for `path` if its locally-cached
    /// generation still matches `current_generation`; otherwise
    /// (re-)maps it via `mmap_threshold`/`resolved_path`/`size` and
    /// remembers the new generation.
    fn sync(
        &mut self,
        path: &str,
        resolved_path: &Path,
        size: u64,
        current_generation: u64,
        mmap_threshold: u64,
    ) -> Option<Arc<Mmap>> {
        if let Some((mapping, gen)) = self.slots.get(path) {
            if *gen == current_generation {
                return Some(Arc::clone(mapping));
            }
        }

        // Stale or never mapped -- (re-)attempt the mapping. A failed
        // or skipped (too-large) mmap still records the generation, so
        // we don't retry the syscall on every single request for a
        // large file.
        let mapped = try_mmap(resolved_path, size, mmap_threshold)
            .ok()
            .flatten()
            .map(Arc::new);

        if let Some(m) = &mapped {
            self.slots
                .insert(path.to_string(), (Arc::clone(m), current_generation));
        } else {
            self.slots.remove(path);
        }
        mapped
    }
}

impl Default for WorkerMmapCache {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Public API: unified FileCache, dispatching to Local or SharedMetadata ──

use std::sync::Mutex;

/// The full result of a successful lookup or fresh fetch: metadata
/// plus, if the file was small enough, its mapped content ready to
/// serve. Distinct from `CacheEntry` (used internally by `LocalCache`)
/// because `SharedMetadata` mode's result combines a shared-table
/// snapshot with a per-worker mmap lookup that `CacheEntry` alone
/// doesn't carry enough information to redo on every access.
pub struct Lookup {
    pub resolved_path: PathBuf,
    pub etag: String,
    pub last_modified: String,
    pub mime_type: String,
    pub size: u64,
    pub mtime: SystemTime,
    pub negative: bool,
    pub mapped: Option<Arc<Mmap>>,
}

impl From<CacheEntry> for Lookup {
    fn from(e: CacheEntry) -> Self {
        Lookup {
            resolved_path: e.resolved_path,
            etag: e.etag,
            last_modified: e.last_modified,
            mime_type: e.mime_type,
            size: e.size,
            mtime: e.mtime,
            negative: e.negative,
            mapped: e.mapped,
        }
    }
}

enum Backend {
    Local(Mutex<LocalCache>),
    SharedMetadata(SharedMetadataCache),
}

/// The static-file cache. One instance shared (via `Arc`) across every
/// worker; each worker additionally owns its own `WorkerMmapCache` for
/// `SharedMetadata` mode (see `FileCache::worker_mmap_cache`, called
/// once per worker at startup).
pub struct FileCache {
    config: FileCacheConfig,
    backend: Backend,
}

impl FileCache {
    pub fn new(config: FileCacheConfig) -> Self {
        let backend = match config.mode {
            CacheMode::Local => Backend::Local(Mutex::new(LocalCache::new(config.clone()))),
            CacheMode::SharedMetadata => {
                Backend::SharedMetadata(SharedMetadataCache::new(config.clone()))
            }
        };
        FileCache { config, backend }
    }

    /// Constructs a fresh, empty per-worker mmap cache. Only meaningful
    /// (used) in `SharedMetadata` mode; harmless to construct
    /// regardless of mode so callers don't need to branch on it.
    pub fn worker_mmap_cache(&self) -> WorkerMmapCache {
        WorkerMmapCache::new()
    }

    /// Looks up `path`. `worker_mmap` is this worker's own mapping
    /// cache (ignored in `Local` mode, where mapped content already
    /// lives inside the worker-local `CacheEntry` itself).
    pub fn get(&self, path: &str, worker_mmap: &mut WorkerMmapCache) -> Option<Lookup> {
        match &self.backend {
            Backend::Local(local) => {
                let mut local = local.lock().unwrap();
                local.get(path).map(Lookup::from)
            }
            Backend::SharedMetadata(shared) => {
                let (snapshot, generation) = shared.get_metadata(path)?;
                if snapshot.negative {
                    return Some(Lookup {
                        resolved_path: snapshot.resolved_path,
                        etag: String::new(),
                        last_modified: String::new(),
                        mime_type: String::new(),
                        size: 0,
                        mtime: UNIX_EPOCH,
                        negative: true,
                        mapped: None,
                    });
                }
                let mapped = worker_mmap.sync(
                    path,
                    &snapshot.resolved_path,
                    snapshot.size,
                    generation,
                    self.config.mmap_threshold,
                );
                Some(Lookup {
                    resolved_path: snapshot.resolved_path,
                    etag: snapshot.etag,
                    last_modified: snapshot.last_modified,
                    mime_type: snapshot.mime_type,
                    size: snapshot.size,
                    mtime: snapshot.mtime,
                    negative: false,
                    mapped,
                })
            }
        }
    }

    /// Stores a freshly-resolved file's metadata (and, in `Local`
    /// mode, its mapped content -- `SharedMetadata` mode maps lazily
    /// per-worker on the next `get`, see `WorkerMmapCache::sync`).
    pub fn put(&self, path: &str, resolved_path: PathBuf, size: u64, mtime: SystemTime) {
        let etag = make_etag(mtime, size);
        let last_modified = crate::util::time::format_http_date(
            mtime.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        );
        let mime_type = guess_mime_type(&resolved_path).to_string();

        match &self.backend {
            Backend::Local(local) => {
                let mapped = try_mmap(&resolved_path, size, self.config.mmap_threshold)
                    .ok()
                    .flatten()
                    .map(Arc::new);
                let entry = CacheEntry {
                    resolved_path,
                    etag,
                    last_modified,
                    mime_type,
                    size,
                    mtime,
                    cached_at: Instant::now(),
                    negative: false,
                    mapped,
                };
                local.lock().unwrap().put(path, entry);
            }
            Backend::SharedMetadata(shared) => {
                shared.put_metadata(
                    path,
                    SharedMetaSnapshot {
                        resolved_path,
                        etag,
                        last_modified,
                        mime_type,
                        size,
                        mtime,
                        cached_at: Instant::now(),
                        negative: false,
                    },
                );
            }
        }
    }

    pub fn put_negative(&self, path: &str, resolved_path: PathBuf) {
        if self.config.negative_ttl.is_none() {
            return;
        }
        match &self.backend {
            Backend::Local(local) => {
                local.lock().unwrap().put_negative(path, resolved_path);
            }
            Backend::SharedMetadata(shared) => {
                shared.put_metadata(
                    path,
                    SharedMetaSnapshot {
                        resolved_path,
                        etag: String::new(),
                        last_modified: String::new(),
                        mime_type: String::new(),
                        size: 0,
                        mtime: UNIX_EPOCH,
                        cached_at: Instant::now(),
                        negative: true,
                    },
                );
            }
        }
    }

    pub fn invalidate(&self, path: &str) {
        match &self.backend {
            Backend::Local(local) => local.lock().unwrap().invalidate(path),
            Backend::SharedMetadata(shared) => shared.invalidate(path),
        }
    }
}

// ─── MIME type lookup ───────────────────────────────────────────────────

const MIME_TYPES: &[(&str, &str)] = &[
    (".html", "text/html"),
    (".htm", "text/html"),
    (".css", "text/css"),
    (".js", "application/javascript"),
    (".json", "application/json"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".gif", "image/gif"),
    (".svg", "image/svg+xml"),
    (".ico", "image/x-icon"),
    (".txt", "text/plain"),
    (".pdf", "application/pdf"),
];

pub fn guess_mime_type(path: &Path) -> &'static str {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return "application/octet-stream";
    };
    let ext_with_dot = format!(".{ext}");
    MIME_TYPES
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(&ext_with_dot))
        .map(|(_, mime)| *mime)
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub(super) fn write_temp_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    pub(super) fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "routa_file_cache_test_{}_{}",
            std::process::id(),
            fastrand_f64().to_bits()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ─── MIME type ──────────────────────────────────────────────────

    #[test]
    fn mime_type_known_extension() {
        assert_eq!(guess_mime_type(Path::new("app.js")), "application/javascript");
        assert_eq!(guess_mime_type(Path::new("style.CSS")), "text/css");
    }

    #[test]
    fn mime_type_unknown_extension_falls_back() {
        assert_eq!(
            guess_mime_type(Path::new("file.xyz")),
            "application/octet-stream"
        );
        assert_eq!(
            guess_mime_type(Path::new("no_extension")),
            "application/octet-stream"
        );
    }

    // ─── ETag ───────────────────────────────────────────────────────

    #[test]
    fn etag_is_deterministic_for_same_inputs() {
        let t = UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(make_etag(t, 500), make_etag(t, 500));
    }

    #[test]
    fn etag_differs_for_different_size() {
        let t = UNIX_EPOCH + Duration::from_secs(1000);
        assert_ne!(make_etag(t, 500), make_etag(t, 501));
    }

    // ─── LOCAL mode: basic put/get ──────────────────────────────────

    #[test]
    fn local_mode_put_then_get_hits() {
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"hello");
        let meta = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put("/a.txt", file.clone(), meta.len(), meta.modified().unwrap());
        let hit = cache.get("/a.txt", &mut mmap_cache);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.size, 5);
        assert!(!hit.negative);
        assert!(hit.mapped.is_some());
        assert_eq!(&hit.mapped.unwrap()[..], b"hello");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_mode_miss_returns_none() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();
        assert!(cache.get("/nope.txt", &mut mmap_cache).is_none());
    }

    #[test]
    fn local_mode_negative_caching() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            negative_ttl: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put_negative("/missing.txt", PathBuf::from("/missing.txt"));
        let hit = cache.get("/missing.txt", &mut mmap_cache);
        assert!(hit.is_some());
        assert!(hit.unwrap().negative);
    }

    #[test]
    fn local_mode_negative_caching_disabled_by_default() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            negative_ttl: None,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put_negative("/missing.txt", PathBuf::from("/missing.txt"));
        assert!(cache.get("/missing.txt", &mut mmap_cache).is_none());
    }

    #[test]
    fn local_mode_invalidate_removes_entry() {
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"hello");
        let meta = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put("/a.txt", file, meta.len(), meta.modified().unwrap());
        assert!(cache.get("/a.txt", &mut mmap_cache).is_some());

        cache.invalidate("/a.txt");
        assert!(cache.get("/a.txt", &mut mmap_cache).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn local_mode_lru_evicts_least_recently_used() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            eviction: EvictionPolicy::Lru,
            max_entries: 2,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        let now = SystemTime::now();
        cache.put("/a", PathBuf::from("/a"), 1, now);
        cache.put("/b", PathBuf::from("/b"), 1, now);
        // Touch /a so /b becomes the least-recently-used.
        cache.get("/a", &mut mmap_cache);
        cache.put("/c", PathBuf::from("/c"), 1, now);

        assert!(cache.get("/a", &mut mmap_cache).is_some());
        assert!(cache.get("/b", &mut mmap_cache).is_none());
        assert!(cache.get("/c", &mut mmap_cache).is_some());
    }

    // ─── SHARED_METADATA mode ────────────────────────────────────────

    #[test]
    fn shared_mode_put_then_get_hits() {
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"shared hello");
        let meta = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put("/a.txt", file, meta.len(), meta.modified().unwrap());
        let hit = cache.get("/a.txt", &mut mmap_cache);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(&hit.mapped.unwrap()[..], b"shared hello");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shared_mode_visible_across_independent_mmap_caches() {
        // Simulates two different workers: each has its own
        // WorkerMmapCache, but both see the same shared metadata table.
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"cross worker");
        let meta = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            ..Default::default()
        });
        let mut worker_a_mmap = cache.worker_mmap_cache();
        let mut worker_b_mmap = cache.worker_mmap_cache();

        cache.put("/a.txt", file, meta.len(), meta.modified().unwrap());

        let hit_a = cache.get("/a.txt", &mut worker_a_mmap);
        let hit_b = cache.get("/a.txt", &mut worker_b_mmap);
        assert!(hit_a.is_some());
        assert!(hit_b.is_some());
        assert_eq!(&hit_a.unwrap().mapped.unwrap()[..], b"cross worker");
        assert_eq!(&hit_b.unwrap().mapped.unwrap()[..], b"cross worker");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shared_mode_invalidate_visible_immediately() {
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"v1");
        let meta = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put("/a.txt", file, meta.len(), meta.modified().unwrap());
        assert!(cache.get("/a.txt", &mut mmap_cache).is_some());

        cache.invalidate("/a.txt");
        assert!(cache.get("/a.txt", &mut mmap_cache).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shared_mode_generation_change_causes_remap() {
        let dir = temp_dir();
        let file = write_temp_file(&dir, "a.txt", b"version-1");
        let meta1 = std::fs::metadata(&file).unwrap();

        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put("/a.txt", file.clone(), meta1.len(), meta1.modified().unwrap());
        let first = cache.get("/a.txt", &mut mmap_cache).unwrap();
        assert_eq!(&first.mapped.unwrap()[..], b"version-1");

        // Simulate a re-fetch after invalidation (content on disk
        // changed, then put() called again with new metadata) -- the
        // worker's mmap cache must notice the generation moved and
        // re-map rather than keep serving the old mapping.
        cache.invalidate("/a.txt");
        std::fs::write(&file, b"version-2-longer").unwrap();
        let meta2 = std::fs::metadata(&file).unwrap();
        cache.put("/a.txt", file, meta2.len(), meta2.modified().unwrap());

        let second = cache.get("/a.txt", &mut mmap_cache).unwrap();
        assert_eq!(&second.mapped.unwrap()[..], b"version-2-longer");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shared_mode_negative_caching() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            negative_ttl: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put_negative("/missing.txt", PathBuf::from("/missing.txt"));
        let hit = cache.get("/missing.txt", &mut mmap_cache);
        assert!(hit.is_some());
        assert!(hit.unwrap().negative);
    }

    // ─── Eviction policies (smoke tests -- exact victim choice for LFU
    // is probabilistic, so these only check the cache stays within its
    // configured size, not which specific key gets evicted) ─────────

    #[test]
    fn max_entries_respected_under_lru() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            eviction: EvictionPolicy::Lru,
            max_entries: 3,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();
        let now = SystemTime::now();

        for i in 0..10 {
            cache.put(&format!("/{i}"), PathBuf::from(format!("/{i}")), 1, now);
        }

        let hits = (0..10)
            .filter(|i| cache.get(&format!("/{i}"), &mut mmap_cache).is_some())
            .count();
        assert!(hits <= 3, "expected at most 3 entries retained, got {hits}");
    }

    #[test]
    fn max_entries_respected_under_lfu() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            eviction: EvictionPolicy::Lfu,
            max_entries: 3,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();
        let now = SystemTime::now();

        for i in 0..10 {
            cache.put(&format!("/{i}"), PathBuf::from(format!("/{i}")), 1, now);
        }

        let hits = (0..10)
            .filter(|i| cache.get(&format!("/{i}"), &mut mmap_cache).is_some())
            .count();
        assert!(hits <= 3, "expected at most 3 entries retained, got {hits}");
    }

    #[test]
    fn max_entries_respected_under_ttl_only() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            eviction: EvictionPolicy::TtlOnly,
            max_entries: 3,
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();
        let now = SystemTime::now();

        for i in 0..10 {
            cache.put(&format!("/{i}"), PathBuf::from(format!("/{i}")), 1, now);
        }

        let hits = (0..10)
            .filter(|i| cache.get(&format!("/{i}"), &mut mmap_cache).is_some())
            .count();
        assert!(hits <= 3, "expected at most 3 entries retained, got {hits}");
    }

    // ─── TTL expiry ─────────────────────────────────────────────────

    #[test]
    fn ttl_strategy_expires_after_duration() {
        let cache = FileCache::new(FileCacheConfig {
            mode: CacheMode::Local,
            strategy: RevalidationStrategy::Ttl,
            ttl: Duration::from_millis(20),
            ..Default::default()
        });
        let mut mmap_cache = cache.worker_mmap_cache();
        let now = SystemTime::now();

        cache.put("/a", PathBuf::from("/a"), 1, now);
        assert!(cache.get("/a", &mut mmap_cache).is_some());

        std::thread::sleep(Duration::from_millis(40));
        assert!(cache.get("/a", &mut mmap_cache).is_none());
    }
}

// ─── inotify integration ────────────────────────────────────────────────
//
// Runs on `notify`'s own background thread (the cache itself --
// `DashMap`-backed in `SharedMetadata` mode -- is already safe to
// invalidate from any thread, so there's no need to route filesystem
// events through the worker event loop just to reach it). One
// `FileWatcher` is shared (via `Arc`) across every worker; `watch_path`
// registers a resolved file path the first time it's cached, and the
// watcher's callback invalidates that same path (by its original
// request path, not the resolved filesystem path -- see
// `PathRegistry`) the moment the OS reports a change.

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::Mutex as StdMutex;

/// Maps a resolved filesystem path back to the request path(s) that
/// are cached under it, so a filesystem event (which only carries the
/// resolved path) can invalidate the right cache entries. A single
/// resolved path can back more than one request path in principle
/// (e.g. two different `static_dir` prefixes pointing at overlapping
/// directories), so this maps to a small `Vec` rather than assuming a
/// 1:1 relationship.
struct PathRegistry {
    resolved_to_request: HashMap<PathBuf, Vec<String>>,
}

impl PathRegistry {
    fn new() -> Self {
        PathRegistry {
            resolved_to_request: HashMap::new(),
        }
    }

    fn register(&mut self, resolved_path: PathBuf, request_path: &str) -> bool {
        let entry = self.resolved_to_request.entry(resolved_path).or_default();
        if entry.iter().any(|p| p == request_path) {
            return false; // already registered, no need to add a new watch
        }
        entry.push(request_path.to_string());
        true
    }

    fn request_paths_for(&self, resolved_path: &Path) -> Vec<String> {
        self.resolved_to_request
            .get(resolved_path)
            .cloned()
            .unwrap_or_default()
    }

    fn unregister(&mut self, resolved_path: &Path) {
        self.resolved_to_request.remove(resolved_path);
    }
}

/// Watches cached files for changes and invalidates them in `cache`
/// immediately, rather than waiting for TTL expiry. Only meaningful
/// when `FileCacheConfig::strategy` is `RevalidationStrategy::Inotify`
/// -- see `FileCache::with_watcher` for how a cache and watcher are
/// connected.
pub struct FileWatcher {
    watcher: StdMutex<RecommendedWatcher>,
    registry: Arc<StdMutex<PathRegistry>>,
}

impl FileWatcher {
    /// Creates a watcher whose events call `on_change(request_path)`
    /// for every registered request path backed by the resolved
    /// filesystem path that changed. Typically `on_change` is
    /// `move |path| cache.invalidate(&path)` for some `Arc<FileCache>`
    /// -- see `FileCache::with_watcher`, which wires this up directly
    /// rather than requiring every caller to repeat this boilerplate.
    pub fn new<F>(on_change: F) -> notify::Result<Self>
    where
        F: Fn(String) + Send + 'static,
    {
        let registry = Arc::new(StdMutex::new(PathRegistry::new()));
        let registry_for_callback = Arc::clone(&registry);

        let watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            let Ok(event) = res else { return };
            // Only react to events that actually indicate the cached
            // content might be stale -- modification, removal, or the
            // file being replaced (rename covers atomic
            // save-via-rename, a common editor/deploy pattern).
            if !matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Create(_)
            ) {
                return;
            }
            let registry = registry_for_callback.lock().unwrap();
            for changed_path in &event.paths {
                for request_path in registry.request_paths_for(changed_path) {
                    on_change(request_path);
                }
            }
        })?;

        Ok(FileWatcher {
            watcher: StdMutex::new(watcher),
            registry,
        })
    }

    /// Registers `resolved_path` (the real filesystem path, after any
    /// symlink resolution) to be watched, associated with
    /// `request_path` (the original request path the cache is keyed
    /// by). Safe to call repeatedly for the same path -- only the
    /// first call for a given resolved path actually adds an OS-level
    /// watch.
    pub fn watch_path(&self, resolved_path: &Path, request_path: &str) {
        let is_new = self
            .registry
            .lock()
            .unwrap()
            .register(resolved_path.to_path_buf(), request_path);
        if is_new {
            // Best-effort: a failed watch just means this entry falls
            // back to TTL-based revalidation instead, never a hard
            // error -- matches the "watch is an enhancement, not a
            // correctness requirement" stance the rest of this
            // module's strategy handling takes (e.g. `Inotify` without
            // an active watch degrading to a generous TTL multiple).
            let _ = self
                .watcher
                .lock()
                .unwrap()
                .watch(resolved_path, RecursiveMode::NonRecursive);
        }
    }

    pub fn unwatch_path(&self, resolved_path: &Path) {
        let _ = self.watcher.lock().unwrap().unwatch(resolved_path);
        self.registry.lock().unwrap().unregister(resolved_path);
    }
}

impl FileCache {
    /// Convenience: builds a `FileWatcher` wired to invalidate this
    /// cache directly, and returns it wrapped in an `Arc` so the
    /// caller can also call `watch_path` after each `put` (see
    /// `http::static_files`, which does so whenever
    /// `FileCacheConfig::strategy` is `RevalidationStrategy::Inotify`).
    /// Returns `Err` if the platform's watcher backend fails to
    /// initialize -- callers should fall back to
    /// `RevalidationStrategy::StatTtl` in that case rather than
    /// failing startup entirely.
    pub fn with_watcher(self: &Arc<Self>) -> notify::Result<Arc<FileWatcher>> {
        let cache = Arc::clone(self);
        FileWatcher::new(move |request_path| {
            cache.invalidate(&request_path);
        })
        .map(Arc::new)
    }
}

#[cfg(test)]
mod watcher_tests {
    use super::tests::{temp_dir, write_temp_file};
    use super::*;
    use std::io::Write as _;
    use std::sync::mpsc;

    #[test]
    fn file_modification_triggers_invalidation_callback() {
        let dir = temp_dir();
        let file_path = dir.join("watched.txt");
        std::fs::write(&file_path, b"v1").unwrap();

        let (tx, rx) = mpsc::channel::<String>();
        let watcher = FileWatcher::new(move |request_path| {
            tx.send(request_path).ok();
        })
        .expect("create watcher");

        watcher.watch_path(&file_path, "/watched.txt");

        // Give the watcher a moment to fully register before mutating.
        std::thread::sleep(Duration::from_millis(100));

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap();
        f.write_all(b"v2-changed").unwrap();
        f.flush().unwrap();
        drop(f);

        let received = rx.recv_timeout(Duration::from_secs(5));
        assert_eq!(received.as_deref(), Ok("/watched.txt"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn watch_integrated_with_file_cache_invalidates_on_change() {
        let dir = temp_dir();
        let file_path = write_temp_file(&dir, "a.txt", b"original");
        let meta = std::fs::metadata(&file_path).unwrap();

        let cache = Arc::new(FileCache::new(FileCacheConfig {
            mode: CacheMode::SharedMetadata,
            strategy: RevalidationStrategy::Inotify,
            ..Default::default()
        }));
        let watcher = cache.with_watcher().expect("create watcher");
        let mut mmap_cache = cache.worker_mmap_cache();

        cache.put(
            "/a.txt",
            file_path.clone(),
            meta.len(),
            meta.modified().unwrap(),
        );
        watcher.watch_path(&file_path, "/a.txt");
        assert!(cache.get("/a.txt", &mut mmap_cache).is_some());

        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&file_path, b"changed content here").unwrap();

        // Poll briefly for the watcher's background thread to process
        // the event and invalidate -- filesystem event delivery isn't
        // instantaneous.
        let mut invalidated = false;
        for _ in 0..50 {
            if cache.get("/a.txt", &mut mmap_cache).is_none() {
                invalidated = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            invalidated,
            "expected cache entry to be invalidated after file modification"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
