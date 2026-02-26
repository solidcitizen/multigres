//! Shared metrics — atomic counters for observability.
//!
//! Wrapped in `Arc<Metrics>` and passed to pool, resolver, and connection handler.
//! No external crate needed — we format Prometheus exposition text manually.

use std::sync::atomic::{AtomicU64, Ordering};

/// Shared metrics counters, all lock-free via AtomicU64.
pub struct Metrics {
    // ─── Connections ─────────────────────────────────────────────────────
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,

    // ─── Pool ────────────────────────────────────────────────────────────
    pub pool_checkouts: AtomicU64,
    pub pool_reuses: AtomicU64,
    pub pool_creates: AtomicU64,
    pub pool_checkins: AtomicU64,
    pub pool_discards: AtomicU64,
    pub pool_timeouts: AtomicU64,

    // ─── Resolvers ───────────────────────────────────────────────────────
    pub resolver_cache_hits: AtomicU64,
    pub resolver_cache_misses: AtomicU64,
    /// Per-resolver execution counts (indexed by resolver order).
    pub resolver_executions: Vec<AtomicU64>,
    /// Per-resolver error counts (indexed by resolver order).
    pub resolver_errors: Vec<AtomicU64>,
    /// Resolver names for label rendering (indexed by resolver order).
    pub resolver_names: Vec<String>,
}

impl Metrics {
    /// Create a new Metrics instance with zeroed counters.
    /// `resolver_names` determines the size of per-resolver vectors.
    pub fn new(resolver_names: Vec<String>) -> Self {
        let n = resolver_names.len();
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            pool_checkouts: AtomicU64::new(0),
            pool_reuses: AtomicU64::new(0),
            pool_creates: AtomicU64::new(0),
            pool_checkins: AtomicU64::new(0),
            pool_discards: AtomicU64::new(0),
            pool_timeouts: AtomicU64::new(0),
            resolver_cache_hits: AtomicU64::new(0),
            resolver_cache_misses: AtomicU64::new(0),
            resolver_executions: (0..n).map(|_| AtomicU64::new(0)).collect(),
            resolver_errors: (0..n).map(|_| AtomicU64::new(0)).collect(),
            resolver_names,
        }
    }

    /// Increment a counter by 1 and return the previous value.
    #[inline]
    pub fn inc(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Decrement a counter by 1 (saturating).
    #[inline]
    pub fn dec(counter: &AtomicU64) {
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}
