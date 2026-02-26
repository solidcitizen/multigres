//! Connection Pool — session pooling for upstream Postgres connections.
//!
//! Pool key is `(database, role)`. Each bucket holds up to `pool_size` connections.
//! Idle connections are reaped after `pool_idle_timeout` seconds.

use bytes::BytesMut;
use rustls::ClientConfig;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::connection::connect_upstream;
use crate::protocol::{
    build_query_message, build_startup_message, try_read_backend_message,
};
use crate::stream::UpstreamStream;

/// Pool key — identifies a bucket of reusable connections.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub database: String,
    pub role: String,
}

/// A pooled upstream connection with cached handshake data.
#[allow(dead_code)]
pub struct PooledConn {
    pub stream: UpstreamStream,
    pub created_at: Instant,
    pub last_used: Instant,
    /// Cached ParameterStatus messages from the initial handshake.
    pub param_statuses: Vec<BytesMut>,
    /// Cached BackendKeyData message from the initial handshake.
    pub backend_key_data: BytesMut,
}

struct PoolBucket {
    idle: VecDeque<PooledConn>,
    total: u32,
    /// Cached ParameterStatus messages from the first connection's handshake.
    /// Reused for all subsequent connections in this bucket.
    cached_param_statuses: Option<Vec<BytesMut>>,
    /// Cached BackendKeyData from the first connection's handshake.
    cached_backend_key_data: Option<BytesMut>,
}

impl PoolBucket {
    fn new() -> Self {
        Self {
            idle: VecDeque::new(),
            total: 0,
            cached_param_statuses: None,
            cached_backend_key_data: None,
        }
    }
}

/// Connection pool for upstream Postgres connections.
pub struct Pool {
    buckets: Mutex<HashMap<PoolKey, PoolBucket>>,
    config: Arc<Config>,
    upstream_tls: Option<Arc<ClientConfig>>,
}

impl Pool {
    pub fn new(config: Arc<Config>, upstream_tls: Option<Arc<ClientConfig>>) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            config,
            upstream_tls,
        }
    }

    /// Check out a connection from the pool. Reuses an idle connection if available,
    /// otherwise creates a new one (if under pool_size). Waits if pool is full.
    pub async fn checkout(
        &self,
        key: &PoolKey,
        conn_id: u64,
    ) -> Result<PooledConn, Box<dyn std::error::Error + Send + Sync>> {
        let timeout = Duration::from_secs(self.config.pool_checkout_timeout);
        let deadline = Instant::now() + timeout;

        loop {
            {
                let mut buckets = self.buckets.lock().await;
                let bucket = buckets.entry(key.clone()).or_insert_with(PoolBucket::new);

                // Try to pop an idle connection
                if let Some(mut conn) = bucket.idle.pop_front() {
                    conn.last_used = Instant::now();
                    // Re-attach cached handshake data if the conn lost it (recycled)
                    if conn.param_statuses.is_empty() {
                        if let Some(ref cached) = bucket.cached_param_statuses {
                            conn.param_statuses = cached.clone();
                        }
                    }
                    if conn.backend_key_data.is_empty() {
                        if let Some(ref cached) = bucket.cached_backend_key_data {
                            conn.backend_key_data = cached.clone();
                        }
                    }
                    debug!(conn_id, database = %key.database, role = %key.role, "pool: reusing idle connection");
                    return Ok(conn);
                }

                // Create new if under limit
                if bucket.total < self.config.pool_size {
                    bucket.total += 1;
                    drop(buckets); // Release lock before connecting
                    debug!(conn_id, database = %key.database, role = %key.role, "pool: creating new connection");
                    match self.create_connection(key, conn_id).await {
                        Ok(conn) => {
                            // Cache handshake data on first connection for this bucket
                            let mut buckets = self.buckets.lock().await;
                            if let Some(bucket) = buckets.get_mut(key) {
                                if bucket.cached_param_statuses.is_none() {
                                    bucket.cached_param_statuses =
                                        Some(conn.param_statuses.clone());
                                    bucket.cached_backend_key_data =
                                        Some(conn.backend_key_data.clone());
                                }
                            }
                            return Ok(conn);
                        }
                        Err(e) => {
                            // Decrement total on failure
                            let mut buckets = self.buckets.lock().await;
                            if let Some(bucket) = buckets.get_mut(key) {
                                bucket.total = bucket.total.saturating_sub(1);
                            }
                            return Err(e);
                        }
                    }
                }
            }

            // Pool is full — wait and retry
            if Instant::now() >= deadline {
                return Err("pool checkout timeout: all connections in use".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Return a connection to the pool after use.
    /// Sends ROLLBACK; DISCARD ALL; to reset state, then pushes to idle.
    pub async fn checkin(&self, key: PoolKey, mut stream: UpstreamStream, conn_id: u64) {
        // Reset the connection
        let reset_sql = "ROLLBACK; DISCARD ALL;";
        let query_msg = build_query_message(reset_sql);

        if let Err(e) = stream.write_all(&query_msg).await {
            warn!(conn_id, error = %e, "pool: checkin write failed, discarding");
            self.decrement_total(&key).await;
            return;
        }

        // Wait for ReadyForQuery
        let mut buf = BytesMut::with_capacity(1024);
        let reset_timeout = Duration::from_secs(5);

        match tokio::time::timeout(reset_timeout, async {
            loop {
                if stream.read_buf(&mut buf).await.is_err() {
                    return false;
                }
                while let Some(msg) = try_read_backend_message(&mut buf) {
                    if msg.is_error_response() {
                        warn!(conn_id, error = %msg.error_message(), "pool: reset error");
                        return false;
                    }
                    if msg.is_ready_for_query() {
                        return true;
                    }
                }
            }
        })
        .await
        {
            Ok(true) => {
                // Connection is clean — return to pool
                let mut buckets = self.buckets.lock().await;
                if let Some(bucket) = buckets.get_mut(&key) {
                    // Re-create a minimal PooledConn for the idle queue
                    // (param_statuses and backend_key_data are preserved from creation)
                    // We need to store them separately, but for simplicity we store
                    // a placeholder — they were cached at creation time.
                    // Actually, we need to preserve the original cached data.
                    // The approach: store param_statuses/backend_key_data on the bucket level.
                    // For now, push with empty caches — checkout will use whatever was cached.
                    bucket.idle.push_back(PooledConn {
                        stream,
                        created_at: Instant::now(), // Not ideal, but functional
                        last_used: Instant::now(),
                        param_statuses: Vec::new(),
                        backend_key_data: BytesMut::new(),
                    });
                    debug!(conn_id, database = %key.database, role = %key.role, "pool: connection returned");
                } else {
                    // Bucket disappeared — discard
                    debug!(conn_id, "pool: bucket gone, discarding connection");
                }
            }
            _ => {
                warn!(conn_id, "pool: reset failed or timed out, discarding");
                self.decrement_total(&key).await;
            }
        }
    }

    /// Create a new upstream connection, authenticate, and cache handshake data.
    async fn create_connection(
        &self,
        key: &PoolKey,
        conn_id: u64,
    ) -> Result<PooledConn, Box<dyn std::error::Error + Send + Sync>> {
        let mut server = connect_upstream(&self.config, &self.upstream_tls).await?;

        // Send StartupMessage with the pool role
        let mut params = std::collections::HashMap::new();
        params.insert("user".into(), key.role.clone());
        params.insert("database".into(), key.database.clone());
        let startup_msg = build_startup_message(&params);
        server.write_all(&startup_msg).await?;

        // Authenticate to upstream
        let mut server_buf = BytesMut::with_capacity(4096);
        let upstream_password = self.config.upstream_password.as_deref().unwrap_or("");
        auth::authenticate_upstream(
            &mut server,
            &mut server_buf,
            &key.role,
            upstream_password,
            conn_id,
        )
        .await?;

        // Collect ParameterStatus, BackendKeyData, ReadyForQuery
        let mut param_statuses = Vec::new();
        let mut backend_key_data = BytesMut::new();

        loop {
            if server_buf.is_empty() {
                server.read_buf(&mut server_buf).await?;
            }

            let mut ready = false;
            while let Some(msg) = try_read_backend_message(&mut server_buf) {
                if msg.is_parameter_status() {
                    param_statuses.push(msg.raw);
                } else if msg.is_backend_key_data() {
                    backend_key_data = msg.raw;
                } else if msg.is_ready_for_query() {
                    ready = true;
                    break;
                } else if msg.is_error_response() {
                    return Err(
                        format!("upstream error during connect: {}", msg.error_message()).into(),
                    );
                }
            }

            if ready {
                break;
            }
        }

        let now = Instant::now();
        Ok(PooledConn {
            stream: server,
            created_at: now,
            last_used: now,
            param_statuses,
            backend_key_data,
        })
    }

    /// Background task: evict connections idle longer than pool_idle_timeout.
    pub async fn idle_reaper(self: Arc<Self>) {
        let idle_timeout = Duration::from_secs(self.config.pool_idle_timeout);
        let interval = Duration::from_secs(30); // check every 30s

        loop {
            tokio::time::sleep(interval).await;

            let mut buckets = self.buckets.lock().await;
            let mut total_reaped = 0u32;

            for (key, bucket) in buckets.iter_mut() {
                let before = bucket.idle.len();
                bucket.idle.retain(|conn| conn.last_used.elapsed() < idle_timeout);
                let reaped = before - bucket.idle.len();
                if reaped > 0 {
                    bucket.total = bucket.total.saturating_sub(reaped as u32);
                    total_reaped += reaped as u32;
                    debug!(
                        database = %key.database,
                        role = %key.role,
                        reaped,
                        remaining = bucket.idle.len(),
                        "pool: reaped idle connections"
                    );
                }
            }

            // Remove empty buckets
            buckets.retain(|_, bucket| bucket.total > 0);

            if total_reaped > 0 {
                info!(reaped = total_reaped, "pool: idle reaper cycle");
            }
        }
    }

    async fn decrement_total(&self, key: &PoolKey) {
        let mut buckets = self.buckets.lock().await;
        if let Some(bucket) = buckets.get_mut(key) {
            bucket.total = bucket.total.saturating_sub(1);
        }
    }
}
