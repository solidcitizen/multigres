//! TCP Listener — accepts connections and spawns per-connection tasks.
//! Supports both plain and TLS listeners.

use rustls::ClientConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::config::{Config, PoolMode};
use crate::connection;
use crate::pool::Pool;
use crate::stream::ClientStream;
use crate::tls;

static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Start the Pgvpd proxy server.
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    config.validate().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // ─── Build TLS state once at startup ────────────────────────────────

    // TLS termination (client → Pgvpd)
    let tls_acceptor = match (&config.tls_port, &config.tls_cert, &config.tls_key) {
        (Some(_), Some(cert), Some(key)) => {
            let server_config = tls::build_server_config(cert, key)?;
            Some(TlsAcceptor::from(server_config))
        }
        _ => None,
    };

    // TLS origination (Pgvpd → upstream)
    let upstream_tls: Option<Arc<ClientConfig>> = if config.upstream_tls {
        Some(tls::build_client_config(
            config.upstream_tls_verify,
            config.upstream_tls_ca.as_deref(),
        )?)
    } else {
        None
    };

    // ─── Connection pool (if configured) ────────────────────────────────

    let config = Arc::new(config);

    let pool: Option<Arc<Pool>> = if config.pool_mode == PoolMode::Session {
        let pool = Arc::new(Pool::new(Arc::clone(&config), upstream_tls.clone()));
        // Spawn idle reaper background task
        let reaper_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            reaper_pool.idle_reaper().await;
        });
        info!(
            pool_mode = %config.pool_mode,
            pool_size = config.pool_size,
            idle_timeout = config.pool_idle_timeout,
            checkout_timeout = config.pool_checkout_timeout,
            "connection pool"
        );
        Some(pool)
    } else {
        None
    };

    // ─── Plain listener (always starts) ─────────────────────────────────

    let plain_addr = format!("{}:{}", config.listen_host, config.listen_port);
    let plain_listener = TcpListener::bind(&plain_addr).await?;

    info!(
        addr = %plain_addr,
        upstream = %format!("{}:{}", config.upstream_host, config.upstream_port),
        separator = %config.tenant_separator,
        context_vars = %config.context_variables.join(", "),
        "plain listener"
    );

    if !config.superuser_bypass.is_empty() {
        info!(bypass = %config.superuser_bypass.join(", "), "superuser bypass");
    }

    if upstream_tls.is_some() {
        info!(
            verify = config.upstream_tls_verify,
            "upstream TLS enabled"
        );
    }

    info!(
        timeout_secs = config.handshake_timeout_secs,
        "handshake timeout"
    );

    // ─── TLS listener (if configured) ───────────────────────────────────

    if let (Some(tls_port), Some(acceptor)) = (config.tls_port, tls_acceptor) {
        let tls_addr = format!("{}:{}", config.listen_host, tls_port);
        let tls_listener = TcpListener::bind(&tls_addr).await?;
        info!(addr = %tls_addr, "TLS listener");

        let tls_config = Arc::clone(&config);
        let tls_upstream = upstream_tls.clone();
        let tls_pool = pool.clone();

        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((socket, _)) => {
                        let config = Arc::clone(&tls_config);
                        let upstream = tls_upstream.clone();
                        let pool = tls_pool.clone();
                        let acceptor = acceptor.clone();
                        let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

                        tokio::spawn(async move {
                            match acceptor.accept(socket).await {
                                Ok(tls_stream) => {
                                    let client = ClientStream::Tls(tls_stream);
                                    connection::handle_connection(
                                        client, config, upstream, pool, conn_id,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(conn_id, error = %e, "TLS handshake failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "TLS accept error");
                    }
                }
            }
        });
    }

    // ─── Plain accept loop (runs on main task) ──────────────────────────

    loop {
        let (socket, _) = plain_listener.accept().await?;
        let config = Arc::clone(&config);
        let upstream = upstream_tls.clone();
        let pool = pool.clone();
        let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

        tokio::spawn(async move {
            let client = ClientStream::Plain(socket);
            connection::handle_connection(client, config, upstream, pool, conn_id).await;
        });
    }
}
