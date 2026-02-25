//! TCP Listener — accepts connections and spawns per-connection tasks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
use crate::connection;

static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Start the Multigres proxy server.
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", config.listen_host, config.listen_port);
    let listener = TcpListener::bind(&addr).await?;

    info!(
        addr = %addr,
        upstream = %format!("{}:{}", config.upstream_host, config.upstream_port),
        separator = %config.tenant_separator,
        context_vars = %config.context_variables.join(", "),
        "multigres listening"
    );

    if !config.superuser_bypass.is_empty() {
        info!(bypass = %config.superuser_bypass.join(", "), "superuser bypass");
    }

    let config = Arc::new(config);

    loop {
        let (socket, _) = listener.accept().await?;
        let config = Arc::clone(&config);
        let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

        tokio::spawn(async move {
            connection::handle_connection(socket, config, conn_id).await;
        });
    }
}
