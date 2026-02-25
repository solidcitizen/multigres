//! Per-Connection Handler
//!
//! Async state machine managing a single client connection through:
//!   WaitStartup → Authenticating → PostAuth → Injecting → Transparent

use bytes::BytesMut;
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::protocol::{
    build_error_response, build_query_message, build_startup_message, escape_literal, quote_ident,
    try_read_backend_message, try_read_startup, StartupType, SSL_DENY,
};
use crate::stream::{ClientStream, UpstreamStream};
use crate::tls::parse_server_name;

/// Handle a single client connection through its full lifecycle.
pub async fn handle_connection(
    mut client: ClientStream,
    config: Arc<Config>,
    upstream_tls: Option<Arc<ClientConfig>>,
    conn_id: u64,
) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    debug!(conn_id, peer, "new connection");

    let timeout = Duration::from_secs(config.handshake_timeout_secs);

    // Handshake phases (startup + auth + injection) run under timeout.
    // The transparent pipe runs without timeout so long queries work.
    // Extract the server stream before awaiting copy_bidirectional so
    // the non-Send error type doesn't live across the await boundary.
    let server = match tokio::time::timeout(
        timeout,
        handshake(&mut client, &config, &upstream_tls, conn_id),
    )
    .await
    {
        Ok(Ok(Some(server))) => server,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            debug!(conn_id, error = %e, "connection ended");
            return;
        }
        Err(_) => {
            warn!(conn_id, "handshake timeout");
            send_error(
                &mut client,
                "FATAL",
                "08006",
                "handshake timeout — no StartupMessage received in time",
            )
            .await;
            return;
        }
    };

    let mut server = server;
    debug!(conn_id, "transparent pipe");
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
        debug!(conn_id, error = %e, "connection ended");
    }
}

/// Run the handshake phases: startup parsing, auth relay, context injection.
/// Returns `Some(server)` if we should enter transparent pipe mode,
/// or `None` if the connection was fully handled (cancel, superuser bypass).
async fn handshake(
    client: &mut ClientStream,
    config: &Config,
    upstream_tls: &Option<Arc<ClientConfig>>,
    conn_id: u64,
) -> Result<Option<UpstreamStream>, Box<dyn std::error::Error + Send + Sync>> {
    // ─── Phase 1: Read StartupMessage ───────────────────────────────────

    let mut buf = BytesMut::with_capacity(1024);

    let startup = loop {
        client.read_buf(&mut buf).await?;

        match try_read_startup(&mut buf) {
            Some(StartupType::SslRequest) => {
                debug!(conn_id, "SSL request denied");
                client.write_all(SSL_DENY).await?;
                continue;
            }
            Some(StartupType::CancelRequest) => {
                debug!(conn_id, "cancel request — closing");
                return Ok(None);
            }
            Some(StartupType::Startup(s)) => break s,
            None => continue,
        }
    };

    let raw_user = startup.params.get("user").cloned().unwrap_or_default();
    if raw_user.is_empty() {
        send_error(client, "FATAL", "08004", "no username in StartupMessage").await;
        return Ok(None);
    }

    let database = startup
        .params
        .get("database")
        .cloned()
        .unwrap_or_else(|| "default".into());

    // ─── Superuser bypass ───────────────────────────────────────────────

    if config.superuser_bypass.contains(&raw_user) {
        info!(conn_id, user = %raw_user, "superuser bypass");
        let mut server = connect_upstream(config, upstream_tls).await?;
        let original = build_startup_message(&startup.params);
        server.write_all(&original).await?;
        if !buf.is_empty() {
            server.write_all(&buf).await?;
        }
        // Superuser bypass: go straight to transparent pipe
        return Ok(Some(server));
    }

    // ─── Extract tenant context from username ───────────────────────────

    let sep_idx = match raw_user.find(&config.tenant_separator) {
        Some(i) => i,
        None => {
            send_error(
                client,
                "FATAL",
                "28000",
                &format!(
                    "username must contain context values separated by '{}'",
                    config.tenant_separator
                ),
            )
            .await;
            return Ok(None);
        }
    };

    let actual_user = &raw_user[..sep_idx];
    let tenant_payload = &raw_user[sep_idx + config.tenant_separator.len()..];

    if actual_user.is_empty() || tenant_payload.is_empty() {
        send_error(client, "FATAL", "28000", "empty role or context in username").await;
        return Ok(None);
    }

    let context_values: Vec<&str> = if config.context_variables.len() > 1 {
        tenant_payload.split(&config.value_separator).collect()
    } else {
        vec![tenant_payload]
    };

    if context_values.len() != config.context_variables.len() {
        send_error(
            client,
            "FATAL",
            "28000",
            &format!(
                "expected {} context value(s), got {}",
                config.context_variables.len(),
                context_values.len()
            ),
        )
        .await;
        return Ok(None);
    }

    if context_values.iter().any(|v| v.is_empty()) {
        send_error(client, "FATAL", "28000", "empty context value in username").await;
        return Ok(None);
    }

    let context_summary: String = config
        .context_variables
        .iter()
        .zip(context_values.iter())
        .map(|(var, val)| format!("{var}={val}"))
        .collect::<Vec<_>>()
        .join(", ");

    info!(
        conn_id,
        context = %context_summary,
        role = actual_user,
        database = %database,
        "tenant connection"
    );

    // ─── Phase 2: Connect to upstream ───────────────────────────────────

    let mut server = connect_upstream(config, upstream_tls).await?;
    debug!(
        conn_id,
        host = %config.upstream_host,
        port = config.upstream_port,
        "connected to upstream"
    );

    // Send rewritten StartupMessage
    let mut rewritten_params = startup.params.clone();
    rewritten_params.insert("user".into(), actual_user.to_string());
    let startup_msg = build_startup_message(&rewritten_params);
    server.write_all(&startup_msg).await?;

    if !buf.is_empty() {
        server.write_all(&buf).await?;
        buf.clear();
    }

    // ─── Phase 3: Authentication ────────────────────────────────────────

    let mut server_buf = BytesMut::with_capacity(4096);
    let mut auth_done = false;

    while !auth_done {
        server.read_buf(&mut server_buf).await?;

        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_auth_ok() {
                debug!(conn_id, "authentication OK");
                client.write_all(&msg.raw).await?;
                auth_done = true;
                break;
            }

            if msg.is_error_response() {
                warn!(conn_id, error = %msg.error_message(), "auth error from server");
            }

            client.write_all(&msg.raw).await?;

            if msg.is_auth_challenge() {
                let mut client_buf = BytesMut::with_capacity(1024);
                client.read_buf(&mut client_buf).await?;
                server.write_all(&client_buf).await?;
            }
        }
    }

    // ─── Phase 4: Post-auth — wait for ReadyForQuery ────────────────────

    let buffered_ready: BytesMut = loop {
        if server_buf.is_empty() {
            server.read_buf(&mut server_buf).await?;
        }

        let mut ready_msg = None;
        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_ready_for_query() {
                debug!(conn_id, "ReadyForQuery buffered — injecting context");
                ready_msg = Some(msg.raw);
                break;
            }

            if msg.is_error_response() {
                warn!(conn_id, error = %msg.error_message(), "post-auth error");
            }

            client.write_all(&msg.raw).await?;
        }

        if let Some(raw) = ready_msg {
            break raw;
        }
    };

    // ─── Phase 5: Inject tenant context ─────────────────────────────────

    let mut set_clauses = Vec::new();
    for (var, val) in config.context_variables.iter().zip(context_values.iter()) {
        let safe_val = escape_literal(val)?;
        set_clauses.push(format!("SET {var} = {safe_val}"));
    }
    set_clauses.push(format!("SET ROLE {}", quote_ident(actual_user)?));
    let sql = set_clauses.join("; ") + ";";

    debug!(conn_id, sql = %sql, "injecting");
    let query_msg = build_query_message(&sql);
    server.write_all(&query_msg).await?;

    // Consume server's response to our SET commands
    loop {
        server.read_buf(&mut server_buf).await?;

        let mut injection_done = false;
        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_error_response() {
                error!(conn_id, error = %msg.error_message(), "context injection failed");
                client.write_all(&msg.raw).await?;
                return Err(msg.error_message().into());
            }

            if msg.is_ready_for_query() {
                info!(
                    conn_id,
                    context = %context_summary,
                    role = actual_user,
                    "context set"
                );
                client.write_all(&buffered_ready).await?;
                injection_done = true;
                break;
            }

            if msg.is_parameter_status() {
                client.write_all(&msg.raw).await?;
            }
        }

        if injection_done {
            break;
        }
    }

    // Flush any remaining buffered server data
    if !server_buf.is_empty() {
        client.write_all(&server_buf).await?;
    }

    Ok(Some(server))
}

/// Connect to upstream Postgres, optionally wrapping in TLS.
async fn connect_upstream(
    config: &Config,
    upstream_tls: &Option<Arc<ClientConfig>>,
) -> Result<UpstreamStream, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect((&*config.upstream_host, config.upstream_port)).await?;

    if let Some(tls_config) = upstream_tls {
        let server_name = parse_server_name(&config.upstream_host)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls_config));
        let tls_stream = connector.connect(server_name, tcp).await?;
        Ok(UpstreamStream::Tls(tls_stream))
    } else {
        Ok(UpstreamStream::Plain(tcp))
    }
}

async fn send_error(client: &mut ClientStream, severity: &str, sqlstate: &str, message: &str) {
    warn!(message, "rejecting connection");
    let msg = build_error_response(severity, sqlstate, message);
    let _ = client.write_all(&msg).await;
    let _ = client.shutdown().await;
}
