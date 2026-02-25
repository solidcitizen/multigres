//! Per-Connection Handler
//!
//! Async state machine managing a single client connection through:
//!   WaitStartup → Authenticating → PostAuth → Injecting → Transparent

use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::protocol::{
    build_error_response, build_query_message, build_startup_message, escape_literal, quote_ident,
    try_read_backend_message, try_read_startup, StartupType, SSL_DENY,
};

/// Handle a single client connection through its full lifecycle.
pub async fn handle_connection(mut client: TcpStream, config: Arc<Config>, conn_id: u64) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    debug!(conn_id, peer, "new connection");

    if let Err(e) = run_connection(&mut client, &config, conn_id).await {
        debug!(conn_id, error = %e, "connection ended");
    }
}

async fn run_connection(
    client: &mut TcpStream,
    config: &Config,
    conn_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // ─── Phase 1: Read StartupMessage ───────────────────────────────────

    let mut buf = BytesMut::with_capacity(1024);

    let startup = loop {
        client.read_buf(&mut buf).await?;

        match try_read_startup(&mut buf) {
            Some(StartupType::SslRequest) => {
                debug!(conn_id, "SSL request denied");
                client.write_all(SSL_DENY).await?;
                // Client will retry with plaintext StartupMessage
                continue;
            }
            Some(StartupType::CancelRequest) => {
                debug!(conn_id, "cancel request — closing");
                return Ok(());
            }
            Some(StartupType::Startup(s)) => break s,
            None => continue, // need more data
        }
    };

    let raw_user = startup.params.get("user").cloned().unwrap_or_default();
    if raw_user.is_empty() {
        send_error(client, "FATAL", "08004", "no username in StartupMessage").await;
        return Ok(());
    }

    let database = startup
        .params
        .get("database")
        .cloned()
        .unwrap_or_else(|| "default".into());

    // ─── Superuser bypass ───────────────────────────────────────────────

    if config.superuser_bypass.contains(&raw_user) {
        info!(conn_id, user = %raw_user, "superuser bypass");
        let mut server =
            TcpStream::connect((&*config.upstream_host, config.upstream_port)).await?;
        // Forward original startup message
        let original = build_startup_message(&startup.params);
        server.write_all(&original).await?;
        // Forward any buffered data
        if !buf.is_empty() {
            server.write_all(&buf).await?;
        }
        // Transparent pipe
        tokio::io::copy_bidirectional(client, &mut server).await?;
        return Ok(());
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
            return Ok(());
        }
    };

    let actual_user = &raw_user[..sep_idx];
    let tenant_payload = &raw_user[sep_idx + config.tenant_separator.len()..];

    if actual_user.is_empty() || tenant_payload.is_empty() {
        send_error(client, "FATAL", "28000", "empty role or context in username").await;
        return Ok(());
    }

    // Split payload into multiple values if needed
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
        return Ok(());
    }

    if context_values.iter().any(|v| v.is_empty()) {
        send_error(client, "FATAL", "28000", "empty context value in username").await;
        return Ok(());
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

    let mut server = TcpStream::connect((&*config.upstream_host, config.upstream_port)).await?;
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

    // Forward any extra client data buffered after StartupMessage
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

            // Forward auth challenges, errors, etc. to client
            client.write_all(&msg.raw).await?;

            // If server sent an auth challenge expecting a client response, relay it
            if msg.is_auth_challenge() {
                let mut client_buf = BytesMut::with_capacity(1024);
                client.read_buf(&mut client_buf).await?;
                server.write_all(&client_buf).await?;
            }
        }
    }

    // ─── Phase 4: Post-auth — wait for ReadyForQuery ────────────────────

    let buffered_ready: BytesMut = loop {
        // If there's leftover data in server_buf from auth phase, process it first
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

            // Forward ParameterStatus, BackendKeyData, etc. to client
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
                // Server confirmed our SETs. Send buffered ReadyForQuery to client.
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

            // Forward ParameterStatus if server sends them for SET commands
            if msg.is_parameter_status() {
                client.write_all(&msg.raw).await?;
            }
            // CommandComplete — consume silently
        }

        if injection_done {
            break;
        }
    }

    // ─── Phase 6: Transparent pipe ──────────────────────────────────────

    debug!(conn_id, "transparent pipe");

    // Flush any remaining buffered server data
    if !server_buf.is_empty() {
        client.write_all(&server_buf).await?;
    }

    // Zero-copy bidirectional relay
    tokio::io::copy_bidirectional(client, &mut server).await?;

    Ok(())
}

async fn send_error(client: &mut TcpStream, severity: &str, sqlstate: &str, message: &str) {
    warn!(message, "rejecting connection");
    let msg = build_error_response(severity, sqlstate, message);
    let _ = client.write_all(&msg).await;
    let _ = client.shutdown().await;
}
