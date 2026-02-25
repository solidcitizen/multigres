/**
 * Pgvpd — Per-Connection Handler
 *
 * State machine managing the lifecycle of a single client connection:
 *
 *   WAIT_STARTUP ──→ Parse StartupMessage, extract tenant from username
 *        │              Rewrite username, connect to upstream
 *        ▼
 *   AUTHENTICATING ──→ Proxy auth messages bidirectionally
 *        │              Detect AuthenticationOk from server
 *        ▼
 *   POST_AUTH ──────→ Forward ParameterStatus, BackendKeyData to client
 *        │              When ReadyForQuery arrives: buffer it, move to INJECTING
 *        ▼
 *   INJECTING ──────→ Send SET commands to upstream
 *        │              Consume server response (CommandComplete, ReadyForQuery)
 *        │              Forward buffered ReadyForQuery to client
 *        ▼
 *   TRANSPARENT ────→ Bidirectional pipe — all traffic forwarded as-is
 */

import * as net from "node:net";
import {
  MessageFramer,
  parseStartupMessage,
  buildStartupMessage,
  buildQueryMessage,
  buildErrorResponse,
  isSSLRequest,
  isCancelRequest,
  isAuthOk,
  isReadyForQuery,
  isErrorResponse,
  extractErrorMessage,
  SSL_DENY,
  BackendMsg,
  type BackendMessage,
} from "./protocol.js";
import type { PgvpdConfig } from "./config.js";
import { log } from "./log.js";

enum State {
  WAIT_STARTUP = "WAIT_STARTUP",
  CONNECTING = "CONNECTING",
  AUTHENTICATING = "AUTHENTICATING",
  POST_AUTH = "POST_AUTH",
  INJECTING = "INJECTING",
  TRANSPARENT = "TRANSPARENT",
  CLOSED = "CLOSED",
}

export class Connection {
  private state: State = State.WAIT_STARTUP;
  private clientFramer = new MessageFramer();
  private serverFramer = new MessageFramer();
  private upstream: net.Socket | null = null;
  private contextValues: string[] = [];
  private actualUser: string | null = null;
  private isBypass = false;
  private bufferedReadyForQuery: Buffer | null = null;
  private connId: string;

  constructor(
    private client: net.Socket,
    private config: PgvpdConfig,
    connId: string,
  ) {
    this.connId = connId;

    client.on("data", (data: Buffer) => this.onClientData(data));
    client.on("error", (err) => this.handleError("client", err));
    client.on("close", () => this.cleanup("client closed"));
  }

  // ─── Client Data Handler ────────────────────────────────────────────────

  private onClientData(data: Buffer): void {
    try {
      switch (this.state) {
        case State.WAIT_STARTUP:
          this.handleStartupData(data);
          break;

        case State.AUTHENTICATING:
        case State.POST_AUTH:
          // Forward client auth messages to server
          this.upstream?.write(data);
          break;

        case State.INJECTING:
          // Client shouldn't be sending data yet (they haven't received
          // ReadyForQuery), but buffer it just in case
          this.clientFramer.push(data);
          break;

        case State.TRANSPARENT:
          // Direct pipe to upstream
          this.upstream?.write(data);
          break;

        default:
          break;
      }
    } catch (err) {
      this.handleError("client-handler", err as Error);
    }
  }

  // ─── Startup Phase ──────────────────────────────────────────────────────

  private handleStartupData(data: Buffer): void {
    this.clientFramer.push(data);
    const msg = this.clientFramer.nextStartupMessage();
    if (!msg) return; // need more data

    // Handle SSLRequest — deny and wait for the real StartupMessage
    if (isSSLRequest(msg)) {
      log.debug(this.connId, "SSL request denied");
      this.client.write(SSL_DENY);
      // Client will retry with a plaintext StartupMessage
      return; // stay in WAIT_STARTUP
    }

    // Handle CancelRequest — not supported in v0.1
    if (isCancelRequest(msg)) {
      log.debug(this.connId, "Cancel request — closing");
      this.client.end();
      this.state = State.CLOSED;
      return;
    }

    // Parse the StartupMessage
    const startup = parseStartupMessage(msg);
    const rawUser = startup.params.get("user");

    if (!rawUser) {
      this.sendErrorAndClose("FATAL", "08004", "No username in StartupMessage");
      return;
    }

    // Check for superuser bypass
    if (this.config.superuserBypass.includes(rawUser)) {
      log.info(this.connId, `Superuser bypass: ${rawUser}`);
      this.isBypass = true;
      this.connectUpstream(msg); // forward original message as-is
      return;
    }

    // Extract tenant context from username
    const sepIdx = rawUser.indexOf(this.config.tenantSeparator);
    if (sepIdx === -1) {
      this.sendErrorAndClose(
        "FATAL",
        "28000",
        `Username must contain context values separated by '${this.config.tenantSeparator}'`,
        `Expected format: role${this.config.tenantSeparator}value1 (e.g. app_user${this.config.tenantSeparator}acme)`,
      );
      return;
    }

    this.actualUser = rawUser.slice(0, sepIdx);
    const tenantPayload = rawUser.slice(sepIdx + 1);

    if (!this.actualUser || !tenantPayload) {
      this.sendErrorAndClose(
        "FATAL",
        "28000",
        "Empty role or context values in username",
      );
      return;
    }

    // Split payload into multiple values if multiple context variables configured
    if (this.config.contextVariables.length > 1) {
      this.contextValues = tenantPayload.split(this.config.valueSeparator);
    } else {
      this.contextValues = [tenantPayload];
    }

    if (this.contextValues.length !== this.config.contextVariables.length) {
      this.sendErrorAndClose(
        "FATAL",
        "28000",
        `Expected ${this.config.contextVariables.length} context value(s), got ${this.contextValues.length}`,
        `Context variables: ${this.config.contextVariables.join(", ")}. Separate values with '${this.config.valueSeparator}'.`,
      );
      return;
    }

    if (this.contextValues.some((v) => !v)) {
      this.sendErrorAndClose("FATAL", "28000", "Empty context value in username");
      return;
    }

    const contextSummary = this.config.contextVariables
      .map((v, i) => `${v}=${this.contextValues[i]}`)
      .join(", ");
    log.info(
      this.connId,
      `Context: ${contextSummary} | Role: ${this.actualUser} | DB: ${startup.params.get("database") || "default"}`,
    );

    // Rewrite the StartupMessage with the actual username
    const newParams = new Map(startup.params);
    newParams.set("user", this.actualUser);
    const rewrittenMsg = buildStartupMessage(newParams);

    this.connectUpstream(rewrittenMsg);
  }

  // ─── Upstream Connection ────────────────────────────────────────────────

  private connectUpstream(startupMsg: Buffer): void {
    this.state = State.CONNECTING;

    this.upstream = net.createConnection(
      {
        host: this.config.upstreamHost,
        port: this.config.upstreamPort,
      },
      () => {
        log.debug(
          this.connId,
          `Connected to upstream ${this.config.upstreamHost}:${this.config.upstreamPort}`,
        );

        // Send the (possibly rewritten) StartupMessage
        this.upstream!.write(startupMsg);

        // If any extra client data was buffered after the StartupMessage, forward it
        if (this.clientFramer.hasData()) {
          this.upstream!.write(this.clientFramer.drain());
        }

        this.state = this.isBypass ? State.TRANSPARENT : State.AUTHENTICATING;

        if (this.isBypass) {
          // For bypass connections, go straight to transparent pipe
          this.enterTransparent();
        }
      },
    );

    this.upstream.on("data", (data: Buffer) => this.onServerData(data));
    this.upstream.on("error", (err) => this.handleError("upstream", err));
    this.upstream.on("close", () => this.cleanup("upstream closed"));
  }

  // ─── Server Data Handler ────────────────────────────────────────────────

  private onServerData(data: Buffer): void {
    try {
      switch (this.state) {
        case State.TRANSPARENT:
          // Direct pipe to client
          this.client.write(data);
          break;

        case State.AUTHENTICATING:
          this.handleAuthData(data);
          break;

        case State.POST_AUTH:
          this.handlePostAuthData(data);
          break;

        case State.INJECTING:
          this.handleInjectionResponse(data);
          break;

        default:
          // Forward anyway as a safety net
          this.client.write(data);
          break;
      }
    } catch (err) {
      this.handleError("server-handler", err as Error);
    }
  }

  // ─── Authentication Phase ───────────────────────────────────────────────

  private handleAuthData(data: Buffer): void {
    this.serverFramer.push(data);

    let msg: BackendMessage | null;
    while ((msg = this.serverFramer.nextBackendMessage()) !== null) {
      if (isAuthOk(msg)) {
        log.debug(this.connId, "Authentication OK");
        this.client.write(msg.raw);
        this.state = State.POST_AUTH;

        // Process any remaining buffered messages in POST_AUTH mode
        if (this.serverFramer.hasData()) {
          this.handlePostAuthData(this.serverFramer.drain());
        }
        return;
      }

      if (isErrorResponse(msg)) {
        const errMsg = extractErrorMessage(msg);
        log.warn(this.connId, `Auth error from server: ${errMsg}`);
      }

      // Forward all auth messages to client (auth challenges, errors, etc.)
      this.client.write(msg.raw);
    }
  }

  // ─── Post-Auth Phase ────────────────────────────────────────────────────

  private handlePostAuthData(data: Buffer): void {
    this.serverFramer.push(data);

    let msg: BackendMessage | null;
    while ((msg = this.serverFramer.nextBackendMessage()) !== null) {
      if (isReadyForQuery(msg)) {
        // Buffer ReadyForQuery — don't send to client yet
        this.bufferedReadyForQuery = msg.raw;
        log.debug(this.connId, "ReadyForQuery buffered — injecting tenant context");
        this.injectTenantContext();
        return;
      }

      if (isErrorResponse(msg)) {
        const errMsg = extractErrorMessage(msg);
        log.warn(this.connId, `Post-auth error: ${errMsg}`);
      }

      // Forward ParameterStatus, BackendKeyData, NoticeResponse, etc.
      this.client.write(msg.raw);
    }
  }

  // ─── Context Injection ──────────────────────────────────────────────────

  private injectTenantContext(): void {
    this.state = State.INJECTING;

    // Build SET commands for each context variable.
    // Values are sanitized defensively even though they come from
    // the username field of the StartupMessage.
    const setClauses = this.config.contextVariables.map((varName, i) => {
      const safeValue = escapeLiteral(this.contextValues[i]);
      return `SET ${varName} = ${safeValue}`;
    });

    // Final SET ROLE enforces NOBYPASSRLS
    setClauses.push(`SET ROLE ${quoteIdent(this.actualUser!)}`);

    const sql = setClauses.join("; ") + ";";

    log.debug(this.connId, `Injecting: ${sql}`);
    this.upstream!.write(buildQueryMessage(sql));
  }

  private handleInjectionResponse(data: Buffer): void {
    this.serverFramer.push(data);

    let msg: BackendMessage | null;
    while ((msg = this.serverFramer.nextBackendMessage()) !== null) {
      if (isErrorResponse(msg)) {
        const errMsg = extractErrorMessage(msg);
        log.error(this.connId, `Context injection failed: ${errMsg}`);
        // Forward the error to the client and close
        this.client.write(msg.raw);
        this.cleanup("injection failed");
        return;
      }

      if (isReadyForQuery(msg)) {
        // Server has processed our SET commands.
        // Now send the buffered ReadyForQuery to the client.
        const summary = this.config.contextVariables
          .map((v, i) => `${v}=${this.contextValues[i]}`)
          .join(", ");
        log.info(this.connId, `Context set — ${summary}, role=${this.actualUser}`);

        if (this.bufferedReadyForQuery) {
          this.client.write(this.bufferedReadyForQuery);
          this.bufferedReadyForQuery = null;
        }

        // Flush any client data that arrived during injection
        if (this.clientFramer.hasData()) {
          this.upstream!.write(this.clientFramer.drain());
        }

        this.enterTransparent();
        return;
      }

      // CommandComplete ('C') for our SET commands — consume silently
      // ParameterStatus ('S') — forward to client (server may send these for SET)
      if (msg.type === BackendMsg.ParameterStatus) {
        this.client.write(msg.raw);
      }
      // Everything else from our injection (CommandComplete, etc.) — consume
    }
  }

  // ─── Transparent Pipe ───────────────────────────────────────────────────

  private enterTransparent(): void {
    this.state = State.TRANSPARENT;
    log.debug(this.connId, "Entering transparent pipe mode");

    // Flush any remaining buffered server data
    if (this.serverFramer.hasData()) {
      this.client.write(this.serverFramer.drain());
    }
  }

  // ─── Error Handling ─────────────────────────────────────────────────────

  private sendErrorAndClose(
    severity: string,
    sqlstate: string,
    message: string,
    detail?: string,
  ): void {
    log.warn(this.connId, `Rejecting: ${message}`);
    this.client.write(buildErrorResponse(severity, sqlstate, message, detail));
    this.client.end();
    this.state = State.CLOSED;
  }

  private handleError(source: string, err: Error): void {
    if ((err as NodeJS.ErrnoException).code === "ECONNRESET") {
      log.debug(this.connId, `${source} connection reset`);
    } else {
      log.error(this.connId, `${source} error: ${err.message}`);
    }
    this.cleanup(`${source} error`);
  }

  private cleanup(reason: string): void {
    if (this.state === State.CLOSED) return;
    this.state = State.CLOSED;

    log.debug(this.connId, `Closing: ${reason}`);

    this.client.destroy();
    this.upstream?.destroy();
    this.upstream = null;
  }
}

// ─── SQL Escaping ───────────────────────────────────────────────────────────

/**
 * Escape a string as a SQL literal (single-quoted, with ' doubled).
 * This is intentionally conservative — only allows alphanumeric, underscore,
 * hyphen, and dot characters. Everything else is rejected.
 */
function escapeLiteral(value: string): string {
  // Reject any characters that have no business being in a tenant ID
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(value)) {
    throw new Error(`Invalid tenant ID: contains disallowed characters: ${value}`);
  }
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * Quote an identifier (double-quoted, with " doubled).
 * Same conservative character check.
 */
function quoteIdent(value: string): string {
  if (!/^[a-zA-Z0-9_]+$/.test(value)) {
    throw new Error(`Invalid identifier: ${value}`);
  }
  return `"${value.replace(/"/g, '""')}"`;
}
