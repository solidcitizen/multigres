/**
 * Pgvpd — Proxy Server
 *
 * TCP server that accepts client connections and hands them off to
 * the Connection state machine for tenant extraction and context injection.
 */

import * as net from "node:net";
import type { PgvpdConfig } from "./config.js";
import { Connection } from "./connection.js";
import { log } from "./log.js";

let connectionCounter = 0;

function nextConnId(): string {
  return `conn-${++connectionCounter}`;
}

/**
 * Start the Pgvpd proxy server.
 *
 * Returns the net.Server instance for programmatic control.
 */
export function startProxy(config: PgvpdConfig): net.Server {
  const server = net.createServer((clientSocket: net.Socket) => {
    const connId = nextConnId();
    const remote = `${clientSocket.remoteAddress}:${clientSocket.remotePort}`;
    log.debug(connId, `New connection from ${remote}`);

    // Each connection gets its own state machine
    new Connection(clientSocket, config, connId);
  });

  server.on("error", (err) => {
    log.error("server", `Server error: ${err.message}`);
  });

  server.listen(config.listenPort, config.listenHost, () => {
    log.info(
      "server",
      `Pgvpd listening on ${config.listenHost}:${config.listenPort}`,
    );
    log.info(
      "server",
      `Upstream: ${config.upstreamHost}:${config.upstreamPort}`,
    );
    log.info(
      "server",
      `Tenant separator: '${config.tenantSeparator}' | Context vars: ${config.contextVariables.join(", ")}`,
    );
    if (config.superuserBypass.length > 0) {
      log.info(
        "server",
        `Superuser bypass: ${config.superuserBypass.join(", ")}`,
      );
    }
  });

  return server;
}
