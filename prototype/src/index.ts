#!/usr/bin/env node

/**
 * Multigres — Virtual Private Database for PostgreSQL
 *
 * A TCP proxy that makes tenant identity intrinsic to the connection,
 * so your ORM never knows about multi-tenancy.
 */

import { loadConfig } from "./config.js";
import { startProxy } from "./proxy.js";
import { log } from "./log.js";

const BANNER = `
  ╔══════════════════════════════════════════════════╗
  ║             M U L T I G R E S  v0.1             ║
  ║      Virtual Private Database for PostgreSQL     ║
  ╚══════════════════════════════════════════════════╝
`;

// Handle --help
if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(BANNER);
  console.log(`Usage: multigres [options]

Options:
  --config <path>          Config file path (default: multigres.conf)
  --port <number>          Listen port (default: 6432)
  --listen-host <host>     Bind address (default: 127.0.0.1)
  --upstream-host <host>   Postgres host (default: 127.0.0.1)
  --upstream-port <number> Postgres port (default: 5432)
  --separator <char>       Tenant separator in username (default: '.')
  --context <vars>         Comma-separated Postgres session variable names
                           (default: app.current_tenant_id)
  --value-separator <c>    Separator for multiple values in tenant payload
                           (default: ':')
  --superuser <names>      Comma-separated bypass usernames (default: postgres)
  --log-level <level>      debug | info | warn | error (default: info)
  --help, -h               Show this help

Environment Variables:
  MULTIGRES_PORT, MULTIGRES_HOST, MULTIGRES_UPSTREAM_HOST,
  MULTIGRES_UPSTREAM_PORT, MULTIGRES_TENANT_SEPARATOR,
  MULTIGRES_CONTEXT_VARIABLES, MULTIGRES_VALUE_SEPARATOR,
  MULTIGRES_SUPERUSER_BYPASS,
  MULTIGRES_LOG_LEVEL

How it works:
  1. Your app connects to Multigres with username 'app_user.tenant_abc'
  2. Multigres extracts the tenant ID, rewrites the username to 'app_user'
  3. After auth, Multigres injects: SET app.current_tenant_id = 'tenant_abc'
  4. All queries are scoped by RLS policies — the ORM never knows

Example:
  multigres --port 6432 --upstream-port 5432 --separator '.'
  psql -h localhost -p 6432 -U app_user.acme mydb
`);
  process.exit(0);
}

// Handle --version
if (process.argv.includes("--version") || process.argv.includes("-v")) {
  console.log("multigres 0.1.0");
  process.exit(0);
}

// Load config and start
const config = loadConfig();
log.setLevel(config.logLevel);

console.error(BANNER);

const server = startProxy(config);

// Graceful shutdown
function shutdown(signal: string): void {
  log.info("server", `${signal} received — shutting down`);
  server.close(() => {
    log.info("server", "All connections closed");
    process.exit(0);
  });

  // Force exit after 5 seconds
  setTimeout(() => {
    log.warn("server", "Forcing exit after timeout");
    process.exit(1);
  }, 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
