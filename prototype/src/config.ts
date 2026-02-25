/**
 * Pgvpd — Configuration
 *
 * Loads config from (in priority order):
 *   1. CLI flags (--port, --upstream-host, etc.)
 *   2. Environment variables (PGVPD_PORT, etc.)
 *   3. Config file (pgvpd.conf or --config path)
 *   4. Defaults
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

export interface PgvpdConfig {
  /** Port Pgvpd listens on for client connections */
  listenPort: number;

  /** Hostname to bind to */
  listenHost: string;

  /** Upstream Postgres host */
  upstreamHost: string;

  /** Upstream Postgres port */
  upstreamPort: number;

  /**
   * Character that separates the role from the tenant ID in the username.
   * Example: with separator '.', username 'app_user.tenant_abc' yields
   *   role = 'app_user', tenant = 'tenant_abc'
   */
  tenantSeparator: string;

  /**
   * Postgres session variable names for context injection.
   * Multiple variables are supported for apps that need more than one
   * dimension of identity (e.g., tenant + user).
   *
   * The tenant payload extracted from the username is split by
   * `valueSeparator` and mapped positionally to these variables.
   *
   * Example with contextVariables = ['app.current_list_id', 'app.current_user_id']
   * and valueSeparator = ':':
   *   username 'app_user.list123:user456' yields:
   *     SET app.current_list_id = 'list123';
   *     SET app.current_user_id = 'user456';
   */
  contextVariables: string[];

  /**
   * Separator for splitting the tenant payload into multiple values.
   * Only used when contextVariables has more than one entry.
   * Default: ':'
   */
  valueSeparator: string;

  /**
   * Usernames that bypass tenant extraction entirely.
   * These connections are passed through to upstream as-is.
   * Typically: ['postgres'] for admin/migration access.
   */
  superuserBypass: string[];

  /** Log level */
  logLevel: "debug" | "info" | "warn" | "error";
}

const DEFAULTS: PgvpdConfig = {
  listenPort: 6432,
  listenHost: "127.0.0.1",
  upstreamHost: "127.0.0.1",
  upstreamPort: 5432,
  tenantSeparator: ".",
  contextVariables: ["app.current_tenant_id"],
  valueSeparator: ":",
  superuserBypass: ["postgres"],
  logLevel: "info",
};

/**
 * Parse a simple key=value config file.
 * Lines starting with # are comments. Blank lines are ignored.
 */
function parseConfigFile(path: string): Record<string, string> {
  const content = readFileSync(path, "utf8");
  const result: Record<string, string> = {};

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    result[key] = value;
  }

  return result;
}

/**
 * Parse CLI arguments into a key-value map.
 * Supports: --key value, --key=value
 */
function parseCLIArgs(args: string[]): Record<string, string> {
  const result: Record<string, string> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("--")) continue;

    const eqIdx = arg.indexOf("=");
    if (eqIdx !== -1) {
      result[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
    } else if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
      result[arg.slice(2)] = args[i + 1];
      i++;
    }
  }

  return result;
}

/** Map of config file/CLI key names to config property names. */
const KEY_MAP: Record<string, keyof PgvpdConfig> = {
  port: "listenPort",
  "listen-port": "listenPort",
  listen_port: "listenPort",
  host: "listenHost",
  "listen-host": "listenHost",
  listen_host: "listenHost",
  "upstream-host": "upstreamHost",
  upstream_host: "upstreamHost",
  "upstream-port": "upstreamPort",
  upstream_port: "upstreamPort",
  "tenant-separator": "tenantSeparator",
  tenant_separator: "tenantSeparator",
  separator: "tenantSeparator",
  "context-variables": "contextVariables",
  context_variables: "contextVariables",
  context: "contextVariables",
  "value-separator": "valueSeparator",
  value_separator: "valueSeparator",
  "superuser-bypass": "superuserBypass",
  superuser_bypass: "superuserBypass",
  superuser: "superuserBypass",
  "log-level": "logLevel",
  log_level: "logLevel",
};

/** Map of environment variable names to config property names. */
const ENV_MAP: Record<string, keyof PgvpdConfig> = {
  PGVPD_PORT: "listenPort",
  PGVPD_HOST: "listenHost",
  PGVPD_UPSTREAM_HOST: "upstreamHost",
  PGVPD_UPSTREAM_PORT: "upstreamPort",
  PGVPD_TENANT_SEPARATOR: "tenantSeparator",
  PGVPD_CONTEXT_VARIABLES: "contextVariables",
  PGVPD_VALUE_SEPARATOR: "valueSeparator",
  PGVPD_SUPERUSER_BYPASS: "superuserBypass",
  PGVPD_LOG_LEVEL: "logLevel",
};

/**
 * Load configuration from all sources and merge with defaults.
 */
export function loadConfig(argv: string[] = process.argv.slice(2)): PgvpdConfig {
  const config: PgvpdConfig = { ...DEFAULTS };

  // 1. Config file (lowest priority after defaults)
  const cliArgs = parseCLIArgs(argv);
  const configPath = cliArgs["config"] || "pgvpd.conf";
  const resolvedPath = resolve(configPath);

  if (existsSync(resolvedPath)) {
    const fileValues = parseConfigFile(resolvedPath);
    applyValues(config, fileValues, KEY_MAP);
  }

  // 2. Environment variables
  const envValues: Record<string, string> = {};
  for (const [envKey, configKey] of Object.entries(ENV_MAP)) {
    const val = process.env[envKey];
    if (val !== undefined) {
      envValues[configKey] = val;
    }
  }
  applyValues(config, envValues, null);

  // 3. CLI arguments (highest priority)
  applyValues(config, cliArgs, KEY_MAP);

  return config;
}

function applyValues(
  config: PgvpdConfig,
  values: Record<string, string>,
  keyMap: Record<string, keyof PgvpdConfig> | null,
): void {
  for (const [rawKey, rawValue] of Object.entries(values)) {
    const configKey = keyMap ? keyMap[rawKey] || (rawKey as keyof PgvpdConfig) : (rawKey as keyof PgvpdConfig);
    if (!(configKey in DEFAULTS)) continue;

    switch (configKey) {
      case "listenPort":
      case "upstreamPort": {
        const num = parseInt(rawValue, 10);
        if (!isNaN(num) && num > 0 && num < 65536) {
          config[configKey] = num;
        }
        break;
      }
      case "superuserBypass":
        config.superuserBypass = rawValue.split(",").map((s) => s.trim());
        break;
      case "contextVariables":
        config.contextVariables = rawValue.split(",").map((s) => s.trim());
        break;
      case "logLevel":
        if (["debug", "info", "warn", "error"].includes(rawValue)) {
          config.logLevel = rawValue as PgvpdConfig["logLevel"];
        }
        break;
      default:
        (config as unknown as Record<string, unknown>)[configKey] = rawValue;
    }
  }
}
