/**
 * Pgvpd — Structured Logger
 *
 * Simple logger that prefixes messages with timestamp, level, and connection ID.
 */

type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_COLORS: Record<LogLevel, string> = {
  debug: "\x1b[90m", // gray
  info: "\x1b[36m", // cyan
  warn: "\x1b[33m", // yellow
  error: "\x1b[31m", // red
};

const RESET = "\x1b[0m";

let currentLevel: LogLevel = "info";

function write(level: LogLevel, connId: string, message: string): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[currentLevel]) return;

  const timestamp = new Date().toISOString().slice(11, 23); // HH:MM:SS.mmm
  const color = LEVEL_COLORS[level];
  const tag = level.toUpperCase().padEnd(5);
  const prefix = connId ? `[${connId}] ` : "";

  process.stderr.write(
    `${color}${timestamp} ${tag}${RESET} ${prefix}${message}\n`,
  );
}

export const log = {
  setLevel(level: LogLevel): void {
    currentLevel = level;
  },

  debug(connId: string, message: string): void {
    write("debug", connId, message);
  },

  info(connId: string, message: string): void {
    write("info", connId, message);
  },

  warn(connId: string, message: string): void {
    write("warn", connId, message);
  },

  error(connId: string, message: string): void {
    write("error", connId, message);
  },
};
