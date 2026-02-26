#!/usr/bin/env bash
set -euo pipefail

# Standalone runner for Drizzle ORM tests.
# Assumes pgvpd is already running on PGVPD_PORT (default 16432).

cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install --silent
fi

echo "Running Drizzle ORM tests..."
PGVPD_SUITE="${PGVPD_SUITE:-all}" npx tsx test.ts
