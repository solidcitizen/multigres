#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# pgvpd Integration Tests
# ============================================================================
# Runs end-to-end tests against a real Postgres instance via Docker.
#
# Usage:  ./tests/run.sh
# ============================================================================

cd "$(dirname "$0")/.."

PGVPD_PORT=16432
PG_PORT=15432
PG_HOST=127.0.0.1
PG_DB=pgvpd_test
PG_USER=postgres
PG_PASS=testpass
TEST_UUID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UNKNOWN_UUID="00000000-0000-0000-0000-000000000000"

PASSED=0
FAILED=0
ERRORS=""
PGVPD_PID=""

# ─── Helpers ───────────────────────────────────────────────────────────────

cleanup() {
  if [ -n "$PGVPD_PID" ] && kill -0 "$PGVPD_PID" 2>/dev/null; then
    kill "$PGVPD_PID" 2>/dev/null || true
    wait "$PGVPD_PID" 2>/dev/null || true
  fi
  PGVPD_PID=""
}

cleanup_all() {
  cleanup
  echo ""
  echo "Stopping Postgres..."
  docker compose -f tests/docker-compose.yml down -v 2>/dev/null || true
}

trap cleanup_all EXIT

pass() {
  PASSED=$((PASSED + 1))
  echo "  PASS: $1"
}

fail() {
  FAILED=$((FAILED + 1))
  ERRORS="${ERRORS}  FAIL: $1\n"
  echo "  FAIL: $1"
}

start_pgvpd() {
  local config="$1"
  local logfile="tests/pgvpd-test.log"
  ./target/debug/pgvpd --config "$config" > "$logfile" 2>&1 &
  PGVPD_PID=$!
  # Wait for pgvpd to start accepting connections
  local retries=0
  while ! nc -z $PG_HOST $PGVPD_PORT 2>/dev/null; do
    retries=$((retries + 1))
    if [ $retries -gt 30 ]; then
      echo "ERROR: pgvpd did not start within 3 seconds"
      cat "$logfile"
      exit 1
    fi
    sleep 0.1
  done
}

stop_pgvpd() {
  if [ -n "$PGVPD_PID" ] && kill -0 "$PGVPD_PID" 2>/dev/null; then
    kill "$PGVPD_PID" 2>/dev/null || true
    wait "$PGVPD_PID" 2>/dev/null || true
  fi
  PGVPD_PID=""
}

pgvpd_log() {
  cat tests/pgvpd-test.log 2>/dev/null || true
}

# Run a psql command through pgvpd; captures stdout
run_psql() {
  local user="$1"
  shift
  PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "$user" -d $PG_DB \
    -t -A --no-psqlrc "$@" 2>&1 || true
}

# Run a psql command through pgvpd with a specific password
run_psql_pw() {
  local user="$1"
  local pw="$2"
  shift 2
  PGPASSWORD="$pw" psql -h $PG_HOST -p $PGVPD_PORT -U "$user" -d $PG_DB \
    -t -A --no-psqlrc "$@" 2>&1 || true
}

# ─── Start Postgres ───────────────────────────────────────────────────────

echo "Starting Postgres..."
docker compose -f tests/docker-compose.yml up -d --wait

echo "Loading fixtures..."
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d $PG_DB \
  -f tests/fixtures.sql -v ON_ERROR_STOP=1 > /dev/null

echo "Building pgvpd..."
cargo build --quiet

# ═══════════════════════════════════════════════════════════════════════════
# Suite 1: Passthrough Mode
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 1: Passthrough Mode ═══"
start_pgvpd tests/pgvpd-test.conf

# Test 1.1: Tenant A isolation
result=$(run_psql "app_user.tenant_a" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Alice Corp" && echo "$result" | grep -q "Alice LLC" && ! echo "$result" | grep -q "Bob"; then
  pass "1.1 Tenant A isolation — sees only tenant_a rows"
else
  fail "1.1 Tenant A isolation — unexpected result: $result"
fi

# Test 1.2: Tenant B isolation
result=$(run_psql "app_user.tenant_b" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Bob Inc" && echo "$result" | grep -q "Bob Ltd" && ! echo "$result" | grep -q "Alice"; then
  pass "1.2 Tenant B isolation — sees only tenant_b rows"
else
  fail "1.2 Tenant B isolation — unexpected result: $result"
fi

# Test 1.3: Superuser bypass
result=$(run_psql "postgres" -c "SELECT count(*) FROM tenants")
if echo "$result" | grep -q "4"; then
  pass "1.3 Superuser bypass — sees all 4 rows"
else
  fail "1.3 Superuser bypass — unexpected result: $result"
fi

# Test 1.4: Bad username (no separator)
result=$(run_psql "baduser" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "fatal\|error\|refused\|closed"; then
  pass "1.4 Bad username — connection rejected"
else
  fail "1.4 Bad username — expected error, got: $result"
fi

# Test 1.5: Context variable set
result=$(run_psql "app_user.tenant_a" -c "SELECT current_setting('app.current_tenant_id', true)")
if echo "$result" | grep -q "tenant_a"; then
  pass "1.5 Context variable — app.current_tenant_id = tenant_a"
else
  fail "1.5 Context variable — unexpected result: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 2: Pool Mode
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 2: Pool Mode ═══"
start_pgvpd tests/pgvpd-pool-test.conf

# Test 2.1: Pool auth + tenant isolation
result=$(run_psql "app_user.tenant_a" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Alice Corp" && ! echo "$result" | grep -q "Bob"; then
  pass "2.1 Pool auth + isolation — tenant_a isolated"
else
  fail "2.1 Pool auth + isolation — unexpected result: $result"
fi

# Test 2.2: Bad pool password
result=$(run_psql_pw "app_user.tenant_a" "wrongpass" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "fatal\|error\|refused\|denied\|closed\|password"; then
  pass "2.2 Bad pool password — rejected"
else
  fail "2.2 Bad pool password — expected error, got: $result"
fi

# Test 2.3: Superuser bypass in pool mode
result=$(run_psql "postgres" -c "SELECT count(*) FROM tenants")
if echo "$result" | grep -q "4"; then
  pass "2.3 Superuser bypass (pool mode) — sees all rows"
else
  fail "2.3 Superuser bypass (pool mode) — unexpected result: $result"
fi

# Test 2.4: Pool reuse — first connection returns to pool, second reuses it
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
sleep 0.3
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
if pgvpd_log | grep -q "reusing idle connection"; then
  pass "2.4 Pool reuse — idle connection reused"
else
  fail "2.4 Pool reuse — no 'reusing idle connection' in logs"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 3: Resolvers
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 3: Resolvers ═══"
start_pgvpd tests/pgvpd-resolver-test.conf

# Test 3.1: Resolver populates context
result=$(run_psql "app_user.$TEST_UUID" -c "SELECT current_setting('app.org_id', true)")
if echo "$result" | grep -q "11111111-2222-3333-4444-555555555555"; then
  pass "3.1 Resolver populates context — app.org_id resolved"
else
  fail "3.1 Resolver populates context — unexpected result: $result"
fi

# Also check org_role
result=$(run_psql "app_user.$TEST_UUID" -c "SELECT current_setting('app.org_role', true)")
if echo "$result" | grep -q "admin"; then
  pass "3.1b Resolver populates context — app.org_role = admin"
else
  fail "3.1b Resolver populates context — unexpected org_role: $result"
fi

# Test 3.2: Resolver no rows (unknown UUID)
result=$(run_psql "app_user.$UNKNOWN_UUID" -c "SELECT current_setting('app.org_id', true)")
# With required=false and no rows, the variable should be empty or unset
if [ -z "$(echo "$result" | tr -d '[:space:]')" ] || echo "$result" | grep -q "^$"; then
  pass "3.2 Resolver no rows — app.org_id empty (fail-closed)"
else
  fail "3.2 Resolver no rows — expected empty, got: $result"
fi

# Test 3.3: Cache hit
# First connection populates cache
run_psql "app_user.$TEST_UUID" -c "SELECT 1" > /dev/null 2>&1
# Second connection should hit cache
run_psql "app_user.$TEST_UUID" -c "SELECT 1" > /dev/null 2>&1
if pgvpd_log | grep -q "cache hit"; then
  pass "3.3 Cache hit — resolver result cached"
else
  fail "3.3 Cache hit — no 'cache hit' in logs"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 4: Admin API
# ═══════════════════════════════════════════════════════════════════════════

ADMIN_PORT=19090

echo ""
echo "═══ Suite 4: Admin API ═══"
start_pgvpd tests/pgvpd-admin-test.conf

# Wait for admin port to be ready
retries=0
while ! nc -z $PG_HOST $ADMIN_PORT 2>/dev/null; do
  retries=$((retries + 1))
  if [ $retries -gt 30 ]; then
    echo "ERROR: admin API did not start within 3 seconds"
    pgvpd_log
    fail "4.0 Admin API startup"
    stop_pgvpd
    break
  fi
  sleep 0.1
done

# Test 4.1: Health endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/health)
if echo "$result" | grep -q '"status":"ok"'; then
  pass "4.1 /health — returns ok"
else
  fail "4.1 /health — unexpected result: $result"
fi

# Test 4.2: Metrics endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/metrics)
if echo "$result" | grep -q "pgvpd_connections_total" && echo "$result" | grep -q "pgvpd_pool_checkouts_total"; then
  pass "4.2 /metrics — contains expected metric names"
else
  fail "4.2 /metrics — unexpected result: $result"
fi

# Test 4.3: Status endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/status)
if echo "$result" | grep -q '"connections_total"' && echo "$result" | grep -q '"pool"'; then
  pass "4.3 /status — returns JSON with pool info"
else
  fail "4.3 /status — unexpected result: $result"
fi

# Test 4.4: Metrics update after a connection
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
sleep 0.3
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/metrics)
if echo "$result" | grep -q "pgvpd_connections_total [1-9]"; then
  pass "4.4 /metrics — connections_total incremented after connection"
else
  fail "4.4 /metrics — connections_total not incremented: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════

TOTAL=$((PASSED + FAILED))
echo ""
echo "═══════════════════════════════════"
echo "  Results: $PASSED/$TOTAL passed"
if [ $FAILED -gt 0 ]; then
  echo ""
  echo -e "$ERRORS"
  echo "═══════════════════════════════════"
  exit 1
else
  echo "  All tests passed."
  echo "═══════════════════════════════════"
  exit 0
fi
