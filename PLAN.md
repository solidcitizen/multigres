# Pgvpd — Virtual Private Database for PostgreSQL

## The Problem

Every multi-tenant application on Postgres faces the same architectural gap:

**Postgres has the policy engine (RLS) but not the session-identity primitive.**

Oracle solved this decades ago with Virtual Private Database (VPD). You set an
application context via `DBMS_SESSION.SET_CONTEXT`, and every query on that
connection is transparently scoped to the tenant. The ORM never knows. The
application code never filters by `tenant_id`. The database *is* the security
boundary.

Postgres RLS can do the same filtering — but someone has to call `SET
app.current_tenant_id` on every connection, and if they forget, the failure
mode is **fail-open**: the query runs as a superuser and returns all tenants'
data. Every ORM, every connection pool, every middleware framework treats
connections as fungible resources. None of them understand that a connection
carries identity.

The result: every team hand-rolls the same AsyncLocalStorage + Proxy +
connection-pinning infrastructure, takes permanent ownership of security
plumbing, and prays nobody adds a route that forgets to set the context.

**Pgvpd closes this gap.**

## The Solution

Pgvpd is a lightweight TCP proxy that sits between your application and
PostgreSQL. It makes tenant identity intrinsic to the connection — the way
Oracle VPD does — so your ORM stays completely unaware of multi-tenancy.

```
┌─────────────┐       ┌───────────┐       ┌──────────────┐
│ Application │──TCP──│ Pgvpd │──TCP──│  PostgreSQL   │
│  (Drizzle,  │       │   Proxy   │       │  (RLS active) │
│  Prisma,    │       │           │       │              │
│  pg, etc.)  │       │ Extracts  │       │ Enforces     │
│             │       │ tenant    │       │ isolation    │
│ Connects as │       │ from user │       │ via policies │
│ app.tenant  │       │ name      │       │              │
└─────────────┘       └───────────┘       └──────────────┘
```

### How It Works

1. Application connects to Pgvpd with a tenant-encoded username:
   `app_user.tenant_abc` (separator is configurable)

2. Pgvpd parses out the tenant ID (`tenant_abc`), rewrites the username
   to `app_user`, and forwards the connection to upstream Postgres.

3. After authentication completes, Pgvpd injects:
   ```sql
   SET app.current_tenant_id = 'tenant_abc';
   SET ROLE app_user;
   ```

4. All subsequent traffic is transparently proxied. Every query the ORM sends
   hits a connection where RLS policies are active and scoped to the tenant.

5. The application never calls `SET ROLE`. Never sets a session variable.
   Never knows about tenancy. **The connection is the identity.**

### Fail-Closed Guarantee

- `app_user` is created with `NOSUPERUSER NOBYPASSRLS`
- `FORCE ROW LEVEL SECURITY` is enabled on all tenant-scoped tables
- RLS policies reference `current_tenant_id()` which returns `NULL` if unset
- `NULL` matches zero rows → **no context = no data**
- If Pgvpd fails to inject context, the connection is useless, not dangerous

### What This Means for Application Code

Before Pgvpd:
```typescript
// Middleware has to set context, pin connections, manage cleanup...
await setListContext(req, listId, userId);
// ...hope every route calls this...
const contacts = await db.select().from(contactMaster);
// ...hope AsyncLocalStorage didn't break...
// ...hope cleanup runs on every exit path...
```

After Pgvpd:
```typescript
// Connect with tenant in username. Done.
const db = drizzle(pool); // pool points at Pgvpd
const contacts = await db.select().from(contactMaster);
// RLS handles everything. The ORM doesn't know or care.
```

## Architecture

### Current Architecture (v0.9)

Written in Rust with [tokio](https://tokio.rs/) for async I/O. Single static
binary, no runtime dependencies.

```
State Machine (per connection):

  WAIT_STARTUP ──→ Parse client's StartupMessage
       │              Extract tenant from username
       │              Rewrite username
       ▼
  AUTHENTICATING ──→ Passthrough: relay auth exchange bidirectionally
       │              Pool mode: pgvpd authenticates client (cleartext),
       │              then authenticates to upstream (cleartext/MD5/SCRAM)
       ▼
  POST_AUTH ──────→ Forward ParameterStatus, BackendKeyData
       │              Buffer first ReadyForQuery
       │              (Pool mode: checkout from pool, DISCARD ALL)
       ▼
  RESOLVING ──────→ Execute context resolvers (if configured)
       │              Chain results via bind parameters
       │              Cache results with configurable TTL
       ▼
  INJECTING ──────→ Send SET commands to server
       │              Consume server response
       │              Forward buffered ReadyForQuery to client
       ▼
  TRANSPARENT ────→ Passthrough: zero-copy bidirectional pipe
       │              (tokio::io::copy_bidirectional)
       │            Pool mode: message-aware pipe (pipe_pooled)
       │              Intercepts Terminate ('X') to preserve upstream
       ▼
  CLEANUP ────────→ Pool mode: ROLLBACK → DISCARD ALL → return to idle pool
```

Components:
- `src/protocol.rs` — Wire protocol parser and message builders
- `src/connection.rs` — Per-connection async state machine
- `src/auth.rs` — Client-facing and upstream-facing authentication
- `src/pool.rs` — Session connection pool with idle reaper
- `src/resolver.rs` — Context resolver engine (SQL queries, caching, dependency ordering)
- `src/proxy.rs` — TCP/TLS listener, pool creation, connection dispatch
- `src/config.rs` — Configuration (file, env vars, CLI flags via clap)
- `src/stream.rs` — Plain/TLS stream abstraction
- `src/tls.rs` — TLS configuration builders
- `src/tenant.rs` — Per-tenant isolation (allow/deny, connection limits, rate limiting)
- `src/admin.rs` — Admin HTTP API (health, metrics, status)
- `src/metrics.rs` — Shared atomic counters for observability
- `src/main.rs` — Entry point, tracing setup

### Where we're going

pgvpd is evolving from a tenant isolation proxy into an **application security
context engine** — the Postgres equivalent of Oracle's Real Application
Security (RAS).

The key insight from Oracle's VPD → RAS evolution: the database should resolve
the user's security context, not the application. The application provides
identity ("who is this user?"). The database determines access ("what can they
see?"). Context resolvers (v0.4) implement this by running configurable SQL
queries at connection time to build the full security context from database
state.

```
Today:    App provides identity + context → pgvpd injects → Postgres enforces
v0.4:     App provides identity → pgvpd resolves context from DB → injects → Postgres enforces
```

This enables multi-dimensional RBAC (ownership + ACL grants + team membership +
org roles) without the application being in the security path.

### Superuser Bypass

Connections using a configured superuser username (e.g., `postgres`) are
passed through without tenant extraction, context injection, or pooling. This
allows admin/migration tools to connect directly.

## Roadmap

### v0.1 — TCP Proxy ✓
Core proxy: tenant extraction from username, auth relay, context injection,
transparent pipe. Single binary, zero dependencies.

### v0.2 — TLS + Hardening ✓
- TLS termination (client → Pgvpd)
- TLS origination (Pgvpd → upstream)
- Handshake timeout enforcement

### v0.3 — Connection Pooling ✓
- Session pooling (upstream connections reused across clients)
- Pgvpd-side client auth (cleartext) + upstream auth (cleartext/MD5/SCRAM)
- Pool checkout/checkin with connection reset
- Idle connection reaper
- Superuser bypass connections never pooled

### v0.4 — Context Resolvers ✓
The architectural pivot from "tenant isolation proxy" to "application security
context engine." Inspired by Oracle's evolution from VPD to Real Application
Security (RAS): the database resolves the user's full security context at
connection time, not the application.

- **Resolver engine**: `[[resolver]]` config blocks — named SQL queries that
  run post-auth to derive session variables from database state
- **Dependency ordering**: resolvers chain (org_membership → team_memberships
  → case_grants), each using results from prior resolvers as bind parameters
- **Context caching**: resolved context cached in-process keyed by
  `(resolver_name, input_params)` with configurable TTL — critical for pool
  mode where re-resolving on every checkout is expensive
- **Fail-closed semantics**: resolver error/timeout → connection terminated;
  no rows → variable set to NULL (RLS matches nothing)
- **Resolver-only mode**: username carries identity only (`app_user.user-uuid`),
  all context (org, teams, grants, even role) comes from resolvers — the
  endgame for full RAS equivalence
- **Integration tests**: 13 end-to-end tests via `./tests/run.sh` — passthrough
  isolation, pool auth/reuse, resolver context resolution, cache hits, superuser
  bypass. Uses Docker Compose for a real Postgres instance.

This enables multi-dimensional RBAC:
```
user sees case IF:
    case.creator_id = user_id              -- ownership
    OR EXISTS direct_grant(user, case)      -- ACL
    OR EXISTS team_grant(user_teams, case)  -- team membership
    OR user.org_role = 'admin'             -- org-wide admin
```

RFC: `docs/rfcs/rfc-context-resolvers.md`

### v0.5 — Observability + Admin ✓
- **Admin HTTP API** on configurable `admin_port` (axum):
  - `GET /health` — 200 OK JSON for load balancer health checks
  - `GET /metrics` — Prometheus exposition format (connections, pool, resolver counters)
  - `GET /status` — JSON snapshot of pool buckets and resolver state
- **Shared metrics** (`Arc<Metrics>`) with `AtomicU64` counters — no external prometheus crate
- **Connection metrics**: total accepted, currently active
- **Pool metrics**: checkouts, reuses, creates, checkins, discards, timeouts; per-bucket total/idle
- **Resolver metrics**: cache hits/misses, per-resolver executions/errors, cache size

### v0.6 — Advanced Isolation ✓
- **Tenant allow/deny lists**: `tenant_allow` / `tenant_deny` config — reject connections at handshake before any upstream work
- **Per-tenant connection limits**: `tenant_max_connections` — RAII guard (TenantGuard) ensures count is always decremented on connection end
- **Per-tenant rate limiting**: `tenant_rate_limit` — fixed-window (1-second) rate limiter per tenant
- **Query timeout**: `tenant_query_timeout` — idle timeout in pool mode (resets on data transfer), connection lifetime timeout in passthrough mode
- **TenantRegistry**: shared per-tenant state with lazy creation, no new crate dependencies
- **Metrics**: `pgvpd_tenant_rejected_total{reason=deny|limit|rate}`, `pgvpd_tenant_timeouts_total`

### v0.7 — SQL Helpers + Convenience ✓
- `pgvpd_context()`, `pgvpd_context_array()`, `pgvpd_context_contains()`
- `pgvpd_protect_acl()` for multi-path RLS policies
- Installable via `sql/helpers.sql`

### v0.8 — CI + Release Infrastructure ✓
Everything needed so the project can be properly released and maintained.
- **Housekeeping**: `Cargo.toml` metadata (repository, homepage, keywords, categories), MIT `LICENSE` file, `CHANGELOG.md` (retroactive v0.1–v0.7)
- **GitHub Actions CI**: cargo check, test, clippy, fmt, integration tests via Docker service container
- **GitHub Actions Release**: on tag push — cross-compile Linux/macOS binaries, GitHub Release, crates.io publish
- **Dockerfile**: multi-stage build (rust builder → slim runtime)

### v0.9 — Hardening ✓
Unit tests for critical code paths that only have integration coverage today.
- **Protocol parsing tests** (`src/protocol.rs`): malformed startup messages, backend message framing edge cases, SQL escaping
- **Config validation tests** (`src/config.rs`): missing required fields, invalid combinations, env var override precedence, malformed config
- **Auth edge case tests** (`src/auth.rs`): MD5 hash computation, SCRAM message parsing
- **Connection throughput benchmark** (`benches/throughput.rs`): passthrough latency vs direct connection
- **README update**: CI badge, benchmark results, install-from-release instructions

### v1.0 — Release ✓
Version bump + tag push. Release automation publishes binaries and the crate. After v0.8 (infrastructure) and v0.9 (hardening), v1.0 is a ceremony — the code has been running in production since v0.7.

## Design Principles

1. **The database is the security boundary.** Pgvpd sets context. Postgres
   enforces isolation. The application is not in the security path.

2. **Fail-closed, always.** No context = no data. Never fail-open.

3. **ORM-transparent.** If it speaks the Postgres wire protocol, it works with
   Pgvpd. No SDK, no wrapper, no middleware.

4. **Zero application changes.** Point your connection string at Pgvpd and
   encode the tenant in the username. That's it.

5. **Minimal surface area.** A proxy should be boring. Parse what's needed,
   inject what's needed, pipe everything else.
