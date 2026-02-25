# Multigres — Virtual Private Database for PostgreSQL

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

**Multigres closes this gap.**

## The Solution

Multigres is a lightweight TCP proxy that sits between your application and
PostgreSQL. It makes tenant identity intrinsic to the connection — the way
Oracle VPD does — so your ORM stays completely unaware of multi-tenancy.

```
┌─────────────┐       ┌───────────┐       ┌──────────────┐
│ Application │──TCP──│ Multigres │──TCP──│  PostgreSQL   │
│  (Drizzle,  │       │   Proxy   │       │  (RLS active) │
│  Prisma,    │       │           │       │              │
│  pg, etc.)  │       │ Extracts  │       │ Enforces     │
│             │       │ tenant    │       │ isolation    │
│ Connects as │       │ from user │       │ via policies │
│ app.tenant  │       │ name      │       │              │
└─────────────┘       └───────────┘       └──────────────┘
```

### How It Works

1. Application connects to Multigres with a tenant-encoded username:
   `app_user.tenant_abc` (separator is configurable)

2. Multigres parses out the tenant ID (`tenant_abc`), rewrites the username
   to `app_user`, and forwards the connection to upstream Postgres.

3. After authentication completes, Multigres injects:
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
- If Multigres fails to inject context, the connection is useless, not dangerous

### What This Means for Application Code

Before Multigres:
```typescript
// Middleware has to set context, pin connections, manage cleanup...
await setListContext(req, listId, userId);
// ...hope every route calls this...
const contacts = await db.select().from(contactMaster);
// ...hope AsyncLocalStorage didn't break...
// ...hope cleanup runs on every exit path...
```

After Multigres:
```typescript
// Connect with tenant in username. Done.
const db = drizzle(pool); // pool points at Multigres
const contacts = await db.select().from(contactMaster);
// RLS handles everything. The ORM doesn't know or care.
```

## Architecture

### v0.1 — TCP Proxy (this release)

Core proxy that handles the connection lifecycle:

```
State Machine (per connection):

  WAIT_STARTUP ──→ Parse client's StartupMessage
       │              Extract tenant from username
       │              Rewrite username
       ▼
  AUTHENTICATING ──→ Proxy auth exchange bidirectionally
       │              Detect AuthenticationOk
       ▼
  POST_AUTH ──────→ Forward ParameterStatus, BackendKeyData
       │              Buffer first ReadyForQuery
       ▼
  INJECTING ──────→ Send SET commands to server
       │              Consume server response
       │              Forward buffered ReadyForQuery to client
       ▼
  TRANSPARENT ────→ Pipe all traffic bidirectionally
```

Components:
- `src/protocol.ts` — Wire protocol parser (StartupMessage, message framing)
- `src/connection.ts` — Per-connection state machine
- `src/proxy.ts` — TCP server, accepts and manages connections
- `src/config.ts` — Configuration (file, env vars, CLI flags)
- `src/index.ts` — CLI entry point
- `sql/setup.sql` — Postgres-side setup (roles, functions, helpers)

### SSL Handling (v0.1)

Client-side SSL requests are denied with `'N'` — the client falls back to
plaintext. This is fine for local development. TLS termination is planned for
v0.2.

### Authentication (v0.1)

All auth mechanisms (cleartext, MD5, SCRAM-SHA-256) are proxied transparently.
Multigres doesn't inspect passwords — it just forwards the auth exchange
between client and server. The rewritten username in the StartupMessage
determines which role the server authenticates against.

### Superuser Bypass

Connections using a configured superuser username (e.g., `postgres`) are
passed through without tenant extraction or context injection. This allows
admin/migration tools to connect directly.

## Roadmap

### v0.2 — TLS + Hardening
- TLS termination (client → Multigres)
- TLS origination (Multigres → upstream)
- Connection timeout enforcement
- Health check endpoint
- Structured logging (JSON)

### v0.3 — Connection Pooling
- Built-in connection pool (replace PgBouncer in the stack)
- Per-tenant pool isolation options
- Pool metrics and monitoring

### v0.4 — Observability + Admin
- Admin API (HTTP) for runtime config, metrics, pool status
- Per-tenant query counts, latency percentiles
- Prometheus metrics endpoint

### v0.5 — Advanced Isolation
- Per-tenant rate limiting
- Per-tenant connection limits
- Query timeout per tenant
- Tenant allow/deny lists

### v0.9 — Rust Rewrite
- Rewrite proxy in Rust for production-grade performance
- Single static binary, no runtime dependencies
- Lower latency, smaller memory footprint, no GC pauses
- TypeScript v0.1–v0.5 serves as the reference implementation and spec

### v1.0 — Production Ready
- Battle-tested with real workloads
- Comprehensive test suite (unit, integration, chaos)
- Performance benchmarks vs direct connection
- Documentation site
- Published to crates.io and as prebuilt binaries

## Design Principles

1. **The database is the security boundary.** Multigres sets context. Postgres
   enforces isolation. The application is not in the security path.

2. **Fail-closed, always.** No context = no data. Never fail-open.

3. **ORM-transparent.** If it speaks the Postgres wire protocol, it works with
   Multigres. No SDK, no wrapper, no middleware.

4. **Zero application changes.** Point your connection string at Multigres and
   encode the tenant in the username. That's it.

5. **Minimal surface area.** A proxy should be boring. Parse what's needed,
   inject what's needed, pipe everything else.
