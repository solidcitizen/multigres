# Pgvpd

**Virtual Private Database for PostgreSQL**

Pgvpd is a TCP proxy that makes tenant identity intrinsic to the database
connection — the way Oracle VPD does — so your ORM stays completely unaware of
multi-tenancy. The database enforces isolation. The application just connects.

```
Your App ──→ Pgvpd Proxy ──→ PostgreSQL (RLS enforced)
              ↕                     ↕
        Extracts tenant        Policies filter
        from username          by tenant context
```

## The Problem

Postgres RLS can enforce tenant isolation, but someone has to call
`SET app.current_tenant_id` on every connection. If they forget, queries
run as a superuser and return **all tenants' data**. Every team hand-rolls
the same middleware, connection-pinning, and AsyncLocalStorage plumbing.
The application becomes the security boundary — and applications make mistakes.

## The Solution

Encode the tenant in the username. Pgvpd handles the rest.

```bash
# Instead of connecting as:
psql -U app_user -d mydb

# Connect as:
psql -h localhost -p 6432 -U app_user.acme -d mydb
```

Pgvpd extracts `acme` as the tenant ID, rewrites the username to
`app_user`, and after authentication injects:

```sql
SET app.current_tenant_id = 'acme';
SET ROLE app_user;
```

Every subsequent query is scoped by RLS. The ORM never knows.

## Quick Start

### 1. Build

```bash
git clone https://github.com/solidcitizen/pgvpd.git
cd pgvpd
cargo build --release
```

The binary is at `target/release/pgvpd`.

### 2. Set up Postgres

```bash
psql -U postgres -d your_database -f sql/setup.sql
```

This creates:
- `app_user` role with `NOSUPERUSER NOBYPASSRLS`
- `current_tenant_id()` function (fail-closed: returns NULL if unset)
- `pgvpd_protect()` helper to enable RLS on your tables
- `pgvpd_status()` to verify protection

### 3. Protect your tables

```sql
SELECT pgvpd_protect('contacts', 'tenant_id');
SELECT pgvpd_protect('invoices', 'org_id');
SELECT pgvpd_protect('orders', 'tenant_id');

-- Verify
SELECT * FROM pgvpd_status();
```

### 4. Start Pgvpd

```bash
# Point at your Postgres instance
./target/release/pgvpd --upstream-port 5432

# Or with a config file
cp pgvpd.conf.example pgvpd.conf
./target/release/pgvpd --config pgvpd.conf
```

### 5. Connect through Pgvpd

```bash
# From psql
psql -h localhost -p 6432 -U app_user.acme mydb

# From your application — just change the connection string
DATABASE_URL=postgresql://app_user.acme:password@localhost:6432/mydb
```

Your ORM (Drizzle, Prisma, TypeORM, etc.) connects to Pgvpd instead of
Postgres directly. No code changes. No middleware. No connection pinning.

## How It Works

**Passthrough mode** (default):

1. **Client connects** with username `app_user.acme`
2. **Pgvpd parses** the tenant ID (`acme`) from the username
3. **Username is rewritten** to `app_user` for upstream Postgres
4. **Auth is proxied** transparently (supports cleartext, MD5, SCRAM-SHA-256)
5. **Context resolvers** run (if configured) — SQL queries that derive additional session variables from database state
6. **After auth**, Pgvpd injects `SET app.current_tenant_id = 'acme'` (plus any resolver-derived variables)
7. **All traffic** is then piped transparently — zero overhead (`tokio::io::copy_bidirectional`)
8. **RLS policies** on every tenant-scoped table enforce isolation

**Pool mode** (`pool_mode = session`):

Steps 1–2 are the same, but Pgvpd authenticates the client itself (cleartext), checks out a pooled upstream connection, resets it (`DISCARD ALL`), resolves + injects context, and uses a message-aware pipe (`pipe_pooled`) that intercepts Terminate messages so the upstream connection can be returned to the pool. On disconnect, the connection is cleaned up with `ROLLBACK` → `DISCARD ALL` and returned to the idle pool.

### Fail-Closed Guarantee

- `app_user` has `NOSUPERUSER NOBYPASSRLS` — cannot bypass RLS
- `FORCE ROW LEVEL SECURITY` is on — even table owners are filtered
- `current_tenant_id()` returns `NULL` if the variable isn't set
- RLS policies match `tenant_id = current_tenant_id()` — NULL matches nothing
- **No context = no data. Never fail-open.**

### Superuser Bypass

Admin connections (e.g., `postgres`) are passed through without tenant
extraction. Configure bypass usernames in `pgvpd.conf`:

```
superuser_bypass = postgres
```

## Configuration

| Option | Default | Env Var | Description |
|--------|---------|---------|-------------|
| `port` | 6432 | `PGVPD_PORT` | Listen port |
| `listen_host` | 127.0.0.1 | `PGVPD_HOST` | Bind address |
| `upstream_host` | 127.0.0.1 | `PGVPD_UPSTREAM_HOST` | Postgres host |
| `upstream_port` | 5432 | `PGVPD_UPSTREAM_PORT` | Postgres port |
| `tenant_separator` | `.` | `PGVPD_TENANT_SEPARATOR` | Separator in username |
| `context_variables` | `app.current_tenant_id` | `PGVPD_CONTEXT_VARIABLES` | Comma-separated session variables |
| `value_separator` | `:` | `PGVPD_VALUE_SEPARATOR` | Separator for multiple values |
| `superuser_bypass` | `postgres` | `PGVPD_SUPERUSER_BYPASS` | Bypass usernames (comma-separated) |
| `log_level` | `info` | `PGVPD_LOG_LEVEL` | debug/info/warn/error |
| `handshake_timeout` | 30 | `PGVPD_HANDSHAKE_TIMEOUT` | Max seconds for startup + auth + injection |
| `tls_port` | *(disabled)* | `PGVPD_TLS_PORT` | TLS listen port (requires tls_cert + tls_key) |
| `tls_cert` | — | `PGVPD_TLS_CERT` | Path to PEM certificate for TLS termination |
| `tls_key` | — | `PGVPD_TLS_KEY` | Path to PEM private key for TLS termination |
| `upstream_tls` | false | `PGVPD_UPSTREAM_TLS` | Connect to upstream Postgres over TLS |
| `upstream_tls_verify` | true | `PGVPD_UPSTREAM_TLS_VERIFY` | Verify upstream TLS certificate |
| `upstream_tls_ca` | — | `PGVPD_UPSTREAM_TLS_CA` | Custom CA cert for upstream TLS |
| `pool_mode` | none | `PGVPD_POOL_MODE` | `none` (passthrough) or `session` (pooling) |
| `pool_size` | 20 | `PGVPD_POOL_SIZE` | Max upstream connections per (database, role) |
| `pool_password` | — | `PGVPD_POOL_PASSWORD` | Password clients must provide in pool mode |
| `upstream_password` | — | `PGVPD_UPSTREAM_PASSWORD` | Password pgvpd uses to authenticate upstream |
| `pool_idle_timeout` | 300 | `PGVPD_POOL_IDLE_TIMEOUT` | Seconds idle before pooled connection is closed |
| `pool_checkout_timeout` | 5 | `PGVPD_POOL_CHECKOUT_TIMEOUT` | Seconds to wait when pool is full |
| `resolvers` | — | `PGVPD_RESOLVERS` | Path to context resolver TOML file |
| `admin_port` | *(disabled)* | `PGVPD_ADMIN_PORT` | HTTP port for admin API (health, metrics, status) |

Configuration is loaded in priority order: defaults → config file → environment variables → CLI flags.

### Multiple Context Variables

For apps that need more than one dimension of identity (e.g., tenant + user):

```
# pgvpd.conf
context_variables = app.current_list_id,app.current_user_id
value_separator = :
```

Username: `app_user.list123:user456` — Pgvpd injects both:

```sql
SET app.current_list_id = 'list123';
SET app.current_user_id = 'user456';
SET ROLE app_user;
```

## Connection Pooling

With `pool_mode = session`, Pgvpd maintains a pool of upstream Postgres
connections keyed by `(database, role)`. Clients authenticate to Pgvpd
directly (cleartext), and Pgvpd checks out a pooled upstream connection,
resets it, injects context, and pipes traffic using a message-aware
forwarder that intercepts Terminate messages to preserve the upstream
connection.

```ini
# pgvpd.conf
pool_mode = session
pool_size = 20
pool_password = secret
upstream_password = upstream_secret
pool_idle_timeout = 300
pool_checkout_timeout = 5
```

On disconnect, connections are cleaned up (`ROLLBACK` → `DISCARD ALL`) and
returned to the idle pool. An idle reaper closes connections that have been
unused longer than `pool_idle_timeout`. Superuser bypass connections are
never pooled.

## Context Resolvers

Resolvers are SQL queries that run after authentication to derive additional
session variables from database state — the Postgres equivalent of Oracle's
Real Application Security. The application provides identity (a user UUID);
the database resolves the full security context (org membership, team grants,
ACLs).

```toml
# resolvers.toml
[[resolver]]
name = "org_membership"
query = "SELECT org_id, role FROM org_members WHERE user_id = $1"
params = ["app.current_user_id"]
inject = { "app.org_id" = "org_id", "app.org_role" = "role" }
cache_ttl = 300
```

Configure with `resolvers = resolvers.toml` in your config file. Resolvers
execute in dependency order, chain results via bind parameters, and cache
results with configurable TTL. Failed required resolvers terminate the
connection (fail-closed).

## TLS

**TLS termination** (client → Pgvpd): clients connect over TLS to
`tls_port`. Requires `tls_cert` and `tls_key` pointing to PEM files. The
plain listener continues on `port`.

**TLS origination** (Pgvpd → upstream): set `upstream_tls = true` to connect
to Postgres over TLS. Use `upstream_tls_verify = false` for self-signed
certs, or `upstream_tls_ca` for a custom CA.

## Integration Tests

End-to-end tests run against a real Postgres instance via Docker:

```bash
./tests/run.sh
```

This starts a Postgres container, loads fixtures, builds pgvpd, and runs
test suites for passthrough mode, pool mode, and resolvers (13 tests total).
Requires Docker and `psql`.

## With Drizzle ORM

```typescript
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

// Point at Pgvpd, encode tenant in username
const pool = new Pool({
  host: "localhost",
  port: 6432,
  user: `app_user.${tenantId}`,   // <-- tenant goes here
  password: "app_user_password",   // password for app_user role
  database: "mydb",
});

const db = drizzle(pool);

// Every query is now tenant-scoped. No middleware. No context. No pinning.
const contacts = await db.select().from(contactMaster);
```

See **[docs/drizzle-integration.md](docs/drizzle-integration.md)** for the
full guide: Express integration, pool-per-tenant patterns, transactions,
migration from connection pinning, and troubleshooting.

## Documentation

- **[docs/architecture.md](docs/architecture.md)** — How Pgvpd works:
  connection lifecycle, state machine, security model, wire protocol, and
  comparison with alternatives.
- **[docs/drizzle-integration.md](docs/drizzle-integration.md)** — Step-by-step
  guide for Drizzle ORM: Express middleware, pool strategies, multi-context
  variables, migration from connection pinning.
- **[PLAN.md](PLAN.md)** — Design rationale, roadmap, and the problem
  Pgvpd solves.

## Architecture

Pgvpd is written in **Rust** using [tokio](https://tokio.rs/) for async
I/O. It implements the minimum subset of the Postgres v3 wire protocol needed
for:

- Parsing `StartupMessage` to extract the tenant-encoded username
- Rewriting the username before forwarding to upstream Postgres
- Relaying SCRAM-SHA-256 (and other) authentication exchanges
- Executing context resolvers (SQL queries to derive session state)
- Injecting `SET` commands after authentication
- Bidirectional piping for all subsequent traffic

In passthrough mode, after the initial handshake (~3 messages), Pgvpd
adds **zero overhead** — it's a direct TCP pipe via
`tokio::io::copy_bidirectional`. In pool mode, the pipe (`pipe_pooled`) does
message-aware forwarding to intercept Terminate messages and preserve
upstream connections for reuse.

Components: `protocol.rs` (wire protocol), `connection.rs` (state machine),
`auth.rs` (authentication), `pool.rs` (connection pool), `resolver.rs`
(context resolvers), `stream.rs` (plain/TLS abstraction), `tls.rs` (TLS
config), `admin.rs` (HTTP admin API), `metrics.rs` (observability counters).

Single static binary. No runtime dependencies.

See **[docs/architecture.md](docs/architecture.md)** for the full
architecture deep-dive.

## License

MIT
