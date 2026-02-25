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

1. **Client connects** with username `app_user.acme`
2. **Pgvpd parses** the tenant ID (`acme`) from the username
3. **Username is rewritten** to `app_user` for upstream Postgres
4. **Auth is proxied** transparently (supports cleartext, MD5, SCRAM-SHA-256)
5. **After auth**, Pgvpd injects `SET app.current_tenant_id = 'acme'`
6. **All traffic** is then piped transparently — zero overhead
7. **RLS policies** on every tenant-scoped table enforce isolation

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
- Injecting `SET` commands after authentication
- Zero-copy bidirectional piping for all subsequent traffic

After the initial handshake (~3 messages), Pgvpd adds **zero overhead** —
it's a direct TCP pipe via `tokio::io::copy_bidirectional`.

Single static binary. No runtime dependencies.

See **[docs/architecture.md](docs/architecture.md)** for the full
architecture deep-dive.

## License

MIT
