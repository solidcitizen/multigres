# Multigres

**Virtual Private Database for PostgreSQL**

Multigres is a TCP proxy that makes tenant identity intrinsic to the database
connection — the way Oracle VPD does — so your ORM stays completely unaware of
multi-tenancy. The database enforces isolation. The application just connects.

```
Your App ──→ Multigres Proxy ──→ PostgreSQL (RLS enforced)
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

Encode the tenant in the username. Multigres handles the rest.

```bash
# Instead of connecting as:
psql -U app_user -d mydb

# Connect as:
psql -h localhost -p 6432 -U app_user.acme -d mydb
```

Multigres extracts `acme` as the tenant ID, rewrites the username to
`app_user`, and after authentication injects:

```sql
SET app.current_tenant_id = 'acme';
SET ROLE app_user;
```

Every subsequent query is scoped by RLS. The ORM never knows.

## Quick Start

### 1. Install

```bash
git clone https://github.com/your-org/multigres.git
cd multigres
npm install
npm run build
```

### 2. Set up Postgres

```bash
psql -U postgres -d your_database -f sql/setup.sql
```

This creates:
- `app_user` role with `NOSUPERUSER NOBYPASSRLS`
- `current_tenant_id()` function (fail-closed: returns NULL if unset)
- `multigres_protect()` helper to enable RLS on your tables
- `multigres_status()` to verify protection

### 3. Protect your tables

```sql
SELECT multigres_protect('contacts', 'tenant_id');
SELECT multigres_protect('invoices', 'org_id');
SELECT multigres_protect('orders', 'tenant_id');

-- Verify
SELECT * FROM multigres_status();
```

### 4. Start Multigres

```bash
# Point at your Postgres instance
npx multigres --upstream-port 5432

# Or with a config file
cp multigres.conf.example multigres.conf
npx multigres --config multigres.conf
```

### 5. Connect through Multigres

```bash
# From psql
psql -h localhost -p 6432 -U app_user.acme mydb

# From your application — just change the connection string
DATABASE_URL=postgresql://app_user.acme:password@localhost:6432/mydb
```

Your ORM (Drizzle, Prisma, TypeORM, etc.) connects to Multigres instead of
Postgres directly. No code changes. No middleware. No connection pinning.

## How It Works

1. **Client connects** with username `app_user.acme`
2. **Multigres parses** the tenant ID (`acme`) from the username
3. **Username is rewritten** to `app_user` for upstream Postgres
4. **Auth is proxied** transparently (supports cleartext, MD5, SCRAM-SHA-256)
5. **After auth**, Multigres injects `SET app.current_tenant_id = 'acme'`
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
extraction. Configure bypass usernames in `multigres.conf`:

```
superuser_bypass = postgres
```

## Configuration

| Option | Default | Env Var | Description |
|--------|---------|---------|-------------|
| `port` | 6432 | `MULTIGRES_PORT` | Listen port |
| `listen_host` | 127.0.0.1 | `MULTIGRES_HOST` | Bind address |
| `upstream_host` | 127.0.0.1 | `MULTIGRES_UPSTREAM_HOST` | Postgres host |
| `upstream_port` | 5432 | `MULTIGRES_UPSTREAM_PORT` | Postgres port |
| `tenant_separator` | `.` | `MULTIGRES_TENANT_SEPARATOR` | Separator in username |
| `context_variables` | `app.current_tenant_id` | `MULTIGRES_CONTEXT_VARIABLES` | Comma-separated session variables |
| `value_separator` | `:` | `MULTIGRES_VALUE_SEPARATOR` | Separator for multiple values |
| `superuser_bypass` | `postgres` | `MULTIGRES_SUPERUSER_BYPASS` | Bypass usernames (comma-separated) |
| `log_level` | `info` | `MULTIGRES_LOG_LEVEL` | debug/info/warn/error |

### Multiple Context Variables

For apps that need more than one dimension of identity (e.g., tenant + user):

```
# multigres.conf
context_variables = app.current_list_id,app.current_user_id
value_separator = :
```

Username: `app_user.list123:user456` — Multigres injects both:

```sql
SET app.current_list_id = 'list123';
SET app.current_user_id = 'user456';
SET ROLE app_user;
```

## With Drizzle ORM

```typescript
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

// Point at Multigres, encode tenant in username
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

- **[docs/architecture.md](docs/architecture.md)** — How Multigres works:
  connection lifecycle, state machine, security model, wire protocol, and
  comparison with alternatives.
- **[docs/drizzle-integration.md](docs/drizzle-integration.md)** — Step-by-step
  guide for Drizzle ORM: Express middleware, pool strategies, multi-context
  variables, migration from connection pinning.
- **[PLAN.md](PLAN.md)** — Design rationale, roadmap, and the problem
  Multigres solves.

## Architecture

Multigres is a **zero-dependency** Node.js TCP proxy that implements the
minimum subset of the Postgres wire protocol needed for:

- Parsing `StartupMessage` to extract the tenant-encoded username
- Rewriting the username before forwarding to upstream Postgres
- Detecting `AuthenticationOk` to know when auth is complete
- Injecting `SET` commands after authentication
- Transparent bidirectional piping for all subsequent traffic

After the initial handshake (~3 messages), Multigres adds **zero overhead** —
it's a direct TCP pipe.

See **[docs/architecture.md](docs/architecture.md)** for the full
architecture deep-dive.

## License

MIT
