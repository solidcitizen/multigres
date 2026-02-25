# Using Multigres with Drizzle ORM

This guide shows how to integrate Multigres into a Drizzle ORM application
to get transparent, database-enforced tenant isolation with zero application-
layer security code.

## What Changes

| Before Multigres | After Multigres |
|---|---|
| `AsyncLocalStorage` + connection pinning | Not needed |
| `SET ROLE app_user` in middleware | Not needed |
| `set_config('app.tenant_id', ...)` per request | Not needed |
| `res.on('close')` cleanup handlers | Not needed |
| Proxy wrapper on `db` export | Not needed |
| `WHERE tenant_id = ?` in queries | Not needed (RLS handles it) |
| Connection string points at Postgres | Connection string points at Multigres |
| Username: `app_user` | Username: `app_user.tenant_id` |

The only change is the connection string. Everything else disappears.

## Basic Setup

### 1. Schema with RLS policies

Define your tables normally. The `tenant_id` column is the only multi-tenancy
artifact in your schema:

```typescript
// schema.ts
import { pgTable, serial, text, uuid, varchar } from "drizzle-orm/pg-core";

export const contacts = pgTable("contacts", {
  id: serial("id").primaryKey(),
  tenantId: varchar("tenant_id", { length: 255 }).notNull(),
  name: text("name").notNull(),
  email: text("email"),
});
```

Run `multigres_protect` on each tenant-scoped table:

```sql
SELECT multigres_protect('contacts', 'tenant_id');
```

You never write `WHERE tenant_id = ?` in application code. The RLS policy
handles filtering. Your queries are just:

```typescript
const allContacts = await db.select().from(contacts);
// Returns only the current tenant's contacts — guaranteed by the database
```

### 2. Database connection

Point your pool at Multigres instead of Postgres directly. Encode the tenant
ID in the username:

```typescript
// db.ts
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

export function createTenantDb(tenantId: string) {
  const pool = new Pool({
    host: "localhost",
    port: 6432,                          // Multigres port
    user: `app_user.${tenantId}`,        // tenant encoded in username
    password: "app_user_password",
    database: "mydb",
  });

  return drizzle(pool, { schema });
}
```

That's it. No `AsyncLocalStorage`. No `Proxy`. No connection pinning. No
cleanup middleware. The pool connects through Multigres, which sets the tenant
context on every connection. RLS does the rest.

## Express Integration

### Per-request tenant resolution

In a typical Express app, you resolve the tenant from the request (auth
token, session, URL parameter) and create a scoped database instance:

```typescript
// server.ts
import express from "express";
import { createTenantDb } from "./db";

const app = express();

// Middleware: resolve tenant, attach scoped db to request
app.use((req, res, next) => {
  const tenantId = req.headers["x-tenant-id"] as string;
  if (!tenantId) {
    return res.status(400).json({ error: "Missing tenant ID" });
  }

  // Create a tenant-scoped db — every query through this instance
  // is isolated to this tenant by the database, not by your code
  req.db = createTenantDb(tenantId);
  next();
});

// Routes just use req.db — no tenant filtering needed
app.get("/contacts", async (req, res) => {
  const result = await req.db.select().from(contacts);
  res.json(result);
  // Returns ONLY this tenant's contacts. Guaranteed.
});

app.delete("/contacts/:id", async (req, res) => {
  await req.db.delete(contacts).where(eq(contacts.id, req.params.id));
  // Can only delete this tenant's contacts. Even if the ID belongs
  // to another tenant, the DELETE affects zero rows.
  res.json({ ok: true });
});
```

### Pool-per-tenant vs pool-per-request

**Pool-per-tenant** (recommended for most apps): Create one pool per tenant
and cache it. Each pool holds connections pre-configured for that tenant:

```typescript
// db.ts
import { drizzle, NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const tenantPools = new Map<string, NodePgDatabase<typeof schema>>();

export function getTenantDb(tenantId: string): NodePgDatabase<typeof schema> {
  let db = tenantPools.get(tenantId);
  if (!db) {
    const pool = new Pool({
      host: "localhost",
      port: 6432,
      user: `app_user.${tenantId}`,
      password: "app_user_password",
      database: "mydb",
      max: 5,                  // per-tenant pool size
      idleTimeoutMillis: 30000,
    });
    db = drizzle(pool, { schema });
    tenantPools.set(tenantId, db);
  }
  return db;
}
```

**Single shared pool**: If you have many tenants with light traffic, a
pool-per-tenant may waste connections. Instead, create a new pool per request
with `max: 1`:

```typescript
export function getTenantDb(tenantId: string): NodePgDatabase<typeof schema> {
  const pool = new Pool({
    host: "localhost",
    port: 6432,
    user: `app_user.${tenantId}`,
    password: "app_user_password",
    database: "mydb",
    max: 1,
  });
  return drizzle(pool, { schema });
}
```

This creates a fresh connection per request. Slightly more overhead, but
guarantees no connection reuse across tenants.

## Multiple Context Variables

Some applications need more than one dimension of identity. For example, an
app that scopes data by both list/workspace AND user:

```
# multigres.conf
context_variables = app.current_list_id,app.current_user_id
value_separator = :
```

Encode both values in the username, separated by `:`:

```typescript
// Connect as: app_user.<list_id>:<user_id>
const pool = new Pool({
  host: "localhost",
  port: 6432,
  user: `app_user.${listId}:${userId}`,
  password: "app_user_password",
  database: "mydb",
});
```

Multigres injects both:

```sql
SET app.current_list_id = '<list_id>';
SET app.current_user_id = '<user_id>';
SET ROLE app_user;
```

RLS policies can reference both variables:

```sql
CREATE POLICY tenant_isolation ON contacts
  FOR ALL TO app_user
  USING (
    list_id = current_setting('app.current_list_id', true)
    AND has_list_access(list_id)  -- checks app.current_user_id internally
  );
```

## Transactions

Transactions work normally. Multigres sets the context at the connection
level, so every statement within a transaction inherits it:

```typescript
await db.transaction(async (tx) => {
  // Both statements run on the same connection, same tenant context
  await tx.insert(contacts).values({ name: "Alice", tenantId, email: "a@b.com" });
  await tx.insert(auditLog).values({ action: "contact_created", tenantId });
  // If either fails, both roll back. Tenant scoping is maintained throughout.
});
```

No need for `SET LOCAL ROLE` inside transactions — the connection already has
the role and context set by Multigres before any application queries run.

## Admin / Worker Operations

For operations that need to bypass RLS — migrations, background workers,
cross-tenant reporting — connect with a superuser bypass username:

```typescript
// Admin pool — bypasses Multigres tenant extraction
const adminPool = new Pool({
  host: "localhost",
  port: 6432,                     // through Multigres (bypass)
  user: "postgres",               // configured in superuser_bypass
  password: "postgres_password",
  database: "mydb",
});

// Or connect directly to Postgres, skipping Multigres entirely
const directPool = new Pool({
  host: "localhost",
  port: 5432,                     // direct to Postgres
  user: "postgres",
  password: "postgres_password",
  database: "mydb",
});

const adminDb = drizzle(adminPool, { schema });

// This sees ALL tenants' data — no RLS filtering
const allContacts = await adminDb.select().from(contacts);
```

## Migrating from Connection Pinning

If you're currently using the `AsyncLocalStorage` + `Proxy` + pinned
`PoolClient` pattern (like the one described in our architectural
discussion), here's the migration path:

### Before (hand-rolled VPD)

```typescript
// db.ts — complex proxy machinery
import { AsyncLocalStorage } from "node:async_hooks";

export interface RequestDbContext {
  pinnedDb: NodePgDatabase<typeof schema>;
}
export const requestContext = new AsyncLocalStorage<RequestDbContext>();
export const poolDb = drizzle(pool, { schema });
export const db = new Proxy(poolDb, {
  get(_target, prop) {
    const activeDb = requestContext.getStore()?.pinnedDb ?? poolDb;
    const val = Reflect.get(activeDb, prop, activeDb);
    if (typeof val === 'function') return val.bind(activeDb);
    return val;
  },
}) as NodePgDatabase<typeof schema>;

// middleware/list.ts — connection pinning + cleanup
export async function setListContext(req, listId, userId) {
  const client = await pool.connect();
  await client.query(`SELECT set_config('app.current_list_id', $1, false)`, [listId]);
  await client.query(`SELECT set_config('app.current_user_id', $1, false)`, [userId]);
  await client.query('SET ROLE app_user');
  const pinnedDb = drizzle(client, { schema });
  (req as any)._pinnedClient = client;
  requestContext.enterWith({ pinnedDb });
}

export const listContextCleanup: RequestHandler = (req, res, next) => {
  res.on('close', () => {
    const client = (req as any)._pinnedClient;
    if (client) {
      client.query('RESET ROLE; RESET app.current_list_id; RESET app.current_user_id;')
        .finally(() => client.release());
    }
  });
  next();
};
```

### After (Multigres)

```typescript
// db.ts — just a pool and drizzle
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "../shared/schema";

export function getTenantDb(listId: string, userId: string) {
  const pool = new Pool({
    host: "localhost",
    port: 6432,
    user: `app_user.${listId}:${userId}`,
    password: "app_user_password",
    database: "mydb",
  });
  return drizzle(pool, { schema });
}

// middleware — just resolve the tenant and attach the db
app.use((req, res, next) => {
  const { listId, userId } = resolveFromSession(req);
  req.db = getTenantDb(listId, userId);
  next();
});
```

**Deleted**: `AsyncLocalStorage`, `requestContext`, `Proxy`, `poolDb`,
`setListContext`, `listContextCleanup`, `_pinnedClient`, `RESET ROLE`,
connection pool `on('connect')` safety net.

All of that infrastructure existed because the application was the security
boundary. With Multigres, the database is the security boundary. The
application just connects.

## Connection String Format

For tools and libraries that use a connection URL:

```
postgresql://app_user.acme:password@localhost:6432/mydb
              ───────┬────
                     └── role.tenant encoded in username
```

With multiple context variables:

```
postgresql://app_user.list123%3Auser456:password@localhost:6432/mydb
                              ───┬───
                                 └── %3A is URL-encoded ':'
```

Note: the `:` in the username must be URL-encoded as `%3A` when used in a
connection URL, since `:` is the username/password separator. When using
pool options (`user: "app_user.list123:user456"`), no encoding is needed.

## Troubleshooting

### "Username must contain context values separated by '.'"

The connecting username doesn't have the tenant separator. Make sure the
pool's `user` option includes the tenant: `app_user.my_tenant`.

### "Expected N context value(s), got M"

The number of values in the username doesn't match the configured
`context_variables`. If you have `context_variables = a,b`, the username
must have two values: `app_user.val1:val2`.

### Queries return zero rows

This is the fail-closed guarantee working correctly. Check:
1. Is the tenant ID correct? Does data exist for that tenant?
2. Is `app.current_tenant_id` (or your custom variable) being checked by
   your RLS policies?
3. Connect as `postgres` (superuser bypass) to verify the data exists.

### "permission denied for table X"

The `app_user` role needs `GRANT SELECT, INSERT, UPDATE, DELETE ON X TO
app_user`. The `multigres_protect()` function does this automatically.
For existing tables, run it again or grant manually.
