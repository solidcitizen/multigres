# Pgvpd Implementation Plan — Cadence Platform

## Current State

Cadence Platform today:
- **All database access** goes through Supabase JS client (`@supabase/supabase-js`) → PostgREST (REST API)
- **No direct PostgreSQL connections** exist anywhere in the stack
- Backend uses `service_role` key (bypasses RLS; authorization enforced in application middleware)
- Frontend uses `anon` key (RLS enforced via JWT + `get_user_account_id()` bridge)
- Deployed on Azure VMs via Docker Compose (frontend, backend, redis)
- Supabase hosted on supabase.co (managed)

## Target State (Side-by-Side)

```
┌──────────────┐
│   SvelteKit  │──→ Supabase PostgREST (:443) ──→ Postgres
│  (frontend)  │    (anon key, JWT, RLS)           (unchanged)
└──────────────┘

┌──────────────┐
│  Node.js API │──→ Supabase PostgREST (:443) ──→ Postgres
│  (existing)  │    (service_role, bypasses RLS)   (unchanged)
└──────────────┘

┌──────────────┐
│  New services│──→ pgvpd (:6432) ──TLS──→ Supabase Direct (:5432)
│  (migration, │    app_user.{identity}       pgvpd authenticates as app_user,
│  integration,│    context injected,          then SET ROLE authenticated.
│  workers)    │    SET ROLE authenticated     Same role, same policies, same RLS.
└──────────────┘
```

---

## Prerequisites

### 1. Supabase Plan — Direct Connection Access

**Required: Supabase Pro plan or higher.**

Pgvpd connects to Postgres via the wire protocol, not PostgREST. This requires Supabase's **direct connection** endpoint:

```
db.[project-ref].supabase.co:5432
```

Verify access:
```bash
# From the Azure VM where pgvpd will run
psql "postgresql://postgres.[project-ref]:[db-password]@db.[project-ref].supabase.co:5432/postgres?sslmode=require"
```

If this fails with a connection timeout, you may need:
- **IPv4 add-on** ($4/mo) — Supabase defaults to IPv6; Azure VMs may not have IPv6 egress
- **Network allowlist** — If Supabase has IP restrictions enabled, add the Azure VM's public IP

### 2. Supabase Connection Password

You need the **database password** (not the JWT keys). Find it in:
- Supabase Dashboard → Settings → Database → Connection string → Direct connection
- Or the `SUPABASE_DB_PASSWORD` if you stored it in your environment config

This password authenticates `postgres` for setup and `app_user` for runtime connections.

---

## Phase 1: Database Setup (Supabase SQL Editor)

All SQL runs in the **Supabase Dashboard SQL Editor** (connected as `postgres`) or via `psql` with the direct connection.

### Step 1.1: Create the app_user role

```sql
-- Run pgvpd's setup.sql (creates app_user, helper functions, pgvpd_protect)
-- Paste the contents of sql/setup.sql into Supabase SQL Editor

-- After running, verify:
SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
FROM pg_roles WHERE rolname = 'app_user';
-- Expected: app_user | f | f | t
```

**Supabase caveat:** The `postgres` user on supabase.com is not a true superuser — it's a member of `supabase_admin`. The setup.sql handles this gracefully (catches `insufficient_privilege` and logs a notice). If `ALTER ROLE` fails, verify attributes manually.

### Step 1.2: Set the app_user password

```sql
ALTER ROLE app_user WITH PASSWORD 'your-secure-password-here';
```

Store this password securely — it goes in pgvpd's deployment config and in the connection strings of new services.

### Step 1.3: Grant app_user the `authenticated` role

Instead of duplicating table grants and RLS policies for `app_user`, grant it the
existing `authenticated` role. pgvpd will `SET ROLE authenticated` after connecting,
so all existing policies, grants, and RLS checks apply unchanged.

```sql
-- Allow app_user to assume the authenticated role
GRANT authenticated TO app_user;
```

That's it. No per-table grants for `app_user`. No new policies. pgvpd authenticates
as `app_user` (LOGIN role), then immediately becomes `authenticated` — the same role
PostgREST uses. Every existing RLS policy works for both paths.

**Grant resolver lookup access:** Resolvers run *before* `SET ROLE`, so `app_user`
itself needs SELECT on the tables resolvers will query (Phase 4). For now, skip this —
resolvers aren't needed until v0.4.

### Step 1.4: Create unified identity function

Replace the existing `get_user_account_id()` with a unified function that works
for both PostgREST (JWT) and pgvpd (session variable) connections:

```sql
-- Unified identity: returns user account ID regardless of connection path
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID
LANGUAGE plpgsql STABLE SECURITY DEFINER
AS $$
DECLARE
  pgvpd_id TEXT;
BEGIN
  -- Try pgvpd session context first
  pgvpd_id := NULLIF(current_setting('app.user_id', true), '');
  IF pgvpd_id IS NOT NULL THEN
    RETURN pgvpd_id::UUID;
  END IF;

  -- Fall back to Supabase Auth (PostgREST path)
  RETURN get_user_account_id();
END;
$$;
```

Then update existing RBAC helper functions to use the unified function:

```sql
-- Replace get_user_account_id() → current_app_user_id() in:
--   user_can_access_case()
--   current_user_is_org_admin()
--   current_user_is_org_member()
--   user_case_role()
--   get_user_default_org_id()
--   (and any other functions that call get_user_account_id())
--
-- Example for one function:
CREATE OR REPLACE FUNCTION current_user_is_org_admin(p_org_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
AS $$
  SELECT EXISTS (
    SELECT 1 FROM org_memberships
    WHERE user_id = current_app_user_id()  -- was: get_user_account_id()
      AND org_id = p_org_id
      AND role = 'admin'
  );
$$;
```

**This is the only migration that touches existing code.** One find-and-replace
across the RBAC helper functions. All RLS policies that call these functions
automatically work for both PostgREST and pgvpd connections.

### Step 1.5: Verify both paths work

```sql
-- Verify existing PostgREST path still works (via Supabase client)
-- current_app_user_id() falls through to get_user_account_id() → auth.email()

-- Verify pgvpd path works
SET app.user_id = 'some-user-uuid';
SELECT current_app_user_id();
-- Expected: some-user-uuid

-- Verify existing policies are unchanged
SELECT schemaname, tablename, policyname, permissive, roles, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
-- No new policies. Same policies. Both paths use them.
```

---

## Phase 2: Deploy pgvpd

### Step 2.1: Build the binary

```bash
cd ~/projects/pgvpd
cargo build --release
# Binary: target/release/pgvpd (~2MB static binary)
```

### Step 2.2: Where to run pgvpd

**Option A (recommended for initial setup): On the Azure VM alongside the backend**

pgvpd runs as a sidecar next to the Docker Compose stack. New services connect to `localhost:6432`.

```
Azure VM
├── docker-compose (frontend, backend, redis)  ← existing, unchanged
├── pgvpd (:6432)                              ← new, runs natively or in Docker
│   └── connects to db.PROJECT.supabase.co:5432 over TLS
└── new-service (connects to localhost:6432)    ← new
```

**Option B: As a Docker service in docker-compose.yml**

Add pgvpd to the existing compose stack:

```yaml
services:
  # ... existing services unchanged ...

  pgvpd:
    image: pgvpd:latest  # or build from source
    ports:
      - "6432:6432"
    volumes:
      - ./pgvpd.conf:/etc/pgvpd/pgvpd.conf:ro
    environment:
      - PGVPD_UPSTREAM_HOST=db.PROJECT.supabase.co
      - PGVPD_UPSTREAM_PORT=5432
      - PGVPD_UPSTREAM_TLS=true
      - PGVPD_LOG_LEVEL=info
    networks:
      - robocomp-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "6432"]
      interval: 10s
      timeout: 3s
      retries: 3
```

### Step 2.3: Configure pgvpd

```toml
# pgvpd.conf

# Listen for application connections
listen_host = 0.0.0.0
listen_port = 6432

# Upstream: Supabase direct connection
upstream_host = db.PROJECT.supabase.co
upstream_port = 5432

# TLS to Supabase (REQUIRED — Supabase enforces SSL)
upstream_tls = true
upstream_tls_verify = true

# Tenant/identity extraction
tenant_separator = .
context_variables = app.user_id

# Session role: become `authenticated` after connecting (see issue #3)
# app_user is LOGIN-only; all RLS policies target `authenticated`
set_role = authenticated

# Superuser bypass (for migrations, admin tasks)
superuser_bypass = postgres

# Logging
log_level = info
```

### Step 2.4: Verify connectivity

```bash
# Start pgvpd
./target/release/pgvpd --config pgvpd.conf

# Test superuser bypass (should connect directly to Supabase)
psql -h localhost -p 6432 -U postgres -d postgres -c "SELECT current_user, version();"

# Test tenant connection (should inject context and SET ROLE authenticated)
psql -h localhost -p 6432 -U app_user.test-user-id -d postgres \
  -c "SELECT current_user, current_setting('app.user_id', true);"
# Expected: authenticated | test-user-id
#           ^^^^^^^^^^^^^ confirms SET ROLE worked
```

---

## Phase 3: First Integration — Data Migration Service

Start with a concrete use case that doesn't touch existing code.

### Example: Org-scoped data import

A migration script that imports case data for a specific organization:

```typescript
import pg from 'pg';

const orgId = process.env.ORG_ID;

// Connect through pgvpd with org identity
const pool = new pg.Pool({
  host: 'localhost',
  port: 6432,
  user: `app_user.${orgId}`,       // org-level isolation
  password: process.env.APP_USER_PASSWORD,
  database: 'postgres',
  ssl: false,                       // TLS handled by pgvpd → Supabase
});

// All queries automatically scoped to this org via RLS
const result = await pool.query('SELECT * FROM cases');
// Returns only cases where org_id = orgId (via RLS policy)

// Insert is also scoped — org_id enforced by WITH CHECK
await pool.query(
  'INSERT INTO cases (title, "userId", org_id) VALUES ($1, $2, $3)',
  ['Imported Case', userId, orgId]
);
```

This uses pgvpd v0.3 (current) with simple tenant isolation. No resolvers needed yet.

---

## Phase 4: Context Resolvers (After pgvpd v0.4)

When v0.4 ships, add resolvers for user-level identity:

```toml
# pgvpd.conf additions

context_variables = app.user_id

[[resolver]]
name = "user_account"
query = """
  SELECT id::text AS account_id
  FROM "userAccounts"
  WHERE id = $1::uuid
  LIMIT 1
"""
params = ["app.user_id"]
inject = { "app.account_id" = "account_id" }
required = true  # fail-closed: unknown user = no connection

[[resolver]]
name = "org_membership"
query = """
  SELECT om.org_id::text, om.role
  FROM org_memberships om
  WHERE om.user_id = $1::uuid
  LIMIT 1
"""
params = ["app.user_id"]
inject = { "app.org_id" = "org_id", "app.org_role" = "role" }
required = false
depends_on = ["user_account"]

[[resolver]]
name = "team_ids"
query = """
  SELECT array_agg(tm.team_id)::text AS team_ids
  FROM team_memberships tm
  JOIN teams t ON t.id = tm.team_id
  WHERE tm.user_id = $1::uuid
    AND t.org_id = $2::uuid
    AND t.is_active = true
"""
params = ["app.user_id", "app.org_id"]
inject = { "app.team_ids" = "team_ids" }
required = false
depends_on = ["org_membership"]
```

New integration services connect as `app_user.{user_uuid}` and get full RBAC context resolved automatically.

---

## Supabase-Specific Concerns

### Will this work with supabase.com?

**Yes**, with these specific considerations:

| Concern | Status | Notes |
|---------|--------|-------|
| Direct PG connection | ✅ Pro plan+ | Port 5432, `db.[ref].supabase.co` |
| TLS required | ✅ Supported | `upstream_tls = true` in pgvpd config |
| `postgres` not true superuser | ✅ Handled | setup.sql catches `insufficient_privilege` |
| CREATE ROLE app_user | ✅ Works | `postgres` can create roles on Supabase |
| ALTER ROLE attributes | ⚠️ May need manual verify | NOSUPERUSER NOBYPASSRLS may need dashboard |
| FORCE ROW LEVEL SECURITY | ✅ Works | Standard SQL, no special privileges |
| IPv4 connectivity | ⚠️ Check | Azure VM may need Supabase IPv4 add-on ($4/mo) |
| Connection limits | ⚠️ Monitor | Pro plan: 60 direct connections. pgvpd pooling helps. |
| Supabase built-in roles | ✅ No conflict | app_user is separate from anon/authenticated/service_role |
| Existing RLS policies | ✅ No conflict | New policies target `TO app_user` only |
| PostgREST continues working | ✅ Unchanged | Different connection path entirely |
| Realtime continues working | ✅ Unchanged | Separate WebSocket service |
| Supabase Auth continues | ✅ Unchanged | JWT-based, pgvpd doesn't touch it |
| Supabase Storage | ✅ Unchanged | Managed by Supabase, not accessed via pgvpd |

### Connection limit management

Supabase Pro allows ~60 direct connections. With pgvpd's built-in session pooling (v0.3), you can multiplex many application connections over fewer upstream connections:

```toml
# pgvpd.conf — pooling
pool_mode = session
pool_size = 10              # 10 upstream connections to Supabase
pool_idle_timeout = 300     # close idle connections after 5 min
pool_checkout_timeout = 5   # wait 5s for available connection
```

This means pgvpd uses at most 10 of your 60 direct connection slots, while serving many more application connections.

### Supabase Dashboard SQL Editor

All Phase 1 SQL can be run directly in the Supabase Dashboard SQL Editor. No `psql` access required for initial setup. For ongoing migrations, use the standard `supabase/migrations/` workflow and apply them via the Supabase CLI or dashboard.

---

## What Changes in Existing Code

**Nothing.** That's the point of side-by-side. The existing stack is untouched:

| Component | Changes |
|-----------|---------|
| SvelteKit frontend | None |
| Node.js API (existing endpoints) | None |
| Supabase Auth | None |
| Supabase Realtime | None |
| Supabase Storage | None |
| Existing RLS policies | None (new policies are additive, target `app_user` only) |
| Docker Compose | Add pgvpd service (optional) |
| Environment config | Add pgvpd connection vars for new services |

---

## Migration Path Forward

```
Now ──────────────────────────────────────────────────────────────→ Future

Phase 1          Phase 2           Phase 3          Phase 4
DB setup +       First service     v0.4 resolvers   Migrate existing
pgvpd deploy     through pgvpd     for user RBAC    endpoints to pgvpd
                 (data migration)                    (optional, gradual)

PostgREST ✅     PostgREST ✅      PostgREST ✅     PostgREST optional
pgvpd new ✅     pgvpd active ✅   pgvpd RBAC ✅    pgvpd primary ✅
```

Each phase is independently valuable. You can stop at any phase and have a working system. The existing PostgREST-based stack never breaks.

---

## Checklist

### Before starting
- [ ] Confirm Supabase Pro plan (direct connection access)
- [ ] Get database password from Supabase Dashboard
- [ ] Test direct connection from Azure VM (`psql` to port 5432)
- [ ] If connection fails: enable IPv4 add-on or check network allowlist

### Phase 1 — Database setup
- [ ] Run setup.sql in Supabase SQL Editor
- [ ] Verify app_user role attributes
- [ ] Set app_user password
- [ ] Grant app_user access to target tables
- [ ] Create pgvpd_context() helper functions
- [ ] Create dual-path RLS policies for app_user
- [ ] Verify existing policies unaffected

### Phase 2 — Deploy pgvpd
- [ ] Build pgvpd binary (or Docker image)
- [ ] Write pgvpd.conf with Supabase direct connection
- [ ] Deploy to Azure VM (native or Docker Compose)
- [ ] Verify superuser bypass works
- [ ] Verify tenant connection + context injection works
- [ ] Monitor connection usage in Supabase Dashboard

### Phase 3 — First integration service
- [ ] Build data migration or integration service
- [ ] Connect through pgvpd with org-level identity
- [ ] Verify RLS scoping (only sees correct org's data)
- [ ] Verify fail-closed (bad identity = no data)

### Phase 4 — Context resolvers (after pgvpd v0.4)
- [ ] Write resolver config for org/team/grant resolution
- [ ] Test resolved context injection
- [ ] Write richer RLS policies using resolved context
- [ ] Build new integration APIs using user-level identity
