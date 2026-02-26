# RFC: Context Resolvers — Database-Resolved Session Context

## Summary

Extend pgvpd beyond static, username-encoded context to support **database-resolved context**: SQL queries that run at connection time to derive session variables from database state. This enables multi-dimensional RBAC, declarative ACL patterns, and full Oracle VPD parity — while preserving pgvpd's fail-closed guarantees and ORM-transparency.

## Motivation

### What pgvpd does today

pgvpd injects context that the **application already knows**:

```
app connects as app_user.acme → pgvpd injects SET app.current_tenant_id = 'acme'
```

The application determines the tenant, encodes it in the username, and pgvpd passes it through to Postgres. This works well for simple tenant isolation where a single scalar (`tenant_id`) is the entire security boundary.

### Where this breaks down

Real-world multi-tenant applications rarely have a single access dimension. Consider a legal document platform where a user's visible cases are determined by:

```
user sees case IF:
    case.creator_id = user_id                         -- ownership
    OR EXISTS grant IN case_user_access               -- direct ACL grant
    OR EXISTS grant IN case_team_access                -- team-based grant
        WHERE user IN team.members
    OR user.org_role = 'admin'                        -- org-wide admin
```

This can't be encoded in a username. The application would need to:
1. Query the database for the user's org, teams, grants, and role
2. Encode all of that into the connection username
3. Keep it in sync as memberships change

This defeats the purpose. The application is back in the security path, duplicating authorization logic, and the context is stale the moment a membership changes.

### What Oracle VPD actually does

Oracle's VPD doesn't just set static context — it runs **policy functions** that query the database to build session context:

```sql
-- Oracle: policy function queries DB state to build WHERE clause
CREATE FUNCTION case_access_policy(schema VARCHAR2, tab VARCHAR2)
RETURN VARCHAR2 AS
BEGIN
  RETURN 'org_id IN (SELECT org_id FROM memberships WHERE user_id = SYS_CONTEXT(''app'', ''user_id''))';
END;
```

The equivalent in Postgres + pgvpd would be: at connection time, pgvpd runs configurable SQL against the database to resolve a user's full security context, then injects the results as session variables that RLS policies reference.

### The architectural shift

```
Today:    App knows context → encodes in username → pgvpd injects → Postgres enforces
Proposed: App provides identity → pgvpd resolves context from DB → injects → Postgres enforces
```

The database becomes the single source of truth for access control. The application only needs to know "who is this user?" — not "what can they access?"

## Proposal

### Context Resolvers

A **context resolver** is a named SQL query that pgvpd executes against the upstream database after authentication, using values from username-encoded context as bind parameters. The query results are injected as additional session variables.

#### Configuration

```toml
# pgvpd.conf

# --- Existing static context (unchanged) ---
context_variables = app.user_id
tenant_separator = .

# --- New: context resolvers ---

[[resolver]]
name = "org_membership"
query = """
  SELECT org_id, role
  FROM org_memberships
  WHERE user_id = $1 AND is_active = true
  LIMIT 1
"""
params = ["app.user_id"]              # bind from already-resolved context
inject = { "app.org_id" = "org_id", "app.org_role" = "role" }
required = false                       # if no rows, set to NULL (fail-closed)

[[resolver]]
name = "team_memberships"
query = """
  SELECT array_agg(team_id)::text AS team_ids
  FROM team_memberships tm
  JOIN teams t ON t.id = tm.team_id
  WHERE tm.user_id = $1 AND t.org_id = $2::uuid AND t.is_active = true
"""
params = ["app.user_id", "app.org_id"]  # chains from prior resolver
inject = { "app.team_ids" = "team_ids" }
required = false
depends_on = ["org_membership"]         # execution order

[[resolver]]
name = "case_grants"
query = """
  SELECT array_agg(DISTINCT case_id)::text AS granted_case_ids
  FROM (
    SELECT case_id FROM case_user_access WHERE user_id = $1
    UNION
    SELECT case_id FROM case_team_access WHERE team_id = ANY($2::uuid[])
  ) grants
"""
params = ["app.user_id", "app.team_ids"]
inject = { "app.granted_case_ids" = "granted_case_ids" }
required = false
depends_on = ["team_memberships"]
```

#### Connection lifecycle with resolvers

```
WAIT_STARTUP ──→ Parse username: app_user.user_uuid_here
     │              Extract: app.user_id = 'user_uuid_here'
     ▼
AUTHENTICATING ──→ Relay auth exchange (unchanged)
     ▼
POST_AUTH ──────→ Buffer ReadyForQuery (unchanged)
     ▼
RESOLVING ──────→ Execute resolvers in dependency order:   ← NEW STATE
     │              1. org_membership  → app.org_id, app.org_role
     │              2. team_memberships → app.team_ids
     │              3. case_grants      → app.granted_case_ids
     ▼
INJECTING ──────→ SET app.user_id = 'uuid';
     │              SET app.org_id = 'org-uuid';
     │              SET app.org_role = 'admin';
     │              SET app.team_ids = '{team1,team2}';
     │              SET app.granted_case_ids = '{42,55,99}';
     │              SET ROLE app_user;
     ▼
TRANSPARENT ────→ Zero-copy pipe (unchanged)
```

#### RLS policies using resolved context

```sql
-- Simple: org-scoped isolation
CREATE POLICY org_isolation ON cases
  USING (org_id::text = current_setting('app.org_id', true));

-- Rich: multi-path access (ownership + grants + admin)
CREATE POLICY case_access ON cases USING (
  "userId"::text = current_setting('app.user_id', true)           -- creator
  OR id::text = ANY(string_to_array(
      current_setting('app.granted_case_ids', true), ','))         -- ACL grant
  OR current_setting('app.org_role', true) = 'admin'              -- org admin
);
```

### Design Constraints

#### 1. Resolvers run on a privileged connection

Resolver queries need to read membership/ACL tables that are themselves RLS-protected. Options:

- **Option A (recommended):** Resolvers run as the superuser/setup role (before `SET ROLE app_user`), reading from tables that are only visible to the privileged role. This is analogous to Oracle's `SECURITY DEFINER` policy functions.
- **Option B:** Resolver queries run via a dedicated `pgvpd_resolver` role with explicit grants on ACL tables.

#### 2. Resolver results are immutable for the session

Once context is resolved and injected, it's fixed for the connection lifetime. If a user's team membership changes, new connections pick up the change; existing connections retain the old context. This matches connection pool semantics and is consistent with Oracle VPD behavior.

#### 3. Fail-closed on resolver failure

| Scenario | Behavior |
|----------|----------|
| Resolver query returns no rows | Variable set to NULL (fail-closed via RLS) |
| Resolver query errors | Connection terminated (fail-closed) |
| Resolver timeout | Connection terminated (fail-closed) |
| Resolver returns multiple rows | First row used (or error, configurable) |
| `required = true` and no rows | Connection terminated |

#### 4. Resolver overhead is connection-time only

Resolvers execute once per connection, during the existing post-auth pause. For pooled connections, they execute once per pool checkout (if context changes) or once per connection establishment. After resolving, the connection enters the zero-copy transparent pipe — no per-query overhead.

### pgvpd_protect() Evolution

Extend the SQL helper to support richer policy patterns:

```sql
-- Existing: simple tenant isolation (unchanged)
SELECT pgvpd_protect('invoices', 'tenant_id');

-- New: multi-path access policy
SELECT pgvpd_protect_acl('cases', '{
  "paths": [
    {"column": "creator_id",  "context_var": "app.user_id",  "op": "="},
    {"column": "id",          "context_var": "app.granted_case_ids", "op": "ANY"},
    {"column": "org_id",      "context_var": "app.org_id",   "op": "=",
     "when": "app.org_role = ''admin''"}
  ]
}');

-- New: array membership
SELECT pgvpd_protect_array('documents', 'case_id', 'app.granted_case_ids');
```

These are convenience wrappers — users can always write raw `CREATE POLICY` statements.

### Helper Functions

Ship standard helper functions for common patterns:

```sql
-- Read a context variable as a UUID array
CREATE FUNCTION pgvpd_context_array(var_name TEXT)
RETURNS UUID[]
LANGUAGE sql STABLE SECURITY INVOKER AS $$
  SELECT string_to_array(
    NULLIF(current_setting(var_name, true), ''), ','
  )::UUID[];
$$;

-- Check if a value is in a context array
CREATE FUNCTION pgvpd_context_contains(var_name TEXT, val UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY INVOKER AS $$
  SELECT val = ANY(pgvpd_context_array(var_name));
$$;

-- Get context as text (fail-closed: returns NULL)
CREATE FUNCTION pgvpd_context(var_name TEXT)
RETURNS TEXT
LANGUAGE sql STABLE SECURITY INVOKER AS $$
  SELECT NULLIF(current_setting(var_name, true), '');
$$;
```

Usage in RLS:
```sql
CREATE POLICY case_access ON cases USING (
  "userId"::text = pgvpd_context('app.user_id')
  OR pgvpd_context_contains('app.granted_case_ids', id)
  OR (org_id::text = pgvpd_context('app.org_id')
      AND pgvpd_context('app.org_role') = 'admin')
);
```

## Alternatives Considered

### A. Application-side resolution (status quo for complex RBAC)

The application queries memberships, encodes everything in the username. Problems: app is in the security path, context goes stale, username becomes unwieldy (`app_user.uid.orgid.role.team1:team2:team3.case1:case2`).

### B. Postgres-side session setup function

Application calls `SELECT pgvpd_setup_session('user-uuid')` after connecting, which internally resolves context. Problems: application must remember to call it (pgvpd exists to eliminate this), loses fail-closed guarantee, doesn't work with ORMs that don't support post-connect hooks.

### C. Middleware/sidecar pattern

Run a separate service that maintains a cache of user→context mappings, and pgvpd queries it via HTTP. Problems: adds a network hop, cache staleness, another service to operate. Database is already the source of truth — querying it directly is simpler.

## Scope and Phasing

### Phase 1: Core resolver engine
- Resolver configuration (TOML `[[resolver]]` blocks)
- Dependency ordering and chained parameter binding
- `RESOLVING` state in the connection state machine
- Fail-closed semantics on all error paths
- Single-row result injection

### Phase 2: SQL helpers and convenience functions
- `pgvpd_protect_acl()` for multi-path policies
- `pgvpd_context_array()`, `pgvpd_context_contains()` helpers
- `pgvpd_protect_array()` for array-column policies

### Phase 3: Pool integration
- Re-resolve context on pool checkout (if identity changes)
- Cache resolver results per (user, resolver) with configurable TTL
- Metrics: resolver execution time, cache hit rate

### Phase 4: Declarative ACL tables (optional, higher-level)
- pgvpd-managed `pgvpd_grants` table schema
- Built-in resolver that reads from `pgvpd_grants`
- `pgvpd_grant()` / `pgvpd_revoke()` convenience functions
- This layer is optional — resolvers already support arbitrary SQL

## Compatibility

- **Backward compatible:** Existing static context (`context_variables`) continues to work unchanged. Resolvers are additive.
- **Supabase:** Works with direct connections (port 5432). Resolver queries run server-side, so PostgREST is not involved.
- **Any Postgres 12+:** Resolvers use standard SQL. No extensions required.
- **Existing RLS policies:** Resolved context is injected via the same `SET` mechanism. Existing `current_setting()` / `current_tenant_id()` calls work unchanged.

## Open Questions

1. **Resolver connection role:** Should resolvers run as the authenticated role (pre-SET ROLE) or as a dedicated resolver role? The pre-SET ROLE approach is simpler but means the connecting role needs SELECT on ACL tables.

2. **Resolver result caching:** Should pgvpd cache resolver results in-process (keyed by input params) with a TTL? This would reduce DB load for pooled connections but introduces staleness.

3. **Array serialization format:** PostgreSQL array literal (`{a,b,c}`) vs comma-separated vs JSON array? PostgreSQL array literal is most natural for `= ANY()` in RLS policies.

4. **Maximum resolver chain depth:** Should there be a limit on resolver dependency depth to prevent pathological configurations?

5. **Resolver-only mode:** Should pgvpd support a mode where identity comes entirely from the authenticated Postgres role (no username encoding), with resolvers doing all the work? This would enable integration with JWT-based auth (e.g., Supabase Auth) where the username is fixed but the JWT carries identity.
