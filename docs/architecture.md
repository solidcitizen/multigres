# Multigres Architecture

## The Gap in the Postgres Ecosystem

Oracle solved multi-tenant data isolation decades ago with Virtual Private
Database (VPD). You set an application context via
`DBMS_SESSION.SET_CONTEXT`, and every query on that connection is
transparently scoped to the tenant. The ORM never knows. The policy layer is
invisible to application logic.

Postgres has the same filtering engine (RLS) but not the same session-identity
primitive. `set_config` is a key-value store hanging off the session —
nothing about the connection credentials themselves carries tenant identity.
The database can't derive "who is this tenant?" from the connection alone.

Every Node.js/TypeScript team building on Postgres re-discovers this gap and
hand-rolls the same solution: `AsyncLocalStorage` for request context,
connection pinning to keep `SET ROLE` and queries on the same connection,
cleanup middleware to reset state, and a `Proxy` wrapper to make it
transparent. They take permanent ownership of security plumbing, and the
failure mode is always the same: a developer adds a route, forgets the
middleware, and queries run as a superuser. Fail-open. Cross-tenant data
breach.

**Multigres closes this gap by moving tenant identity into the connection
itself.**

## How It Works

```
┌─────────────┐         ┌────────────────┐         ┌──────────────┐
│ Application │──TCP───→│   Multigres    │──TCP───→│  PostgreSQL  │
│             │         │                │         │              │
│ Connects as │         │ 1. Parse user  │         │ Authenticates│
│ app_user.   │         │ 2. Extract     │         │ as app_user  │
│   acme      │         │    tenant      │         │              │
│             │         │ 3. Rewrite to  │         │ After auth:  │
│ Sends       │         │    app_user    │         │ SET context  │
│ normal SQL  │         │ 4. Inject SET  │         │ SET ROLE     │
│             │←──TCP───│ 5. Transparent │←──TCP───│              │
│ Gets only   │         │    pipe        │         │ RLS filters  │
│ acme's data │         │                │         │ every query  │
└─────────────┘         └────────────────┘         └──────────────┘
```

### Connection Lifecycle

Each client connection goes through a five-state machine:

```
  WAIT_STARTUP
       │
       │  Client sends StartupMessage with user=app_user.acme
       │  → Parse tenant from username
       │  → Rewrite username to app_user
       │  → Connect to upstream Postgres
       ▼
  AUTHENTICATING
       │
       │  Proxy auth messages bidirectionally
       │  Client ←→ Multigres ←→ Postgres
       │  (cleartext, MD5, SCRAM-SHA-256 all work)
       │  → Detect AuthenticationOk from server
       ▼
  POST_AUTH
       │
       │  Forward ParameterStatus, BackendKeyData to client
       │  → When ReadyForQuery arrives from server: BUFFER IT
       │    (don't send to client yet)
       ▼
  INJECTING
       │
       │  Send to server:
       │    SET app.current_tenant_id = 'acme';
       │    SET ROLE app_user;
       │  → Consume server's CommandComplete responses
       │  → When server sends ReadyForQuery (confirming SETs):
       │    Forward the ORIGINAL buffered ReadyForQuery to client
       ▼
  TRANSPARENT
       │
       │  Bidirectional TCP pipe. Zero overhead.
       │  All queries hit a connection with:
       │    - app.current_tenant_id = 'acme'
       │    - ROLE = app_user (NOBYPASSRLS)
       │  RLS policies filter every result set.
       ▼
  (connection close)
```

### Why Buffer ReadyForQuery?

The critical timing issue: the client must not send any queries until the
tenant context is set. Postgres signals "I'm ready for queries" with the
`ReadyForQuery` message. By buffering it, we create a window to inject our
`SET` commands before the client knows the connection is ready. The client
only receives `ReadyForQuery` after the context injection is confirmed.

### Why SET ROLE?

Even though Multigres sets the context variable, the connection must also
switch to a role that cannot bypass RLS. The `app_user` role is created with
`NOSUPERUSER NOBYPASSRLS`, so `SET ROLE app_user` ensures RLS policies are
evaluated on every query. Without this, a connection running as `postgres`
(or any role with `BYPASSRLS`) would ignore RLS policies regardless of the
context variable.

## Security Model

### Two Trust Tiers

```
┌──────────────────────────────────────┐
│           Multigres Proxy            │
├──────────────┬───────────────────────┤
│ Tenant Path  │  Superuser Bypass     │
│              │                       │
│ app_user.*   │  postgres             │
│ ↓            │  ↓                    │
│ Extract      │  Pass through         │
│ tenant       │  as-is                │
│ ↓            │  ↓                    │
│ SET context  │  No injection         │
│ SET ROLE     │  No role switch       │
│ ↓            │  ↓                    │
│ RLS enforced │  RLS bypassed         │
│              │  (for admin/workers)  │
└──────────────┴───────────────────────┘
```

**Tenant connections** (`app_user.acme`): Context is set, role is switched,
RLS is enforced. The application cannot bypass isolation even if it tries.

**Superuser bypass** (`postgres`): Passed through without modification.
Used for migrations, admin tools, background workers that legitimately need
cross-tenant access. Configured via `superuser_bypass` setting.

### Fail-Closed Guarantee

The system is designed so that every failure mode results in **no data
returned**, never **all data returned**:

| Failure | Outcome |
|---------|---------|
| Multigres crashes | Connection fails. App gets error. No data leaked. |
| Context injection fails | Multigres closes connection. No queries run. |
| `app.current_tenant_id` not set | `current_tenant_id()` returns NULL. RLS matches zero rows. |
| Developer writes `SELECT * FROM contacts` | RLS appends the tenant filter. Only tenant's rows returned. |
| Developer writes `DELETE FROM contacts` | RLS scopes the delete. Only tenant's rows affected. |
| Someone connects as `app_user` without tenant | Username rejected — no separator found. Connection refused. |

### Defense in Depth — Done Right

Multigres follows the principle that **each layer should be authoritative for
its own concern**, not duplicate another layer's logic:

| Layer | Responsibility |
|-------|---------------|
| Application | Authenticate the user. Determine the tenant. Connect with the right username. |
| Multigres | Extract tenant from username. Set context. Switch role. |
| PostgreSQL | Enforce isolation via RLS policies. Fail-closed. |

The application does NOT write `WHERE tenant_id = ?`. That's the database's
job. Duplicating it in application code is not defense in depth — it's
redundant logic that creates synchronization obligations with no enforcement
mechanism. If the two drift, you get silent data discrepancies, not safety.

## Wire Protocol

Multigres implements the minimum subset of the
[Postgres v3 wire protocol](https://www.postgresql.org/docs/current/protocol-message-formats.html)
needed for the proxy lifecycle:

### Messages Parsed

| Message | Direction | Why |
|---------|-----------|-----|
| StartupMessage | Client → Server | Extract username, rewrite, forward |
| SSLRequest | Client → Server | Deny with 'N' (v0.1) |
| Authentication (R) | Server → Client | Detect AuthenticationOk |
| ReadyForQuery (Z) | Server → Client | Buffer during injection |
| ErrorResponse (E) | Server → Client | Detect injection failures |
| CommandComplete (C) | Server → Client | Consume injection responses |
| ParameterStatus (S) | Server → Client | Forward during post-auth |

### Messages Not Parsed (Transparent)

Everything else — `Query`, `Parse`, `Bind`, `Execute`, `DataRow`,
`RowDescription`, `CopyData`, extended query protocol messages — are piped
through without inspection. After entering `TRANSPARENT` state, Multigres
is a zero-overhead TCP relay.

## Component Map

```
src/
├── index.ts          CLI entry point, banner, shutdown handling
├── proxy.ts          TCP server, accepts connections
├── connection.ts     Per-connection state machine (the core logic)
├── protocol.ts       Wire protocol primitives:
│                       - StartupMessage parse/build
│                       - MessageFramer (TCP stream → messages)
│                       - Query message builder
│                       - ErrorResponse builder
│                       - Message type detection helpers
├── config.ts         Configuration from file/env/CLI
└── log.ts            Structured colored logger

sql/
└── setup.sql         Postgres-side setup:
                        - app_user role (NOSUPERUSER NOBYPASSRLS)
                        - current_tenant_id() function (fail-closed)
                        - multigres_protect() helper
                        - multigres_status() verification
```

## Performance Characteristics

| Phase | Overhead |
|-------|----------|
| Startup (WAIT_STARTUP → INJECTING) | ~2 extra SQL statements per connection |
| Transparent pipe | Zero — raw TCP relay, no message parsing |
| Memory | ~1KB per connection (socket buffers + state) |

Multigres adds latency only during connection setup. Once in transparent
mode, it's equivalent to a direct TCP connection.

## Comparison with Alternatives

| Approach | Who enforces isolation? | ORM-transparent? | Fail mode |
|----------|------------------------|-------------------|-----------|
| Application `WHERE tenant_id = ?` | Application | Yes | Fail-open (forgot WHERE) |
| AsyncLocalStorage + connection pinning | Application | Yes | Fail-open (broke context) |
| Drizzle `createDrizzle` wrapper | Application | Partially | Fail-open (forgot `db.rls()`) |
| Supabase PostgREST | Infrastructure | No (must use REST) | Fail-closed |
| Nile | Database | Yes | Fail-closed |
| **Multigres** | **Database** | **Yes** | **Fail-closed** |
