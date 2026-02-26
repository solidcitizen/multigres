# Pgvpd Architecture

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

Every team building on Postgres re-discovers this gap and hand-rolls the same
solution: middleware for request context, connection pinning to keep `SET ROLE`
and queries on the same connection, cleanup handlers to reset state. They take
permanent ownership of security plumbing, and the failure mode is always the
same: a developer adds a route, forgets the middleware, and queries run as a
superuser. Fail-open. Cross-tenant data breach.

**Pgvpd closes this gap by moving tenant identity into the connection
itself.**

## How It Works

```
┌─────────────┐         ┌────────────────┐         ┌──────────────┐
│ Application │──TCP───→│   Pgvpd    │──TCP───→│  PostgreSQL  │
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

Each client connection goes through the following state machine. Passthrough
mode and pool mode share the same states but differ in authentication and
the transparent pipe phase.

```
  WAIT_STARTUP
       │
       │  Client sends StartupMessage with user=app_user.acme
       │  → Parse tenant from username
       │  → Rewrite username to app_user
       │  Passthrough: connect to upstream Postgres
       │  Pool mode: pgvpd authenticates client (cleartext)
       ▼
  AUTHENTICATING
       │
       │  Passthrough: relay auth exchange bidirectionally
       │    Client ←→ Pgvpd ←→ Postgres
       │    (cleartext, MD5, SCRAM-SHA-256 all work)
       │    Multi-round-trip SASL handled correctly
       │  Pool mode: pgvpd verifies client password, then
       │    checks out a pooled upstream connection
       │  → Detect AuthenticationOk
       ▼
  POST_AUTH
       │
       │  Forward ParameterStatus, BackendKeyData to client
       │  → When ReadyForQuery arrives from server: BUFFER IT
       │    (don't send to client yet)
       │  Pool mode: DISCARD ALL to reset session state
       ▼
  RESOLVING
       │
       │  Execute context resolvers (if configured)
       │  Each resolver: SQL query → bind params from prior results
       │  Results cached with configurable TTL
       │  Required resolver returning no rows → terminate connection
       ▼
  INJECTING
       │
       │  Send to server:
       │    SET app.current_tenant_id = 'acme';
       │    SET app.org_id = '<resolved>';    (if resolvers configured)
       │    SET ROLE app_user;
       │  → Consume server's CommandComplete responses
       │  → When server sends ReadyForQuery (confirming SETs):
       │    Forward the ORIGINAL buffered ReadyForQuery to client
       ▼
  TRANSPARENT
       │
       │  Passthrough: zero-copy bidirectional pipe
       │    (tokio::io::copy_bidirectional)
       │  Pool mode: message-aware pipe (pipe_pooled)
       │    Intercepts Terminate ('X') from client to preserve upstream
       │    All other messages forwarded with message framing
       │  All queries hit a connection with:
       │    - app.current_tenant_id = 'acme'
       │    - ROLE = app_user (NOBYPASSRLS)
       │  RLS policies filter every result set.
       ▼
  CLEANUP (pool mode only)
       │
       │  Send ROLLBACK (ends any open transaction)
       │  Send DISCARD ALL (resets all session state)
       │  Two separate SimpleQuery messages (DISCARD ALL
       │  cannot run inside a transaction block)
       │  → Return connection to idle pool
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

Even though Pgvpd sets the context variable, the connection must also
switch to a role that cannot bypass RLS. The `app_user` role is created with
`NOSUPERUSER NOBYPASSRLS`, so `SET ROLE app_user` ensures RLS policies are
evaluated on every query. Without this, a connection running as `postgres`
(or any role with `BYPASSRLS`) would ignore RLS policies regardless of the
context variable.

## Security Model

### Two Trust Tiers

```
┌──────────────────────────────────────┐
│           Pgvpd Proxy            │
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
| Pgvpd crashes | Connection fails. App gets error. No data leaked. |
| Context injection fails | Pgvpd closes connection. No queries run. |
| `app.current_tenant_id` not set | `current_tenant_id()` returns NULL. RLS matches zero rows. |
| Developer writes `SELECT * FROM contacts` | RLS appends the tenant filter. Only tenant's rows returned. |
| Developer writes `DELETE FROM contacts` | RLS scopes the delete. Only tenant's rows affected. |
| Someone connects as `app_user` without tenant | Username rejected — no separator found. Connection refused. |

### Defense in Depth — Done Right

Pgvpd follows the principle that **each layer should be authoritative for
its own concern**, not duplicate another layer's logic:

| Layer | Responsibility |
|-------|---------------|
| Application | Authenticate the user. Determine the tenant. Connect with the right username. |
| Pgvpd | Extract tenant from username. Set context. Switch role. |
| PostgreSQL | Enforce isolation via RLS policies. Fail-closed. |

The application does NOT write `WHERE tenant_id = ?`. That's the database's
job. Duplicating it in application code is not defense in depth — it's
redundant logic that creates synchronization obligations with no enforcement
mechanism. If the two drift, you get silent data discrepancies, not safety.

## Wire Protocol

Pgvpd implements the minimum subset of the
[Postgres v3 wire protocol](https://www.postgresql.org/docs/current/protocol-message-formats.html)
needed for the proxy lifecycle:

### Messages Parsed

| Message | Direction | Why |
|---------|-----------|-----|
| StartupMessage | Client → Server | Extract username, rewrite, forward |
| SSLRequest | Client → Server | TLS negotiation (accept or deny) |
| CancelRequest | Client → Server | Detect and close gracefully |
| Authentication (R) | Server → Client | Relay auth challenges, detect AuthenticationOk |
| ReadyForQuery (Z) | Server → Client | Buffer during injection |
| ErrorResponse (E) | Server → Client | Detect injection/resolver failures |
| CommandComplete (C) | Server → Client | Consume injection responses |
| ParameterStatus (S) | Server → Client | Forward during post-auth and injection |
| RowDescription (T) | Server → Client | Parse column names during resolver queries |
| DataRow (D) | Server → Client | Parse resolver result rows |
| BackendKeyData (K) | Server → Client | Cache for pool mode client synthesis |
| Terminate (X) | Client → Server | Intercepted in pool mode (`pipe_pooled`) to preserve upstream |

### SCRAM-SHA-256 Handling

SCRAM authentication requires multiple round-trips. Pgvpd distinguishes
between auth messages that expect a client response (SASL, SASLContinue) and
those that don't (SASLFinal, AuthenticationOk), preventing deadlocks during
the handshake.

### Messages Not Parsed (Transparent)

Everything else — `Query`, `Parse`, `Bind`, `Execute`, `CopyData`,
extended query protocol messages — are piped through without inspection.
In passthrough mode, Pgvpd is a zero-overhead TCP relay via
`tokio::io::copy_bidirectional`. In pool mode, `pipe_pooled` does
message-level framing to intercept Terminate but forwards all other
messages without deep parsing.

## Component Map

```
src/
├── main.rs           Entry point, banner, tracing setup
├── proxy.rs          TCP/TLS listener, pool/resolver creation, connection dispatch
├── connection.rs     Per-connection async state machine (the core logic)
│                       - Passthrough: auth relay → resolve → inject → copy_bidirectional
│                       - Pool mode: client auth → checkout → reset → resolve → inject → pipe_pooled
├── protocol.rs       Wire protocol primitives:
│                       - StartupMessage parse/build
│                       - Backend message framing (type + length + payload)
│                       - Query message builder
│                       - ErrorResponse builder
│                       - Auth challenge detection (SCRAM-aware)
│                       - SQL escaping (escape_literal, quote_ident)
├── auth.rs           Client-facing auth (pool mode) and upstream auth (cleartext/MD5/SCRAM)
├── pool.rs           Session connection pool:
│                       - Keyed by (database, role)
│                       - Checkout/checkin with ROLLBACK + DISCARD ALL reset
│                       - Idle reaper background task
├── resolver.rs       Context resolver engine:
│                       - TOML config parsing, topological sort
│                       - SQL query execution with parameter substitution
│                       - In-process cache with configurable TTL
├── stream.rs         Plain/TLS stream abstraction (ClientStream, UpstreamStream)
├── tls.rs            TLS configuration builders (server + client)
├── admin.rs          Admin HTTP API (/health, /metrics, /status)
├── metrics.rs        Shared atomic counters for observability
└── config.rs         Configuration from file/env/CLI (clap)

sql/
└── setup.sql         Postgres-side setup:
                        - app_user role (NOSUPERUSER NOBYPASSRLS)
                        - current_tenant_id() function (fail-closed)
                        - pgvpd_protect() helper
                        - pgvpd_status() verification

tests/
├── run.sh            Integration test runner (Docker + psql)
├── fixtures.sql      Test data (tenants, org members, RLS policies)
├── docker-compose.yml  Postgres container for tests
└── *.conf            Per-suite config files

prototype/            TypeScript prototype (validated the architecture)
```

## Performance Characteristics

| Phase | Overhead |
|-------|----------|
| Startup (connection setup → injection) | ~2 extra SQL statements per connection (+ resolver queries if configured) |
| Passthrough transparent pipe | Zero — `tokio::io::copy_bidirectional`, no message parsing |
| Pool mode transparent pipe | Minimal — `pipe_pooled` does message framing (1-byte type + 4-byte length) to intercept Terminate; all other data forwarded without deep parsing |
| Pool checkout | Reuse: ~0 (pop from idle queue). New: one upstream TCP connect + auth handshake |
| Pool checkin | Two SimpleQuery round-trips: ROLLBACK + DISCARD ALL |
| Resolver execution | One SQL round-trip per resolver (cached results skip the query) |
| Memory | Minimal per-connection: socket buffers + BytesMut state |
| Binary | Single static binary, ~2MB release build, no runtime dependencies |

Pgvpd adds latency only during connection setup. In passthrough mode, once
in transparent state, it's equivalent to a direct TCP connection. In pool
mode, `pipe_pooled` adds negligible overhead for message framing. Tokio's
async runtime handles thousands of concurrent connections on a single thread.

## Comparison with Alternatives

| Approach | Who enforces isolation? | ORM-transparent? | Fail mode |
|----------|------------------------|-------------------|-----------|
| Application `WHERE tenant_id = ?` | Application | Yes | Fail-open (forgot WHERE) |
| AsyncLocalStorage + connection pinning | Application | Yes | Fail-open (broke context) |
| Drizzle `createDrizzle` wrapper | Application | Partially | Fail-open (forgot `db.rls()`) |
| Supabase PostgREST | Infrastructure | No (must use REST) | Fail-closed |
| Nile | Database | Yes | Fail-closed |
| **Pgvpd** | **Database** | **Yes** | **Fail-closed** |
