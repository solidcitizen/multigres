# Changelog

All notable changes to pgvpd are documented here.

## [0.8.0] — 2026-02-25

### Added
- GitHub Actions CI (cargo check, test, clippy, fmt, integration tests)
- GitHub Actions release workflow (cross-compiled binaries, crates.io publish)
- Dockerfile (multi-stage build)
- LICENSE file (MIT)
- This changelog

### Changed
- Cargo.toml: added crates.io metadata (repository, homepage, keywords, categories, readme)
- PLAN.md: replaced vague v1.0 milestone with concrete v0.8/v0.9 plan

## [0.7.0] — 2025-06-01

### Added
- SQL helper functions: `pgvpd_context()`, `pgvpd_context_array()`, `pgvpd_context_uuid_array()`, `pgvpd_context_contains()`, `pgvpd_context_text_contains()`
- `pgvpd_protect_acl()` for multi-path RLS policies (ownership + ACL grants + team membership + org roles)
- `sql/helpers.sql` installable script
- 10 new integration tests for SQL helpers

## [0.6.0] — 2025-05-01

### Added
- Tenant allow/deny lists (`tenant_allow`, `tenant_deny`)
- Per-tenant connection limits (`tenant_max_connections`)
- Per-tenant rate limiting (`tenant_rate_limit`) — fixed-window 1-second rate limiter
- Query/idle timeout (`tenant_query_timeout`)
- `TenantRegistry` — shared per-tenant state with lazy creation
- Metrics: `pgvpd_tenant_rejected_total{reason=deny|limit|rate}`, `pgvpd_tenant_timeouts_total`
- Configurable `set_role` target (override SET ROLE username)
- 5 integration tests for tenant isolation

## [0.5.0] — 2025-04-01

### Added
- Admin HTTP API on configurable `admin_port` (axum)
  - `GET /health` — 200 OK for load balancer health checks
  - `GET /metrics` — Prometheus exposition format
  - `GET /status` — JSON pool and resolver state
- Shared metrics (`Arc<Metrics>`) with `AtomicU64` counters
- Connection, pool, and resolver metrics
- 4 integration tests for admin API

## [0.4.0] — 2025-03-01

### Added
- Context resolver engine: `[[resolver]]` config blocks — SQL queries that run post-auth to derive session variables from database state
- Dependency ordering: resolvers chain via bind parameters
- Context caching with configurable TTL
- Fail-closed semantics: resolver error → connection terminated
- Resolver-only mode: all context derived from database, not username
- 13 end-to-end integration tests (passthrough, pool, resolver)

## [0.3.0] — 2025-02-01

### Added
- Session connection pooling (`pool_mode = session`)
- Pgvpd-side client authentication (cleartext)
- Upstream authentication (cleartext, MD5, SCRAM-SHA-256)
- Pool checkout/checkin with `DISCARD ALL` reset
- Idle connection reaper
- Superuser bypass (never pooled)

## [0.2.0] — 2025-01-15

### Added
- TLS termination (client → pgvpd)
- TLS origination (pgvpd → upstream Postgres)
- Handshake timeout enforcement

## [0.1.0] — 2025-01-01

### Added
- Initial release: TCP proxy with tenant extraction from username
- Auth relay (passthrough)
- Context injection (`SET` commands after auth)
- Transparent bidirectional pipe (`tokio::io::copy_bidirectional`)
- Single static binary, zero runtime dependencies
