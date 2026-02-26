-- ============================================================================
-- pgvpd Integration Test Fixtures
-- ============================================================================
-- Run as superuser (postgres) against pgvpd_test database.
-- Sets up roles, functions, test tables, and resolver support tables.
-- ============================================================================

-- ─── 1. Run the standard pgvpd setup ──────────────────────────────────────

\i sql/setup.sql

-- ─── 2. Set app_user password for test environment ────────────────────────

ALTER ROLE app_user WITH PASSWORD 'testpass';

-- ─── 3. Create test table ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  id serial PRIMARY KEY,
  tenant_id text NOT NULL,
  name text NOT NULL
);

INSERT INTO tenants (tenant_id, name) VALUES
  ('tenant_a', 'Alice Corp'),
  ('tenant_a', 'Alice LLC'),
  ('tenant_b', 'Bob Inc'),
  ('tenant_b', 'Bob Ltd');

-- Protect with RLS
SELECT pgvpd_protect('tenants', 'tenant_id');

-- ─── 4. Resolver support tables ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS org_memberships (
  user_id uuid NOT NULL,
  org_id uuid NOT NULL,
  role text NOT NULL,
  is_active bool NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS team_memberships (
  user_id uuid NOT NULL,
  team_id uuid NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL,
  is_active bool NOT NULL DEFAULT true
);

-- Test data: known user with org membership
INSERT INTO org_memberships (user_id, org_id, role, is_active) VALUES
  ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '11111111-2222-3333-4444-555555555555', 'admin', true),
  ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '99999999-9999-9999-9999-999999999999', 'viewer', false);

-- Grant SELECT on resolver tables to app_user
GRANT SELECT ON org_memberships TO app_user;
GRANT SELECT ON team_memberships TO app_user;
GRANT SELECT ON teams TO app_user;

-- Grant sequence usage for tenants table
GRANT USAGE, SELECT ON SEQUENCE tenants_id_seq TO app_user;

-- ─── 5. Install SQL helpers ────────────────────────────────────────────────

\i sql/helpers.sql

-- ─── 6. Create test table for pgvpd_protect_acl ──────────────────────────

CREATE TABLE IF NOT EXISTS acl_cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id uuid,
  org_id uuid,
  title text NOT NULL
);

INSERT INTO acl_cases (id, creator_id, org_id, title) VALUES
  ('aaaaaaaa-0000-0000-0000-000000000001', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '11111111-2222-3333-4444-555555555555', 'Case owned by test user'),
  ('aaaaaaaa-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000099', '11111111-2222-3333-4444-555555555555', 'Case in same org'),
  ('aaaaaaaa-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000099', '99999999-9999-9999-9999-999999999999', 'Case in other org');

GRANT SELECT, INSERT, UPDATE, DELETE ON acl_cases TO app_user;

-- ─── Done ─────────────────────────────────────────────────────────────────

DO $$ BEGIN RAISE NOTICE 'Test fixtures loaded.'; END $$;
