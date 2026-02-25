-- ============================================================================
-- Multigres: PostgreSQL Setup Script
-- ============================================================================
--
-- Run this against your Postgres database to configure the roles, functions,
-- and policies needed for Multigres VPD.
--
-- Prerequisites:
--   - Connected as a superuser (postgres)
--   - Target database already exists
--
-- Usage:
--   psql -U postgres -d your_database -f sql/setup.sql
--
-- ============================================================================

-- ─── 1. Create the application role ─────────────────────────────────────────
--
-- This role is used for all tenant-scoped connections through Multigres.
-- CRITICAL: NOBYPASSRLS ensures RLS policies are ALWAYS enforced.
--           NOSUPERUSER ensures the role can never escalate.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user WITH LOGIN PASSWORD 'changeme'
      NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
    RAISE NOTICE 'Created role: app_user';
  ELSE
    -- Verify security attributes (best-effort — may fail on managed Postgres
    -- where the connecting role lacks SUPERUSER, e.g. Supabase).
    BEGIN
      ALTER ROLE app_user WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
      RAISE NOTICE 'Role app_user already exists — verified security attributes';
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE NOTICE 'Role app_user exists — cannot alter (managed Postgres). Verify attributes manually:';
      RAISE NOTICE '  SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = ''app_user'';';
    END;
  END IF;

  -- Grant app_user to the current role so SET ROLE works
  BEGIN
    EXECUTE format('GRANT app_user TO %I', current_user);
  EXCEPTION WHEN duplicate_object THEN
    NULL; -- already granted
  END;
END $$;

-- ─── 2. Fail-closed tenant ID function ──────────────────────────────────────
--
-- Returns the current tenant ID from session variables.
-- Returns NULL if not set → RLS policies using this will match zero rows.
-- This is the FAIL-CLOSED guarantee.

CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $$
BEGIN
  RETURN NULLIF(current_setting('app.current_tenant_id', true), '');
EXCEPTION
  WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION current_tenant_id() IS
  'Multigres: Returns current tenant ID from session. NULL = fail-closed (no rows visible).';

-- ─── 3. Helper: Enable Multigres RLS on a table ────────────────────────────
--
-- Call this for every tenant-scoped table.
-- It enables RLS, FORCES it (even for table owners), and creates
-- the standard isolation policy.
--
-- Usage:
--   SELECT multigres_protect('contacts', 'tenant_id');
--   SELECT multigres_protect('invoices', 'org_id');

CREATE OR REPLACE FUNCTION multigres_protect(
  target_table TEXT,
  tenant_column TEXT DEFAULT 'tenant_id'
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  policy_name TEXT;
BEGIN
  -- Enable RLS
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target_table);

  -- Force RLS even for table owner
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', target_table);

  -- Grant DML to app_user
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_user', target_table);

  -- Create fail-closed isolation policy
  policy_name := 'multigres_tenant_isolation_' || target_table;

  -- Drop existing policy if it exists (idempotent)
  EXECUTE format('DROP POLICY IF EXISTS %I ON %I', policy_name, target_table);

  EXECUTE format(
    'CREATE POLICY %I ON %I FOR ALL TO app_user USING (%I = current_tenant_id()) WITH CHECK (%I = current_tenant_id())',
    policy_name,
    target_table,
    tenant_column,
    tenant_column
  );

  RAISE NOTICE 'Multigres: Protected table "%" on column "%" — RLS enabled, fail-closed policy active',
    target_table, tenant_column;
END;
$$;

COMMENT ON FUNCTION multigres_protect(TEXT, TEXT) IS
  'Multigres: Enable RLS + FORCE + fail-closed tenant isolation on a table.';

-- ─── 4. Verification helper ─────────────────────────────────────────────────
--
-- Lists all tables and their Multigres protection status.

CREATE OR REPLACE FUNCTION multigres_status()
RETURNS TABLE (
  table_name TEXT,
  rls_enabled BOOLEAN,
  rls_forced BOOLEAN,
  policy_count BIGINT
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    c.relname::TEXT AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS rls_forced,
    (SELECT count(*) FROM pg_policies p WHERE p.tablename = c.relname) AS policy_count
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind = 'r'
    AND n.nspname = 'public'
  ORDER BY c.relname;
$$;

COMMENT ON FUNCTION multigres_status() IS
  'Multigres: Show RLS protection status for all public tables.';

-- ─── 5. Grant usage on sequences (needed for INSERT with serial/identity) ───

DO $$
DECLARE
  seq RECORD;
BEGIN
  FOR seq IN
    SELECT sequence_name FROM information_schema.sequences
    WHERE sequence_schema = 'public'
  LOOP
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %I TO app_user', seq.sequence_name);
  END LOOP;
END $$;

-- ─── Done ───────────────────────────────────────────────────────────────────

DO $$
BEGIN
  RAISE NOTICE '';
  RAISE NOTICE '══════════════════════════════════════════════════════════════';
  RAISE NOTICE '  Multigres setup complete.';
  RAISE NOTICE '';
  RAISE NOTICE '  Next steps:';
  RAISE NOTICE '    1. Protect your tables:';
  RAISE NOTICE '       SELECT multigres_protect(''your_table'', ''tenant_id'');';
  RAISE NOTICE '';
  RAISE NOTICE '    2. Change the app_user password:';
  RAISE NOTICE '       ALTER ROLE app_user WITH PASSWORD ''your_secure_password'';';
  RAISE NOTICE '';
  RAISE NOTICE '    3. Start Multigres:';
  RAISE NOTICE '       multigres --upstream-port 5432';
  RAISE NOTICE '';
  RAISE NOTICE '    4. Connect through Multigres:';
  RAISE NOTICE '       psql -h localhost -p 6432 -U app_user.my_tenant mydb';
  RAISE NOTICE '';
  RAISE NOTICE '    5. Verify isolation:';
  RAISE NOTICE '       SELECT * FROM multigres_status();';
  RAISE NOTICE '══════════════════════════════════════════════════════════════';
END $$;
