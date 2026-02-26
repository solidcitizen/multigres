-- ============================================================================
-- Pgvpd: SQL Helper Functions for RLS Policies
-- ============================================================================
--
-- Convenience functions that make RLS policies readable and composable.
-- All functions are STABLE SECURITY INVOKER — safe for RLS and index use.
--
-- Install:
--   psql -U postgres -d your_database -f sql/helpers.sql
--
-- ============================================================================

-- ─── pgvpd_context(var_name) ────────────────────────────────────────────────
--
-- Read a session variable, fail-closed (NULL if unset or empty).
--
-- Usage in RLS:
--   USING ("userId"::text = pgvpd_context('app.user_id'))

CREATE OR REPLACE FUNCTION pgvpd_context(var_name TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT NULLIF(current_setting(var_name, true), '');
$$;

COMMENT ON FUNCTION pgvpd_context(TEXT) IS
  'Pgvpd: Read a session variable. Returns NULL if unset or empty (fail-closed).';

-- ─── pgvpd_context_array(var_name) ──────────────────────────────────────────
--
-- Parse a comma-separated session variable into a TEXT array.
-- Returns NULL if the variable is unset or empty.
--
-- Usage:
--   SELECT pgvpd_context_array('app.team_ids')  →  {team1,team2,team3}

CREATE OR REPLACE FUNCTION pgvpd_context_array(var_name TEXT)
RETURNS TEXT[]
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT string_to_array(pgvpd_context(var_name), ',');
$$;

COMMENT ON FUNCTION pgvpd_context_array(TEXT) IS
  'Pgvpd: Parse a comma-separated session variable into a TEXT[]. NULL if unset.';

-- ─── pgvpd_context_uuid_array(var_name) ─────────────────────────────────────
--
-- Parse a comma-separated session variable into a UUID array.
-- Returns NULL if the variable is unset or empty.
--
-- Usage:
--   SELECT pgvpd_context_uuid_array('app.granted_case_ids')

CREATE OR REPLACE FUNCTION pgvpd_context_uuid_array(var_name TEXT)
RETURNS UUID[]
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT pgvpd_context_array(var_name)::uuid[];
$$;

COMMENT ON FUNCTION pgvpd_context_uuid_array(TEXT) IS
  'Pgvpd: Parse a comma-separated session variable into a UUID[]. NULL if unset.';

-- ─── pgvpd_context_contains(var_name, val) ──────────────────────────────────
--
-- Check if a UUID is in a comma-separated session variable.
-- Shorthand for: val = ANY(pgvpd_context_uuid_array(var_name))
--
-- Usage in RLS:
--   USING (pgvpd_context_contains('app.granted_case_ids', id))

CREATE OR REPLACE FUNCTION pgvpd_context_contains(var_name TEXT, val UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT COALESCE(val = ANY(pgvpd_context_uuid_array(var_name)), false);
$$;

COMMENT ON FUNCTION pgvpd_context_contains(TEXT, UUID) IS
  'Pgvpd: Check if a UUID is in a comma-separated session variable.';

-- ─── pgvpd_context_text_contains(var_name, val) ─────────────────────────────
--
-- Check if a TEXT value is in a comma-separated session variable.
-- Shorthand for: val = ANY(pgvpd_context_array(var_name))
--
-- Usage in RLS:
--   USING (pgvpd_context_text_contains('app.roles', role))

CREATE OR REPLACE FUNCTION pgvpd_context_text_contains(var_name TEXT, val TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY INVOKER
AS $$
  SELECT COALESCE(val = ANY(pgvpd_context_array(var_name)), false);
$$;

COMMENT ON FUNCTION pgvpd_context_text_contains(TEXT, TEXT) IS
  'Pgvpd: Check if a TEXT value is in a comma-separated session variable.';

-- ─── pgvpd_protect_acl(target_table, paths) ─────────────────────────────────
--
-- Build a multi-path RLS policy from a JSON config.
-- Each path becomes one OR branch in the policy.
--
-- Supported path types:
--   "text"       — column = pgvpd_context(var)
--   "uuid"       — column = pgvpd_context(var)::uuid
--   "uuid_array" — pgvpd_context_contains(var, column)
--   "text_array" — pgvpd_context_text_contains(var, column)
--
-- Each path may include an optional "when" condition that gates the branch.
--
-- Usage:
--   SELECT pgvpd_protect_acl('cases', '[
--     {"column": "creator_id", "var": "app.user_id", "type": "uuid"},
--     {"column": "id", "var": "app.granted_case_ids", "type": "uuid_array"},
--     {"column": "org_id", "var": "app.org_id", "type": "uuid",
--      "when": "pgvpd_context(''app.org_role'') = ''admin''"}
--   ]');

CREATE OR REPLACE FUNCTION pgvpd_protect_acl(
  target_table TEXT,
  paths JSONB
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  policy_name TEXT;
  expr TEXT := '';
  path JSONB;
  col TEXT;
  var TEXT;
  typ TEXT;
  cond TEXT;
  branch TEXT;
  i INT := 0;
BEGIN
  -- Enable RLS
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target_table);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', target_table);

  -- Grant DML to app_user
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_user', target_table);

  -- Build expression from paths
  FOR path IN SELECT * FROM jsonb_array_elements(paths)
  LOOP
    col  := path->>'column';
    var  := path->>'var';
    typ  := path->>'type';
    cond := path->>'when';

    -- Build the branch expression based on type
    CASE typ
      WHEN 'text' THEN
        branch := format('%I = pgvpd_context(%L)', col, var);
      WHEN 'uuid' THEN
        branch := format('%I = pgvpd_context(%L)::uuid', col, var);
      WHEN 'uuid_array' THEN
        branch := format('pgvpd_context_contains(%L, %I)', var, col);
      WHEN 'text_array' THEN
        branch := format('pgvpd_context_text_contains(%L, %I)', var, col);
      ELSE
        RAISE EXCEPTION 'pgvpd_protect_acl: unknown type "%" for column "%"', typ, col;
    END CASE;

    -- Wrap with optional condition
    IF cond IS NOT NULL THEN
      branch := format('(%s AND %s)', branch, cond);
    END IF;

    -- Combine with OR
    IF i > 0 THEN
      expr := expr || E'\n  OR ';
    END IF;
    expr := expr || branch;
    i := i + 1;
  END LOOP;

  IF i = 0 THEN
    RAISE EXCEPTION 'pgvpd_protect_acl: paths array is empty';
  END IF;

  -- Create the policy
  policy_name := 'pgvpd_acl_' || target_table;

  EXECUTE format('DROP POLICY IF EXISTS %I ON %I', policy_name, target_table);

  EXECUTE format(
    'CREATE POLICY %I ON %I FOR ALL TO app_user USING (%s) WITH CHECK (%s)',
    policy_name,
    target_table,
    expr,
    expr
  );

  RAISE NOTICE 'Pgvpd: Created ACL policy "%" on "%" with % path(s)',
    policy_name, target_table, i;
END;
$$;

COMMENT ON FUNCTION pgvpd_protect_acl(TEXT, JSONB) IS
  'Pgvpd: Build a multi-path RLS policy from a JSON config. Each path is one OR branch.';

-- ─── Done ───────────────────────────────────────────────────────────────────

DO $$ BEGIN RAISE NOTICE 'Pgvpd SQL helpers installed.'; END $$;
