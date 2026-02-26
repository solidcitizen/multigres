import { describe, it } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq } from "drizzle-orm";
import { tenants } from "./schema.js";

const PGVPD_HOST = process.env.PGVPD_HOST ?? "127.0.0.1";
const PGVPD_PORT = Number(process.env.PGVPD_PORT ?? 16432);
const PG_DB = process.env.PG_DB ?? "pgvpd_test";
const PG_PASS = process.env.PG_PASS ?? "testpass";
const SUITE = process.env.PGVPD_SUITE ?? "all";

function makeClient(user: string) {
  return new pg.Client({
    host: PGVPD_HOST,
    port: PGVPD_PORT,
    database: PG_DB,
    user,
    password: PG_PASS,
  });
}

async function withDrizzle<T>(
  user: string,
  fn: (db: ReturnType<typeof drizzle>) => Promise<T>,
): Promise<T> {
  const client = makeClient(user);
  await client.connect();
  try {
    const db = drizzle(client);
    return await fn(db);
  } finally {
    await client.end();
  }
}

// ─── Passthrough Mode ─────────────────────────────────────────────────────

if (SUITE === "passthrough" || SUITE === "all") {
  describe("Suite 7: Drizzle ORM — Passthrough", () => {
    it("7.1  tenant_a SELECT", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        const rows = await db.select().from(tenants).orderBy(tenants.name);
        const names = rows.map((r) => r.name);
        assert.ok(names.includes("Alice Corp"), "should see Alice Corp");
        assert.ok(names.includes("Alice LLC"), "should see Alice LLC");
        assert.ok(!names.some((n) => n.startsWith("Bob")), "should not see Bob rows");
      });
    });

    it("7.1b tenant_b SELECT", async () => {
      await withDrizzle("app_user.tenant_b", async (db) => {
        const rows = await db.select().from(tenants).orderBy(tenants.name);
        const names = rows.map((r) => r.name);
        assert.ok(names.includes("Bob Inc"), "should see Bob Inc");
        assert.ok(names.includes("Bob Ltd"), "should see Bob Ltd");
        assert.ok(!names.some((n) => n.startsWith("Alice")), "should not see Alice rows");
      });
    });

    it("7.2  cross-tenant WHERE returns empty", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        const rows = await db
          .select()
          .from(tenants)
          .where(eq(tenants.tenantId, "tenant_b"));
        assert.equal(rows.length, 0, "tenant_a must not see tenant_b rows");
      });
    });

    it("7.3  INSERT scoped to own tenant", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        try {
          await db
            .insert(tenants)
            .values({ tenantId: "tenant_a", name: "Alice Test Row" });

          const rows = await db
            .select()
            .from(tenants)
            .where(eq(tenants.name, "Alice Test Row"));
          assert.equal(rows.length, 1, "inserted row visible to tenant_a");
        } finally {
          await db
            .delete(tenants)
            .where(eq(tenants.name, "Alice Test Row"));
        }
      });

      // Verify invisibility from tenant_b
      await withDrizzle("app_user.tenant_b", async (db) => {
        const rows = await db
          .select()
          .from(tenants)
          .where(eq(tenants.name, "Alice Test Row"));
        assert.equal(rows.length, 0, "inserted row invisible to tenant_b");
      });
    });

    it("7.3b INSERT wrong tenant_id rejected by WITH CHECK", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        await assert.rejects(
          () =>
            db
              .insert(tenants)
              .values({ tenantId: "tenant_b", name: "Should Fail" }),
          (err: unknown) => {
            assert.ok(err instanceof Error);
            assert.ok(
              /row-level security|new row violates|policy/i.test(err.message),
              `expected RLS violation, got: ${err.message}`,
            );
            return true;
          },
        );
      });
    });

    it("7.4  transaction stays tenant-scoped", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        try {
          await db.transaction(async (tx) => {
            await tx
              .insert(tenants)
              .values({ tenantId: "tenant_a", name: "Alice Txn Row" });

            const rows = await tx
              .select()
              .from(tenants)
              .where(eq(tenants.name, "Alice Txn Row"));
            assert.equal(rows.length, 1, "row visible inside transaction");

            // Verify no cross-tenant leak inside txn
            const leak = await tx
              .select()
              .from(tenants)
              .where(eq(tenants.tenantId, "tenant_b"));
            assert.equal(leak.length, 0, "no tenant_b rows inside txn");
          });
        } finally {
          await db
            .delete(tenants)
            .where(eq(tenants.name, "Alice Txn Row"));
        }
      });
    });

    it("7.5  superuser bypass", async () => {
      await withDrizzle("postgres", async (db) => {
        const rows = await db.select().from(tenants);
        assert.ok(rows.length >= 4, `superuser should see all rows, got ${rows.length}`);
      });
    });
  });
}

// ─── Pool Mode ────────────────────────────────────────────────────────────

if (SUITE === "pool" || SUITE === "all") {
  describe("Suite 7P: Drizzle ORM — Pool", () => {
    it("7P.1 tenant isolation via pool", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        const rows = await db.select().from(tenants).orderBy(tenants.name);
        const names = rows.map((r) => r.name);
        assert.ok(names.includes("Alice Corp"), "should see Alice Corp");
        assert.ok(!names.some((n) => n.startsWith("Bob")), "should not see Bob rows");
      });
    });

    it("7P.2 cross-tenant invisibility via pool", async () => {
      await withDrizzle("app_user.tenant_a", async (db) => {
        const rows = await db
          .select()
          .from(tenants)
          .where(eq(tenants.tenantId, "tenant_b"));
        assert.equal(rows.length, 0, "tenant_a must not see tenant_b rows");
      });
    });

    it("7P.3 superuser bypass via pool", async () => {
      await withDrizzle("postgres", async (db) => {
        const rows = await db.select().from(tenants);
        assert.ok(rows.length >= 4, `superuser should see all rows, got ${rows.length}`);
      });
    });
  });
}
