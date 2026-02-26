import { pgTable, serial, text } from "drizzle-orm/pg-core";

export const tenants = pgTable("tenants", {
  id: serial("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  name: text("name").notNull(),
});
