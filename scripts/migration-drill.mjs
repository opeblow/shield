import { randomUUID } from "node:crypto";
import pg from "pg";
import { spawnSync } from "node:child_process";

const { Client } = pg;
const adminUrl = process.env.DATABASE_URL_MIGRATOR;
if (!adminUrl) throw new Error("DATABASE_URL_MIGRATOR is required");
const parsed = new URL(adminUrl);
const originalDb = parsed.pathname.slice(1);
const tempDb = `shield_migration_${randomUUID().replaceAll("-", "")}`;
parsed.pathname = "/postgres";
const admin = new Client({ connectionString: parsed.toString() });
await admin.connect();
const started = performance.now();
try {
  await admin.query(`CREATE DATABASE "${tempDb}"`);
  const testUrl = new URL(adminUrl);
  testUrl.pathname = `/${tempDb}`;
  const env = { ...process.env, DATABASE_URL_MIGRATOR: testUrl.toString() };
  for (const direction of ["up", "down", "up"]) {
    const result = spawnSync(process.execPath, ["scripts/migrate.mjs", direction], { env, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`${direction} failed: ${result.stderr || result.stdout}`);
    process.stdout.write(result.stdout);
    if (direction === "down") {
      const verifyDown = new Client({ connectionString: testUrl.toString() });
      await verifyDown.connect();
      const empty = await verifyDown.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('tenants','scans','accounts','integration_keys','scan_records')");
      const applied = await verifyDown.query("SELECT count(*)::int AS n FROM schema_migrations");
      await verifyDown.end();
      if (empty.rows[0].n !== 0 || applied.rows[0].n !== 0) throw new Error("down did not remove migrated tables and applied-version records");
    }
  }
  const check = new Client({ connectionString: testUrl.toString() });
  await check.connect();
  const tables = await check.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('tenants','scans','accounts','integration_keys','scan_records')");
  await check.end();
  if (tables.rows[0].n !== 5) throw new Error("up/down/up did not restore all expected tables");
  console.log(JSON.stringify({ database: tempDb, original_database: originalDb, up_down_up_ms: Math.round(performance.now() - started), restored_tables: tables.rows[0].n }));
} finally {
  await admin.query(`DROP DATABASE IF EXISTS "${tempDb}" WITH (FORCE)`);
  await admin.end();
}
