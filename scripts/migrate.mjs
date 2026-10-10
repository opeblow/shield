import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Client } = pg;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = path.join(root, "infra/migrations");
const url = process.env.DATABASE_URL_MIGRATOR ?? process.env.DATABASE_URL;
if (!url) throw new Error("Set DATABASE_URL_MIGRATOR or DATABASE_URL");
const direction = process.argv[2] ?? "up";
if (direction !== "up" && direction !== "down") throw new Error("Usage: node scripts/migrate.mjs up|down");
const client = new Client({ connectionString: url });
await client.connect();
try {
  await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const files = (await readdir(migrationsDir)).filter((name) => /^\d+_[a-z0-9_-]+\.sql$/i.test(name)).sort();
  if (direction === "up") {
    for (const file of files) {
      const existing = await client.query("SELECT 1 FROM schema_migrations WHERE version = $1", [file]);
      if (existing.rowCount) continue;
      await client.query("BEGIN");
      try {
        await client.query(await readFile(path.join(migrationsDir, file), "utf8"));
        await client.query("INSERT INTO schema_migrations(version) VALUES ($1)", [file]);
        await client.query("COMMIT");
        console.log(`UP ${file}`);
      } catch (error) { await client.query("ROLLBACK"); throw error; }
    }
  } else {
    const applied = await client.query("SELECT version FROM schema_migrations ORDER BY version DESC");
    for (const { version } of applied.rows) {
      const downFile = version.replace(/\.sql$/, ".down.sql");
      await client.query("BEGIN");
      try {
        await client.query(await readFile(path.join(migrationsDir, downFile), "utf8"));
        await client.query("DELETE FROM schema_migrations WHERE version = $1", [version]);
        await client.query("COMMIT");
        console.log(`DOWN ${version}`);
      } catch (error) { await client.query("ROLLBACK"); throw error; }
    }
  }
} finally { await client.end(); }
