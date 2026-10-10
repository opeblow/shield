import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import pg from "pg";
import { randomUUID } from "node:crypto";

const { Client } = pg;
const composeFile = process.env.COMPOSE_FILE ?? "infra/verify.compose.yml";
const project = process.env.COMPOSE_PROJECT_NAME ?? "shield-verify";
const backupDir = process.env.REPORT_DIR ?? "reports";
const backupPath = path.join(backupDir, "postgres-backup.dump");
const adminUrl = process.env.DATABASE_URL_MIGRATOR ?? "postgres://shield:shield_local_test_only@127.0.0.1:55432/shield";
const tempDb = `shield_restore_${randomUUID().replaceAll("-", "")}`;
const docker = (args, input) => spawnSync("docker", ["compose", "-f", composeFile, "-p", project, ...args], { input, maxBuffer: 256 * 1024 * 1024 });
function must(result, label) { if (result.error || result.status !== 0) throw new Error(`${label} failed: ${result.error?.message ?? result.stderr}`); return result; }
await mkdir(backupDir, { recursive: true });
const started = performance.now();
const source = new Client({ connectionString: adminUrl });
await source.connect();
const sourceCounts = await source.query("SELECT (SELECT count(*) FROM tenants)::int AS tenants, (SELECT count(*) FROM scans)::int AS scans, (SELECT count(*) FROM accounts)::int AS accounts");
await source.end();
const dump = must(docker(["exec", "-T", "postgres", "pg_dump", "-U", "shield", "-Fc", "shield"]), "pg_dump").stdout;
await writeFile(backupPath, dump);
const parsed = new URL(adminUrl);
parsed.pathname = "/postgres";
const admin = new Client({ connectionString: parsed.toString() });
await admin.connect();
try {
  await admin.query(`CREATE DATABASE "${tempDb}"`);
  must(docker(["exec", "-i", "postgres", "pg_restore", "-U", "shield", "-d", tempDb, "--no-owner"], dump), "pg_restore");
  const restoredUrl = new URL(adminUrl); restoredUrl.pathname = `/${tempDb}`;
  const restored = new Client({ connectionString: restoredUrl.toString() });
  await restored.connect();
  const check = await restored.query("SELECT (SELECT count(*) FROM tenants)::int AS tenants, (SELECT count(*) FROM scans)::int AS scans, (SELECT count(*) FROM accounts)::int AS accounts");
  await restored.end();
  if (JSON.stringify(check.rows[0]) !== JSON.stringify(sourceCounts.rows[0])) throw new Error(`restored row counts differ: source=${JSON.stringify(sourceCounts.rows[0])} restore=${JSON.stringify(check.rows[0])}`);
  const elapsedMs = Math.round(performance.now() - started);
  const result = { backup_file: backupPath, backup_bytes: dump.length, restore_elapsed_ms: elapsedMs, rto_ms: elapsedMs, source_counts: sourceCounts.rows[0], restored_counts: check.rows[0], result: "PASS" };
  await writeFile(path.join(backupDir, "backup-restore.json"), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally {
  await admin.query(`DROP DATABASE IF EXISTS "${tempDb}" WITH (FORCE)`);
  await admin.end();
}
