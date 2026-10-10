import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import pg from "pg";
import { createClient } from "redis";
import { ScanRepository } from "../../dist/apps/api/src/repository.js";

const { Pool } = pg;
const base = process.env.VERIFY_API_URL ?? "http://127.0.0.1:33001";
const base2 = process.env.VERIFY_API_URL_2 ?? "http://127.0.0.1:33003";
const openai = process.env.VERIFY_OPENAI_URL ?? "http://127.0.0.1:4010";
const admin = new Pool({ connectionString: process.env.DATABASE_URL_MIGRATOR });
const runtime = new Pool({ connectionString: process.env.DATABASE_URL_RUNTIME });
const redis = createClient({ url: process.env.REDIS_URL_TEST ?? "redis://127.0.0.1:56379" });
await redis.connect();
test.after(async () => { await Promise.all([admin.end(), runtime.end(), redis.quit()]); });

async function eventually(assertion, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try { return await assertion(); } catch (error) { last = error; await new Promise((resolve) => setTimeout(resolve, 150)); }
  }
  throw last ?? new Error("condition did not become true");
}

test("PostgreSQL RLS blocks cross-tenant reads, updates, deletes and inserts at the database layer", async () => {
  const tenantTables = await admin.query(
    `SELECT c.relname, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced
     FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='public' AND c.relkind='r'
       AND EXISTS (SELECT 1 FROM information_schema.columns col WHERE col.table_schema='public' AND col.table_name=c.relname AND col.column_name='tenant_id')`
  );
  assert.ok(tenantTables.rows.length >= 7, "schema must enumerate tenant-tagged data tables");
  assert.deepEqual(tenantTables.rows.filter((row) => !row.rls || !row.forced).map((row) => row.relname), []);
  const tenantA = await admin.query("INSERT INTO tenants(name) VALUES ('integration-a') RETURNING id");
  const tenantB = await admin.query("INSERT INTO tenants(name) VALUES ('integration-b') RETURNING id");
  const a = tenantA.rows[0].id;
  const b = tenantB.rows[0].id;
  const scanA = randomUUID();
  const scanB = randomUUID();
  const insert = async (id, tenant) => admin.query(
    "INSERT INTO scans(id,tenant_id,input_types,verdict,risk_score,confidence,language,latency_ms,model_version,content_hash,result,expires_at) VALUES ($1,$2,ARRAY['text'],'safe',0,0.5,'en',1,'test',$3,'{}'::jsonb,now()+interval '1 day')",
    [id, tenant, randomUUID()]
  );
  await insert(scanA, a);
  await insert(scanB, b);
  const client = await runtime.connect();
  try {
    await client.query("SELECT set_config('app.tenant_id',$1,false)", [a]);
    const visible = await client.query("SELECT id FROM scans ORDER BY id");
    assert.deepEqual(visible.rows.map((row) => row.id), [scanA]);
    assert.equal((await client.query("UPDATE scans SET verdict='scam' WHERE id=$1", [scanB])).rowCount, 0);
    assert.equal((await client.query("DELETE FROM scans WHERE id=$1", [scanB])).rowCount, 0);
    await assert.rejects(client.query(
      "INSERT INTO scans(id,tenant_id,input_types,verdict,risk_score,confidence,language,latency_ms,model_version,content_hash,result,expires_at) VALUES ($1,$2,ARRAY['text'],'safe',0,0.5,'en',1,'test',$3,'{}'::jsonb,now()+interval '1 day')",
      [randomUUID(), b, randomUUID()]
    ), (error) => error.code === "42501");
  } finally { client.release(); }
  const repository = new ScanRepository(process.env.DATABASE_URL_RUNTIME);
  try {
    await repository.recordUsage(a, "rls-integration");
    assert.deepEqual(await repository.usageSummary(a), [{ metric: "rls-integration", quantity: 1 }]);
    assert.deepEqual(await repository.usageSummary(b), []);
  } finally { await repository.close(); }
});

test("Redis Streams worker claims, completes, acknowledges and dead-letters queue items", async () => {
  const job = await redis.xAdd("shield:verify:jobs", "*", { payload: JSON.stringify({ kind: "integration", marker: randomUUID() }) });
  await eventually(async () => {
    const entries = await redis.xRange("shield:verify:results", "-", "+");
    assert.ok(entries.some((entry) => entry.message.job_id === job && entry.message.status === "completed"));
  });
  const pending = await redis.xPending("shield:verify:jobs", "shield-workers");
  assert.equal(pending.pending, 0);
  const bad = await redis.xAdd("shield:verify:jobs", "*", { payload: "not-json" });
  await eventually(async () => {
    const entries = await redis.xRange("shield:verify:dead-letter", "-", "+");
    assert.ok(entries.some((entry) => entry.message.job_id === bad));
  });
  assert.equal((await redis.xPending("shield:verify:jobs", "shield-workers")).pending, 0);
});

test("concurrent duplicate registration creates one account and rejects all duplicates", async () => {
  const email = `race-${randomUUID()}@example.test`;
  const response = await Promise.all(Array.from({ length: 12 }, () => fetch(`${base}/v1/auth/register`, {
    method: "POST", headers: { "content-type": "application/json", origin: base },
    body: JSON.stringify({ email, password: "integration-password-long" })
  })));
  assert.equal(response.filter((item) => item.status === 201).length, 1);
  assert.equal(response.filter((item) => item.status === 409).length, 11);
  const count = await admin.query("SELECT count(*)::int AS n FROM accounts WHERE email=$1", [email]);
  assert.equal(count.rows[0].n, 1);
});

async function setModelMode(mode) {
  const response = await fetch(`${openai}/__control?mode=${mode}`, { method: "POST" });
  assert.equal(response.status, 200);
}

async function deepScanResult() {
  const response = await fetch(`${base}/v1/scans`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "Urgently send your OTP now to avoid account closure", language: "en", mode: "deep" })
  });
  assert.equal(response.status, 200);
  const initial = await response.json();
  const events = await fetch(`${base}${initial.upgrade_url}`);
  assert.equal(events.status, 200);
  return events.text();
}

test("OpenAI timeout and server errors degrade to rules and recover after provider recovery", async () => {
  await setModelMode("timeout");
  const timeoutEvents = await deepScanResult();
  assert.match(timeoutEvents, /"model_version":"rules-v1"/);
  await setModelMode("error");
  const errorEvents = await deepScanResult();
  assert.match(errorEvents, /"model_version":"rules-v1"/);
  await new Promise((resolve) => setTimeout(resolve, 30_500));
  await setModelMode("ok");
  const recovered = await deepScanResult();
  assert.match(recovered, /"model_version":"rules\+provider-v1"/);
});

function compose(...args) {
  return execFileSync("docker", ["compose", "-f", "infra/verify.compose.yml", "-p", "shield-verify", ...args], { encoding: "utf8" });
}

async function submitDeep(key, text = `Urgently share your one-time code ${key}`) {
  const response = await fetch(`${base}/v1/scans`, {
    method: "POST", headers: { "content-type": "application/json", "idempotency-key": key },
    body: JSON.stringify({ text, language: "en", mode: "deep" })
  });
  assert.equal(response.status, 200, await response.text());
  return response.json();
}

test("real scan queue survives worker kill, API/worker replicas, idempotent retry and full service restart", async () => {
  const key = `queue-${randomUUID()}`;
  const initial = await submitDeep(key);
  assert.equal(initial.verdict, "likely_scam");

  await eventually(async () => {
    const pending = await redis.xPending("shield:scan:jobs", "shield-scan-workers");
    assert.ok(pending.consumers.some((consumer) => consumer.name.startsWith("scan-worker-a")), "slow worker A must own the pending job before it is killed");
  });
  compose("kill", "-s", "SIGKILL", "scan-worker-a");

  const streamUrl = `${base2}${initial.upgrade_url}`;
  const streamed = await fetch(streamUrl, { signal: AbortSignal.timeout(30_000) });
  assert.equal(streamed.status, 200);
  const events = await streamed.text();
  assert.match(events, /event: fast/);
  assert.match(events, /event: deep/);
  assert.match(events, /event: final/);
  const scanId = initial.scan_id;
  const finalEvents = await redis.xRange(`shield:scan:events:${scanId}`, "-", "+");
  assert.equal(finalEvents.filter((event) => event.message.stage === "final").length, 1, "terminal result is committed exactly once");

  compose("up", "-d", "scan-worker-a");
  const replay = await fetch(`${base2}/v1/scans`, {
    method: "POST", headers: { "content-type": "application/json", "idempotency-key": key },
    body: JSON.stringify({ text: `Urgently share your one-time code ${key}`, language: "en", mode: "deep" })
  });
  assert.equal(replay.status, 200);
  assert.equal(replay.headers.get("idempotency-replayed"), "true");
  assert.equal((await replay.json()).scan_id, scanId);

  compose("stop", "scan-worker-a", "scan-worker-b");
  const queuedWhileStopped = await submitDeep(`restart-${randomUUID()}`);
  compose("stop", "api", "api-2", "app", "worker", "openai-mock", "postgres", "redis");
  compose("up", "-d", "--wait", "postgres", "redis", "api", "api-2", "app", "worker", "openai-mock", "scan-worker-a", "scan-worker-b");
  const afterRestart = await fetch(`${base2}${queuedWhileStopped.upgrade_url}`);
  assert.equal(afterRestart.status, 200);
  assert.match(await afterRestart.text(), /event: final/);
});

test("transient scan worker failure retries durably and poison scan messages reach the dead-letter stream", async () => {
  const retryKey = `retry-${randomUUID()}`;
  const retryScan = await submitDeep(retryKey, `[retry-once] Send your OTP ${retryKey}`);
  const retriedResponse = await fetch(`${base2}${retryScan.upgrade_url}`, { signal: AbortSignal.timeout(30_000) });
  assert.equal(retriedResponse.status, 200);
  assert.match(await retriedResponse.text(), /event: final/);
  const retryFinals = await redis.xRange(`shield:scan:events:${retryScan.scan_id}`, "-", "+");
  assert.equal(retryFinals.filter((event) => event.message.stage === "final").length, 1);
  assert.equal(await redis.get(`shield:scan:test-failure:${retryScan.scan_id}`), "1");

  const poisonId = randomUUID();
  await redis.xAdd("shield:scan:jobs", "*", { scan_id: poisonId, payload: "not-json" });
  await eventually(async () => {
    const entries = await redis.xRange("shield:scan:dead-letter", "-", "+");
    assert.ok(entries.some((entry) => entry.message.scan_id === poisonId));
  });
});

test("scan queue applies a hard backpressure limit rather than accepting unbounded work", async () => {
  compose("stop", "scan-worker-a", "scan-worker-b");
  const stream = "shield:scan:jobs";
  const ids = [];
  try {
    assert.equal(await redis.xLen(stream), 0, "completed queue entries should be removed");
    for (let index = 0; index < 500; index += 1) {
      ids.push(await redis.xAdd(stream, "*", { scan_id: randomUUID(), payload: "{}" }));
    }
    const response = await fetch(`${base}/v1/scans`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "Please share your OTP", mode: "deep", language: "en" })
    });
    assert.equal(response.status, 503);
    assert.match(await response.text(), /at capacity/);
  } finally {
    for (const id of ids) { await redis.xAck(stream, "shield-scan-workers", id); await redis.xDel(stream, id); }
    compose("up", "-d", "scan-worker-a", "scan-worker-b");
  }
});

test("progress streams are available across API replicas but isolated from other users", async () => {
  const email = `scan-owner-${randomUUID()}@example.test`;
  const registration = await fetch(`${base}/v1/auth/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "scan-owner-password-123" })
  });
  assert.equal(registration.status, 201);
  const cookie = registration.headers.getSetCookie()[0]?.split(";")[0];
  assert.ok(cookie);
  const response = await fetch(`${base}/v1/scans`, {
    method: "POST", headers: { "content-type": "application/json", cookie },
    body: JSON.stringify({ text: "The bank needs your OTP right now", language: "en", mode: "deep" })
  });
  assert.equal(response.status, 200);
  const initial = await response.json();
  assert.equal((await fetch(`${base2}${initial.upgrade_url}`)).status, 404, "anonymous/other user cannot read a private scan stream");
  const ownerStream = await fetch(`${base2}${initial.upgrade_url}`, { headers: { cookie }, signal: AbortSignal.timeout(30_000) });
  assert.equal(ownerStream.status, 200);
  assert.match(await ownerStream.text(), /event: final/);
});

test("real service health checks report API and worker ready", async () => {
  const api = await fetch(`${base}/healthz`);
  const worker = await fetch(process.env.VERIFY_WORKER_URL ?? "http://127.0.0.1:33002/healthz");
  assert.equal(api.status, 200);
  assert.equal(worker.status, 200);
});
