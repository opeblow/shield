import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createClient } from "redis";

const composeFile = process.env.COMPOSE_FILE ?? "infra/verify.compose.yml";
const project = process.env.COMPOSE_PROJECT_NAME ?? "shield-verify";
const api = process.env.VERIFY_API_URL ?? "http://127.0.0.1:33001";
const redis = createClient({ url: process.env.REDIS_URL_TEST ?? "redis://127.0.0.1:56379" });
redis.on("error", () => {});
const results = [];
function compose(args) {
  const result = spawnSync("docker", ["compose", "-f", composeFile, "-p", project, ...args], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`docker compose ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}
async function waitFor(check, label, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if (await check()) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${label}`);
}
const started = performance.now();
await redis.connect();
try {
  compose(["stop", "worker"]);
  const marker = `worker-recovery-${Date.now()}`;
  await redis.xAdd("shield:verify:jobs", "*", { payload: JSON.stringify({ marker }) });
  await new Promise((resolve) => setTimeout(resolve, 1_500));
  let resultsFound = await redis.xRange("shield:verify:results", "-", "+");
  if (resultsFound.some((row) => row.message.payload?.includes(marker))) throw new Error("Stopped worker processed queued item unexpectedly");
  compose(["start", "worker"]);
  await waitFor(async () => (await redis.xRange("shield:verify:results", "-", "+")).some((row) => row.message.payload?.includes(marker)), "worker queue recovery");
  results.push({ dependency: "worker", result: "PASS", observation: "queued item completed after worker restart" });

  compose(["stop", "postgres"]);
  await waitFor(async () => (await (await fetch(`${api}/readyz`)).json()).persistence === "unavailable", "PostgreSQL outage visibility");
  compose(["start", "postgres"]);
  await waitFor(async () => (await (await fetch(`${api}/readyz`)).json()).persistence === "postgres", "PostgreSQL recovery");
  results.push({ dependency: "postgres", result: "PASS", observation: "readiness reported persistence unavailable during outage and postgres after restart" });

  compose(["stop", "redis"]);
  const scanRequest = () => fetch(`${api}/v1/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: "Please send your OTP urgently", language: "en", mode: "fast" }) });
  await waitFor(async () => (await scanRequest()).status === 503, "Redis dependent API degradation", 15_000);
  compose(["start", "redis"]);
  await waitFor(async () => (await scanRequest()).status === 200, "Redis dependent API recovery", 30_000);
  results.push({ dependency: "redis", result: "PASS", observation: "scan failed closed with 503 while Redis was down and succeeded after restart" });
  const report = { elapsed_ms: Math.round(performance.now() - started), results };
  await mkdir(process.env.REPORT_DIR ?? "reports", { recursive: true });
  await writeFile(`${process.env.REPORT_DIR ?? "reports"}/chaos.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
} finally { await redis.quit(); }
