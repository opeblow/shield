import { randomUUID } from "node:crypto";
import { logEvent } from "../../../packages/shared/src/safe-log.js";
import { scanText } from "../../../packages/risk-engine/src/scan.js";
import type { Language } from "../../../packages/risk-engine/src/types.js";
import { deliverWebhook } from "../../../packages/shared/src/webhooks.js";
import { keyringFromEnv } from "../../../packages/shared/src/crypto.js";
import { lookupIntelligence } from "./context.js";
import { loadEnv } from "./env.js";
import { RedisScanQueue } from "./jobs.js";
import { OpenAiProvider } from "./provider.js";
import { ScanRepository } from "./repository.js";
import { PgReputationStore } from "./reputation.js";
import { PgScanRecordStore } from "./scan-records.js";
import { redactSensitive } from "../../../packages/shared/src/redaction.js";

const env = loadEnv();
if (!env.redisUrl || !env.databaseUrl) throw new Error("Scan worker requires REDIS_URL and DATABASE_URL");
const queue = new RedisScanQueue(env.redisUrl);
const provider = new OpenAiProvider(env.openAiKey, env.openAiModel, 3500, env.openAiBaseUrl);
const reputation = new PgReputationStore(env.databaseUrl, env.blindPepper ? Buffer.from(env.blindPepper) : undefined);
const records = new PgScanRecordStore(env.databaseUrl);
const repository = new ScanRepository(env.databaseUrl);
const consumer = `${process.env.SCAN_CONSUMER_ID ?? process.env.HOSTNAME ?? "scan-worker"}-${process.pid}-${randomUUID()}`;
let stopping = false;
let active = false;

async function processClaimed(claim: NonNullable<Awaited<ReturnType<RedisScanQueue["claim"]>>>): Promise<void> {
  const { job } = claim;
  if (await queue.status(job.scanId) === "done") {
    await queue.acknowledge(claim);
    return;
  }
  await queue.setStatus(job.scanId, "running");
  const scanStarted = performance.now();
  const result = await scanText(job.text, {
    scanId: job.scanId,
    language: job.language as Language,
    lookup: async (entities) => lookupIntelligence(entities, reputation),
    ...(env.openAiKey && env.openAiModel ? { assess: (text: string, signals: Record<string, boolean>) => provider.assess(text, signals) } : {})
  });
  const scanMs = performance.now() - scanStarted;
  result.input_types = job.inputTypes;
  const redacted = redactSensitive(job.text).text;
  const persistStarted = performance.now();
  await repository.save(result, redacted, job.tenantId);
  await records.save({
    scanId: job.scanId, ownerId: job.ownerId, tenantId: job.tenantId, verdict: result.verdict,
    riskScore: result.risk_score, scamTypes: result.scam_types, language: result.customer_message.language,
    redactedText: redacted, createdAt: new Date().toISOString()
  });
  const persistMs = performance.now() - persistStarted;
  await queue.publish(job.scanId, "deep", result);
  if (job.tenantId) try {
    const keyring = keyringFromEnv();
    const hooks = await repository.activeWebhooks(job.tenantId, keyring);
    for (const hook of hooks) {
      if (!hook.events.includes("scan.completed")) continue;
      const delivery = await deliverWebhook({ url: hook.url, secret: hook.secret, event: "scan.completed", payload: result, deliveryId: `${job.scanId}:${hook.id}` });
      await repository.recordWebhookDelivery(hook.id, "scan.completed", delivery.delivered, delivery.attempts, delivery.status ?? null).catch(() => {});
    }
  } catch { /* completion remains durable; webhook delivery has its own retries and replay key */ }
  const completionStarted = performance.now();
  await queue.complete(claim, result);
  const streamIdTime = Number(claim.entryId.split("-")[0]);
  logEvent("scan_worker_stage", {
    scanId: job.scanId,
    queue_wait_ms: Number.isFinite(streamIdTime) ? Math.max(0, Date.now() - streamIdTime) : null,
    scan_ms: Math.round(scanMs), persistence_ms: Math.round(persistMs), completion_ms: Math.round(performance.now() - completionStarted)
  });
}

export async function runScanWorker(): Promise<void> {
  await queue.connect();
  process.on("SIGTERM", () => { stopping = true; });
  process.on("SIGINT", () => { stopping = true; });
  while (!stopping) {
    const claim = await queue.claim(consumer, Number(process.env.SCAN_RECLAIM_MS ?? 60_000));
    if (!claim) continue;
    active = true;
    const reclaimMs = Number(process.env.SCAN_RECLAIM_MS ?? 60_000);
    const heartbeat = setInterval(() => { void queue.heartbeat(consumer, claim.entryId).catch(() => {}); }, Math.max(250, Math.floor(reclaimMs / 3)));
    try {
      if (claim.job.retryAt && claim.job.retryAt > Date.now()) await new Promise((resolve) => setTimeout(resolve, claim.job.retryAt! - Date.now()));
      const testDelay = Number(process.env.VERIFY_TEST_WORKER_DELAY_MS ?? 0);
      if (Number.isFinite(testDelay) && testDelay > 0) await new Promise((resolve) => setTimeout(resolve, testDelay));
      if (process.env.VERIFY_TEST_FAIL_ONCE === "1" && claim.job.text.startsWith("[retry-once]")) {
        const firstAttempt = await queue.client.set(`shield:scan:test-failure:${claim.job.scanId}`, "1", { NX: true, EX: 300 });
        if (firstAttempt === "OK") throw new Error("injected_transient_failure");
      }
      await processClaimed(claim);
    }
    catch (error) {
      const reason = error instanceof Error ? error.message : "scan_worker_failed";
      await queue.retry(claim, reason, Number(process.env.SCAN_MAX_ATTEMPTS ?? 5));
    } finally { clearInterval(heartbeat); active = false; }
  }
  while (active) await new Promise((resolve) => setTimeout(resolve, 25));
  await Promise.all([queue.close(), records.close(), reputation.close(), repository.close()]);
}
