import { createClient, type RedisClientType } from "redis";
import type { ScanResult } from "../../../packages/risk-engine/src/types.js";

export type ScanStage = "fast" | "deep" | "final";
export type ScanEvent = { stage: ScanStage; result: ScanResult; id: string };
export type DeepScanJob = {
  scanId: string;
  text: string;
  language: string;
  inputTypes: string[];
  tenantId: string | null;
  ownerId: string | null;
  attempts: number;
  retryAt?: number;
};
export type ClaimedScanJob = { entryId: string; job: DeepScanJob };

const STREAM = "shield:scan:jobs";
const GROUP = "shield-scan-workers";
const MAX_QUEUE = 500;
const JOB_TTL_SECONDS = 48 * 60 * 60;

/** Redis is the source of truth for scan work and progress; API replicas may serve any SSE request. */
export class RedisScanQueue {
  readonly client: RedisClientType;
  constructor(url: string, client?: RedisClientType) {
    this.client = client ?? createClient({ url });
    this.client.on("error", () => {});
  }

  async connect(): Promise<void> {
    if (!this.client.isOpen) await this.client.connect();
    await this.client.xGroupCreate(STREAM, GROUP, "0", { MKSTREAM: true }).catch((error: unknown) => {
      if (!String(error).includes("BUSYGROUP")) throw error;
    });
  }

  async publish(scanId: string, stage: ScanStage, result: ScanResult): Promise<void> {
    const stateKey = this.stateKey(scanId);
    const eventsKey = this.eventsKey(scanId);
    const script = `
      if redis.call('HEXISTS', KEYS[1], ARGV[1] .. '_result') == 1 then return 0 end
      redis.call('HSET', KEYS[1], 'status', ARGV[1], 'result', ARGV[2], ARGV[1] .. '_result', ARGV[2])
      redis.call('EXPIRE', KEYS[1], ARGV[4])
      redis.call('XADD', KEYS[2], '*', 'stage', ARGV[1], 'result', ARGV[2])
      redis.call('EXPIRE', KEYS[2], ARGV[4])
      return 1
    `;
    await this.client.eval(script, { keys: [stateKey, eventsKey], arguments: [stage, JSON.stringify(result), scanId, String(JOB_TTL_SECONDS)] });
  }

  async enqueue(job: DeepScanJob, fastResult: ScanResult): Promise<"queued" | "duplicate" | "full"> {
    const script = `
      if redis.call('EXISTS', KEYS[4]) == 1 then return 0 end
      if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[3]) then return -1 end
      redis.call('SET', KEYS[4], '1', 'EX', ARGV[4])
      redis.call('HSET', KEYS[2], 'status', 'queued')
      redis.call('EXPIRE', KEYS[2], ARGV[4])
      redis.call('EXPIRE', KEYS[3], ARGV[4])
      redis.call('HSET', KEYS[2], 'status', 'fast', 'result', ARGV[5], 'fast_result', ARGV[5], 'owner_id', ARGV[6], 'tenant_id', ARGV[7])
      redis.call('XADD', KEYS[3], '*', 'stage', 'fast', 'result', ARGV[5])
      redis.call('XADD', KEYS[1], '*', 'scan_id', ARGV[1], 'payload', ARGV[2])
      return 1
    `;
    const result = Number(await this.client.eval(script, {
      keys: [STREAM, this.stateKey(job.scanId), this.eventsKey(job.scanId), `shield:scan:idem:${job.scanId}`],
      arguments: [job.scanId, JSON.stringify(job), String(MAX_QUEUE), String(JOB_TTL_SECONDS), JSON.stringify(fastResult), job.ownerId ?? "", job.tenantId ?? ""]
    }));
    return result === 1 ? "queued" : result === 0 ? "duplicate" : "full";
  }

  async events(scanId: string, afterId = "-"): Promise<ScanEvent[]> {
    const start = afterId === "-" ? "-" : `(${afterId}`;
    const rows = await this.client.xRange(this.eventsKey(scanId), start, "+", { COUNT: 100 });
    return rows.map((row) => ({
      id: row.id,
      stage: row.message.stage as ScanStage,
      result: JSON.parse(row.message.result ?? "{}") as ScanResult
    }));
  }

  async status(scanId: string): Promise<string | null> {
    return await this.client.hGet(this.stateKey(scanId), "status");
  }

  async result(scanId: string): Promise<ScanResult | null> {
    const result = await this.client.hGet(this.stateKey(scanId), "result");
    return result ? JSON.parse(result) as ScanResult : null;
  }

  async authorized(scanId: string, ownerId: string | null, tenantId: string | null): Promise<boolean> {
    const values = await this.client.hmGet(this.stateKey(scanId), ["owner_id", "tenant_id"]);
    if (values[0] === null && values[1] === null) return false;
    const expectedOwner = values[0] || null;
    const expectedTenant = values[1] || null;
    return expectedOwner === ownerId && expectedTenant === tenantId;
  }

  async setStatus(scanId: string, status: string): Promise<void> {
    await this.client.hSet(this.stateKey(scanId), "status", status);
    await this.client.expire(this.stateKey(scanId), JOB_TTL_SECONDS);
  }

  async claim(consumer: string, reclaimMs: number): Promise<ClaimedScanJob | null> {
    const reclaimed = await this.client.xAutoClaim(STREAM, GROUP, consumer, reclaimMs, "0-0", { COUNT: 1 });
    let row = reclaimed.messages[0];
    if (!row) {
      const streams = await this.client.xReadGroup(GROUP, consumer, [{ key: STREAM, id: ">" }], { COUNT: 1, BLOCK: 1000 });
      row = streams?.[0]?.messages[0];
    }
    if (!row) return null;
    try {
      const job = JSON.parse(row.message.payload ?? "") as DeepScanJob;
      if (!job.scanId || !job.text) throw new Error("invalid_scan_job");
      return { entryId: row.id, job };
    } catch (error) {
      await this.deadLetter(row.id, row.message.scan_id ?? "unknown", String(error));
      return null;
    }
  }

  async retry(claim: ClaimedScanJob, error: string, maxAttempts: number): Promise<void> {
    const next = claim.job.attempts + 1;
    if (next >= maxAttempts) {
      await this.deadLetter(claim.entryId, claim.job.scanId, error);
      return;
    }
    const delay = Math.floor(Math.min(30_000, 500 * 2 ** next) * (0.5 + Math.random()));
    const job = { ...claim.job, attempts: next, retryAt: Date.now() + delay };
    const script = `
      redis.call('XADD', KEYS[1], '*', 'scan_id', ARGV[2], 'payload', ARGV[3])
      redis.call('XACK', KEYS[1], ARGV[1], ARGV[4]); redis.call('XDEL', KEYS[1], ARGV[4])
      return 1
    `;
    await this.client.eval(script, { keys: [STREAM], arguments: [GROUP, job.scanId, JSON.stringify(job), claim.entryId] });
  }

  /** Atomically records one terminal result and acknowledges the queue item. */
  async complete(claim: ClaimedScanJob, result: ScanResult): Promise<boolean> {
    const script = `
      if redis.call('HGET', KEYS[1], 'status') == 'done' then
        redis.call('XACK', KEYS[3], ARGV[1], ARGV[2]); redis.call('XDEL', KEYS[3], ARGV[2]); return 0
      end
      redis.call('HSET', KEYS[1], 'status', 'done', 'result', ARGV[3])
      redis.call('EXPIRE', KEYS[1], ARGV[4])
      redis.call('XADD', KEYS[2], '*', 'stage', 'final', 'result', ARGV[3])
      redis.call('EXPIRE', KEYS[2], ARGV[4])
      redis.call('XACK', KEYS[3], ARGV[1], ARGV[2]); redis.call('XDEL', KEYS[3], ARGV[2])
      return 1
    `;
    return Number(await this.client.eval(script, {
      keys: [this.stateKey(claim.job.scanId), this.eventsKey(claim.job.scanId), STREAM],
      arguments: [GROUP, claim.entryId, JSON.stringify(result), String(JOB_TTL_SECONDS)]
    })) === 1;
  }

  async acknowledge(claim: ClaimedScanJob): Promise<void> {
    await this.client.xAck(STREAM, GROUP, claim.entryId);
    await this.client.xDel(STREAM, claim.entryId);
  }

  async heartbeat(consumer: string, entryId: string): Promise<void> {
    await this.client.xClaim(STREAM, GROUP, consumer, 0, [entryId]);
  }

  async close(): Promise<void> { if (this.client.isOpen) await this.client.quit(); }

  private stateKey(scanId: string): string { return `shield:scan:state:${scanId}`; }
  private eventsKey(scanId: string): string { return `shield:scan:events:${scanId}`; }

  private async deadLetter(entryId: string, scanId: string, error: string): Promise<void> {
    const script = `
      redis.call('XADD', KEYS[2], 'MAXLEN', '~', 1000, '*', 'scan_id', ARGV[3], 'error', ARGV[4])
      redis.call('HSET', KEYS[3], 'status', 'dead')
      redis.call('EXPIRE', KEYS[3], ARGV[5])
      redis.call('XACK', KEYS[1], ARGV[1], ARGV[2]); redis.call('XDEL', KEYS[1], ARGV[2])
      return 1
    `;
    await this.client.eval(script, { keys: [STREAM, "shield:scan:dead-letter", this.stateKey(scanId)], arguments: [GROUP, entryId, scanId, error.slice(0, 500), String(JOB_TTL_SECONDS)] });
  }
}
