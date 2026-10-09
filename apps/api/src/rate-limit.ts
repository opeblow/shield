import { createClient, type RedisClientType } from "redis";
import { blindIndex } from "../../../packages/shared/src/crypto.js";

export type RateLimitResult = { allowed: boolean; retryAfterMs: number };
export interface RateLimiter { consume(identity: string, limit: number, windowMs: number): Promise<RateLimitResult>; close(): Promise<void> }

const script = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
if count <= tonumber(ARGV[2]) then return {1, 0} end
return {0, math.max(0, redis.call('PTTL', KEYS[1]))}
`;

export class RedisRateLimiter implements RateLimiter {
  private readonly client: RedisClientType;
  constructor(url: string, private readonly pepper: Buffer) {
    this.client = createClient({ url });
    this.client.on("error", () => {});
  }
  async connect(): Promise<void> { await this.client.connect(); }
  async consume(identity: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const digest = blindIndex(identity, this.pepper);
    const result = await this.client.eval(script, { keys: [`shield:rate:${digest}`], arguments: [String(windowMs), String(limit)] }) as number[];
    return { allowed: result[0] === 1, retryAfterMs: Number(result[1] ?? 0) };
  }
  async close(): Promise<void> { if (this.client.isOpen) await this.client.quit(); }
}

export class MemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, { started: number; count: number }>();
  async consume(identity: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    let bucket = this.buckets.get(identity);
    if (!bucket || now - bucket.started >= windowMs) { bucket = { started: now, count: 0 }; this.buckets.set(identity, bucket); }
    bucket.count += 1;
    const retryAfterMs = Math.max(0, windowMs - (now - bucket.started));
    return { allowed: bucket.count <= limit, retryAfterMs: bucket.count <= limit ? 0 : retryAfterMs };
  }
  async close(): Promise<void> { this.buckets.clear(); }
}
