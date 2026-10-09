import { randomUUID } from "node:crypto";
import { sign, verifySignature } from "./crypto.js";

export type DeliveryHeaders = Record<string, string>;

/** HMAC-SHA-256 over `timestamp.body`. The timestamp is part of the signed payload. */
export function webhookSignature(secret: string | Buffer, timestamp: number, body: string | Buffer): string {
  return sign(`${timestamp}.${body}`, Buffer.isBuffer(secret) ? secret : Buffer.from(secret));
}

export function verifyWebhookSignature(secret: string | Buffer, timestamp: number, body: string | Buffer, signature: string, options: { toleranceMs?: number; now?: number } = {}): boolean {
  const toleranceMs = options.toleranceMs ?? 5 * 60 * 1000;
  const now = options.now ?? Date.now();
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > toleranceMs) return false;
  return verifySignature(`${timestamp}.${body}`, signature, Buffer.isBuffer(secret) ? secret : Buffer.from(secret));
}

/** In-memory replay guard keyed by a unique delivery id; used to reject duplicate webhook deliveries. */
export class ReplayGuard {
  private readonly seen = new Map<string, number>();
  constructor(private readonly ttlMs = 10 * 60 * 1000, private readonly now: () => number = Date.now) {}

  /** Registers an id; returns false when the id was already seen inside the TTL window. */
  accept(id: string): boolean {
    const current = this.now();
    for (const [key, expiry] of this.seen) if (expiry <= current) this.seen.delete(key);
    if (this.seen.has(id)) return false;
    this.seen.set(id, current + this.ttlMs);
    return true;
  }
}

export type DispatchResult = { delivered: boolean; attempts: number; status?: number };

export type WebhookDispatcherOptions = {
  deliver?: (url: string, body: string, headers: DeliveryHeaders) => Promise<{ status: number }>;
  maxAttempts?: number;
  baseDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
};

/** Delivers a signed webhook with bounded exponential backoff. The default sleep honours abort signals in real deployments. */
export async function deliverWebhook(input: { url: string; secret: string; event: string; payload: unknown }, options: WebhookDispatcherOptions = {}): Promise<DispatchResult> {
  const deliver = options.deliver ?? defaultDeliver;
  const maxAttempts = options.maxAttempts ?? 4;
  const baseDelayMs = options.baseDelayMs ?? 200;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const body = JSON.stringify(input.payload);
  const deliveryId = randomUUID();
  let lastStatus: number | undefined;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const timestamp = Date.now();
    const headers: DeliveryHeaders = {
      "content-type": "application/json",
      "x-shield-event": input.event,
      "x-shield-delivery": deliveryId,
      "x-shield-timestamp": String(timestamp),
      "x-shield-signature": webhookSignature(input.secret, timestamp, body)
    };
    try {
      const response = await deliver(input.url, body, headers);
      lastStatus = response.status;
      if (response.status >= 200 && response.status < 300) return { delivered: true, attempts: attempt, status: response.status };
      if (response.status < 500 && response.status !== 429) return { delivered: false, attempts: attempt, status: response.status };
    } catch {
      // transient network failure: retry
    }
    if (attempt < maxAttempts) await sleep(baseDelayMs * 2 ** (attempt - 1));
  }
  return lastStatus === undefined ? { delivered: false, attempts: maxAttempts } : { delivered: false, attempts: maxAttempts, status: lastStatus };
}

async function defaultDeliver(url: string, body: string, headers: DeliveryHeaders): Promise<{ status: number }> {
  const response = await fetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(5_000) });
  return { status: response.status };
}
