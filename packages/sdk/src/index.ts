import type { Assessment, TransactionContext } from "../../risk-engine/src/assess.js";
import type { Language, ScanResult } from "../../risk-engine/src/types.js";

export type ShieldClientOptions = { baseUrl: string; apiKey?: string; fetchImpl?: typeof fetch; timeoutMs?: number };
export type ScanRequest = { text?: string; inputs?: Array<Record<string, unknown>>; language?: Language; mode?: "fast" | "deep" };
export type LookupType = "account" | "phone" | "url";
export type ReportInput = { type: LookupType; value: string; scamType: string; evidence?: string };

export class ShieldError extends Error {
  constructor(public readonly status: number, public readonly detail: string) { super(detail); this.name = "ShieldError"; }
}

/** Thin, dependency-free TypeScript client for the Shield `/v1` API. */
export class ShieldClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  constructor(options: ShieldClientOptions) {
    if (!/^https?:\/\//.test(options.baseUrl)) throw new Error("baseUrl must be an absolute HTTP(S) URL");
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    if (options.apiKey !== undefined) this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    if (init.body) headers.set("content-type", "application/json");
    if (this.apiKey) headers.set("authorization", `Bearer ${this.apiKey}`);
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers, signal: AbortSignal.timeout(this.timeoutMs) });
    if (response.status === 204) return undefined as T;
    const body = await response.json().catch(() => ({})) as { detail?: string };
    if (!response.ok) throw new ShieldError(response.status, body.detail ?? `Request failed with status ${response.status}`);
    return body as T;
  }

  scan(input: ScanRequest): Promise<ScanResult & { upgrade_url?: string }> {
    return this.request("/v1/scans", { method: "POST", body: JSON.stringify(input) });
  }

  assess(context: TransactionContext & { policy?: unknown }): Promise<Assessment> {
    return this.request("/v1/assess", { method: "POST", body: JSON.stringify(context) });
  }

  lookup(type: LookupType, value: string): Promise<{ type: LookupType; reports: number; verifiedReports: number; score: number; lastSeen: string | null }> {
    return this.request("/v1/lookup", { method: "POST", body: JSON.stringify({ type, value }) });
  }

  report(input: ReportInput): Promise<{ report_id: string; status: string }> {
    return this.request("/v1/reports", { method: "POST", body: JSON.stringify(input) });
  }

  speak(text: string, language: Language): Promise<{ language: Language; mime_type: string; audio_base64: string; provider: string }> {
    return this.request("/v1/voice/speak", { method: "POST", body: JSON.stringify({ text, language }) });
  }

  createWebhook(url: string, events: string[]): Promise<{ id: string; secret: string; events: string[] }> {
    return this.request("/v1/webhooks", { method: "POST", body: JSON.stringify({ url, events }) });
  }

  listWebhooks(): Promise<{ webhooks: Array<{ id: string; url: string; events: string[]; status: string }> }> {
    return this.request("/v1/webhooks", { method: "GET" });
  }

  deleteWebhook(id: string): Promise<void> {
    return this.request(`/v1/webhooks/${id}`, { method: "DELETE" });
  }

  usage(): Promise<{ tenant_id: string; usage: Array<{ metric: string; quantity: number }>; quota: { plan: string; monthly_scans: number } }> {
    return this.request("/v1/usage", { method: "GET" });
  }
}
