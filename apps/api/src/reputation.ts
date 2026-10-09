import { Pool } from "pg";
import { createHash, createHmac, randomUUID } from "node:crypto";
import type { Intelligence } from "../../../packages/risk-engine/src/scan.js";
import { domainOf, phoneDigits } from "./directory.js";

export type IdentifierKind = "account" | "phone" | "url";
export type ReportStatus = "pending" | "verified" | "rejected";

export type IdentifierReport = {
  id: string;
  kind: IdentifierKind;
  value: string;
  scamType: string;
  status: ReportStatus;
  createdAt: string;
  decidedAt: string | null;
};

export type ReputationSummary = { kind: IdentifierKind; value: string; reports: number; verified: number; pending: number; firstSeen: string | null; lastSeen: string | null };

export function canonicalIdentifier(kind: IdentifierKind, value: string): string {
  if (kind === "phone") return phoneDigits(value).replace(/^234(?=\d{10})/, "").replace(/^0(?=\d{10})/, "");
  if (kind === "url") return domainOf(value);
  return value.trim().replace(/\D/g, "");
}

export function labelFor(kind: IdentifierKind, value: string): string {
  if (kind === "url") return domainOf(value);
  const canonical = canonicalIdentifier(kind, value);
  if (kind === "account" && canonical.length >= 4) return `•••• ${canonical.slice(-4)}`;
  return canonical || (value.length > 24 ? `${value.slice(0, 21)}…` : value);
}

export function identifierKey(kind: IdentifierKind, value: string, pepper?: Buffer): string {
  const canonical = canonicalIdentifier(kind, value);
  if (pepper && pepper.length > 0) return createHmac("sha256", pepper).update(canonical).digest("hex");
  return createHash("sha256").update(canonical).digest("hex");
}

export interface ReputationStore {
  submit(input: { kind: IdentifierKind; value: string; scamType: string; source: string }): Promise<{ id: string; label: string; status: ReportStatus }>;
  get(id: string): Promise<{ id: string; kind: IdentifierKind; valueKey: string } | null>;
  decide(id: string, action: "verify" | "reject"): Promise<boolean>;
  pending(): Promise<IdentifierReport[]>;
  summaryFor(kind: IdentifierKind, value: string): Promise<ReputationSummary | null>;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

export class MemoryReputationStore implements ReputationStore {
  private readonly reports = new Map<string, IdentifierReport>();
  private readonly pepper: Buffer | undefined;
  constructor(pepper?: Buffer) {
    this.pepper = pepper;
  }

  async submit(input: { kind: IdentifierKind; value: string; scamType: string; source: string }): Promise<{ id: string; label: string; status: ReportStatus }> {
    const id = randomUUID();
    this.reports.set(id, { id, kind: input.kind, value: input.value, scamType: input.scamType, status: "pending", createdAt: new Date().toISOString(), decidedAt: null });
    return { id, label: labelFor(input.kind, input.value), status: "pending" };
  }

  async decide(id: string, action: "verify" | "reject"): Promise<boolean> {
    const report = this.reports.get(id);
    if (!report || report.status !== "pending") return false;
    report.status = action === "verify" ? "verified" : "rejected";
    report.decidedAt = new Date().toISOString();
    return true;
  }

  async get(id: string): Promise<{ id: string; kind: IdentifierKind; valueKey: string } | null> {
    const report = this.reports.get(id);
    if (!report) return null;
    return { id, kind: report.kind, valueKey: identifierKey(report.kind, report.value, this.pepper) };
  }

  async pending(): Promise<IdentifierReport[]> {
    return [...this.reports.values()].filter((report) => report.status === "pending").sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async summaryFor(kind: IdentifierKind, value: string): Promise<ReputationSummary | null> {
    const key = identifierKey(kind, value, this.pepper);
    const matching = [...this.reports.values()].filter((report) => report.kind === kind && identifierKey(report.kind, report.value, this.pepper) === key);
    if (matching.length === 0) return null;
    const verified = matching.filter((report) => report.status === "verified").length;
    const pending = matching.filter((report) => report.status === "pending").length;
    const sorted = [...matching].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    return {
      kind,
      value,
      reports: matching.length,
      verified,
      pending,
      firstSeen: sorted[0]?.createdAt ?? null,
      lastSeen: sorted[sorted.length - 1]?.createdAt ?? null
    };
  }

  async ready(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    return;
  }
}

export class PgReputationStore implements ReputationStore {
  readonly pool: Pool;
  private readonly pepper: Buffer | undefined;
  constructor(connectionString: string, pepper?: Buffer, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 5, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
    this.pepper = pepper;
  }

  async submit(input: { kind: IdentifierKind; value: string; scamType: string; source: string }): Promise<{ id: string; label: string; status: ReportStatus }> {
    const result = await this.pool.query<{ id: string }>(
      "INSERT INTO identifier_reports (kind, value_key, value_label, scam_type, source) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [input.kind, identifierKey(input.kind, input.value, this.pepper), labelFor(input.kind, input.value), input.scamType, input.source]
    );
    return { id: result.rows[0]!.id, label: labelFor(input.kind, input.value), status: "pending" };
  }

  async decide(id: string, action: "verify" | "reject"): Promise<boolean> {
    const result = await this.pool.query("UPDATE identifier_reports SET status = $1, decided_at = now() WHERE id = $2 AND status = 'pending'", [action === "verify" ? "verified" : "rejected", id]);
    return (result.rowCount ?? 0) > 0;
  }

  async get(id: string): Promise<{ id: string; kind: IdentifierKind; valueKey: string } | null> {
    const result = await this.pool.query<{ kind: string; value_key: string }>("SELECT kind, value_key FROM identifier_reports WHERE id = $1", [id]);
    const row = result.rows[0];
    return row ? { id, kind: row.kind as IdentifierKind, valueKey: row.value_key } : null;
  }

  async pending(): Promise<IdentifierReport[]> {
    const result = await this.pool.query<{ id: string; kind: string; value_label: string; scam_type: string; created_at: Date; decided_at: Date | null }>(
      "SELECT id, kind, value_label, scam_type, created_at, decided_at FROM identifier_reports WHERE status = 'pending' ORDER BY created_at"
    );
    return result.rows.map((row) => ({ id: row.id, kind: row.kind as IdentifierKind, value: row.value_label, scamType: row.scam_type, status: "pending" as const, createdAt: row.created_at.toISOString(), decidedAt: row.decided_at ? row.decided_at.toISOString() : null }));
  }

  async summaryFor(kind: IdentifierKind, value: string): Promise<ReputationSummary | null> {
    const result = await this.pool.query<{ key: string; status: string; created_at: Date }>(
      "SELECT value_key AS key, status, created_at FROM identifier_reports WHERE kind = $1 AND value_key = $2",
      [kind, identifierKey(kind, value, this.pepper)]
    );
    const rows = result.rows;
    if (rows.length === 0) return null;
    const verified = rows.filter((row) => row.status === "verified").length;
    const pending = rows.filter((row) => row.status === "pending").length;
    const times = rows.map((row) => row.created_at.getTime());
    return {
      kind,
      value,
      reports: rows.length,
      verified,
      pending,
      firstSeen: new Date(Math.min(...times)).toISOString(),
      lastSeen: new Date(Math.max(...times)).toISOString()
    };
  }

  async ready(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1 FROM identifier_reports LIMIT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export function intelligenceFromSummaries(summaries: ReputationSummary[]): Intelligence | undefined {
  const strongest = summaries.find((summary) => summary.verified > 0) ?? summaries.find((summary) => summary.reports > 0);
  if (!strongest) return undefined;
  return { reports: strongest.reports, verified: strongest.verified > 0, firstSeen: strongest.firstSeen, lastSeen: strongest.lastSeen };
}