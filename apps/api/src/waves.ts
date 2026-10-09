import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { identifierKey, labelFor, type IdentifierKind } from "./reputation.js";

export type FraudWave = {
  id: string;
  kind: IdentifierKind;
  value: string;
  label: string;
  count: number;
  first_seen: string;
  last_seen: string;
  status: "active" | "resolved";
};

export interface WaveStore {
  save(wave: FraudWave): Promise<void>;
  recent(sinceIso: string): Promise<FraudWave[]>;
  close(): Promise<void>;
}

export class MemoryWaveStore implements WaveStore {
  private readonly waves = new Map<string, FraudWave>();
  async save(wave: FraudWave): Promise<void> { this.waves.set(wave.id, wave); }
  async recent(sinceIso: string): Promise<FraudWave[]> {
    const since = Date.parse(sinceIso);
    return [...this.waves.values()].filter((wave) => Date.parse(wave.last_seen) >= since).sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
  }
  async close(): Promise<void> { return; }
}

export class PgWaveStore implements WaveStore {
  readonly pool: Pool;
  constructor(connectionString: string, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 3, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
  }
  async save(wave: FraudWave): Promise<void> {
    await this.pool.query(
      `INSERT INTO fraud_waves (id, kind, value_key, label, count, started_at, last_seen_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO UPDATE SET count = EXCLUDED.count, last_seen_at = EXCLUDED.last_seen_at, status = EXCLUDED.status`,
      [wave.id, wave.kind, wave.value, wave.label, wave.count, wave.first_seen, wave.last_seen, wave.status]
    );
  }
  async recent(sinceIso: string): Promise<FraudWave[]> {
    const result = await this.pool.query<{ id: string; kind: string; label: string; count: number; started_at: Date; last_seen_at: Date; status: string }>(
      "SELECT id, kind, label, count, started_at, last_seen_at, status FROM fraud_waves WHERE last_seen_at >= $1 ORDER BY last_seen_at DESC",
      [sinceIso]
    );
    return result.rows.map((row) => ({ id: row.id, kind: row.kind as IdentifierKind, value: row.label, label: row.label, count: row.count, first_seen: row.started_at.toISOString(), last_seen: row.last_seen_at.toISOString(), status: row.status === "resolved" ? "resolved" : "active" }));
  }
  async close(): Promise<void> { await this.pool.end(); }
}

export type WaveWatchDeps = {
  now?: () => number;
  windowMs?: number;
  threshold?: number;
  cooldownMs?: number;
  resolveMs?: number;
  store?: WaveStore;
};

/**
 * Detects brief surges of moderator-verified reports against one identifier
 * (e.g. three verified reports for a phone within 30 minutes) and suppresses
 * repeat alerts inside a cooldown window. Backs the fraud-wave scheduler.
 */
export class WaveWatch {
  private readonly now: () => number;
  private readonly windowMs: number;
  private readonly threshold: number;
  private readonly cooldownMs: number;
  private readonly resolveMs: number;
  private readonly store: WaveStore | undefined;
  private readonly verifications = new Map<string, number[]>();
  private readonly issued = new Map<string, number>();
  private readonly waves = new Map<string, FraudWave>();

  constructor(deps: WaveWatchDeps = {}) {
    this.now = deps.now ?? Date.now;
    this.windowMs = deps.windowMs ?? 30 * 60_000;
    this.threshold = deps.threshold ?? 3;
    this.cooldownMs = deps.cooldownMs ?? 6 * 60 * 60_000;
    this.resolveMs = deps.resolveMs ?? 24 * 60 * 60_000;
    this.store = deps.store;
  }

  recordVerified(kind: IdentifierKind, rawValue: string, key: string = identifierKey(kind, rawValue)): FraudWave | null {
    const now = this.now();
    const marks = this.verifications.get(key) ?? [];
    marks.push(now);
    this.verifications.set(key, marks.filter((mark) => now - mark <= this.windowMs));
    const lastIssued = this.issued.get(key);
    if (lastIssued && now - lastIssued < this.cooldownMs) return null;
    const wave = this.verifications.get(key);
    if (!wave || wave.length < this.threshold) return null;
    const existing = this.waves.get(key);
    const waveRecord: FraudWave = {
      id: existing?.id ?? randomUUID(),
      kind,
      value: rawValue,
      label: labelFor(kind, rawValue),
      count: wave.length,
      first_seen: existing?.first_seen ?? new Date(wave[0]!).toISOString(),
      last_seen: new Date(now).toISOString(),
      status: "active"
    };
    this.waves.set(key, waveRecord);
    this.issued.set(key, now);
    void this.store?.save(waveRecord).catch(() => {});
    return waveRecord;
  }

  tick(now = this.now()): FraudWave[] {
    const resolved: FraudWave[] = [];
    for (const [key, wave] of this.waves) {
      if (wave.status === "active" && now - Date.parse(wave.last_seen) > this.resolveMs) {
        const updated: FraudWave = { ...wave, status: "resolved" };
        this.waves.set(key, updated);
        void this.store?.save(updated).catch(() => {});
        resolved.push(updated);
      }
    }
    return resolved;
  }

  recent(now = this.now()): FraudWave[] {
    const horizon = now - 48 * 60 * 60_000;
    return [...this.waves.values()]
      .filter((wave) => Date.parse(wave.last_seen) >= horizon)
      .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
  }
}