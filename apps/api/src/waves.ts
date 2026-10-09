import { randomUUID } from "node:crypto";
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

export type WaveWatchDeps = {
  now?: () => number;
  windowMs?: number;
  threshold?: number;
  cooldownMs?: number;
  resolveMs?: number;
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
  private readonly verifications = new Map<string, number[]>();
  private readonly issued = new Map<string, number>();
  private readonly waves = new Map<string, FraudWave>();

  constructor(deps: WaveWatchDeps = {}) {
    this.now = deps.now ?? Date.now;
    this.windowMs = deps.windowMs ?? 30 * 60_000;
    this.threshold = deps.threshold ?? 3;
    this.cooldownMs = deps.cooldownMs ?? 6 * 60 * 60_000;
    this.resolveMs = deps.resolveMs ?? 24 * 60 * 60_000;
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
    return waveRecord;
  }

  tick(now = this.now()): FraudWave[] {
    const resolved: FraudWave[] = [];
    for (const [key, wave] of this.waves) {
      if (wave.status === "active" && now - Date.parse(wave.last_seen) > this.resolveMs) {
        const updated: FraudWave = { ...wave, status: "resolved" };
        this.waves.set(key, updated);
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