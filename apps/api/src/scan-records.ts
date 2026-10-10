import { Pool } from "pg";

export type ScanRecord = {
  scanId: string;
  ownerId: string | null;
  tenantId: string | null;
  verdict: string;
  riskScore: number;
  scamTypes: string[];
  language: string;
  redactedText: string;
  createdAt: string;
};

export interface ScanRecordStore {
  save(record: ScanRecord): Promise<void>;
  get(scanId: string): Promise<ScanRecord | null>;
  close(): Promise<void>;
}

const TTL_MS = 48 * 60 * 60 * 1000;
const MAX_RECORDS = 10_000;

export class MemoryScanRecordStore implements ScanRecordStore {
  private readonly records = new Map<string, ScanRecord>();

  async save(record: ScanRecord): Promise<void> {
    this.prune();
    this.records.set(record.scanId, record);
    while (this.records.size > MAX_RECORDS) {
      const oldest = this.records.keys().next().value;
      if (!oldest) break;
      this.records.delete(oldest);
    }
  }

  async get(scanId: string): Promise<ScanRecord | null> {
    const record = this.records.get(scanId);
    if (!record) return null;
    if (Date.now() - new Date(record.createdAt).getTime() > TTL_MS) { this.records.delete(scanId); return null; }
    return record;
  }

  private prune(): void {
    const cutoff = Date.now() - TTL_MS;
    for (const [id, record] of this.records) {
      if (new Date(record.createdAt).getTime() < cutoff) this.records.delete(id);
    }
  }

  async close(): Promise<void> {}
}

export class PgScanRecordStore implements ScanRecordStore {
  readonly pool: Pool;
  constructor(connectionString: string, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 10, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
  }

  async save(record: ScanRecord): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [record.tenantId ?? ""]);
      await client.query(
        `INSERT INTO scan_records (scan_id, owner_id, tenant_id, verdict, risk_score, scam_types, language, redacted_text, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (scan_id) DO UPDATE SET owner_id = EXCLUDED.owner_id, tenant_id = EXCLUDED.tenant_id,
           verdict = EXCLUDED.verdict, risk_score = EXCLUDED.risk_score, scam_types = EXCLUDED.scam_types,
           language = EXCLUDED.language, redacted_text = EXCLUDED.redacted_text`,
        [record.scanId, record.ownerId, record.tenantId, record.verdict, record.riskScore, record.scamTypes, record.language, record.redactedText, record.createdAt]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async get(scanId: string): Promise<ScanRecord | null> {
    const result = await this.pool.query<{
      scan_id: string; owner_id: string | null; tenant_id: string | null; verdict: string;
      risk_score: number; scam_types: string[]; language: string; redacted_text: string; created_at: Date;
    }>(
      `SELECT scan_id, owner_id, tenant_id, verdict, risk_score, scam_types, language, redacted_text, created_at
       FROM scan_records WHERE scan_id = $1 AND created_at >= now() - interval '48 hours'`,
      [scanId]
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      scanId: row.scan_id,
      ownerId: row.owner_id,
      tenantId: row.tenant_id,
      verdict: row.verdict,
      riskScore: row.risk_score,
      scamTypes: row.scam_types,
      language: row.language,
      redactedText: row.redacted_text,
      createdAt: row.created_at.toISOString()
    };
  }

  async close(): Promise<void> { await this.pool.end(); }
}
