import { Pool } from "pg";
import type { ScanResult } from "../../../packages/risk-engine/src/types.js";
import { apiKeyId, blindIndex, decryptField, encryptField, hashSecret, sha256, verifySecret, type EncryptedField, type Keyring } from "../../../packages/shared/src/crypto.js";
import { normalizeIdentifier, type LookupType } from "../../../packages/shared/src/identifiers.js";

export function resultForStorage(result: ScanResult): object {
  return {
    scan_id: result.scan_id,
    verdict: result.verdict,
    risk_score: result.risk_score,
    confidence: result.confidence,
    scam_types: result.scam_types,
    language: result.customer_message.language,
    latency_ms: result.latency_ms,
    model_version: result.model_version,
    community_available: result.community.available
  };
}

export class ScanRepository {
  readonly pool: Pool;
  constructor(connectionString: string, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 10, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
  }

  async save(result: ScanResult, redactedInput: string, tenantId: string | null = null): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId ?? ""]);
      const hash = sha256(redactedInput.normalize("NFC"));
      const retentionHours = Math.min(24, Math.max(1, Number(process.env.DATA_RETENTION_HOURS_CONSUMER ?? "24")));
      await client.query(
        `INSERT INTO scans (id, tenant_id, user_id, input_types, verdict, risk_score, confidence, scam_types, language, latency_ms, model_version, content_hash, redacted_input_cipher, result, created_at, expires_at)
         VALUES ($1, $2, NULL, ARRAY['text'], $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11::jsonb, now(), now() + ($12::text || ' hours')::interval)`,
        [result.scan_id, tenantId, result.verdict, result.risk_score, result.confidence, result.scam_types, result.customer_message.language, result.latency_ms, result.model_version, hash, JSON.stringify(resultForStorage(result)), retentionHours]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async createApiKey(tenantId: string, key: string, pepper: Buffer, scopes: string[], expiresAt: Date | null = null): Promise<void> {
    const keyId = apiKeyId(key);
    if (!keyId) throw new Error("Invalid Shield API key format");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      await client.query(
        "INSERT INTO api_keys (tenant_id, key_id, key_hash, scopes, expires_at) VALUES ($1, $2, $3, $4, $5)",
        [tenantId, keyId, hashSecret(key, pepper), scopes, expiresAt]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async createTenant(name: string): Promise<string> {
    const result = await this.pool.query<{ id: string }>("INSERT INTO tenants (name) VALUES ($1) RETURNING id", [name]);
    const tenantId = result.rows[0]?.id;
    if (!tenantId) throw new Error("Tenant creation failed");
    return tenantId;
  }

  async lookup(type: LookupType, value: string, pepper: Buffer): Promise<{ reports: number; verifiedReports: number; score: number; lastSeen: string | null } | null> {
    const normalized = normalizeIdentifier(type, value);
    const index = blindIndex(`entity:${normalized}`, pepper, "v1");
    const result = await this.pool.query<{ report_count: number; verified_count: number; score: string; last_seen: Date | null }>(
      `SELECT r.report_count, r.verified_count, r.score, e.last_seen
       FROM entities e JOIN entity_reputation r ON r.entity_id = e.id
       WHERE e.type = $1 AND e.blind_index = $2 AND e.pepper_version = 'v1'`,
      [type, index]
    );
    const row = result.rows[0];
    if (!row) return null;
    return { reports: row.report_count, verifiedReports: row.verified_count, score: Number(row.score), lastSeen: row.last_seen?.toISOString() ?? null };
  }

  async reportIdentifier(input: { type: LookupType; value: string; scamType: string; reporter: string; pepper: Buffer; evidence?: string; keyring: Keyring }): Promise<string> {
    const normalized = normalizeIdentifier(input.type, input.value);
    const entityIndex = blindIndex(`entity:${normalized}`, input.pepper, "v1");
    const reporterIndex = blindIndex(`reporter:${input.reporter}`, input.pepper, "v1");
    const encryptedEvidence = input.evidence
      ? JSON.stringify(encryptField(input.evidence, "community-reports", input.keyring))
      : null;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const entity = await client.query<{ id: string }>(
        `INSERT INTO entities (type, blind_index, pepper_version)
         VALUES ($1, $2, 'v1')
         ON CONFLICT (type, blind_index, pepper_version)
         DO UPDATE SET last_seen = now()
         RETURNING id`,
        [input.type, entityIndex]
      );
      const entityId = entity.rows[0]?.id;
      if (!entityId) throw new Error("Could not create report entity");
      const encryptedIdentifier = JSON.stringify(encryptField(normalized, `community-entity:${entityId}`, input.keyring));
      await client.query("UPDATE entities SET normalized_cipher = COALESCE(normalized_cipher, $2::jsonb) WHERE id = $1", [entityId, encryptedIdentifier]);
      const report = await client.query<{ id: string }>(
        `INSERT INTO reports (entity_id, reporter_blind_index, scam_type, description_cipher, status)
         VALUES ($1, $2, $3, $4::jsonb, 'pending') RETURNING id`,
        [entityId, reporterIndex, input.scamType, encryptedEvidence]
      );
      const reportId = report.rows[0]?.id;
      if (!reportId) throw new Error("Could not create community report");
      await client.query("COMMIT");
      return reportId;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async listPendingReports(keyring: Keyring): Promise<Array<{ id: string; type: LookupType; identifier: string; scamType: string; evidence: string | null; createdAt: string }>> {
    const result = await this.pool.query<{
      id: string; entity_id: string; type: LookupType; normalized_cipher: EncryptedField | null;
      scam_type: string; description_cipher: EncryptedField | null; created_at: Date;
    }>(
      `SELECT r.id, r.entity_id, e.type, e.normalized_cipher, r.scam_type, r.description_cipher, r.created_at
       FROM reports r JOIN entities e ON e.id = r.entity_id
       WHERE r.status = 'pending' ORDER BY r.created_at ASC LIMIT 100`
    );
    return result.rows.map((row) => {
      if (!row.normalized_cipher) throw new Error("A pending report is missing its encrypted identifier");
      return {
        id: row.id,
        type: row.type,
        identifier: decryptField(row.normalized_cipher, `community-entity:${row.entity_id}`, keyring),
        scamType: row.scam_type,
        evidence: row.description_cipher ? decryptField(row.description_cipher, "community-reports", keyring) : null,
        createdAt: row.created_at.toISOString()
      };
    });
  }

  async moderateReport(reportId: string, action: "verify" | "reject"): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('shield-audit-chain', 0))");
      const report = await client.query<{ entity_id: string; status: string }>(
        "SELECT entity_id, status FROM reports WHERE id = $1 FOR UPDATE", [reportId]
      );
      const row = report.rows[0];
      if (!row || row.status !== "pending") { await client.query("ROLLBACK"); return false; }
      await client.query("UPDATE reports SET status = $2 WHERE id = $1 AND status = 'pending'", [reportId, action === "verify" ? "verified" : "rejected"]);
      if (action === "verify") {
        await client.query(
          `INSERT INTO entity_reputation (entity_id, report_count, verified_count, score, last_computed_at)
           VALUES ($1, 1, 1, 10, now())
           ON CONFLICT (entity_id) DO UPDATE SET
             report_count = entity_reputation.report_count + 1,
             verified_count = entity_reputation.verified_count + 1,
             score = LEAST(100, (entity_reputation.verified_count + 1) * 10),
             last_computed_at = now()`,
          [row.entity_id]
        );
      }
      const previous = await client.query<{ entry_hash: string }>("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1");
      const previousHash = previous.rows[0]?.entry_hash ?? "0".repeat(64);
      const actionName = `community_report_${action}`;
      const entryHash = sha256(`${previousHash}\ncommunity-moderator\n${actionName}\n${reportId}`);
      await client.query(
        "INSERT INTO audit_logs (tenant_id, actor, action, target, prev_hash, entry_hash) VALUES (NULL, 'community-moderator', $1, $2, $3, $4)",
        [actionName, reportId, previousHash, entryHash]
      );
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async authenticateApiKey(key: string, pepper: Buffer, requiredScope: string): Promise<string | null> {
    const keyId = apiKeyId(key);
    if (!keyId) return null;
    const result = await this.pool.query<{ tenant_id: string; key_hash: string; scopes: string[] }>(
      "SELECT tenant_id, key_hash, scopes FROM resolve_api_key($1)",
      [keyId]
    );
    const record = result.rows[0];
    if (!record || !record.scopes.includes(requiredScope) || !verifySecret(key, record.key_hash, pepper)) return null;
    return record.tenant_id;
  }

  async recordUsage(tenantId: string, metric: string, quantity = 1): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      await client.query("INSERT INTO usage_events (tenant_id, metric, quantity) VALUES ($1, $2, $3)", [tenantId, metric, quantity]);
    } finally { client.release(); }
  }

  async usageSummary(tenantId: string, since = new Date(Date.now() - 30 * 24 * 3600 * 1000)): Promise<Array<{ metric: string; quantity: number }>> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await client.query<{ metric: string; quantity: string }>(
        "SELECT metric, COALESCE(SUM(quantity), 0) AS quantity FROM usage_events WHERE tenant_id = $1 AND at >= $2 GROUP BY metric ORDER BY metric",
        [tenantId, since]
      );
      return result.rows.map((row) => ({ metric: row.metric, quantity: Number(row.quantity) }));
    } finally { client.release(); }
  }

  async createWebhook(tenantId: string, url: string, events: string[], secret: string, keyring: Keyring): Promise<string> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const cipher = JSON.stringify(encryptField(secret, `webhook:${tenantId}`, keyring));
      const result = await client.query<{ id: string }>(
        "INSERT INTO webhooks (tenant_id, url, secret_cipher, events) VALUES ($1, $2, $3::jsonb, $4) RETURNING id",
        [tenantId, url, cipher, events]
      );
      await client.query("COMMIT");
      const id = result.rows[0]?.id;
      if (!id) throw new Error("Webhook creation failed");
      return id;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async listWebhooks(tenantId: string): Promise<Array<{ id: string; url: string; events: string[]; status: string }>> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await client.query<{ id: string; url: string; events: string[]; status: string }>(
        "SELECT id, url, events, status FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC", [tenantId]
      );
      return result.rows;
    } finally { client.release(); }
  }

  async deleteWebhook(tenantId: string, webhookId: string): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await client.query("DELETE FROM webhooks WHERE tenant_id = $1 AND id = $2", [tenantId, webhookId]);
      await client.query("COMMIT");
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }

  async activeWebhooks(tenantId: string, keyring: Keyring): Promise<Array<{ id: string; url: string; events: string[]; secret: string }>> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await client.query<{ id: string; url: string; events: string[]; secret_cipher: EncryptedField }>(
        "SELECT id, url, events, secret_cipher FROM webhooks WHERE tenant_id = $1 AND status = 'active'", [tenantId]
      );
      return result.rows.map((row) => ({ id: row.id, url: row.url, events: row.events, secret: decryptField(row.secret_cipher, `webhook:${tenantId}`, keyring) }));
    } finally { client.release(); }
  }

  async recordWebhookDelivery(webhookId: string, event: string, delivered: boolean, attempts: number, status: number | null): Promise<void> {
    await this.pool.query(
      "INSERT INTO webhook_deliveries (webhook_id, event, delivered, attempts, status) VALUES ($1, $2, $3, $4, $5)",
      [webhookId, event, delivered, attempts, status]
    );
  }

  async ready(): Promise<boolean> {
    try {
      const result = await this.pool.query<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = current_schema() AND c.relname IN ('scans','api_keys')`
      );
      const scans = result.rows.find((row) => row.relname === "scans");
      const apiKeys = result.rows.find((row) => row.relname === "api_keys");
      return Boolean(scans?.relrowsecurity && scans.relforcerowsecurity && apiKeys?.relrowsecurity);
    } catch { return false; }
  }

  async close(): Promise<void> { await this.pool.end(); }
}
