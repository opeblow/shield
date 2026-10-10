import { Pool } from "pg";
import { randomUUID } from "node:crypto";

export const INTEGRATION_SCOPES = ["scans:write", "lookup:read", "directory:read", "certificates:read"] as const;
export type IntegrationScope = (typeof INTEGRATION_SCOPES)[number];

export type IntegrationKey = {
  id: string;
  name: string;
  scopes: IntegrationScope[];
  keyHash: string;
  createdAt: string;
  revokedAt: string | null;
};

export interface IntegrationKeyStore {
  create(input: { name: string; keyHash: string; scopes: IntegrationScope[]; createdBy: string }): Promise<IntegrationKey>;
  findByHash(keyHash: string): Promise<IntegrationKey | null>;
  list(createdBy: string): Promise<IntegrationKey[]>;
  revoke(id: string, createdBy: string): Promise<boolean>;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

export class MemoryIntegrationKeyStore implements IntegrationKeyStore {
  private readonly keys = new Map<string, { key: IntegrationKey; createdBy: string }>();

  async create(input: { name: string; keyHash: string; scopes: IntegrationScope[]; createdBy: string }): Promise<IntegrationKey> {
    const key: IntegrationKey = { id: randomUUID(), name: input.name, scopes: input.scopes, keyHash: input.keyHash, createdAt: new Date().toISOString(), revokedAt: null };
    this.keys.set(key.id, { key, createdBy: input.createdBy });
    return key;
  }

  async findByHash(keyHash: string): Promise<IntegrationKey | null> {
    for (const { key } of this.keys.values()) {
      if (key.keyHash === keyHash && !key.revokedAt) return key;
    }
    return null;
  }

  async list(createdBy: string): Promise<IntegrationKey[]> {
    return [...this.keys.values()].filter((entry) => entry.createdBy === createdBy).map(({ key }) => key).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async revoke(id: string, createdBy: string): Promise<boolean> {
    const entry = this.keys.get(id);
    if (!entry || entry.createdBy !== createdBy || entry.key.revokedAt) return false;
    entry.key.revokedAt = new Date().toISOString();
    return true;
  }

  async ready(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    return;
  }
}

export class PgIntegrationKeyStore implements IntegrationKeyStore {
  readonly pool: Pool;
  constructor(connectionString: string, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 5, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
  }

  async create(input: { name: string; keyHash: string; scopes: IntegrationScope[]; createdBy: string }): Promise<IntegrationKey> {
    const result = await this.pool.query<{ id: string; created_at: Date }>(
      "INSERT INTO integration_keys (name, scopes, key_hash, created_by) VALUES ($1, $2, $3, $4) RETURNING id, created_at",
      [input.name, input.scopes, input.keyHash, input.createdBy]
    );
    const row = result.rows[0]!;
    return { id: row.id, name: input.name, scopes: input.scopes, keyHash: input.keyHash, createdAt: row.created_at.toISOString(), revokedAt: null };
  }

  async findByHash(keyHash: string): Promise<IntegrationKey | null> {
    const result = await this.pool.query<{ id: string; name: string; scopes: string[]; created_at: Date; revoked_at: Date | null }>(
      "SELECT id, name, scopes, created_at, revoked_at FROM integration_keys WHERE key_hash = $1 AND revoked_at IS NULL",
      [keyHash]
    );
    const row = result.rows[0];
    return row ? { id: row.id, name: row.name, scopes: row.scopes as IntegrationScope[], keyHash, createdAt: row.created_at.toISOString(), revokedAt: row.revoked_at ? row.revoked_at.toISOString() : null } : null;
  }

  async list(createdBy: string): Promise<IntegrationKey[]> {
    const result = await this.pool.query<{ id: string; name: string; scopes: string[]; key_hash: string; created_at: Date; revoked_at: Date | null }>(
      "SELECT id, name, scopes, key_hash, created_at, revoked_at FROM integration_keys WHERE created_by = $1 ORDER BY created_at", [createdBy]
    );
    return result.rows.map((row) => ({ id: row.id, name: row.name, scopes: row.scopes as IntegrationScope[], keyHash: row.key_hash, createdAt: row.created_at.toISOString(), revokedAt: row.revoked_at ? row.revoked_at.toISOString() : null }));
  }

  async revoke(id: string, createdBy: string): Promise<boolean> {
    const result = await this.pool.query("UPDATE integration_keys SET revoked_at = now() WHERE id = $1 AND created_by = $2 AND revoked_at IS NULL", [id, createdBy]);
    return (result.rowCount ?? 0) > 0;
  }

  async ready(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1 FROM integration_keys LIMIT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
