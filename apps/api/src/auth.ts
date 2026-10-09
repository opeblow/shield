import { Pool } from "pg";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback) as (password: string, salt: Buffer, keylen: number, options: ScryptOptions) => Promise<Buffer>;

const SCRYPT_PARAMS = { N: 16_384, r: 8, p: 1 } as const;
const KEY_LENGTH = 64;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, KEY_LENGTH, SCRYPT_PARAMS);
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt.toString("base64")}$${derived.toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4]!, "base64");
  const expected = Buffer.from(parts[5]!, "base64");
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p) || expected.length === 0) return false;
  const derived = await scrypt(password, salt, expected.length, { N, r, p });
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export type AuthAccount = { id: string; email: string; createdAt: string };
export type SessionRecord = { userId: string; email: string; expiresAt: Date; revokedAt: Date | null };
export type SessionSummary = { createdAt: string; expiresAt: string; current: boolean };

export interface AuthStore {
  createAccount(email: string, passwordHash: string): Promise<AuthAccount | null>;
  findAccount(email: string): Promise<{ account: AuthAccount; passwordHash: string } | null>;
  createSession(input: { userId: string; email: string; tokenHash: string; expiresAt: Date }): Promise<void>;
  findSession(tokenHash: string): Promise<SessionRecord | null>;
  revokeSession(tokenHash: string): Promise<void>;
  listSessions(userId: string, currentTokenHash: string): Promise<SessionSummary[]>;
  revokeOtherSessions(userId: string, currentTokenHash: string): Promise<void>;
  ready(): Promise<boolean>;
  close(): Promise<void>;
}

export class MemoryAuthStore implements AuthStore {
  private readonly accounts = new Map<string, { account: AuthAccount; passwordHash: string }>();
  private readonly sessions = new Map<string, SessionRecord>();

  async createAccount(email: string, passwordHash: string): Promise<AuthAccount | null> {
    if (this.accounts.has(email)) return null;
    const account = { id: randomUUID(), email, createdAt: new Date().toISOString() };
    this.accounts.set(email, { account, passwordHash });
    return account;
  }

  async findAccount(email: string): Promise<{ account: AuthAccount; passwordHash: string } | null> {
    return this.accounts.get(email) ?? null;
  }

  async createSession(input: { userId: string; email: string; tokenHash: string; expiresAt: Date }): Promise<void> {
    this.sessions.set(input.tokenHash, { userId: input.userId, email: input.email, expiresAt: input.expiresAt, revokedAt: null });
  }

  async findSession(tokenHash: string): Promise<SessionRecord | null> {
    return this.sessions.get(tokenHash) ?? null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    const session = this.sessions.get(tokenHash);
    if (session) session.revokedAt = new Date();
  }

  async listSessions(userId: string, currentTokenHash: string): Promise<SessionSummary[]> {
    return [...this.sessions.entries()].filter(([, session]) => session.userId === userId && !session.revokedAt && session.expiresAt > new Date())
      .map(([tokenHash, session]) => ({ createdAt: "", expiresAt: session.expiresAt.toISOString(), current: tokenHash === currentTokenHash }));
  }

  async revokeOtherSessions(userId: string, currentTokenHash: string): Promise<void> {
    for (const [tokenHash, session] of this.sessions) if (session.userId === userId && tokenHash !== currentTokenHash && !session.revokedAt) session.revokedAt = new Date();
  }

  async ready(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    return;
  }
}

export class PgAuthStore implements AuthStore {
  readonly pool: Pool;
  constructor(connectionString: string, pool?: Pool) {
    this.pool = pool ?? new Pool({ connectionString, max: 5, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 3_000, statement_timeout: 5_000 });
  }

  async createAccount(email: string, passwordHash: string): Promise<AuthAccount | null> {
    try {
      const result = await this.pool.query<{ id: string; email: string; created_at: Date }>(
        "INSERT INTO accounts (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at",
        [email, passwordHash]
      );
      const row = result.rows[0];
      return row ? { id: row.id, email: row.email, createdAt: row.created_at.toISOString() } : null;
    } catch (error) {
      if (typeof error === "object" && error && "code" in error && (error as { code?: string }).code === "23505") return null;
      throw error;
    }
  }

  async findAccount(email: string): Promise<{ account: AuthAccount; passwordHash: string } | null> {
    const result = await this.pool.query<{ id: string; email: string; created_at: Date; password_hash: string }>(
      "SELECT id, email, created_at, password_hash FROM accounts WHERE lower(email) = $1 AND disabled_at IS NULL",
      [email]
    );
    const row = result.rows[0];
    return row ? { account: { id: row.id, email: row.email, createdAt: row.created_at.toISOString() }, passwordHash: row.password_hash } : null;
  }

  async createSession(input: { userId: string; email: string; tokenHash: string; expiresAt: Date }): Promise<void> {
    await this.pool.query("INSERT INTO auth_sessions (token_hash, account_id, expires_at) VALUES ($1, $2, $3)", [input.tokenHash, input.userId, input.expiresAt]);
  }

  async findSession(tokenHash: string): Promise<SessionRecord | null> {
    const result = await this.pool.query<{ account_id: string; email: string; expires_at: Date; revoked_at: Date | null }>(
      `SELECT s.account_id, a.email, s.expires_at, s.revoked_at
       FROM auth_sessions s JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = $1 AND a.disabled_at IS NULL`,
      [tokenHash]
    );
    const row = result.rows[0];
    return row ? { userId: row.account_id, email: row.email, expiresAt: row.expires_at, revokedAt: row.revoked_at } : null;
  }

  async revokeSession(tokenHash: string): Promise<void> {
    await this.pool.query("UPDATE auth_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL", [tokenHash]);
  }

  async listSessions(userId: string, currentTokenHash: string): Promise<SessionSummary[]> {
    const result = await this.pool.query<{ token_hash: string; created_at: Date; expires_at: Date }>(
      "SELECT token_hash, created_at, expires_at FROM auth_sessions WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC", [userId]);
    return result.rows.map((row) => ({ createdAt: row.created_at.toISOString(), expiresAt: row.expires_at.toISOString(), current: row.token_hash === currentTokenHash }));
  }

  async revokeOtherSessions(userId: string, currentTokenHash: string): Promise<void> {
    await this.pool.query("UPDATE auth_sessions SET revoked_at = now() WHERE account_id = $1 AND token_hash <> $2 AND revoked_at IS NULL", [userId, currentTokenHash]);
  }

  async ready(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1 FROM accounts LIMIT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
