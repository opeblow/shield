import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type EncryptedField = { keyId: string; nonce: string; ciphertext: string; tag: string };
export type Keyring = { activeKeyId: string; keys: Readonly<Record<string, Buffer>>; blindPepper: Buffer; secretPepper: Buffer };
export type WrappedTenantKey = { tenantId: string; keyId: string; nonce: string; ciphertext: string; tag: string };

export function keyringFromEnv(env: NodeJS.ProcessEnv = process.env): Keyring {
  const raw = env.FIELD_KEK;
  const key = raw ? Buffer.from(raw, "base64") : undefined;
  if (!key || key.length !== 32) throw new Error("FIELD_KEK must be a base64 encoded 32-byte key");
  const blindPepper = env.BLIND_INDEX_PEPPER;
  const secretPepper = env.API_KEY_PEPPER;
  if (!blindPepper || Buffer.byteLength(blindPepper) < 32 || !secretPepper || Buffer.byteLength(secretPepper) < 32) throw new Error("Blind-index and API-key peppers must each contain at least 32 bytes");
  return { activeKeyId: env.FIELD_KEK_ID ?? "kek-v1", keys: { [env.FIELD_KEK_ID ?? "kek-v1"]: key }, blindPepper: Buffer.from(blindPepper), secretPepper: Buffer.from(secretPepper) };
}

export function encryptField(plaintext: string, tenantId: string, ring: Keyring): EncryptedField {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", ring.keys[ring.activeKeyId]!, nonce);
  cipher.setAAD(Buffer.from(tenantId));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { keyId: ring.activeKeyId, nonce: nonce.toString("base64"), ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

export function decryptField(value: EncryptedField, tenantId: string, ring: Keyring): string {
  const key = ring.keys[value.keyId];
  if (!key) throw new Error("Unknown encryption key id");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(value.nonce, "base64"));
  decipher.setAAD(Buffer.from(tenantId));
  decipher.setAuthTag(Buffer.from(value.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

export function rotateKey(value: EncryptedField, tenantId: string, ring: Keyring): EncryptedField {
  return encryptField(decryptField(value, tenantId, ring), tenantId, ring);
}

export function createTenantKey(tenantId: string, keyId: string, kek: Buffer): { wrapped: WrappedTenantKey; dek: Buffer } {
  if (kek.length !== 32) throw new Error("KEK must be 32 bytes");
  const dek = randomBytes(32);
  const wrapped = seal(dek, tenantId, keyId, kek);
  return { wrapped: { tenantId, ...wrapped }, dek };
}

export function unwrapTenantKey(wrapped: WrappedTenantKey, tenantId: string, kek: Buffer): Buffer {
  if (wrapped.tenantId !== tenantId) throw new Error("Tenant key belongs to another tenant");
  const dek = open({ keyId: wrapped.keyId, nonce: wrapped.nonce, ciphertext: wrapped.ciphertext, tag: wrapped.tag }, tenantId, kek);
  if (dek.length !== 32) throw new Error("Invalid tenant data key");
  return dek;
}

export function rewrapTenantKey(wrapped: WrappedTenantKey, oldKek: Buffer, newKek: Buffer, newKeyId: string): WrappedTenantKey {
  const dek = unwrapTenantKey(wrapped, wrapped.tenantId, oldKek);
  return { tenantId: wrapped.tenantId, ...seal(dek, wrapped.tenantId, newKeyId, newKek) };
}

function seal(plaintext: Buffer, tenantId: string, keyId: string, key: Buffer): Omit<EncryptedField, "keyId"> & { keyId: string } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(tenantId));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { keyId, nonce: nonce.toString("base64"), ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}

function open(value: EncryptedField, tenantId: string, key: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(value.nonce, "base64"));
  decipher.setAAD(Buffer.from(tenantId));
  decipher.setAuthTag(Buffer.from(value.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, "base64")), decipher.final()]);
}

export function blindIndex(normalized: string, pepper: Buffer, version = "v1"): string {
  return `${version}:${createHmac("sha256", pepper).update(normalized, "utf8").digest("hex")}`;
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hashSecret(secret: string, pepper: Buffer): string {
  return createHmac("sha256", pepper).update(secret, "utf8").digest("hex");
}

export function verifySecret(secret: string, expectedHex: string, pepper: Buffer): boolean {
  const actual = Buffer.from(hashSecret(secret, pepper), "hex");
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function sign(payload: string | Buffer, secret: Buffer): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

export function verifySignature(payload: string | Buffer, signatureHex: string, secret: Buffer): boolean {
  if (!/^[a-f\d]{64}$/i.test(signatureHex)) return false;
  const actual = Buffer.from(sign(payload, secret), "hex");
  const expected = Buffer.from(signatureHex, "hex");
  return timingSafeEqual(actual, expected);
}

export function generateOpaqueToken(bytes = 32): string { return randomBytes(bytes).toString("base64url"); }

export function generateApiKey(environment: "live" | "test" = "live"): string {
  return `shd_${environment}_${generateOpaqueToken(9)}_${generateOpaqueToken(32)}`;
}

export function apiKeyId(key: string): string | undefined {
  return /^shd_(?:live|test)_([A-Za-z0-9_-]{12})_[A-Za-z0-9_-]{43}$/.exec(key)?.[1];
}
