export type ProtectedHistoryItem = { version: 1; salt: string; nonce: string; ciphertext: string };

function bytesToBase64(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)); }
function base64ToBytes(value: string): Uint8Array { return Uint8Array.from(atob(value), (character) => character.charCodeAt(0)); }
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function deriveHistoryKey(passphrase: string, salt: Uint8Array, iterations = 600_000): Promise<CryptoKey> {
  if (passphrase.length < 12) throw new Error("History passphrase must be at least 12 characters");
  if (iterations < 600_000) throw new Error("History key derivation cost is below the minimum");
  const material = await crypto.subtle.importKey("raw", toArrayBuffer(new TextEncoder().encode(passphrase)), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: toArrayBuffer(salt), iterations, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptHistory(value: unknown, passphrase: string): Promise<ProtectedHistoryItem> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveHistoryKey(passphrase, salt);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(new TextEncoder().encode("shield-local-history-v1")) }, key, toArrayBuffer(plaintext));
  return { version: 1, salt: bytesToBase64(salt), nonce: bytesToBase64(nonce), ciphertext: bytesToBase64(new Uint8Array(encrypted)) };
}

export async function decryptHistory<T>(value: ProtectedHistoryItem, passphrase: string): Promise<T> {
  if (value.version !== 1) throw new Error("Unsupported encrypted history version");
  const salt = base64ToBytes(value.salt);
  const nonce = base64ToBytes(value.nonce);
  const key = await deriveHistoryKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(new TextEncoder().encode("shield-local-history-v1")) }, key, toArrayBuffer(base64ToBytes(value.ciphertext)));
  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}
