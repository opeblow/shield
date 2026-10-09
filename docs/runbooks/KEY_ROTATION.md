# Runbook — key rotation

Keys are supplied via environment variables. The keyring provides the current
key plus predecessors so ciphertext stays decryptable across a rotation.

## Encryption keyring (`KEYRING`)
1. Generate a new 32-byte base64 key offline; never paste it into shell history.
2. Set the new key as `KEYRING` current and move the previous key into the
   predecessor list. Deploy. New writes use the new key; old data still reads.
3. Schedule a backfill to re-encrypt rows still under the predecessor (see
   `infra/migrations/`); decrypt with old key, re-encrypt with current.
4. After backfill verification, remove the predecessor key and redeploy.

## API key pepper (`API_KEY_PEPPER`)
The pepper salts stored API-key hashes. Rotating it invalidates every key.
1. Provision a second pepper and accept both for a grace window.
2. Reissue tenant keys via `npm run tenant:key`; distribute securely.
3. Retire the old pepper once all tenants have reissued.

## Signing / webhook secrets
Per-webhook secrets are shown once at creation. To rotate: create a replacement
webhook, confirm delivery, then delete the old subscription.

## Verification
- Confirm no plaintext secrets in logs (`safe-log.ts` scrubs known keys).
- Confirm decryption of a sample row under both current and predecessor keys
  before retiring a predecessor.
- Record who rotated, when, and why in the audit chain.
