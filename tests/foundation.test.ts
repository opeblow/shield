import test from "node:test";
import assert from "node:assert/strict";
import { decryptField, encryptField, hashSecret, verifySecret, blindIndex, sign, verifySignature, createTenantKey, unwrapTenantKey, rewrapTenantKey, generateApiKey, apiKeyId, rotateKey, sha256, type Keyring, type EncryptedField } from "../packages/shared/src/crypto.js";
import { redactSensitive } from "../packages/shared/src/redaction.js";
import { scanText } from "../packages/risk-engine/src/scan.js";
import { detectLanguage } from "../packages/risk-engine/src/entities.js";
import { SmsSimulator, UssdSimulator, IvrSimulator } from "../packages/channels/src/simulators.js";
import { scrubLog } from "../packages/shared/src/safe-log.js";
import { resultForStorage, ScanRepository } from "../apps/api/src/repository.js";
import { loadEnv } from "../apps/api/src/env.js";
import { OpenAiProvider } from "../apps/api/src/provider.js";
import { decryptHistory, encryptHistory } from "../packages/shared/src/browser-history.js";
import { verifyMetaChallenge, verifyMetaSignature, WhatsAppSimulator } from "../packages/channels/src/whatsapp.js";
import { communityReportSchema, lookupRequestSchema, moderateReportSchema, scanRequestSchema } from "../apps/api/src/validation.js";
import { normalizeIdentifier } from "../packages/shared/src/identifiers.js";
import { MemoryRateLimiter } from "../apps/api/src/rate-limit.js";
import { analyzeUrl } from "../packages/risk-engine/src/url-analysis.js";

const secret = Buffer.alloc(32, 7);
const ring: Keyring = { activeKeyId: "test", keys: { test: secret }, blindPepper: secret, secretPepper: secret };

test("AES-GCM encrypts with tenant binding and rejects tampering", () => {
  const encrypted = encryptField("private account text", "tenant-a", ring);
  assert.equal(decryptField(encrypted, "tenant-a", ring), "private account text");
  assert.throws(() => decryptField(encrypted, "tenant-b", ring));
  assert.throws(() => decryptField({ ...encrypted, ciphertext: Buffer.from("changed").toString("base64") }, "tenant-a", ring));
});

test("HMAC secrets and blind indexes are not plaintext and fail closed", () => {
  const hashed = hashSecret("shd_live_secret", ring.secretPepper);
  assert.notEqual(hashed, "shd_live_secret");
  assert.equal(verifySecret("shd_live_secret", hashed, ring.secretPepper), true);
  assert.equal(verifySecret("other", hashed, ring.secretPepper), false);
  assert.notEqual(blindIndex("08031234567", ring.blindPepper), "08031234567");
  const signature = sign("123.body", ring.secretPepper);
  assert.equal(verifySignature("123.body", signature, ring.secretPepper), true);
  assert.equal(verifySignature("123.other", signature, ring.secretPepper), false);
  assert.equal(sign("Hi There", Buffer.alloc(20, 0x0b)), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  assert.equal(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("tenant DEKs are isolated and can be rewrapped without changing field data", () => {
  const kekV1 = Buffer.alloc(32, 3);
  const kekV2 = Buffer.alloc(32, 4);
  const { wrapped, dek } = createTenantKey("tenant-a", "kek-v1", kekV1);
  assert.deepEqual(unwrapTenantKey(wrapped, "tenant-a", kekV1), dek);
  assert.throws(() => unwrapTenantKey(wrapped, "tenant-b", kekV1));
  const rotated = rewrapTenantKey(wrapped, kekV1, kekV2, "kek-v2");
  assert.equal(rotated.keyId, "kek-v2");
  assert.deepEqual(unwrapTenantKey(rotated, "tenant-a", kekV2), dek);
  const old = encryptField("kept during rotation", "tenant-a", { ...ring, activeKeyId: "v1", keys: { v1: kekV1 } });
  const newRing = { ...ring, activeKeyId: "v2", keys: { v1: kekV1, v2: kekV2 } };
  assert.equal(decryptField(rotateKey(old, "tenant-a", newRing), "tenant-a", newRing), "kept during rotation");
});

test("API keys use the required public prefix and 256 random bits", () => {
  const key = generateApiKey("live");
  assert.match(key, /^shd_live_[A-Za-z0-9_-]{12}_[A-Za-z0-9_-]{43}$/);
  assert.equal(apiKeyId(key)?.length, 12);
  assert.equal(verifySecret(key, hashSecret(key, ring.secretPepper), ring.secretPepper), true);
});

test("redacts sensitive Nigerian identifiers before model assessment", () => {
  const result = redactSensitive("BVN 12345678901, OTP: 729104, account 0123456789, +2348031234567, jane@example.ng and card 4111111111111111");
  assert.equal(result.text.includes("12345678901"), false);
  assert.equal(result.text.includes("729104"), false);
  assert.equal(result.text.includes("0123456789"), false);
  assert.equal(result.text.includes("+2348031234567"), false);
  assert.equal(result.text.includes("jane@example.ng"), false);
  assert.equal(result.text.includes("4111111111111111"), false);
  const repeated = redactSensitive("Account 0123456789; account 0123456790; acct 0123456789.");
  assert.match(repeated.text, /\[ACCOUNT_1\].*\[ACCOUNT_2\].*\[ACCOUNT_1\]/);
});

test("redacted identifiers are the only text passed to the model and unchecked links never imply safe", async () => {
  let assessed = "";
  const result = await scanText("Urgent claim at https://unknown.example and account 0123456789; OTP: 729104", {
    assess: async (text) => { assessed = text; return { scam: false, scam_types: [], confidence: 0.4, reasons: [] }; }
  });
  assert.equal(assessed.includes("0123456789"), false);
  assert.equal(assessed.includes("729104"), false);
  assert.notEqual(result.verdict, "safe");
  assert.ok(result.reasons.some((reason) => reason.code === "identifier_not_checked"));
  assert.equal(result.community.reports, null);
  assert.equal(result.community.available, false);
});

test("rules flag pressure and private-code requests and use requested language", async () => {
  const result = await scanText("Urgent: send your OTP now or your account will be blocked", { language: "pcm" });
  assert.notEqual(result.verdict, "safe");
  assert.ok(result.reasons.some((reason) => reason.code === "requests_secret_code"));
  assert.equal(result.customer_message.language, "pcm");
  assert.equal(result.customer_message.text.includes("code"), true);
});

test("local-language code requests are flagged with and without diacritics", async () => {
  const examples = [
    { text: "Firanse OTP rẹ bayii ki a le jẹri akọọlẹ banki rẹ", plain: "Firanse OTP re bayii ki a le jeri akọọlẹ banki re", language: "yo" as const },
    { text: "Aiko da lambar sirri ta OTP yanzu don tabbatar da asusun banki", plain: "Aiko da lambar sirri ta OTP yanzu don tabbatar da asusun banki", language: "ha" as const },
    { text: "Zipu OTP gị ugbu a iji nyochaa akaụntụ ụlọ akụ gị", plain: "Zipu OTP gi ugbu a iji nyochaa akaụntụ ụlọ akụ gi", language: "ig" as const }
  ];
  for (const example of examples) {
    const result = await scanText(example.text, { language: example.language });
    const plainResult = await scanText(example.plain, { language: example.language });
    assert.notEqual(result.verdict, "safe");
    assert.notEqual(plainResult.verdict, "safe");
    assert.equal(detectLanguage(example.plain), example.language);
  }
});

test("language detection recognizes accented and unaccented Tier 1 markers", () => {
  assert.equal(detectLanguage("Firanse PIN rẹ ni kiakia"), "yo");
  assert.equal(detectLanguage("Firanse PIN re ni kiakia"), "yo");
  assert.equal(detectLanguage("Tura lambar OTP yanzu"), "ha");
  assert.equal(detectLanguage("Biya kudin rajista yanzu"), "ha");
  assert.equal(detectLanguage("Zipu OTP gị ugbu a"), "ig");
  assert.equal(detectLanguage("Zipu OTP gi ugbu a"), "ig");
  assert.equal(detectLanguage("Ekwenyela nnata akwukwo gi, lelee ya na ngwa gọọmentị"), "ig");
  assert.equal(detectLanguage("An tabbatar da rajistar ka a manhajar hukuma"), "ha");
  assert.equal(detectLanguage("E ku oriire, ẹ wo alaye rẹ"), "yo");
  assert.equal(detectLanguage("Abeg send am now"), "pcm");
});

test("URL inspection flags unsafe structures without making network requests", async () => {
  assert.equal(analyzeUrl("https://example.ng/path#fragment").signals.length, 0);
  assert.ok(analyzeUrl("http://127.0.0.1/admin").signals.some((signal) => signal.code === "url_non_public_host"));
  assert.ok(analyzeUrl("https://trusted.example@attacker.example/login").signals.some((signal) => signal.code === "url_credentials"));
  assert.ok(analyzeUrl("https://xn--pple-43d.example").signals.some((signal) => signal.code === "url_punycode"));
  assert.ok(analyzeUrl("javascript:alert(1)").signals.some((signal) => signal.code === "url_invalid"));
  const scan = await scanText("Open http://127.0.0.1/login now");
  assert.notEqual(scan.verdict, "safe");
  assert.ok(scan.reasons.some((reason) => reason.code === "url_non_public_host"));
});

test("SMS, USSD and IVR simulators complete a real scan flow", async () => {
  const sms = await new SmsSimulator().receive({ from: "+2348000000000", text: "Send your OTP now" });
  assert.notEqual(sms.result.verdict, "safe");
  const ussd = new UssdSimulator();
  assert.match(await ussd.receive("2"), /^CON Enter suspicious message/);
  assert.match(await ussd.receive("Abeg send your PIN now"), /^END (LIKELY_SCAM|SCAM|CAUTION)/);
  const ivr = await new IvrSimulator().receive({ transcript: "Pay fee to receive this grant", language: "ha" });
  assert.equal(ivr.result.customer_message.language, "ha");
});

test("log scrubber removes sensitive values and protected field names", () => {
  const safe = JSON.stringify(scrubLog({ event: "request", bvn: "12345678901", detail: "Call +2348031234567", message: "untrusted content" }));
  assert.equal(safe.includes("12345678901"), false);
  assert.equal(safe.includes("+2348031234567"), false);
  assert.equal(safe.includes("untrusted content"), false);
});

test("community report storage blinds identifiers and encrypts review evidence", async () => {
  const calls: Array<{ sql: string; values?: unknown[] | undefined }> = [];
  const client = {
    async query(sql: string, values?: unknown[]) {
      calls.push({ sql, values });
      if (sql.includes("INSERT INTO entities")) return { rows: [{ id: "entity-id" }] };
      if (sql.includes("INSERT INTO reports")) return { rows: [{ id: "report-id" }] };
      return { rows: [] };
    },
    release() {}
  };
  const repository = new ScanRepository("", { connect: async () => client } as never);
  const id = await repository.reportIdentifier({ type: "phone", value: "08031234567", scamType: "bank_impersonation", reporter: "127.0.0.1", pepper: secret, keyring: ring, evidence: "Caller asked for OTP 123456" });
  assert.equal(id, "report-id");
  const entityInsert = calls.find((call) => call.sql.includes("INSERT INTO entities"))!;
  assert.equal(JSON.stringify(entityInsert.values).includes("+2348031234567"), false);
  const entityCipher = JSON.parse(String(calls.find((call) => call.sql.startsWith("UPDATE entities"))!.values?.[1])) as EncryptedField;
  assert.equal(decryptField(entityCipher, "community-entity:entity-id", ring), "+2348031234567");
  const reportInsert = calls.find((call) => call.sql.includes("INSERT INTO reports"))!;
  assert.equal(reportInsert.sql.includes("'pending'"), true);
  assert.equal(String(reportInsert.values?.[1]).includes("127.0.0.1"), false);
  const evidenceCipher = JSON.parse(String(reportInsert.values?.[3])) as EncryptedField;
  assert.equal(decryptField(evidenceCipher, "community-reports", ring), "Caller asked for OTP 123456");
});

test("only pending reports change reputation, with a hash-chained audit entry", async () => {
  const calls: Array<{ sql: string; values?: unknown[] | undefined }> = [];
  let reportStatus = "pending";
  const client = {
    async query(sql: string, values?: unknown[]) {
      calls.push({ sql, values });
      if (sql.startsWith("SELECT entity_id, status")) return { rows: [{ entity_id: "entity-id", status: reportStatus }] };
      if (sql.startsWith("SELECT entry_hash")) return { rows: [{ entry_hash: "a".repeat(64) }] };
      if (sql.startsWith("UPDATE reports")) reportStatus = "verified";
      return { rows: [] };
    },
    release() {}
  };
  const repository = new ScanRepository("", { connect: async () => client } as never);
  assert.equal(await repository.moderateReport("report-id", "verify"), true);
  assert.ok(calls.some((call) => call.sql.includes("INSERT INTO entity_reputation")));
  const audit = calls.find((call) => call.sql.includes("INSERT INTO audit_logs"))!;
  assert.equal(audit.values?.[0], "community_report_verify");
  assert.equal(audit.values?.[2], "a".repeat(64));
  calls.length = 0;
  assert.equal(await repository.moderateReport("report-id", "reject"), false);
  assert.equal(calls.some((call) => call.sql.includes("INSERT INTO entity_reputation")), false);
});

test("stored scan summary omits submitted identifiers and evidence", async () => {
  const result = await scanText("Send money to account 0123456789 at https://bit.ly/example");
  const stored = JSON.stringify(resultForStorage(result));
  assert.equal(stored.includes("0123456789"), false);
  assert.equal(stored.includes("bit.ly"), false);
  assert.equal(stored.includes("reasons"), false);
  assert.equal(stored.includes("entities"), false);
});

test("production environment rejects development keys and invalid ports", () => {
  assert.throws(() => loadEnv({ NODE_ENV: "production" }), /Missing required production configuration/);
  assert.throws(() => loadEnv({ NODE_ENV: "production", PORT: "3001", DATABASE_URL: "postgres://db", REDIS_URL: "redis://cache", OPENAI_API_KEY: "k", OPENAI_MODEL: "model", AUTH_SECRET: "a", FIELD_KEK: "development-only-key-change-me", BLIND_INDEX_PEPPER: "b", API_KEY_PEPPER: "c", COMMUNITY_MODERATION_TOKEN: "m".repeat(32) }), /Development KEK/);
  assert.throws(() => loadEnv({ NODE_ENV: "development", PORT: "70000" }), /PORT/);
  assert.equal(loadEnv({ NODE_ENV: "development", PORT: "3001" }).port, 3001);
});

test("scan API schema rejects malformed and unexpected input", () => {
  assert.equal(scanRequestSchema.safeParse({ text: "check this", language: "pcm", mode: "fast" }).success, true);
  assert.equal(scanRequestSchema.safeParse({ text: "x", language: "en" }).success, false);
  assert.equal(scanRequestSchema.safeParse({ text: "check this", language: "xx" }).success, false);
  assert.equal(scanRequestSchema.safeParse({ text: "check this", isAdmin: true }).success, false);
});

test("community report schemas require bounded identifiers and explicit moderation actions", () => {
  assert.equal(communityReportSchema.safeParse({ type: "phone", value: "08031234567", scamType: "bank_impersonation" }).success, true);
  assert.equal(communityReportSchema.safeParse({ type: "phone", value: "08031234567", scamType: "unsafe_sql", extra: true }).success, false);
  assert.equal(communityReportSchema.safeParse({ type: "url", value: "x", scamType: "other" }).success, false);
  assert.equal(moderateReportSchema.safeParse({ action: "verify" }).success, true);
  assert.equal(moderateReportSchema.safeParse({ action: "delete" }).success, false);
});

test("blind-index lookup normalization canonicalizes Nigerian identifiers without storing them", () => {
  assert.equal(normalizeIdentifier("phone", "0803 123 4567"), "+2348031234567");
  assert.equal(normalizeIdentifier("phone", "+2348031234567"), "+2348031234567");
  assert.equal(normalizeIdentifier("account", "044:0123456789"), "044:0123456789");
  assert.equal(normalizeIdentifier("url", "HTTPS://Example.com/path?a=private"), normalizeIdentifier("url", "example.com/path"));
  assert.throws(() => normalizeIdentifier("account", "0123456789"), /bank code/);
  assert.equal(lookupRequestSchema.safeParse({ type: "phone", value: "+2348031234567" }).success, true);
  assert.equal(lookupRequestSchema.safeParse({ type: "phone", value: "+2348031234567", tenantId: "other" }).success, false);
});

test("memory rate limiter enforces local scan limits", async () => {
  const limiter = new MemoryRateLimiter();
  assert.equal((await limiter.consume("test-address", 2, 60_000)).allowed, true);
  assert.equal((await limiter.consume("test-address", 2, 60_000)).allowed, true);
  const blocked = await limiter.consume("test-address", 2, 60_000);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterMs > 0);
  await limiter.close();
});

test("OpenAI provider retries a transient failure and validates structured output", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls === 1) return new Response("unavailable", { status: 503 });
    return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ scam: true, scam_types: ["bank_impersonation"], confidence: 0.9, reasons: ["Requests an OTP"] }) } }] }), { status: 200 });
  };
  try {
    const assessment = await new OpenAiProvider("test-key", "test-model", 1_000).assess("send OTP", {});
    assert.equal(calls, 2);
    assert.equal(assessment.scam, true);
    assert.equal(assessment.confidence, 0.9);
  } finally { globalThis.fetch = originalFetch; }
});

test("optional on-device history encrypts with WebCrypto and rejects wrong passphrases", async () => {
  const item = { scanId: "local-only", note: "never store in server" };
  const encrypted = await encryptHistory(item, "a-long-private-passphrase");
  assert.equal(JSON.stringify(encrypted).includes("local-only"), false);
  assert.deepEqual(await decryptHistory<typeof item>(encrypted, "a-long-private-passphrase"), item);
  await assert.rejects(decryptHistory(encrypted, "another-long-passphrase"));
  await assert.rejects(encryptHistory(item, "short"), /at least 12/);
});

test("WhatsApp webhook verification and simulator fail closed and use the common scanner", async () => {
  const raw = Buffer.from("{\"entry\":[]}");
  const signature = `sha256=${sign(raw, ring.secretPepper)}`;
  assert.equal(verifyMetaSignature(raw, signature, ring.secretPepper.toString()), true);
  assert.equal(verifyMetaSignature(Buffer.from("tampered"), signature, ring.secretPepper.toString()), false);
  assert.equal(verifyMetaChallenge("subscribe", "expected", "challenge", "expected"), "challenge");
  assert.equal(verifyMetaChallenge("subscribe", "wrong", "challenge", "expected"), null);
  const reply = await new WhatsAppSimulator().receive({ from: "opaque-sender", messageId: "message-1", text: "Send your OTP now", language: "en" });
  assert.notEqual(reply.result.verdict, "safe");
});
