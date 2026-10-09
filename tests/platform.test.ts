import test from "node:test";
import assert from "node:assert/strict";
import { normalizePolicy, resolveAction } from "../packages/risk-engine/src/policy.js";
import { assessTransaction } from "../packages/risk-engine/src/assess.js";
import { combineInputs, scanCombined } from "../packages/risk-engine/src/combined.js";
import { fetchUrlSafely, isPublicAddress } from "../packages/risk-engine/src/url-fetch.js";
import { sniffArtifactKind, validateArtifact } from "../apps/api/src/ingestion.js";
import { SimulatedSpeechProvider } from "../packages/channels/src/voice.js";
import { ReplayGuard, deliverWebhook, verifyWebhookSignature, webhookSignature } from "../packages/shared/src/webhooks.js";
import { ScanJobRegistry } from "../apps/api/src/jobs.js";
import type { ScanResult } from "../packages/risk-engine/src/types.js";
import { assessRequestSchema, authLoginSchema, authRegisterSchema, scanRequestSchema, voiceSpeakRequestSchema, webhookRequestSchema } from "../apps/api/src/validation.js";
import { MemoryAuthStore, hashPassword, normalizeEmail, verifyPassword } from "../apps/api/src/auth.js";

test("policy bands resolve actions and escalate novel or high-value transfers", () => {
  assert.equal(resolveAction(0), "allow");
  assert.equal(resolveAction(30), "warn");
  assert.equal(resolveAction(50), "delay");
  assert.equal(resolveAction(80), "block");
  assert.equal(resolveAction(0, { payeeNovel: true }), "delay");
  assert.equal(resolveAction(0, { amount: 2_000_000 }), "review");
  const custom = normalizePolicy({ bands: [{ minScore: 0, action: "allow" }], reviewAmount: 100 });
  assert.equal(resolveAction(0, { amount: 500 }, custom), "review");
  assert.throws(() => normalizePolicy({ bands: [{ minScore: 10, action: "warn" }, { minScore: 10, action: "block" }] }), /share/);
});

test("transaction assessment maps risky context to strong actions and lets benign ones through", async () => {
  const risky = await assessTransaction({ amount: 6_000_000, payeeNovel: true, accountAgeDays: 2, hourOfDay: 2, customerScans: 0, message: "Send your OTP now urgently", language: "en" });
  assert.equal(risky.action, "block");
  assert.ok(risky.risk_score >= 70);
  assert.ok(risky.reasons.some((reason) => reason.code === "new_account"));
  assert.equal(risky.customer_message.language, "en");
  const benign = await assessTransaction({ amount: 2_000, payeeNovel: false, language: "en" });
  assert.equal(benign.action, "allow");
  assert.equal(benign.risk_score, 0);
});

test("SSRF-safe fetcher blocks private hosts and re-checks every redirect hop", async () => {
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("10.0.0.1"), false);
  assert.equal(isPublicAddress("127.0.0.1"), false);
  assert.equal(isPublicAddress("169.254.1.1"), false);
  assert.equal(isPublicAddress("::1"), false);
  assert.equal(isPublicAddress("2001:4860:4860::8888"), true);
  const resolve = async (host: string): Promise<string[]> => host === "evil.example" ? ["10.0.0.5"] : ["93.184.216.34"];
  await assert.rejects(fetchUrlSafely("https://evil.example/", { resolve, fetchImpl: (async () => new Response("x")) as unknown as typeof fetch }), /non-public/);
  let calls = 0;
  const fetchImpl = (async (url: string | URL | Request) => {
    calls += 1;
    if (calls === 1) return new Response(null, { status: 302, headers: { location: "https://good.example/page" } });
    assert.match(String(url), /good\.example/);
    return new Response("<html>ok</html>", { status: 200, headers: { "content-type": "text/html" } });
  }) as unknown as typeof fetch;
  const result = await fetchUrlSafely("https://start.example/", { resolve, fetchImpl });
  assert.equal(result.status, 200);
  assert.equal(result.truncated, false);
  assert.match(result.body, /ok/);
  const oversized = await fetchUrlSafely("https://start.example/", { resolve, maxBytes: 8, fetchImpl: (async () => new Response("x".repeat(64))) as unknown as typeof fetch });
  assert.equal(oversized.truncated, true);
  assert.ok(oversized.bytes > 8);
});

test("artifact ingestion sniffs real content and rejects executables and oversized uploads", () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
  assert.equal(sniffArtifactKind(png), "image");
  assert.equal(validateArtifact({ bytes: png, declaredType: "image/png" }).kind, "image");
  assert.throws(() => validateArtifact({ bytes: png, declaredType: "image/svg+xml" }), /SVG/);
  assert.throws(() => validateArtifact({ bytes: png, expectedKind: "audio" }), /Expected/);
  assert.throws(() => validateArtifact({ bytes: png, maxBytes: 4 }), /between 1 byte/);
  assert.throws(() => validateArtifact({ bytes: new Uint8Array([1, 2, 3, 4]) }), /nrecognized/);
  assert.equal(sniffArtifactKind(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31])), "document");
});

test("speech provider transcript, synthesis and interface shape stay deterministic", async () => {
  const provider = new SimulatedSpeechProvider("send your otp now");
  assert.deepEqual(await provider.transcribe(Buffer.from("audio")), { text: "send your otp now" });
  const speech = await provider.speak("hello", "pcm");
  assert.equal(speech.mimeType, "audio/mpeg");
  assert.equal(speech.audio.toString(), "pcm:hello");
});

test("webhook signatures, replay protection and retry backoff fail closed", async () => {
  const secret = "a".repeat(40);
  const timestamp = Date.now();
  const signature = webhookSignature(secret, timestamp, "{\"a\":1}");
  assert.equal(verifyWebhookSignature(secret, timestamp, "{\"a\":1}", signature), true);
  assert.equal(verifyWebhookSignature(secret, timestamp, "{\"a\":2}", signature), false);
  assert.equal(verifyWebhookSignature(secret, timestamp - 10 * 60 * 1000, "{\"a\":1}", signature, { now: timestamp }), false);
  let now = 1_000;
  const guard = new ReplayGuard(100, () => now);
  assert.equal(guard.accept("x"), true);
  assert.equal(guard.accept("x"), false);
  now = 2_000;
  assert.equal(guard.accept("x"), true);
  let attempts = 0;
  const retried = await deliverWebhook({ url: "https://hook.example", secret, event: "scan.completed", payload: { ok: true } }, {
    sleep: async () => {}, deliver: async () => { attempts += 1; return { status: attempts < 3 ? 500 : 200 }; }
  });
  assert.equal(retried.delivered, true);
  assert.equal(retried.attempts, 3);
  const rejected = await deliverWebhook({ url: "https://hook.example", secret, event: "scan.completed", payload: {} }, { sleep: async () => {}, deliver: async () => ({ status: 400 }) });
  assert.equal(rejected.delivered, false);
  assert.equal(rejected.attempts, 1);
});

test("combined inputs merge into one verdict and carry their input types", async () => {
  assert.deepEqual(combineInputs([{ type: "text", text: "urgent" }, { type: "url", value: "https://bit.ly/x" }, { type: "account", bank: "044", number: "0123456789" }]).types, ["text", "url", "account"]);
  assert.throws(() => combineInputs([]), /at least one/);
  const result = await scanCombined([{ type: "text", text: "Send your OTP now" }, { type: "qr", payload: "https://bit.ly/claim" }]);
  assert.notEqual(result.verdict, "safe");
  assert.deepEqual(result.input_types, ["text", "qr"]);
});

test("scan job registry replays stages and reports completion for streaming", () => {
  const jobs = new ScanJobRegistry();
  jobs.create("job-1");
  const seen: string[] = [];
  jobs.subscribe("job-1", (entry) => seen.push(entry.stage));
  jobs.publish("job-1", { stage: "fast", result: {} as ScanResult });
  jobs.complete("job-1");
  assert.deepEqual(seen, ["fast", "final"]);
  assert.equal(jobs.isDone("job-1"), true);
  assert.equal(jobs.subscribe("missing", () => {}), undefined);
});

test("new request schemas validate B2B, combined, webhook and voice payloads", () => {
  assert.equal(assessRequestSchema.safeParse({ amount: 1_000, payeeNovel: true, language: "en" }).success, true);
  assert.equal(assessRequestSchema.safeParse({ amount: -5 }).success, false);
  assert.equal(assessRequestSchema.safeParse({ nope: 1 }).success, false);
  assert.equal(scanRequestSchema.safeParse({ inputs: [{ type: "phone", value: "08031234567" }] }).success, true);
  assert.equal(scanRequestSchema.safeParse({}).success, false);
  assert.equal(scanRequestSchema.safeParse({ text: "check this", language: "pcm", mode: "fast" }).success, true);
  assert.equal(webhookRequestSchema.safeParse({ url: "http://hook.example", events: ["scan.completed"] }).success, false);
  assert.equal(webhookRequestSchema.safeParse({ url: "https://hook.example/x", events: ["scan.completed"] }).success, true);
  assert.equal(voiceSpeakRequestSchema.safeParse({ text: "hi", language: "yo" }).success, true);
});

test("password hashing round-trips and rejects wrong passwords", async () => {
  const hash = await hashPassword("a very long password here");
  assert.notEqual(hash, "a very long password here");
  assert.equal(hash.startsWith("scrypt$"), true);
  assert.equal(await verifyPassword("a very long password here", hash), true);
  assert.equal(await verifyPassword("wrong password", hash), false);
  assert.equal(await verifyPassword("any", "not-a-hash"), false);
});

test("auth identifiers normalise and registration schemas enforce rules", () => {
  assert.equal(normalizeEmail("  Ada@Example.COM "), "ada@example.com");
  assert.equal(authRegisterSchema.safeParse({ email: "ada@example.com", password: "longenough123" }).success, true);
  assert.equal(authRegisterSchema.safeParse({ email: "ada@example.com", password: "short" }).success, false);
  assert.equal(authRegisterSchema.safeParse({ email: "not-an-email", password: "longenough123" }).success, false);
  assert.equal(authLoginSchema.safeParse({ email: "ada@example.com", password: "anything" }).success, true);
  assert.equal(authLoginSchema.safeParse({}).success, false);
});

test("in-memory auth store handles sign-up, session lookup, and sign-out", async () => {
  const store = new MemoryAuthStore();
  const account = await store.createAccount("ada@example.com", "hash");
  assert.ok(account);
  assert.equal(await store.createAccount("ada@example.com", "hash"), null);
  const found = await store.findAccount("ada@example.com");
  assert.ok(found);
  assert.equal(found.passwordHash, "hash");
  const expiresAt = new Date(Date.now() + 60_000);
  await store.createSession({ userId: account.id, email: account.email, tokenHash: "tok", expiresAt });
  const session = await store.findSession("tok");
  assert.ok(session);
  assert.equal(session.email, "ada@example.com");
  assert.equal(session.revokedAt, null);
  await store.revokeSession("tok");
  assert.ok((await store.findSession("tok"))!.revokedAt);
  assert.equal(await store.findSession("nope"), null);
});
