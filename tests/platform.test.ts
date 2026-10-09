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
import { assessRequestSchema, authLoginSchema, authRegisterSchema, batchScanRequestSchema, linkPreviewRequestSchema, scanRequestSchema, voiceSpeakRequestSchema, webhookRequestSchema } from "../apps/api/src/validation.js";
import { MemoryAuthStore, hashPassword, normalizeEmail, verifyPassword } from "../apps/api/src/auth.js";
import { calculateUsageEstimate } from "../apps/api/src/billing.js";
import { canonicalPhone, domainOf, findOfficialChannel } from "../apps/api/src/directory.js";
import { MemoryReputationStore, identifierKey, intelligenceFromSummaries, labelFor } from "../apps/api/src/reputation.js";
import { CERTIFICATE_TTL_SECONDS, certificateCardHtml, issueCertificate, verifyCertificate } from "../apps/api/src/certificates.js";
import { MemoryIntegrationKeyStore } from "../apps/api/src/integration.js";
import { buildShieldContext, lookupIntelligence } from "../apps/api/src/context.js";
import { WaveWatch } from "../apps/api/src/waves.js";
import { SpeechProviderRegistry } from "../packages/channels/src/voice.js";

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
  await store.createSession({ userId: account.id, email: account.email, tokenHash: "other", expiresAt });
  const session = await store.findSession("tok");
  assert.ok(session);
  assert.equal(session.email, "ada@example.com");
  assert.equal(session.revokedAt, null);
  assert.equal((await store.listSessions(account.id, "tok")).find((item) => item.current)?.current, true);
  assert.deepEqual(await store.listSessions("another-user", "other"), []);
  assert.deepEqual(Object.keys((await store.listSessions(account.id, "tok"))[0]!).sort(), ["createdAt", "current", "expiresAt"]);
  await store.revokeOtherSessions(account.id, "tok");
  assert.ok((await store.findSession("other"))!.revokedAt);
  assert.equal((await store.findSession("tok"))!.revokedAt, null, "the current session remains authenticated");
  await store.revokeSession("tok");
  assert.ok((await store.findSession("tok"))!.revokedAt);
  assert.equal(await store.findSession("nope"), null);
});

test("billing estimates use published rates and ignore unknown meters", () => {
  assert.deepEqual(calculateUsageEstimate([{ metric: "scan", quantity: 3 }, { metric: "assess", quantity: 2 }, { metric: "unknown", quantity: 100 }]), {
    currency: "USD", period: "trailing_30_days", status: "estimate",
    lines: [
      { metric: "scan", quantity: 3, unit: "scan", unit_price_minor: 1, amount_minor: 3 },
      { metric: "assess", quantity: 2, unit: "assessment", unit_price_minor: 2, amount_minor: 4 }
    ], total_minor: 7
  });
});

test("official-channel directory normalises phones and domains and finds banks and telcos", () => {
  assert.equal(canonicalPhone("+234 802 900 0000"), "8029000000");
  assert.equal(canonicalPhone("08029000000"), "8029000000");
  assert.equal(domainOf("https://www.gtbank.com/login"), "gtbank.com");
  assert.equal(findOfficialChannel("+2348029000000", "phone").status, "verified");
  assert.equal(findOfficialChannel("08029000000", "phone").channel?.shortName, "GTBank");
  assert.equal(findOfficialChannel("07008250000", "phone").channel?.name, "First Bank of Nigeria");
  assert.equal(findOfficialChannel("https://secure.gtbank.com/app", "url").status, "verified");
  assert.equal(findOfficialChannel("https://fakebank.example/login", "url").status, "not_found");
  assert.equal(findOfficialChannel("", "url").status, "not_found");
});

test("reputation store tracks pending and verified reports with blind identifiers", async () => {
  const store = new MemoryReputationStore();
  const pepper = Buffer.from("test-pepper");
  assert.notEqual(identifierKey("phone", "08029000000"), identifierKey("phone", "08029000000", pepper));
  const first = await store.submit({ kind: "phone", value: "+234 802 900 0000", scamType: "bank_impersonation", source: "check" });
  assert.equal(first.status, "pending");
  assert.equal(first.label, "8029000000");
  const before = await store.summaryFor("phone", "08029000000");
  assert.ok(before);
  assert.equal(before.verified, 0);
  assert.equal(before.pending, 1);
  assert.equal(await store.decide(first.id, "verify"), true);
  assert.equal(await store.decide(first.id, "verify"), false);
  const after = await store.summaryFor("phone", "+2348029000000");
  assert.ok(after);
  assert.equal(after.verified, 1);
  assert.equal(after.pending, 0);
  assert.equal(await store.summaryFor("phone", "07000000000"), null);
  assert.equal(labelFor("account", "0123456789"), "•••• 6789");
});

test("intelligence favours verified reports and drives hard verdicts", () => {
  const base = { kind: "phone" as const, value: "x", reports: 4, verified: 0, pending: 4, firstSeen: "a", lastSeen: "b" };
  const unverified = intelligenceFromSummaries([base]);
  assert.ok(unverified);
  assert.equal(unverified.verified, false);
  assert.equal(unverified.reports, 4);
  const intelligence = intelligenceFromSummaries([{ ...base, reports: 5, verified: 2, pending: 3 }]);
  assert.ok(intelligence);
  assert.equal(intelligence.reports, 5);
  assert.equal(intelligence.verified, true);
});

test("buildShieldContext produces reputation and official-channel context", async () => {
  const store = new MemoryReputationStore(Buffer.from("pepper"));
  await store.submit({ kind: "phone", value: "08029000000", scamType: "bank_impersonation", source: "check" });
  const context = await buildShieldContext({ text: "Reply to 08029000000 urgently or call the bank on +2348029000000", inputs: [] }, store);
  assert.ok(context.official_channels.some((channel) => channel.status === "verified" && channel.shortName === "GTBank"));
  const reported = context.reputation.find((item) => item.value === "+2348029000000");
  assert.ok(reported);
  assert.equal(reported.verified + reported.pending, 1);
});

test("shield lookup hook feeds reputation intelligence into scans", async () => {
  const store = new MemoryReputationStore();
  await store.submit({ kind: "phone", value: "08029000000", scamType: "bank_impersonation", source: "check" });
  await store.decide((await store.pending())[0]!.id, "verify");
  const intelligence = await lookupIntelligence({ urls: [], phones: ["+2348029000000"], accounts: [], amounts: [], brands: [] }, store);
  assert.ok(intelligence);
  assert.equal(intelligence.verified, true);
});

test("certificates issue, verify, reject tampering, and expire safely", () => {
  const secret = Buffer.from("cert-secret");
  const issuedAt = Date.now() - 1_000;
  const token = issueCertificate({ scanId: "scan-1", verdict: "likely_scam", riskScore: 71, scamTypes: ["bank_impersonation"], message: "Send your OTP", issuer: "self", secret, now: new Date(issuedAt) });
  const payload = verifyCertificate(token, secret);
  assert.ok(payload);
  assert.equal(payload.verdict, "likely_scam");
  assert.equal(payload.issuer, "self");
  assert.equal(verifyCertificate(`${token}x`, secret), null);
  assert.equal(verifyCertificate(token.slice(0, 20), secret), null);
  assert.equal(verifyCertificate(token, secret, issuedAt + CERTIFICATE_TTL_SECONDS * 1000 + 1), null);
  assert.equal(verifyCertificate("not-a-token", secret), null);
  const card = certificateCardHtml(payload);
  assert.ok(card.includes("Likely scam"));
  assert.ok(card.includes("Send your OTP"));
  assert.ok(!card.includes("<script"));
});

test("integration key lifecycle: create, authenticate, scope-gate, and revoke", async () => {
  const store = new MemoryIntegrationKeyStore();
  const raw = "sk_live_testraw";
  const created = await store.create({ name: "core-banking", keyHash: raw, scopes: ["scans:write", "lookup:read"], createdBy: "ada@example.com" });
  assert.ok(created.id);
  const found = await store.findByHash(raw);
  assert.ok(found);
  assert.ok((found.scopes as string[]).includes("scans:write"));
  assert.equal(await store.findByHash("wrong-hash"), null);
  assert.equal(await store.revoke(created.id), true);
  assert.equal(await store.findByHash(raw), null);
});

test("link preview fetches bounded HTML, extracts meta, and refuses unsafe hosts", async () => {
  const { previewUrl } = await import("../apps/api/src/preview.js");
  const resolve = async (host: string): Promise<string[]> =>
    host === "evil.example" ? ["10.0.0.9"] : ["93.184.216.34"];
  const page = "<html><head><title>Claims page</title><meta name=\"description\" content=\"Click to claim\"></head><body>link</body></html>";
  const fetchImpl = (async () => new Response(page, { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
  const ok = await previewUrl("https://start.example/claim", { resolve, fetchImpl, maxBytes: 16_384 });
  assert.equal(ok.status, 200);
  assert.equal(ok.title, "Claims page");
  assert.equal(ok.description, "Click to claim");
  assert.equal(ok.content_type, "text/html");
  assert.equal(ok.truncated, false);
  assert.ok(Array.isArray(ok.signals));
  await assert.rejects(previewUrl("https://evil.example/", { resolve, fetchImpl }), /non-public/);
  const binary = await previewUrl("https://start.example/b", { resolve, fetchImpl: (async () => new Response("PNG", { status: 200, headers: { "content-type": "image/png" } })) as unknown as typeof fetch });
  assert.equal(binary.title, null);
});

test("wave detector fires once per cooldown on verified-report surges", () => {
  const marks: number[] = [];
  const watch = new WaveWatch({ now: () => marks.at(-1) ?? 0, windowMs: 30 * 60_000, threshold: 3, cooldownMs: 60_000, resolveMs: 60_000 });
  for (const t of [0, 10_000, 20_000]) {
    marks.push(t);
    const wave = watch.recordVerified("phone", "08029000000");
    if (t === 20_000) {
      assert.ok(wave);
      assert.equal(wave.kind, "phone");
      assert.equal(wave.count, 3);
      assert.equal(wave.status, "active");
    } else {
      assert.equal(wave, null);
    }
  }
  marks.push(50_000);
  assert.equal(watch.recordVerified("phone", "08029000000"), null, "repeat alert suppressed inside 60s cooldown");
  marks.push(90_000);
  const again = watch.recordVerified("phone", "08029000000");
  assert.ok(again, "a new surge after the cooldown fires again");
  assert.equal(again.id, watch.recent().at(-1)?.id ?? null, "same wave identity persists");
  const secondWaveAt = 90_000;
  marks.push(secondWaveAt + 59_000);
  assert.equal(watch.tick(secondWaveAt + 59_000).length, 0, "still active inside resolve window");
  marks.push(secondWaveAt + 61_000);
  const resolved = watch.tick(secondWaveAt + 61_000);
  assert.equal(resolved.length, 1, "one wave resolves after its resolve window");
  assert.equal(resolved[0]!.status, "resolved");
});

test("speech registry resolves preferred and auto providers", () => {
  const registry = new SpeechProviderRegistry().register("simulated", new SimulatedSpeechProvider());
  assert.deepEqual(registry.names(), ["simulated"]);
  assert.equal(registry.resolve("missing"), null);
  assert.equal(registry.resolve("simulated")?.name, "simulated");
  assert.equal(registry.resolve("auto")?.name, "simulated");
});

test("wave 2 validation schemas gate preview and batch payloads", () => {
  assert.equal(linkPreviewRequestSchema.safeParse({ url: "https://example.com/x" }).success, true);
  assert.equal(linkPreviewRequestSchema.safeParse({ url: "ftp://example.com" }).success, false);
  assert.equal(linkPreviewRequestSchema.safeParse({ url: "javascript:alert(1)" }).success, false);
  assert.equal(batchScanRequestSchema.safeParse({ items: [] }).success, false);
  assert.equal(batchScanRequestSchema.safeParse({ items: [{ text: "h" }] }).success, false);
  assert.equal(batchScanRequestSchema.safeParse({ items: [{ text: "check this link https://x.co/a now" }] }).success, true);
  assert.equal(batchScanRequestSchema.safeParse({ items: Array.from({ length: 26 }, () => ({ text: "hello world check now" })) }).success, false);
  const many = batchScanRequestSchema.safeParse({ items: Array.from({ length: 25 }, () => ({ text: "hello world check now" })) });
  assert.equal(many.success, true);
});
