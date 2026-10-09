import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadEnv } from "./env.js";
import { OpenAiProvider } from "./provider.js";
import { scanText } from "../../../packages/risk-engine/src/scan.js";
import { combineInputs, type ScanInput } from "../../../packages/risk-engine/src/combined.js";
import { assessTransaction } from "../../../packages/risk-engine/src/assess.js";
import { normalizePolicy } from "../../../packages/risk-engine/src/policy.js";
import type { Language, ScanResult } from "../../../packages/risk-engine/src/types.js";
import { logEvent } from "../../../packages/shared/src/safe-log.js";
import { generateOpaqueToken, hashSecret, keyringFromEnv, verifySecret } from "../../../packages/shared/src/crypto.js";
import { deliverWebhook } from "../../../packages/shared/src/webhooks.js";
import { SimulatedSpeechProvider, OpenAiSpeechProvider, type SpeechProvider } from "../../../packages/channels/src/voice.js";
import { ScanRepository } from "./repository.js";
import { ScanJobRegistry } from "./jobs.js";
import { redactSensitive } from "../../../packages/shared/src/redaction.js";
import { assessRequestSchema, authLoginSchema, authRegisterSchema, certificateRequestSchema, communityReportSchema, decideReportSchema, integrationKeySchema, lookupRequestSchema, moderateReportSchema, reputationReportSchema, scanRequestSchema, verifyChannelSchema, voiceSpeakRequestSchema, webhookRequestSchema } from "./validation.js";
import { MemoryAuthStore, PgAuthStore, hashPassword, normalizeEmail, verifyPassword, type AuthStore } from "./auth.js";
import { MemoryRateLimiter, RedisRateLimiter, type RateLimiter } from "./rate-limit.js";
import { findOfficialChannel } from "./directory.js";
import { MemoryReputationStore, PgReputationStore, type ReputationStore } from "./reputation.js";
import { MemoryIntegrationKeyStore, PgIntegrationKeyStore, type IntegrationKeyStore, type IntegrationScope } from "./integration.js";
import { issueCertificate, verifyCertificate, certificateCardHtml, CERTIFICATE_TTL_SECONDS } from "./certificates.js";
import { buildShieldContext, lookupIntelligence } from "./context.js";

const env = loadEnv();
const provider = new OpenAiProvider(env.openAiKey, env.openAiModel);
const repository = env.databaseUrl ? new ScanRepository(env.databaseUrl) : undefined;
const authStore: AuthStore = env.databaseUrl ? new PgAuthStore(env.databaseUrl) : new MemoryAuthStore();
const reputationStore: ReputationStore = env.databaseUrl
  ? new PgReputationStore(env.databaseUrl, env.blindPepper ? Buffer.from(env.blindPepper) : undefined)
  : new MemoryReputationStore(env.blindPepper ? Buffer.from(env.blindPepper) : undefined);
const integrationKeyStore: IntegrationKeyStore = env.databaseUrl ? new PgIntegrationKeyStore(env.databaseUrl) : new MemoryIntegrationKeyStore();
const authSecret = Buffer.from(env.authSecret ?? "development-only-auth-secret-change-me");
const SESSION_COOKIE = "shield_session";
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const limit = 64 * 1024;
const webRoot = resolve(process.cwd(), "apps/web/public");
const staticFiles: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", type: "text/html; charset=utf-8" },
  "/landing.js": { file: "landing.js", type: "text/javascript; charset=utf-8" },
  "/auth": { file: "auth.html", type: "text/html; charset=utf-8" },
  "/auth.html": { file: "auth.html", type: "text/html; charset=utf-8" },
  "/auth.js": { file: "auth.js", type: "text/javascript; charset=utf-8" },
  "/recovery": { file: "recovery.html", type: "text/html; charset=utf-8" },
  "/recovery.html": { file: "recovery.html", type: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/qr.js": { file: "qr.js", type: "text/javascript; charset=utf-8" },
  "/snippet.js": { file: "snippet.js", type: "text/javascript; charset=utf-8" },
  "/recovery.js": { file: "recovery.js", type: "text/javascript; charset=utf-8" },
  "/data/recovery.json": { file: "data/recovery.json", type: "application/json; charset=utf-8" },
  "/docs": { file: "docs.html", type: "text/html; charset=utf-8" },
  "/docs.html": { file: "docs.html", type: "text/html; charset=utf-8" },
  "/docs.js": { file: "docs.js", type: "text/javascript; charset=utf-8" },
  "/openapi.yaml": { file: "../../../docs/openapi.yaml", type: "application/yaml; charset=utf-8" },
  "/integrations": { file: "integrations.html", type: "text/html; charset=utf-8" },
  "/integrations.html": { file: "integrations.html", type: "text/html; charset=utf-8" },
  "/integrations.js": { file: "integrations.js", type: "text/javascript; charset=utf-8" },
  "/sw.js": { file: "sw.js", type: "text/javascript; charset=utf-8" },
  "/manifest.webmanifest": { file: "manifest.webmanifest", type: "application/manifest+json; charset=utf-8" },
  "/icon.svg": { file: "icon.svg", type: "image/svg+xml" }
};
const rateLimiter: RateLimiter = env.redisUrl && env.apiKeyPepper
  ? new RedisRateLimiter(env.redisUrl, Buffer.from(env.apiKeyPepper))
  : new MemoryRateLimiter();
const scanJobs = new ScanJobRegistry();
const speechProvider: SpeechProvider = env.openAiKey && env.openAiTranscribeModel && env.openAiTtsModel
  ? new OpenAiSpeechProvider(env.openAiKey, env.openAiTranscribeModel, env.openAiTtsModel)
  : new SimulatedSpeechProvider();
const speechConfigured = Boolean(env.openAiKey && env.openAiTranscribeModel && env.openAiTtsModel);

function problem(res: ServerResponse, status: number, title: string, detail: string): void {
  res.writeHead(status, { "content-type": "application/problem+json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify({ type: "about:blank", title, status, detail }));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += part.length;
    if (size > limit) throw new Error("request_too_large");
    chunks.push(part);
  }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_json");
  return value as Record<string, unknown>;
}

const server = createServer(async (req, res) => {
  const requestId = randomUUID();
  const startedAt = performance.now();
  res.setHeader("x-request-id", requestId);
  res.once("finish", () => logEvent("request_finished", { requestId, method: req.method, status: res.statusCode, duration_ms: Math.round(performance.now() - startedAt) }));
  const path = new URL(req.url ?? "/", "http://localhost").pathname;
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("x-frame-options", "DENY");
  res.setHeader("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  if (req.method === "GET" && (path === "/app" || path === "/app.html" || path === "/integrations" || path === "/integrations.html")) {
    const session = await currentSession(req);
    if (!session) { res.writeHead(302, { location: "/auth", "cache-control": "no-store" }); res.end(); return; }
    const guardedFile = path.startsWith("/integrations") ? "integrations.html" : "app.html";
    try {
      const contents = await readFile(resolve(webRoot, guardedFile));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(contents);
    } catch {
      problem(res, 503, "App unavailable", "The web application assets are unavailable.");
    }
    return;
  }
  if (req.method === "GET" && staticFiles[path]) {
    try {
      const asset = staticFiles[path]!;
      const contents = await readFile(resolve(webRoot, asset.file));
      res.writeHead(200, { "content-type": asset.type, "cache-control": path === "/" ? "no-cache" : "public, max-age=3600" });
      res.end(contents);
    } catch {
      problem(res, 503, "App unavailable", "The web application assets are unavailable.");
    }
    return;
  }
  if (req.method === "GET" && path === "/healthz") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ status: "ok" })); return; }
  if (req.method === "GET" && path === "/readyz") {
    const databaseReady = repository ? await repository.ready() : false;
    const ready = env.nodeEnv !== "production" || databaseReady;
    res.writeHead(ready ? 200 : 503, { "content-type": "application/json" });
    const communityReports = await reputationStore.ready();
    res.end(JSON.stringify({ ready, persistence: databaseReady ? "postgres" : "unavailable", rate_limit: rateLimiter instanceof RedisRateLimiter ? "redis" : "process_local", scan_mode: env.openAiKey && env.openAiModel ? "rules+openai" : "rules-only", community_reports: communityReports }));
    return;
  }
  if (req.method === "POST" && (path === "/v1/auth/register" || path === "/v1/auth/login")) {
    try {
      const address = req.socket.remoteAddress ?? "unknown";
      let rate;
      try { rate = await rateLimiter.consume(`${address}:auth`, 30, 60_000); }
      catch { problem(res, 503, "Authentication unavailable", "Sign in is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const isRegister = path === "/v1/auth/register";
      const validated = (isRegister ? authRegisterSchema : authLoginSchema).safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid credentials", isRegister ? "Enter a valid email and a password of at least 8 characters." : "Enter your email and password."); return; }
      const email = normalizeEmail(validated.data.email);
      const password = validated.data.password;
      let account;
      if (isRegister) {
        const created = await authStore.createAccount(email, await hashPassword(password));
        if (!created) { problem(res, 409, "Account exists", "An account with this email already exists. Try signing in instead."); return; }
        account = created;
      } else {
        const record = await authStore.findAccount(email);
        const valid = record ? await verifyPassword(password, record.passwordHash) : false;
        if (!record || !valid) { problem(res, 401, "Incorrect credentials", "The email or password is incorrect."); return; }
        account = record.account;
      }
      const token = generateOpaqueToken(32);
      await authStore.createSession({ userId: account.id, email: account.email, tokenHash: hashSecret(token, authSecret), expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000) });
      res.writeHead(isRegister ? 201 : 200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "set-cookie": sessionCookie(token) });
      res.end(JSON.stringify({ user: { email: account.email } }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "auth_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 503, "Authentication unavailable", "Sign in could not be completed. Please retry shortly.");
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/auth/logout") {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (token) { try { await authStore.revokeSession(hashSecret(token, authSecret)); } catch { /* best effort */ } }
    res.writeHead(204, { "cache-control": "no-store", "set-cookie": clearedSessionCookie() });
    res.end();
    return;
  }
  if (req.method === "GET" && path === "/v1/auth/me") {
    const session = await currentSession(req);
    if (!session) { problem(res, 401, "Unauthorized", "Sign in to continue."); return; }
    res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify({ user: { email: session.email } }));
    return;
  }
  if (req.method === "POST" && path === "/v1/reputation/reports") {
    try {
      if (!await requireSession(req, res)) return;
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      let rate;
      try { rate = await rateLimiter.consume(`${req.socket.remoteAddress ?? "unknown"}:reputation-report`, 3, 3_600_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Report submission is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const validated = reputationReportSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid report", "Provide an identifier type, value, and scam category."); return; }
      const data = validated.data;
      const created = await reputationStore.submit({ kind: data.type, value: data.value, scamType: data.scamType, source: req.socket.remoteAddress ?? "unknown" });
      res.writeHead(202, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ report_id: created.id, status: created.status, identifier: created.label }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "report_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid report", "The request body must be a JSON object."); return; }
      problem(res, 503, "Report unavailable", "The report could not be stored safely. Please retry shortly.");
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/reputation/lookup") {
    try {
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      let rate;
      try { rate = await rateLimiter.consume(req.socket.remoteAddress ?? "unknown", 30, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Lookup is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const validated = lookupRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide an identifier type and value in the JSON body."); return; }
      const summary = await reputationStore.summaryFor(validated.data.type, validated.data.value);
      if (!summary || summary.reports === 0) { problem(res, 404, "No reputation found", "No community reputation is available for this identifier."); return; }
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ ...summary }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "lookup_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid lookup", "The request body must be a JSON object."); return; }
      problem(res, 503, "Lookup unavailable", "Reputation could not be read safely.");
    }
    return;
  }
  const decideReportMatch = /^\/v1\/reputation\/reports\/([0-9a-f-]{36})\/decide$/i.exec(path);
  if (req.method === "POST" && decideReportMatch) {
    if (!await permitModeration(req, res)) return;
    if (!isCommunityModerator(req)) { problem(res, 401, "Unauthorized", "Moderator credentials are invalid or not configured."); return; }
    try {
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = decideReportSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid moderation action", "Choose verify or reject."); return; }
      const changed = await reputationStore.decide(decideReportMatch[1]!, validated.data.action);
      if (!changed) { problem(res, 409, "Report is no longer pending", "Only pending reports can be moderated."); return; }
      res.writeHead(204, { "cache-control": "no-store" });
      res.end();
    } catch (error) {
      const message = error instanceof Error ? error.message : "moderation_failed";
      if (message === "invalid_json") { problem(res, 400, "Invalid moderation action", "The request body must be a JSON object."); return; }
      problem(res, 503, "Moderation unavailable", "The report could not be updated safely.");
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/certificates") {
    try {
      if (!await requireSession(req, res)) return;
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = certificateRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid certificate request", "Provide a verdict, risk score, and the checked message."); return; }
      const data = validated.data;
      const token = issueCertificate({
        scanId: randomUUID(),
        verdict: data.verdict,
        riskScore: data.risk_score,
        scamTypes: data.scam_types ?? [],
        message: data.message,
        issuer: "Shield",
        secret: authSecret,
        ...(data.note ? { note: data.note } : {})
      });
      const verifiedUntil = new Date(Date.now() + CERTIFICATE_TTL_SECONDS * 1000).toISOString();
      res.writeHead(201, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ certificate_id: verifyCertificate(token, authSecret)?.certificate_id, card_url: `/c/${token}`, verify_url: `/v1/certificates/${token}`, verified_until: verifiedUntil }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "certificate_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid certificate request", "The request body must be a JSON object."); return; }
      problem(res, 503, "Certificate unavailable", "The check card could not be issued.");
    }
    return;
  }
  const certificateVerifyMatch = /^\/v1\/certificates\/(.+)$/.exec(path);
  if (req.method === "GET" && certificateVerifyMatch) {
    const payload = verifyCertificate(certificateVerifyMatch[1]!, authSecret);
    if (!payload) { problem(res, 400, "Certificate invalid", "This check card could not be verified or has expired."); return; }
    res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify({ valid: true, certificate: payload }));
    return;
  }
  const certificateCardMatch = /^\/c\/(.+)$/.exec(path);
  if (req.method === "GET" && certificateCardMatch) {
    const payload = verifyCertificate(certificateCardMatch[1]!, authSecret);
    res.setHeader("content-security-policy", "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader("cache-control", "no-store");
    if (!payload) {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><html><head><meta charset='utf-8'><title>Shield check</title><style>body{font-family:system-ui;background:#eef3e6;display:grid;place-items:center;min-height:100vh;margin:0;color:#18362d}a{color:#1f6d43}</style></head><body><main style='background:#fff;padding:34px;border-radius:18px;max-width:420px;text-align:center'><h1>Check card not available</h1><p>This card's signature is invalid or it has expired. Ask the sender to issue a fresh check from the Shield app.</p></main></body></html>");
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(certificateCardHtml(payload));
    return;
  }
  if (req.method === "POST" && path === "/v1/integration/keys") {
    try {
      if (!await requireSession(req, res)) return;
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = integrationKeySchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid key request", "Provide a key name and at least one scope."); return; }
      const session = await currentSession(req);
      const raw = generateOpaqueToken(32);
      const created = await integrationKeyStore.create({ name: validated.data.name, keyHash: hashSecret(raw, authSecret), scopes: validated.data.scopes, createdBy: session?.email ?? "unknown" });
      res.writeHead(201, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ id: created.id, name: created.name, scopes: created.scopes, key: raw, created_at: created.createdAt, note: "Store this key now. It is shown only once." }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "key_failed";
      if (message === "invalid_json") { problem(res, 400, "Invalid key request", "The request body must be a JSON object."); return; }
      problem(res, 503, "Key unavailable", "The integration key could not be created.");
    }
    return;
  }
  if (req.method === "GET" && path === "/v1/integration/keys") {
    try {
      if (!await requireSession(req, res)) return;
      const keys = await integrationKeyStore.list();
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ keys: keys.map((key) => ({ id: key.id, name: key.name, scopes: key.scopes, created_at: key.createdAt, revoked_at: key.revokedAt, key_preview: `${key.keyHash.slice(0, 8)}…${key.keyHash.slice(-4)}` })) }));
    } catch {
      problem(res, 503, "Key unavailable", "Integration keys could not be listed.");
    }
    return;
  }
  const integrationKeyDelete = /^\/v1\/integration\/keys\/([0-9a-f-]{36})$/i.exec(path);
  if (req.method === "DELETE" && integrationKeyDelete) {
    try {
      if (!await requireSession(req, res)) return;
      const removed = await integrationKeyStore.revoke(integrationKeyDelete[1]!);
      if (!removed) { problem(res, 404, "Key not found", "No active key with that id."); return; }
      res.writeHead(204, { "cache-control": "no-store" });
      res.end();
    } catch { problem(res, 503, "Key unavailable", "The integration key could not be revoked."); }
    return;
  }
  if (req.method === "POST" && path === "/v1/integrations/scan") {
    try {
      const auth = await resolveIntegration(req, "scans:write");
      if (auth.status !== "ok") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
      let rate;
      try { rate = await rateLimiter.consume(`${auth.tenantId}:integrations`, 40, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Scanning is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = scanRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide text or combined inputs and an optional Tier 1 language."); return; }
      const scanInput = validated.data;
      const combined = scanInput.inputs ? combineInputs(scanInput.inputs as ScanInput[]) : null;
      const sourceText = scanInput.text ?? combined!.text;
      const result = await scanText(sourceText, {
        scanId: randomUUID(),
        ...(scanInput.language ? { language: scanInput.language as Language } : {}),
        lookup: async (entities) => lookupIntelligence(entities, reputationStore)
      });
      const shield = await buildShieldContext({ text: sourceText, inputs: scanInput.inputs }, reputationStore);
      const response = combined ? { ...result, input_types: combined.types } : result;
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ ...response, shield }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 400, "Scan failed", message === "Text must contain 2 to 20,000 characters" ? message : "The scan could not be completed.");
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/integrations/verify-channel") {
    try {
      const auth = await resolveIntegration(req, "directory:read");
      if (auth.status !== "ok") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = verifyChannelSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide a phone or URL to verify."); return; }
      const found = findOfficialChannel(validated.data.value, validated.data.type);
      const summary = await reputationStore.summaryFor(validated.data.type, validated.data.value);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ value: validated.data.value, official: found.status, channel: found.channel, reputation: summary && summary.reports > 0 ? summary : null }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 503, "Verification unavailable", "The official-channel check could not be completed.");
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/integrations/lookup") {
    try {
      const auth = await resolveIntegration(req, "lookup:read");
      if (auth.status !== "ok") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = lookupRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide an identifier type and value."); return; }
      const summary = await reputationStore.summaryFor(validated.data.type, validated.data.value);
      if (!summary || summary.reports === 0) { problem(res, 404, "No reputation found", "No community reputation is available for this identifier."); return; }
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ ...summary }));
    } catch {
      problem(res, 503, "Lookup unavailable", "Reputation could not be read safely.");
    }
    return;
  }
  const integrationCertificateMatch = /^\/v1\/integrations\/certificates\/(.+)$/.exec(path);
  if (req.method === "GET" && integrationCertificateMatch) {
    const auth = await resolveIntegration(req, "certificates:read");
    if (auth.status !== "ok") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
    const payload = verifyCertificate(integrationCertificateMatch[1]!, authSecret);
    if (!payload) { problem(res, 400, "Certificate invalid", "This check card could not be verified or has expired."); return; }
    res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify({ valid: true, certificate: payload }));
    return;
  }
  if (req.method === "POST" && path === "/v1/lookup") {
    try {
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      let rate;
      try { rate = await rateLimiter.consume(req.socket.remoteAddress ?? "unknown", 20, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Lookup is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const body = await readJson(req);
      const validated = lookupRequestSchema.safeParse(body);
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide an identifier type and value in the JSON body."); return; }
      if (!repository || !env.blindPepper) { problem(res, 503, "Lookup unavailable", "Identifier reputation is not configured on this service."); return; }
      const reputation = await repository.lookup(validated.data.type, validated.data.value, Buffer.from(env.blindPepper));
      if (!reputation) { problem(res, 404, "No reputation found", "No community reputation is available for this identifier."); return; }
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ type: validated.data.type, ...reputation }));
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Lookup could not be completed.";
      const status = detail.startsWith("Enter ") ? 400 : 503;
      problem(res, status, status === 400 ? "Invalid identifier" : "Lookup unavailable", detail);
    }
    return;
  }
  if (req.method === "POST" && path === "/v1/reports") {
    try {
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      let rate;
      try { rate = await rateLimiter.consume(`${req.socket.remoteAddress ?? "unknown"}:community-report`, 3, 3_600_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Report submission is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const payload = await readJson(req);
      const validated = communityReportSchema.safeParse(payload);
      if (!validated.success) { problem(res, 400, "Invalid report", "Provide an identifier, scam category, and optional short evidence note."); return; }
      if (!repository || !env.blindPepper) { problem(res, 503, "Reports unavailable", "Community reports are not configured on this service."); return; }
      let keyring;
      try { keyring = keyringFromEnv(); }
      catch { problem(res, 503, "Reports unavailable", "Encrypted report storage is not configured on this service."); return; }
      const data = validated.data;
      const id = await repository.reportIdentifier({
        type: data.type, value: data.value, scamType: data.scamType,
        reporter: req.socket.remoteAddress ?? "unknown", pepper: Buffer.from(env.blindPepper), keyring,
        ...(data.evidence ? { evidence: data.evidence } : {})
      });
      res.writeHead(202, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ report_id: id, status: "pending" }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "report_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid report", "The request body must be a JSON object."); return; }
      if (message.startsWith("Enter ")) { problem(res, 400, "Invalid identifier", message); return; }
      problem(res, 503, "Report unavailable", "The report could not be safely stored. Please retry shortly.");
    }
    return;
  }
  if (req.method === "GET" && path === "/v1/admin/community/reports") {
    if (!await permitModeration(req, res)) return;
    if (!isCommunityModerator(req)) { problem(res, 401, "Unauthorized", "Moderator credentials are invalid or not configured."); return; }
    if (!repository) { problem(res, 503, "Moderation unavailable", "Community report storage is unavailable."); return; }
    try {
      const keyring = keyringFromEnv();
      const reports = await repository.listPendingReports(keyring);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ reports }));
    } catch {
      problem(res, 503, "Moderation unavailable", "Encrypted reports could not be read safely.");
    }
    return;
  }
  const moderationMatch = /^\/v1\/admin\/community\/reports\/([0-9a-f-]{36})$/i.exec(path);
  if (req.method === "POST" && moderationMatch) {
    if (!await permitModeration(req, res)) return;
    if (!isCommunityModerator(req)) { problem(res, 401, "Unauthorized", "Moderator credentials are invalid or not configured."); return; }
    if (!repository) { problem(res, 503, "Moderation unavailable", "Community report storage is unavailable."); return; }
    try {
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const payload = await readJson(req);
      const validated = moderateReportSchema.safeParse(payload);
      if (!validated.success) { problem(res, 400, "Invalid moderation action", "Choose verify or reject."); return; }
      const changed = await repository.moderateReport(moderationMatch[1]!, validated.data.action);
      if (!changed) { problem(res, 409, "Report is no longer pending", "Only pending reports can be moderated."); return; }
      res.writeHead(204, { "cache-control": "no-store" });
      res.end();
    } catch { problem(res, 503, "Moderation unavailable", "The report could not be updated safely."); }
    return;
  }
  if (req.method === "POST" && path === "/v1/assess") {
    try {
      const address = req.socket.remoteAddress ?? "unknown";
      let rate;
      try { rate = await rateLimiter.consume(`${address}:assess`, 60, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Assessment is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const auth = await resolveTenant(req, "assess:write");
      if (auth.status === "error") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
      if (auth.status === "anonymous" && repository) { problem(res, 401, "Unauthorized", "A tenant API key is required for transaction assessment."); return; }
      if (!repository && env.nodeEnv === "production") { problem(res, 503, "Assessment unavailable", "Transaction assessment requires persistence in production."); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = assessRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide valid transaction context fields."); return; }
      const data = validated.data;
      let resolvedPolicy;
      if (data.policy) { try { resolvedPolicy = normalizePolicy(data.policy); } catch { problem(res, 400, "Invalid policy", "Policy bands must be unique and within 0 to 100."); return; } }
      const assessment = await assessTransaction({
        ...(data.amount !== undefined ? { amount: data.amount } : {}),
        ...(data.currency !== undefined ? { currency: data.currency } : {}),
        ...(data.beneficiary !== undefined ? { beneficiary: data.beneficiary } : {}),
        ...(data.beneficiaryAccount !== undefined ? { beneficiaryAccount: data.beneficiaryAccount } : {}),
        ...(data.accountAgeDays !== undefined ? { accountAgeDays: data.accountAgeDays } : {}),
        ...(data.payeeNovel !== undefined ? { payeeNovel: data.payeeNovel } : {}),
        ...(data.channel !== undefined ? { channel: data.channel } : {}),
        ...(data.hourOfDay !== undefined ? { hourOfDay: data.hourOfDay } : {}),
        ...(data.customerScans !== undefined ? { customerScans: data.customerScans } : {}),
        ...(data.message !== undefined ? { message: data.message } : {}),
        ...(data.language !== undefined ? { language: data.language } : {})
      }, resolvedPolicy ? { policy: resolvedPolicy } : {});
      if (auth.status === "ok" && repository) { try { await repository.recordUsage(auth.tenantId, "assess"); } catch { logEvent("usage_record_failed", { metric: "assess" }); } }
      void dispatchWebhookEvent(auth.status === "ok" ? auth.tenantId : null, "assess.completed", assessment);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify(assessment));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 400, "Assessment failed", "The transaction could not be assessed.");
    }
    return;
  }
  if (req.method === "GET" && path === "/v1/usage") {
    const auth = await resolveTenant(req, "usage:read");
    if (auth.status !== "ok") { problem(res, 401, "Unauthorized", "A tenant API key with usage:read scope is required."); return; }
    if (!repository) { problem(res, 503, "Usage unavailable", "Usage metering is not configured on this service."); return; }
    try {
      const usage = await repository.usageSummary(auth.tenantId);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ tenant_id: auth.tenantId, usage, quota: { plan: "free", monthly_scans: 1000 } }));
    } catch { problem(res, 503, "Usage unavailable", "Usage could not be read safely."); }
    return;
  }
  if (path === "/v1/webhooks" && (req.method === "GET" || req.method === "POST")) {
    const auth = await resolveTenant(req, req.method === "POST" ? "webhooks:write" : "webhooks:read");
    if (auth.status !== "ok") { problem(res, 401, "Unauthorized", "A tenant API key with webhook permission is required."); return; }
    if (!repository) { problem(res, 503, "Webhooks unavailable", "Webhooks are not configured on this service."); return; }
    try {
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify({ webhooks: await repository.listWebhooks(auth.tenantId) }));
        return;
      }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = webhookRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid webhook", "Provide an HTTPS URL and at least one event type."); return; }
      const keyring = keyringFromEnv();
      const secret = generateOpaqueToken(32);
      const id = await repository.createWebhook(auth.tenantId, validated.data.url, validated.data.events, secret, keyring);
      res.writeHead(201, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ id, secret, events: validated.data.events }));
    } catch { problem(res, 503, "Webhooks unavailable", "The webhook could not be managed safely."); }
    return;
  }
  const webhookDelete = /^\/v1\/webhooks\/([0-9a-f-]{36})$/i.exec(path);
  if (req.method === "DELETE" && webhookDelete) {
    const auth = await resolveTenant(req, "webhooks:write");
    if (auth.status !== "ok") { problem(res, 401, "Unauthorized", "A tenant API key with webhook permission is required."); return; }
    if (!repository) { problem(res, 503, "Webhooks unavailable", "Webhooks are not configured on this service."); return; }
    try {
      const removed = await repository.deleteWebhook(auth.tenantId, webhookDelete[1]!);
      if (!removed) { problem(res, 404, "Webhook not found", "No such webhook for this tenant."); return; }
      res.writeHead(204, { "cache-control": "no-store" });
      res.end();
    } catch { problem(res, 503, "Webhooks unavailable", "The webhook could not be removed safely."); }
    return;
  }
  if (req.method === "POST" && path === "/v1/voice/speak") {
    try {
      const address = req.socket.remoteAddress ?? "unknown";
      let rate;
      try { rate = await rateLimiter.consume(`${address}:speak`, 30, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Voice output is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      if (!speechConfigured && env.nodeEnv === "production") { problem(res, 503, "Voice output unavailable", "A configured speech provider is required in production."); return; }
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = voiceSpeakRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide text and a Tier 1 language."); return; }
      const speech = await speechProvider.speak(validated.data.text, validated.data.language);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      res.end(JSON.stringify({ language: validated.data.language, mime_type: speech.mimeType, audio_base64: speech.audio.toString("base64"), provider: speechConfigured ? "openai" : "simulated" }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 503, "Voice output unavailable", "Speech could not be generated safely.");
    }
    return;
  }
  const scanStream = /^\/v1\/scans\/([0-9a-f-]{36})\/stream$/i.exec(path);
  if (req.method === "GET" && scanStream) {
    const id = scanStream[1]!;
    if (!scanJobs.has(id)) { problem(res, 404, "Not found", "No stream is available for that scan."); return; }
    res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", connection: "keep-alive" });
    const send = (entry: { stage: string; result: unknown }): void => {
      res.write(`event: ${entry.stage}\ndata: ${JSON.stringify(entry.result)}\n\n`);
      if (entry.stage === "final") res.end();
    };
    const unsubscribe = scanJobs.subscribe(id, send) ?? (() => {});
    const keepAlive = setInterval(() => res.write(": ping\n\n"), 15_000);
    req.on("close", () => { clearInterval(keepAlive); unsubscribe(); });
    if (scanJobs.isDone(id)) { clearInterval(keepAlive); res.end(); }
    return;
  }
  if (req.method === "POST" && path === "/v1/scans") {
    try {
      const address = req.socket.remoteAddress ?? "unknown";
      let rate;
      try { rate = await rateLimiter.consume(address, 20, 60_000); }
      catch { problem(res, 503, "Rate limiting unavailable", "Scanning is temporarily unavailable."); return; }
      if (!rate.allowed) { problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`); return; }
      const auth = await resolveTenant(req, "scans:write");
      if (auth.status === "error") { problem(res, auth.code, "Unauthorized", auth.detail); return; }
      const tenantId = auth.status === "ok" ? auth.tenantId : null;
      if (!req.headers["content-type"]?.includes("application/json")) { problem(res, 415, "Unsupported Media Type", "Send a JSON request."); return; }
      const validated = scanRequestSchema.safeParse(await readJson(req));
      if (!validated.success) { problem(res, 400, "Invalid request", "Provide text or combined inputs, an optional Tier 1 language, and mode fast or deep."); return; }
      const scanInput = validated.data;
      const combined = scanInput.inputs ? combineInputs(scanInput.inputs as ScanInput[]) : null;
      const sourceText = scanInput.text ?? combined!.text;
      const scanId = randomUUID();
      const runScan = async (assess?: (text: string, signals: Record<string, boolean>) => Promise<{ scam: boolean; scam_types: string[]; confidence: number; reasons: string[] }>): Promise<ScanResult> => {
        const result = await scanText(sourceText, {
          scanId,
          ...(scanInput.language ? { language: scanInput.language as Language } : {}),
          lookup: async (entities) => lookupIntelligence(entities, reputationStore),
          ...(assess ? { assess } : {})
        });
        return combined ? { ...result, input_types: combined.types } : result;
      };
      const deepAssess = scanInput.mode !== "fast" && Boolean(env.openAiKey && env.openAiModel);
      if (deepAssess) {
        const fast = await runScan();
        scanJobs.create(scanId);
        scanJobs.publish(scanId, { stage: "fast", result: fast });
        if (repository) {
          try { await repository.save(fast, redactSensitive(sourceText).text, tenantId); }
          catch { problem(res, 503, "Storage unavailable", "The scan could not be safely saved. Please retry shortly."); return; }
        } else if (env.nodeEnv === "production") { problem(res, 503, "Storage unavailable", "Scanning is temporarily unavailable."); return; }
        if (tenantId && repository) { try { await repository.recordUsage(tenantId, "scan"); } catch { logEvent("usage_record_failed", { metric: "scan" }); } }
        void (async () => {
          try {
            const deep = await runScan((text, signals) => provider.assess(text, signals));
            scanJobs.publish(scanId, { stage: "deep", result: deep });
            void dispatchWebhookEvent(tenantId, "scan.completed", deep);
          } catch { logEvent("deep_scan_failed", { scanId }); }
          finally { scanJobs.complete(scanId); }
        })();
        res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        const shield = await buildShieldContext({ text: sourceText, inputs: scanInput.inputs }, reputationStore);
        res.end(JSON.stringify({ ...fast, upgrade_url: `/v1/scans/${scanId}/stream`, shield }));
        return;
      }
      const result = await runScan();
      scanJobs.create(scanId);
      scanJobs.publish(scanId, { stage: "final", result });
      scanJobs.complete(scanId);
      if (repository) {
        try { await repository.save(result, redactSensitive(sourceText).text, tenantId); }
        catch { problem(res, 503, "Storage unavailable", "The scan could not be safely saved. Please retry shortly."); return; }
      } else if (env.nodeEnv === "production") {
        problem(res, 503, "Storage unavailable", "Scanning is temporarily unavailable.");
        return;
      }
      if (tenantId && repository) { try { await repository.recordUsage(tenantId, "scan"); } catch { logEvent("usage_record_failed", { metric: "scan" }); } }
      void dispatchWebhookEvent(tenantId, "scan.completed", result);
      res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      const shield = await buildShieldContext({ text: sourceText, inputs: scanInput.inputs }, reputationStore);
      res.end(JSON.stringify({ ...result, shield }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request_failed";
      if (message === "request_too_large") { problem(res, 413, "Payload too large", "The request exceeds the 64 KiB limit."); return; }
      if (message === "invalid_json") { problem(res, 400, "Invalid request", "The request body must be a JSON object."); return; }
      problem(res, 400, "Scan failed", message === "Text must contain 2 to 20,000 characters" ? message : "The scan could not be completed.");
    }
    return;
  }
  problem(res, 404, "Not found", "The requested route does not exist.");
});

type TenantAuth = { status: "anonymous" } | { status: "ok"; tenantId: string } | { status: "error"; code: number; detail: string };
type IntegrationAuth = { status: "ok"; tenantId: string } | { status: "error"; code: number; detail: string };

function parseCookies(req: IncomingMessage): Record<string, string> {
  const header = req.headers.cookie;
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    try { out[key] = decodeURIComponent(part.slice(eq + 1).trim()); } catch { out[key] = part.slice(eq + 1).trim(); }
  }
  return out;
}

function sessionCookie(token: string): string {
  const secure = env.nodeEnv === "production" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
}

function clearedSessionCookie(): string {
  const secure = env.nodeEnv === "production" ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

async function currentSession(req: IncomingMessage): Promise<{ email: string } | null> {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  try {
    const record = await authStore.findSession(hashSecret(token, authSecret));
    if (!record || record.revokedAt || record.expiresAt.getTime() <= Date.now()) return null;
    return { email: record.email };
  } catch { return null; }
}

async function requireSession(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const session = await currentSession(req);
  if (!session) { problem(res, 401, "Unauthorized", "Sign in to continue."); return false; }
  return true;
}

async function resolveIntegration(req: IncomingMessage, scope: IntegrationScope): Promise<IntegrationAuth> {
  const key = req.headers["x-api-key"];
  if (!key || Array.isArray(key)) return { status: "error", code: 401, detail: "Send a valid X-Api-Key header from your integration dashboard." };
  try {
    const record = await integrationKeyStore.findByHash(hashSecret(key, authSecret));
    if (!record) return { status: "error", code: 401, detail: "The API key is invalid or revoked." };
    if (!record.scopes.includes(scope)) return { status: "error", code: 403, detail: `The key lacks the "${scope}" scope.` };
    return { status: "ok", tenantId: record.id };
  } catch { return { status: "error", code: 503, detail: "Authentication is temporarily unavailable." }; }
}

async function resolveTenant(req: IncomingMessage, scope: string): Promise<TenantAuth> {
  const authorization = req.headers.authorization;
  if (!authorization) return { status: "anonymous" };
  const bearer = /^Bearer (.+)$/i.exec(authorization)?.[1];
  if (!bearer || !repository || !env.apiKeyPepper) return { status: "error", code: 401, detail: "The API key could not be verified." };
  try {
    const tenantId = await repository.authenticateApiKey(bearer, Buffer.from(env.apiKeyPepper), scope);
    if (!tenantId) return { status: "error", code: 401, detail: "The API key is invalid, expired, revoked, or lacks permission." };
    return { status: "ok", tenantId };
  } catch { return { status: "error", code: 503, detail: "Authentication is temporarily unavailable." }; }
}

async function dispatchWebhookEvent(tenantId: string | null, event: string, payload: unknown): Promise<void> {
  if (!tenantId || !repository) return;
  let keyring;
  try { keyring = keyringFromEnv(); } catch { return; }
  try {
    const hooks = await repository.activeWebhooks(tenantId, keyring);
    for (const hook of hooks) {
      if (!hook.events.includes(event)) continue;
      const result = await deliverWebhook({ url: hook.url, secret: hook.secret, event, payload });
      try { await repository.recordWebhookDelivery(hook.id, event, result.delivered, result.attempts, result.status ?? null); } catch { /* delivery logging is best effort */ }
    }
  } catch { logEvent("webhook_dispatch_failed", { event }); }
}

function isCommunityModerator(req: IncomingMessage): boolean {
  const provided = /^Bearer (.{32,512})$/i.exec(req.headers.authorization ?? "")?.[1];
  if (!provided || !env.communityModerationToken || !env.apiKeyPepper) return false;
  const pepper = Buffer.from(env.apiKeyPepper);
  return verifySecret(provided, hashSecret(env.communityModerationToken, pepper), pepper);
}

async function permitModeration(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  try {
    const rate = await rateLimiter.consume(`${req.socket.remoteAddress ?? "unknown"}:community-moderation`, 10, 60_000);
    if (!rate.allowed) {
      problem(res, 429, "Rate limit exceeded", `Please retry in ${Math.ceil(rate.retryAfterMs / 1000)} seconds.`);
      return false;
    }
    return true;
  } catch {
    problem(res, 503, "Rate limiting unavailable", "Moderation is temporarily unavailable.");
    return false;
  }
}

async function start(): Promise<void> {
  if (rateLimiter instanceof RedisRateLimiter) await rateLimiter.connect();
  server.listen(env.port, "0.0.0.0", () => logEvent("server_started", { port: env.port, shared_rate_limit: rateLimiter instanceof RedisRateLimiter }));
}
void start().catch(() => { logEvent("server_start_failed"); process.exitCode = 1; });

function shutdown(): void {
  server.close(() => {
    void Promise.all([repository?.close(), authStore.close(), rateLimiter.close(), reputationStore.close(), integrationKeyStore.close()]).finally(() => process.exit(0));
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
