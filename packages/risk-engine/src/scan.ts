import { randomUUID } from "node:crypto";
import { redactSensitive } from "../../shared/src/redaction.js";
import { detectLanguage, extractEntities } from "./entities.js";
import { verdictMessage } from "./catalog.js";
import { evaluateRules } from "./rules.js";
import { analyzeUrl } from "./url-analysis.js";
import type { Language, ScanResult, Verdict } from "./types.js";

export type Intelligence = { reports: number; verified: boolean; firstSeen: string | null; lastSeen: string | null };
export type LlmAssessment = { scam: boolean; scam_types: string[]; confidence: number; reasons: string[] };
export type ScanOptions = { language?: Language; lookup?: (entities: ReturnType<typeof extractEntities>) => Promise<Intelligence | undefined>; assess?: (text: string, signals: Record<string, boolean>) => Promise<LlmAssessment>; scanId?: string };

export async function scanText(rawText: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  if (rawText.trim().length < 2 || rawText.length > 20_000) throw new Error("Text must contain 2 to 20,000 characters");
  const redacted = redactSensitive(rawText);
  const entities = extractEntities(redacted.text);
  const language = options.language ?? detectLanguage(rawText);
  const ruleResult = evaluateRules(redacted.text);
  const urlSignals = entities.urls.flatMap((url) => analyzeUrl(url).signals);
  const intelligence = options.lookup ? await options.lookup(entities) : undefined;
  let llm: LlmAssessment | undefined;
  if (options.assess) {
    try { llm = await options.assess(redacted.text, ruleResult.signals); } catch { /* rules and intelligence remain authoritative fallback */ }
  }
  const unverifiedEntity = !options.lookup && (entities.urls.length + entities.phones.length + entities.accounts.length > 0);
  const score = Math.min(100, ruleResult.findings.reduce((sum, finding) => sum + finding.weight, 0) + urlSignals.reduce((sum, signal) => sum + signal.weight, 0) + (unverifiedEntity ? 20 : 0) + (intelligence?.verified ? 55 : Math.min(20, (intelligence?.reports ?? 0) * 4)) + (llm?.scam ? 20 : 0));
  const hardEvidence = intelligence?.verified ?? false;
  const verdict: Verdict = hardEvidence || score >= 70 ? "scam" : score >= 45 ? "likely_scam" : score >= 20 || llm?.scam ? "caution" : "safe";
  const confidence = hardEvidence ? 0.99 : llm ? Math.max(0.35, Math.min(0.95, 0.45 + (llm.confidence * 0.5))) : Math.max(0.35, Math.min(0.85, 0.45 + ruleResult.findings.length * 0.09));
  const reasons = [
    ...ruleResult.findings.map(({ code, text, evidence }) => ({ code, text, evidence })),
    ...urlSignals.map(({ code, text, evidence }) => ({ code, text, evidence })),
    ...(unverifiedEntity ? [{ code: "identifier_not_checked", text: "A link or identifier was found, but reputation checking is unavailable. Verify it through an official channel.", evidence: "Reputation lookup is not configured" }] : []),
    ...(intelligence && intelligence.reports > 0 ? [{ code: "community_reports", text: `This identifier has ${intelligence.reports} community report${intelligence.reports === 1 ? "" : "s"}.`, evidence: "Community reputation" }] : []),
    ...(llm?.reasons.map((text, index) => ({ code: `model_reason_${index + 1}`, text, evidence: "Assessment of redacted text" })) ?? [])
  ];
  return {
    scan_id: options.scanId ?? randomUUID(), verdict, risk_score: score, confidence, scam_types: [...new Set([...ruleResult.scamTypes, ...(urlSignals.length ? ["phishing_link" as const] : [])])],
    input_types: ["text"],
    reasons, entities, community: { available: Boolean(intelligence), reports: intelligence?.reports ?? null, first_seen: intelligence?.firstSeen ?? null, last_seen: intelligence?.lastSeen ?? null },
    recommended_actions: verdict === "safe" ? ["Confirm payment and account details in your official bank app."] : ["Do not send money or share codes.", "Contact the organization using a number from its official app or card."],
    customer_message: { language, text: verdictMessage(language, verdict), audio_url: null }, language_reviewed: false,
    signals: { rules: { ...ruleResult.signals, ...Object.fromEntries(urlSignals.map((signal) => [signal.code, true])) }, llm: { available: Boolean(llm) }, intel: { available: Boolean(intelligence), match: hardEvidence } },
    model_version: llm ? "rules+provider-v1" : "rules-v1", latency_ms: Math.round(performance.now() - started)
  };
}
