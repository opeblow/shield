import { randomUUID } from "node:crypto";
import { redactSensitive } from "../../shared/src/redaction.js";
import { detectLanguage, extractEntities } from "./entities.js";
import { evaluateRules } from "./rules.js";
import { analyzeUrl } from "./url-analysis.js";
import { verdictMessage } from "./catalog.js";
import { defaultPolicy, resolveAction, type Action, type Policy } from "./policy.js";
import type { Language, ScamType } from "./types.js";

export type TransactionContext = {
  amount?: number;
  currency?: string;
  beneficiary?: string;
  beneficiaryAccount?: string;
  accountAgeDays?: number;
  payeeNovel?: boolean;
  channel?: string;
  hourOfDay?: number;
  customerScans?: number;
  message?: string;
  language?: Language;
};

export type AssessmentReason = { code: string; text: string; evidence: string };

export type Assessment = {
  assessment_id: string;
  risk_score: number;
  confidence: number;
  action: Action;
  scam_types: ScamType[];
  reasons: AssessmentReason[];
  customer_message: { language: Language; text: string };
  signals: { rules: Record<string, boolean>; context: Record<string, boolean> };
  model_version: string;
  latency_ms: number;
};

export type AssessOptions = { policy?: Policy; assess?: (text: string, signals: Record<string, boolean>) => Promise<{ scam: boolean; scam_types: string[]; confidence: number; reasons: string[] }> };

function contextSignals(context: TransactionContext): { signals: Record<string, boolean>; findings: AssessmentReason[] } {
  const signals: Record<string, boolean> = {};
  const findings: AssessmentReason[] = [];
  const amount = context.amount;
  if (amount !== undefined && amount >= 500_000) { signals.high_amount = true; findings.push({ code: "high_amount", text: "This is an unusually large transfer to release in one step.", evidence: `Amount ${context.currency ?? "NGN"} ${amount}` }); }
  if (amount !== undefined && amount >= 5_000_000) { signals.very_high_amount = true; findings.push({ code: "very_high_amount", text: "This is a very large transfer that should be verified in person with the bank.", evidence: `Amount ${context.currency ?? "NGN"} ${amount}` }); }
  if (context.payeeNovel === true) { signals.new_beneficiary = true; findings.push({ code: "new_beneficiary", text: "This is the first transfer to this beneficiary.", evidence: "Beneficiary is new" }); }
  if (context.accountAgeDays !== undefined && context.accountAgeDays < 30) { signals.new_account = true; findings.push({ code: "new_account", text: "The receiving account is very new.", evidence: `Account age ${context.accountAgeDays} days` }); }
  if (context.hourOfDay !== undefined && (context.hourOfDay >= 23 || context.hourOfDay < 6)) { signals.odd_hour = true; findings.push({ code: "odd_hour", text: "The transfer is happening at an unusual hour.", evidence: `Hour ${context.hourOfDay}` }); }
  if (context.customerScans === 0) { signals.first_time_customer = true; findings.push({ code: "first_time_customer", text: "This is the customer's first transaction through Shield.", evidence: "No prior transaction history" }); }
  return { signals, findings };
}

function composeText(context: TransactionContext): string {
  const parts = [context.message ?? "", context.beneficiary ?? "", context.beneficiaryAccount ?? "", context.channel ?? "", context.currency ?? "", context.amount !== undefined ? String(context.amount) : ""];
  return parts.filter((part) => part.trim().length > 0).join(" \n ");
}

const contextWeights: Record<string, number> = { high_amount: 14, very_high_amount: 22, new_beneficiary: 12, new_account: 16, odd_hour: 8, first_time_customer: 10 };

/** Scores a real-time transaction using rules, structural URL analysis and transaction context. */
export async function assessTransaction(context: TransactionContext, options: AssessOptions = {}): Promise<Assessment> {
  const started = performance.now();
  const policy = options.policy ?? defaultPolicy;
  const redacted = redactSensitive(composeText(context));
  const entities = extractEntities(redacted.text);
  const language = context.language ?? detectLanguage(context.message ?? "");
  const ruleResult = evaluateRules(redacted.text);
  const urlSignals = entities.urls.flatMap((url) => analyzeUrl(url).signals);
  const { signals: contextSignalMap, findings: contextFindings } = contextSignals(context);
  let llm: { scam: boolean; scam_types: string[]; confidence: number; reasons: string[] } | undefined;
  if (options.assess) {
    try { llm = await options.assess(redacted.text, { ...ruleResult.signals, ...contextSignalMap }); } catch { /* rules and context remain authoritative */ }
  }
  const score = Math.min(100, ruleResult.findings.reduce((sum, finding) => sum + finding.weight, 0)
    + urlSignals.reduce((sum, signal) => sum + signal.weight, 0)
    + contextFindings.reduce((sum, finding) => sum + (contextWeights[finding.code] ?? 0), 0)
    + (llm?.scam ? 20 : 0));
  const scamTypes: ScamType[] = [...new Set([...ruleResult.scamTypes, ...((urlSignals.length ? ["phishing_link"] : []) as ScamType[])])];
  const reasons: AssessmentReason[] = [
    ...ruleResult.findings.map(({ code, text, evidence }) => ({ code, text, evidence })),
    ...urlSignals.map(({ code, text, evidence }) => ({ code, text, evidence })),
    ...contextFindings,
    ...(llm?.reasons.map((text, index) => ({ code: `model_reason_${index + 1}`, text, evidence: "Assessment of redacted transaction context" })) ?? [])
  ];
  const confidence = llm ? Math.max(0.35, Math.min(0.95, 0.45 + llm.confidence * 0.5)) : Math.max(0.35, Math.min(0.9, 0.45 + (reasons.length) * 0.07));
  const action = resolveAction(score, { ...(context.amount !== undefined ? { amount: context.amount } : {}), ...(context.payeeNovel !== undefined ? { payeeNovel: context.payeeNovel } : {}) }, policy);
  return {
    assessment_id: randomUUID(),
    risk_score: score,
    confidence,
    action,
    scam_types: scamTypes,
    reasons,
    customer_message: { language, text: verdictMessage(language, action === "allow" ? "safe" : action === "review" || action === "block" ? "scam" : "caution") },
    signals: { rules: { ...ruleResult.signals, ...Object.fromEntries(urlSignals.map((signal) => [signal.code, true])) }, context: contextSignalMap },
    model_version: llm ? "rules+provider-v1" : "rules-v1",
    latency_ms: Math.round(performance.now() - started)
  };
}
