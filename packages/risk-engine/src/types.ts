export const languages = ["en", "pcm", "yo", "ha", "ig"] as const;
export type Language = typeof languages[number];
export type Verdict = "safe" | "caution" | "likely_scam" | "scam";
export type ScamType = "fake_credit_alert" | "bank_impersonation" | "phishing_link" | "advance_fee" | "investment_scam" | "romance" | "job_scam" | "grant_refund" | "pos_fraud" | "sim_swap_social" | "other";
export type Finding = { code: string; text: string; evidence: string; weight: number };
export type ScanResult = {
  scan_id: string; verdict: Verdict; risk_score: number; confidence: number; scam_types: ScamType[];
  input_types: string[];
  reasons: Array<{ code: string; text: string; evidence: string }>;
  entities: { urls: string[]; phones: string[]; accounts: string[]; amounts: string[]; brands: string[] };
  community: { available: boolean; reports: number | null; first_seen: string | null; last_seen: string | null };
  recommended_actions: string[]; customer_message: { language: Language; text: string; audio_url: string | null };
  language_reviewed: boolean;
  signals: { rules: Record<string, boolean>; llm: { available: boolean }; intel: { available: boolean; match: boolean } };
  model_version: string; latency_ms: number;
};
