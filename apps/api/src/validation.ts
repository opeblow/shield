import { z } from "zod";
import { actions } from "../../../packages/risk-engine/src/policy.js";

export const languageSchema = z.enum(["en", "pcm", "yo", "ha", "ig"]);

const scamTypes = ["fake_credit_alert", "bank_impersonation", "phishing_link", "advance_fee", "investment_scam", "romance", "job_scam", "grant_refund", "pos_fraud", "sim_swap_social", "other"] as const;
export const integrationScopes = ["scans:write", "lookup:read", "directory:read", "certificates:read"] as const;

export const scanInputSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("text"), text: z.string().trim().min(2).max(20_000) }).strict(),
  z.object({ type: z.literal("url"), value: z.string().trim().min(3).max(2_048) }).strict(),
  z.object({ type: z.literal("account"), bank: z.string().trim().min(2).max(16), number: z.string().trim().regex(/^\d{10}$/) }).strict(),
  z.object({ type: z.literal("phone"), value: z.string().trim().min(3).max(32) }).strict(),
  z.object({ type: z.literal("qr"), payload: z.string().trim().min(2).max(20_000) }).strict()
]);

export const scanRequestSchema = z.object({
  text: z.string().trim().min(2).max(20_000).optional(),
  inputs: z.array(scanInputSchema).min(1).max(8).optional(),
  language: languageSchema.optional(),
  mode: z.enum(["fast", "deep"]).optional()
}).strict().refine((value) => Boolean(value.text) || Boolean(value.inputs?.length), { message: "Provide text or combined inputs" });

const policySchema = z.object({
  bands: z.array(z.object({ minScore: z.number().int().min(0).max(100), action: z.enum(actions) })).min(1).max(8),
  reviewAmount: z.number().nonnegative().optional()
}).strict();

export const assessRequestSchema = z.object({
  amount: z.number().nonnegative().optional(),
  currency: z.string().trim().min(1).max(8).optional(),
  beneficiary: z.string().trim().max(200).optional(),
  beneficiaryAccount: z.string().trim().max(64).optional(),
  accountAgeDays: z.number().int().min(0).max(100_000).optional(),
  payeeNovel: z.boolean().optional(),
  channel: z.string().trim().max(32).optional(),
  hourOfDay: z.number().int().min(0).max(23).optional(),
  customerScans: z.number().int().min(0).optional(),
  message: z.string().trim().max(20_000).optional(),
  language: languageSchema.optional(),
  policy: policySchema.optional()
}).strict();

export const voiceSpeakRequestSchema = z.object({
  text: z.string().trim().min(1).max(1_000),
  language: languageSchema,
  provider: z.string().trim().min(1).max(48).optional()
}).strict();

export const linkPreviewRequestSchema = z.object({
  url: z.string().trim().min(4).max(2_048).regex(/^https?:\/\//i, "Provide an http(s) URL")
}).strict();

export const batchScanRequestSchema = z.object({
  items: z.array(z.object({
    text: z.string().trim().min(2).max(20_000),
    language: languageSchema.optional()
  })).min(1).max(25)
}).strict();

export const webhookEvents = ["scan.completed", "assess.completed", "fraud_wave.detected"] as const;

export const webhookRequestSchema = z.object({
  url: z.string().trim().min(9).max(2_048).regex(/^https:\/\/[^\s]+$/i, "Webhook URLs must use HTTPS"),
  events: z.array(z.enum(webhookEvents)).min(1).max(webhookEvents.length)
}).strict();

export const lookupRequestSchema = z.object({
  type: z.enum(["account", "phone", "url"]),
  value: z.string().trim().min(3).max(2_048)
}).strict();

export const communityReportSchema = z.object({
  type: z.enum(["account", "phone", "url"]),
  value: z.string().trim().min(3).max(2_048),
  scamType: z.enum(scamTypes),
  evidence: z.string().trim().max(2_000).optional()
}).strict();

export const reputationReportSchema = communityReportSchema;

export const decideReportSchema = z.object({ action: z.enum(["verify", "reject"]) }).strict();

export const certificateRequestSchema = z.object({
  scan_id: z.string().uuid("Provide the scan_id of a completed scan"),
  note: z.string().trim().max(500).optional()
}).strict();

export const integrationKeySchema = z.object({
  name: z.string().trim().min(1).max(64),
  scopes: z.array(z.enum(integrationScopes)).min(1).max(4)
}).strict();

export const verifyChannelSchema = z.object({
  type: z.enum(["phone", "url"]),
  value: z.string().trim().min(3).max(2_048)
}).strict();

export const moderateReportSchema = z.object({ action: z.enum(["verify", "reject"]) }).strict();

const emailSchema = z.string().trim().toLowerCase().min(3).max(254).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Enter a valid email address");

export const authRegisterSchema = z.object({
  email: emailSchema,
  password: z.string().min(12, "Password must be at least 12 characters.").max(200)
}).strict();

export const authLoginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(200)
}).strict();

export type ScanRequest = z.infer<typeof scanRequestSchema>;
export type AssessRequest = z.infer<typeof assessRequestSchema>;
export type WebhookRequest = z.infer<typeof webhookRequestSchema>;
