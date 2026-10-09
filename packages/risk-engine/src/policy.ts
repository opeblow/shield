import { z } from "zod";

export const actions = ["allow", "warn", "delay", "block", "review"] as const;
export type Action = typeof actions[number];

export type PolicyBand = { minScore: number; action: Action };
export type Policy = { bands: PolicyBand[]; reviewAmount?: number };

const policySchema = z.object({
  bands: z.array(z.object({ minScore: z.number().int().min(0).max(100), action: z.enum(actions) })).min(1).max(8),
  reviewAmount: z.number().nonnegative().optional()
}).strict();

export const defaultPolicy: Policy = {
  bands: [
    { minScore: 70, action: "block" },
    { minScore: 45, action: "delay" },
    { minScore: 20, action: "warn" },
    { minScore: 0, action: "allow" }
  ],
  reviewAmount: 1_000_000
};

/** Validates a tenant-supplied policy and rejects ambiguous or overlapping bands. */
export function normalizePolicy(input: unknown): Policy {
  const parsed = policySchema.parse(input);
  const scores = parsed.bands.map((band) => band.minScore);
  if (new Set(scores).size !== scores.length) throw new Error("Policy bands must not share a minimum score");
  return parsed as Policy;
}

const severityRank: Record<Action, number> = { allow: 0, warn: 1, review: 2, delay: 3, block: 4 };
const leastSevere = (action: Action, floor: Action): Action => severityRank[action] < severityRank[floor] ? floor : action;

/** Maps a risk score to an action, escalating high-value or novel-beneficiary transactions. */
export function resolveAction(score: number, context: { amount?: number; payeeNovel?: boolean } = {}, policy: Policy = defaultPolicy): Action {
  const band = [...policy.bands].filter((candidate) => score >= candidate.minScore).sort((a, b) => b.minScore - a.minScore)[0];
  let action: Action = band?.action ?? "review";
  if (context.payeeNovel === true) action = leastSevere(action, "delay");
  if (context.amount !== undefined && policy.reviewAmount !== undefined && context.amount >= policy.reviewAmount) action = leastSevere(action, "review");
  return action;
}
