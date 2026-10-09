import type { Finding, ScamType } from "./types.js";

type Rule = { code: string; pattern: RegExp; text: string; weight: number; scamType: ScamType };
const rules: Rule[] = [
  { code: "requests_secret_code", pattern: /\b(?:send|share|tell|give)\b.{0,35}\b(?:otp|pin|bvn|password|verification code)\b|\b(?:otp|pin|bvn)\b.{0,25}\b(?:send|share|tell|give)\b|\b(?:firanse|fi\s+.*\s+ranse|aiko\s+da|tura|zipu|nye\s+m)\b.{0,35}\b(?:otp|pin|koodu|lambar\s+sirri|nọmba\s+mbanye)\b|\b(?:otp|pin)\b.{0,25}\b(?:firanse|aiko|tura|zipu)\b/i, text: "It asks you to share a private code or identity detail.", weight: 45, scamType: "bank_impersonation" },
  { code: "pay_to_receive", pattern: /\b(?:pay|send|transfer)\b.{0,45}\b(?:receive|release|unlock|claim)\b|\b(?:processing|activation|clearance) fee\b|\b(?:san|kwụọ|kwuo)\b.{0,45}\b(?:nata|enweta|nyefee)\b.{0,30}\b(?:onyinye|ego|grant)\b/i, text: "It asks for payment before money or a benefit is released.", weight: 34, scamType: "advance_fee" },
  { code: "urgent_pressure", pattern: /\b(?:urgent|immediately|right now|within \d+ minutes|act fast|last chance|account will be blocked)\b/i, text: "It pressures you to act quickly.", weight: 16, scamType: "other" },
  { code: "secrecy_pressure", pattern: /\b(?:don't tell|do not tell|keep this secret|tell nobody|no tell anybody)\b/i, text: "It tells you to keep the request secret.", weight: 22, scamType: "other" },
  { code: "guaranteed_returns", pattern: /\b(?:guaranteed|risk[- ]free|double your money|100% returns|sure profit)\b/i, text: "It promises unusually certain or high returns.", weight: 30, scamType: "investment_scam" },
  { code: "fake_grant_fee", pattern: /\b(?:grant|palliative|cbn|nelfund|scholarship)\b.{0,70}\b(?:fee|pay|registration|processing)\b/i, text: "It links a grant or public benefit to an upfront fee.", weight: 32, scamType: "grant_refund" },
  { code: "sim_swap_code", pattern: /\b(?:code sent by mistake|verification code|whatsapp code)\b/i, text: "It may be trying to take over an account using a verification code.", weight: 30, scamType: "sim_swap_social" },
  { code: "shortened_link", pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy)\//i, text: "It contains a shortened link that hides its destination.", weight: 18, scamType: "phishing_link" },
  { code: "fake_credit_claim", pattern: /\b(?:credited|transfer successful|payment confirmed)\b.{0,70}\b(?:screenshot|receipt|refund|reverse|mistakenly sent)\b/i, text: "It asks you to act on a payment claim that should be checked in your own bank account.", weight: 26, scamType: "fake_credit_alert" }
  ,{ code: "localized_code_request", pattern: /\b(?:firanse|aiko\s+da|tura|zipu)\b.{0,90}\b(?:otp|pin|(?:lambar\s+sirri)|(?:koodu)|(?:náºmba\s+mbanye))\b|\b(?:otp|pin)\b.{0,90}\b(?:firanse|aiko|tura|zipu)\b/i, text: "It asks for a private security code. Banks and trusted services should not ask you to share one.", weight: 48, scamType: "bank_impersonation" }
  ,{ code: "localized_advance_fee", pattern: /\b(?:san\s+owo|san\s+ow[oó]|biya\s+kudin|kwá»¥á»\s+(?:ego|á»¥gwá»)|kwuo\s+ego)\b.{0,120}\b(?:grant|cbn|aw[iy]n|áº¹bun|onyinye|tallafi|bashin|ego\s+mgbazinye|mgbazinye)\w*|\b(?:grant|cbn|aw[iy]n|áº¹bun|onyinye|tallafi|bashin|ego\s+mgbazinye|mgbazinye)\w*.{0,120}\b(?:san\s+owo|biya\s+kudin|kwá»¥á»|kwuo)\b|\b(?:biya\s+kudin|pay\s+(?:the\s+)?fee)\b.{0,80}\b(?:karbar|receive|claim|grant|tallafi)\b/i, text: "It asks for an upfront payment to receive a grant, loan or benefit. Verify through an official channel first.", weight: 40, scamType: "advance_fee" }
  ,{ code: "localized_benefit_fee", pattern: /\b(?:zipu|kwá»¥á»|kwuo)\b.{0,100}\b(?:onyinye|mgbazinye|á»¥gwá»|grant)\b|\b(?:onyinye|mgbazinye|á»¥gwá»)\b.{0,100}\b(?:zipu|kwá»¥á»|kwuo)\b/i, text: "It connects a payment request with a benefit or loan. Verify the offer independently.", weight: 42, scamType: "advance_fee" }
  ,{ code: "localized_urgent_pressure", pattern: /\b(?:kiakia|bayii|yanzu|ozugbo|gá»á»mentá»‹)\b.{0,90}\b(?:block|kulle|á»¥lá»|grant|tallafi|onyinye|aw[iy]n|account|asusun)\b|\b(?:block|kulle|grant|tallafi|onyinye|aw[iy]n)\b.{0,90}\b(?:kiakia|bayii|yanzu|ozugbo)\b/i, text: "It uses urgency to push you to act quickly. Pause and verify independently.", weight: 20, scamType: "other" }
  ,{ code: "igbo_benefit_fee", pattern: /\bkw\u1ee5\u1ecd\b.{0,120}\b(?:onyinye|mgbazinye|ndebanye|nhazi)\b|\b(?:ndebanye|nhazi)\b.{0,120}\b(?:onyinye|mgbazinye|ego)\b/i, text: "It asks for a fee to receive a benefit or loan. Verify the offer independently.", weight: 42, scamType: "advance_fee" }
  ,{ code: "pidgin_refund_pressure", pattern: /\b(?:dem\s+say|transfer\s+don\s+land|wrong\s+transfer)\b.{0,100}\b(?:refund|send\s+am\s+back)\b.{0,100}\b(?:screenshot|receipt|see\s+this)\b/i, text: "It asks you to refund a claimed transfer based on a screenshot. Check your own account balance first.", weight: 42, scamType: "fake_credit_alert" }
];

export function evaluateRules(text: string): { findings: Finding[]; signals: Record<string, boolean>; scamTypes: ScamType[] } {
  const findings: Finding[] = [];
  const signals: Record<string, boolean> = {};
  for (const rule of rules) {
    const match = rule.pattern.exec(text);
    signals[rule.code] = Boolean(match);
    if (match) findings.push({ code: rule.code, text: rule.text, evidence: match[0].slice(0, 100), weight: rule.weight });
  }
  return { findings, signals, scamTypes: [...new Set(findings.map((finding) => finding.code === "urgent_pressure" || finding.code === "secrecy_pressure" ? "other" : rules.find((rule) => rule.code === finding.code)!.scamType))] };
}
