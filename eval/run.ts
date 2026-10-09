import { evalCases } from "./cases.js";
import { scanText } from "../packages/risk-engine/src/scan.js";

const byLanguage = new Map<string, { tp: number; fn: number; fp: number; tn: number }>();
let tp = 0; let fn = 0; let fp = 0; let tn = 0;
for (const item of evalCases) {
  const result = await scanText(item.text, { language: item.language });
  const positive = result.verdict !== "safe";
  if (item.scam && positive) tp += 1;
  else if (item.scam) fn += 1;
  else if (positive) fp += 1;
  else tn += 1;
  const metrics = byLanguage.get(item.language) ?? { tp: 0, fn: 0, fp: 0, tn: 0 };
  if (item.scam && positive) metrics.tp += 1;
  else if (item.scam) metrics.fn += 1;
  else if (positive) metrics.fp += 1;
  else metrics.tn += 1;
  byLanguage.set(item.language, metrics);
}
const recall = tp / (tp + fn);
const falsePositiveRate = fp / (fp + tn);
const report = { cases: evalCases.length, tp, fn, fp, tn, recall, false_positive_rate: falsePositiveRate, per_language: Object.fromEntries([...byLanguage].map(([language, m]) => [language, { ...m, recall: m.tp / (m.tp + m.fn || 1), false_positive_rate: m.fp / (m.fp + m.tn || 1) }])) };
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (recall < 0.9 || falsePositiveRate > 0.03) process.exitCode = 1;
