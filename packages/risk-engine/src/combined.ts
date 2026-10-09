import { scanText, type ScanOptions } from "./scan.js";
import type { ScanResult } from "./types.js";

export const inputTypes = ["text", "url", "account", "phone", "qr"] as const;
export type InputType = typeof inputTypes[number];

export type ScanInput =
  | { type: "text"; text: string }
  | { type: "url"; value: string }
  | { type: "account"; bank: string; number: string }
  | { type: "phone"; value: string }
  | { type: "qr"; payload: string };

export function combineInputs(inputs: ScanInput[]): { text: string; types: InputType[] } {
  if (inputs.length === 0) throw new Error("Provide at least one input to scan");
  if (inputs.length > 8) throw new Error("A scan accepts at most 8 combined inputs");
  const lines: string[] = [];
  const types: InputType[] = [];
  for (const input of inputs) {
    if (input.type === "text") { if (input.text.trim().length > 0) { lines.push(input.text); types.push("text"); } }
    else if (input.type === "url") { lines.push(input.value); types.push("url"); }
    else if (input.type === "account") { lines.push(`account ${input.bank}:${input.number}`); types.push("account"); }
    else if (input.type === "phone") { lines.push(input.value); types.push("phone"); }
    else { lines.push(input.payload); types.push("qr"); }
  }
  const text = lines.join("\n");
  if (text.trim().length < 2) throw new Error("Combined inputs must contain at least 2 characters");
  return { text, types: [...new Set(types)] };
}

/** Runs one unified verdict across several combined inputs (text, link, QR payload, account, phone). */
export async function scanCombined(inputs: ScanInput[], options: ScanOptions = {}): Promise<ScanResult> {
  const combined = combineInputs(inputs);
  const result = await scanText(combined.text, options);
  return { ...result, input_types: combined.types };
}
