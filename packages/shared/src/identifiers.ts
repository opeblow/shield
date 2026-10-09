import { sha256 } from "./crypto.js";

export type LookupType = "account" | "phone" | "url";

export function normalizeIdentifier(type: LookupType, value: string): string {
  const input = value.trim().normalize("NFC");
  if (type === "phone") {
    const digits = input.replace(/\D/g, "");
    const e164 = digits.startsWith("234") ? `+${digits}` : digits.startsWith("0") ? `+234${digits.slice(1)}` : `+${digits}`;
    if (!/^\+234[789][01]\d{8}$/.test(e164)) throw new Error("Enter a Nigerian mobile number in local or +234 format.");
    return e164;
  }
  if (type === "account") {
    const match = /^([a-z\d_-]{2,16})\s*[:|/]\s*(\d{10})$/i.exec(input);
    if (!match) throw new Error("Enter a bank code and 10-digit account number, for example bank-code:0123456789.");
    return `${match[1]!.toUpperCase()}:${match[2]}`;
  }
  let parsed: URL;
  try { parsed = new URL(input.includes("://") ? input : `https://${input}`); }
  catch { throw new Error("Enter a valid web address."); }
  if (!(["http:", "https:"].includes(parsed.protocol)) || parsed.username || parsed.password) throw new Error("Only public HTTP or HTTPS web addresses can be checked.");
  const domain = parsed.hostname.toLocaleLowerCase().replace(/\.$/, "");
  if (!domain || domain === "localhost") throw new Error("Enter a public web address.");
  const pathHash = sha256(parsed.pathname);
  return `${domain}/${pathHash}`;
}
