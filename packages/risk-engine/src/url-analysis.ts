import { isIP } from "node:net";

export type UrlSignal = { code: "url_invalid" | "url_credentials" | "url_non_public_host" | "url_punycode" | "url_http"; text: string; evidence: string; weight: number };

function nonPublicHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".test")) return true;
  if (isIP(host) === 4) {
    const octets = host.split(".").map(Number);
    return octets[0] === 0 || octets[0] === 10 || octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31) ||
      (octets[0] === 192 && octets[1] === 168) || octets[0]! >= 224;
  }
  if (isIP(host) === 6) {
    const normalized = host.toLowerCase();
    return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:") || normalized.startsWith("::ffff:127.");
  }
  return false;
}

/** Inspects URL structure without making network requests. Never use this as a URL fetcher. */
export function analyzeUrl(raw: string): { normalized: string | null; signals: UrlSignal[] } {
  let parsed: URL;
  try {
    parsed = new URL(raw.startsWith("www.") ? `https://${raw}` : raw);
  } catch {
    return { normalized: null, signals: [{ code: "url_invalid", text: "A link could not be parsed safely. Do not open it until you verify it independently.", evidence: "Invalid URL syntax", weight: 24 }] };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { normalized: null, signals: [{ code: "url_invalid", text: "This link uses an unsupported destination type. Do not open it.", evidence: "Unsupported URL scheme", weight: 35 }] };
  }
  const signals: UrlSignal[] = [];
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (parsed.username || parsed.password) signals.push({ code: "url_credentials", text: "The link hides its destination behind text before the host name.", evidence: "Credentials embedded in URL", weight: 30 });
  if (nonPublicHost(host)) signals.push({ code: "url_non_public_host", text: "The link points to a local or private network address and cannot be verified as a public service.", evidence: "Non-public destination host", weight: 35 });
  if (host.startsWith("xn--") || host.split(".").some((part) => part.startsWith("xn--"))) signals.push({ code: "url_punycode", text: "The link uses an encoded internationalized domain name that may resemble another address.", evidence: "Punycode host label", weight: 20 });
  if (parsed.protocol === "http:") signals.push({ code: "url_http", text: "This link does not use encrypted HTTPS transport.", evidence: "HTTP scheme", weight: 12 });
  parsed.hash = "";
  return { normalized: parsed.toString(), signals };
}
