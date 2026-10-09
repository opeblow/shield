export type ChannelKind = "bank" | "telco";

export type OfficialChannel = {
  id: string;
  kind: ChannelKind;
  name: string;
  shortName: string;
  phones: string[];
  domains: string[];
};

export type ChannelLookupResult = { status: "verified" | "not_found"; channel: { id: string; kind: ChannelKind; name: string; shortName: string } | null };

export const OFFICIAL_DIRECTORY: OfficialChannel[] = [
  { id: "bank-access", kind: "bank", name: "Access Bank", shortName: "Access Bank", phones: ["07003000000", "2002"], domains: ["accessbankplc.com"] },
  { id: "bank-first", kind: "bank", name: "First Bank of Nigeria", shortName: "FirstBank", phones: ["07008250000", "301"], domains: ["firstbanknigeria.com"] },
  { id: "bank-gt", kind: "bank", name: "Guaranty Trust Bank", shortName: "GTBank", phones: ["08029000000", "08022900000"], domains: ["gtbank.com", "gtco.com"] },
  { id: "bank-zenith", kind: "bank", name: "Zenith Bank", shortName: "Zenith", phones: ["07008090000", "09040001234"], domains: ["zenithbank.com"] },
  { id: "bank-uba", kind: "bank", name: "United Bank for Africa", shortName: "UBA", phones: ["07002255242"], domains: ["ubagroup.com", "ubabank.com"] },
  { id: "telco-mtn", kind: "telco", name: "MTN Nigeria", shortName: "MTN", phones: ["180", "131"], domains: ["mtn.ng"] },
  { id: "telco-airtel", kind: "telco", name: "Airtel Nigeria", shortName: "Airtel", phones: ["111"], domains: ["airtel.ng"] },
  { id: "telco-glo", kind: "telco", name: "Globacom", shortName: "Glo", phones: ["121"], domains: ["gloworld.com", "glo.ng"] },
  { id: "telco-9mobile", kind: "telco", name: "9mobile", shortName: "9mobile", phones: ["200", "300000"], domains: ["9mobile.com.ng"] }
];

export function phoneDigits(value: string): string {
  return value.replace(/\D/g, "");
}

export function canonicalPhone(value: string): string {
  let digits = phoneDigits(value);
  if (digits.startsWith("234") && digits.length > 10) digits = digits.slice(3);
  else if (digits.startsWith("0") && digits.length > 9) digits = digits.slice(1);
  return digits;
}

export function domainOf(value: string): string {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return value.toLowerCase().replace(/^https?:\/\//i, "").replace(/^www\./, "").replace(/[^a-z0-9.=_-]/g, "").replace(/\.$/, "");
  }
}

export function findOfficialChannel(value: string, kind: "phone" | "url"): ChannelLookupResult {
  if (kind === "phone") {
    const candidate = canonicalPhone(value);
    if (!candidate) return { status: "not_found", channel: null };
    for (const entry of OFFICIAL_DIRECTORY) {
      for (const known of entry.phones) {
        const knownDigits = canonicalPhone(known);
        if (knownDigits && (candidate === knownDigits || candidate.endsWith(knownDigits) || knownDigits.endsWith(candidate))) {
          return { status: "verified", channel: { id: entry.id, kind: entry.kind, name: entry.name, shortName: entry.shortName } };
        }
      }
    }
    return { status: "not_found", channel: null };
  }
  const host = domainOf(value);
  if (!host) return { status: "not_found", channel: null };
  for (const entry of OFFICIAL_DIRECTORY) {
    for (const known of entry.domains) {
      if (host === known || host.endsWith(`.${known}`)) {
        return { status: "verified", channel: { id: entry.id, kind: entry.kind, name: entry.name, shortName: entry.shortName } };
      }
    }
  }
  return { status: "not_found", channel: null };
}