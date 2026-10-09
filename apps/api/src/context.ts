import { extractEntities } from "../../../packages/risk-engine/src/entities.js";
import type { Intelligence } from "../../../packages/risk-engine/src/scan.js";
import type { ScanInput } from "../../../packages/risk-engine/src/combined.js";
import { findOfficialChannel } from "./directory.js";
import { intelligenceFromSummaries, type IdentifierKind, type ReputationStore, type ReputationSummary } from "./reputation.js";

export type ShieldIdentifier = { kind: IdentifierKind; value: string };

type DirectoryCheck = { value: string; status: "verified" | "not_found"; name: string | null; shortName: string | null };

export type ShieldContext = {
  reputation: Array<ReputationSummary & { value: string }>;
  official_channels: DirectoryCheck[];
};

function identifiersFrom(input: { text?: string; inputs?: ScanInput[] | undefined }): ShieldIdentifier[] {
  const seen = new Set<string>();
  const output: ShieldIdentifier[] = [];
  const push = (kind: IdentifierKind, value: string): void => {
    const trimmed = value.trim();
    if (trimmed.length < 3) return;
    const marker = `${kind}:${trimmed}`;
    if (seen.has(marker)) return;
    seen.add(marker);
    output.push({ kind, value: trimmed });
  };
  for (const item of input.inputs ?? []) {
    if (item.type === "phone") push("phone", item.value);
    else if (item.type === "account") push("account", `${item.bank}/${item.number}`);
    else if (item.type === "url") push("url", item.value);
  }
  if (input.text) {
    const entities = extractEntities(input.text);
    for (const phone of entities.phones) push("phone", phone);
    for (const url of entities.urls) push("url", url);
    for (const account of entities.accounts) push("account", account);
  }
  return output;
}

export async function buildShieldContext(source: { text?: string; inputs?: ScanInput[] | undefined }, reputation: ReputationStore | undefined): Promise<ShieldContext> {
  const identifiers = identifiersFrom(source);
  const reputationContext: Array<ReputationSummary & { value: string }> = [];
  for (const identifier of identifiers) {
    try {
      const summary = await reputation?.summaryFor(identifier.kind, identifier.value);
      if (summary && summary.reports > 0) reputationContext.push(summary);
    } catch { /* reputation is best effort */ }
  }
  const official_channels: DirectoryCheck[] = [];
  for (const identifier of identifiers) {
    if (identifier.kind !== "phone" && identifier.kind !== "url") continue;
    const found = findOfficialChannel(identifier.value, identifier.kind);
    official_channels.push({ value: identifier.value, status: found.status, name: found.channel?.name ?? null, shortName: found.channel?.shortName ?? null });
  }
  return { reputation: reputationContext, official_channels };
}

export async function lookupIntelligence(entities: ReturnType<typeof extractEntities>, reputation: ReputationStore | undefined): Promise<Intelligence | undefined> {
  const identifiers: ShieldIdentifier[] = [];
  for (const phone of entities.phones) identifiers.push({ kind: "phone", value: phone });
  for (const url of entities.urls) identifiers.push({ kind: "url", value: url });
  for (const account of entities.accounts) identifiers.push({ kind: "account", value: account });
  const summaries: ReputationSummary[] = [];
  for (const identifier of identifiers) {
    try {
      const summary = await reputation?.summaryFor(identifier.kind, identifier.value);
      if (summary && summary.reports > 0) summaries.push(summary);
    } catch { /* best effort */ }
  }
  return intelligenceFromSummaries(summaries);
}