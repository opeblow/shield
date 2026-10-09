const sensitiveKey = /(?:token|secret|password|authorization|bvn|nin|account|phone|email|message|content|api.?key)/i;
const sensitiveValue = /(?:\bBVN\s*[:#-]?\s*\d{11}\b|\bNIN\s*[:#-]?\s*\d{11}\b|(?<!\w)(?:\+?234|0)\s*\d(?:[\s-]?\d){9}(?!\w))/gi;

export function scrubLog(value: unknown): unknown {
  if (typeof value === "string") return value.replace(sensitiveValue, "[REDACTED]");
  if (Array.isArray(value)) return value.map(scrubLog);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitiveKey.test(key) ? "[REDACTED]" : scrubLog(item)]));
  }
  return value;
}

export function logEvent(event: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(`${JSON.stringify(scrubLog({ level: "info", event, ...fields }))}\n`);
}
