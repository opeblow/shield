export type RedactionResult = { text: string; counts: Record<string, number> };

function canonical(category: string, value: string): string {
  const digits = value.replace(/\D/g, "");
  if (category === "phone") {
    if (digits.startsWith("234")) return `+${digits}`;
    if (digits.startsWith("0")) return `+234${digits.slice(1)}`;
  }
  if (["bvn", "nin", "account", "card", "phone"].includes(category)) return digits;
  return value.trim().normalize("NFC").toLocaleLowerCase();
}

function replaceStable(text: string, pattern: RegExp, category: string, aliases: Map<string, number>, counters: Map<string, number>): [string, number] {
  let count = 0;
  const next = text.replace(pattern, (match) => {
    count += 1;
    const key = `${category}:${canonical(category, match)}`;
    let id = aliases.get(key);
    if (id === undefined) { id = (counters.get(category) ?? 0) + 1; counters.set(category, id); aliases.set(key, id); }
    return `[${category.toUpperCase()}_${id}]`;
  });
  return [next, count];
}

function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

export function redactSensitive(text: string): RedactionResult {
  const counts: Record<string, number> = {};
  const aliases = new Map<string, number>();
  const counters = new Map<string, number>();
  let result = text.normalize("NFC");
  const steps: Array<[string, RegExp]> = [
    ["bvn", /\bBVN\s*[:#-]?\s*\d{11}\b/gi],
    ["nin", /\bNIN\s*[:#-]?\s*\d{11}\b/gi],
    ["code", /\b(?:OTP|PIN|verification code|one[- ]time password)\s*(?:is|:|=)?\s*\d{4,8}\b/gi],
    ["password", /\b(?:password|passcode)\s*(?:is|:|=)\s*[^\s,.;]+/gi],
    ["email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
    ["account", /\b(?:account|acct|a\/c)\s*(?:number|no\.?|#|:)?\s*\d{10}\b/gi],
    ["phone", /(?<!\w)(?:\+?234|0)\s*\d(?:[\s-]?\d){9}(?!\w)/g]
  ];
  for (const [category, pattern] of steps) {
    const [next, count] = replaceStable(result, pattern, category, aliases, counters);
    result = next;
    counts[category] = count;
  }
  let cardCount = 0;
  result = result.replace(/\b(?:\d[ -]?){13,19}\b/g, (candidate) => {
    if (!luhn(candidate)) return candidate;
    cardCount += 1;
    return replaceStable(candidate, /.+/, "card", aliases, counters)[0];
  });
  counts.card = cardCount;
  return { text: result, counts };
}
