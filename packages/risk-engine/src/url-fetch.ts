import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

export type SafeFetchResult = { url: string; status: number; contentType: string; bytes: number; truncated: boolean; body: string };
export type SafeFetchDeps = {
  fetchImpl?: typeof fetch;
  resolve?: (host: string) => Promise<string[]>;
  maxRedirects?: number;
  maxBytes?: number;
  timeoutMs?: number;
  maxChars?: number;
};

const defaultResolve = async (host: string): Promise<string[]> => (await lookup(host, { all: true })).map((record) => record.address);

function blockedV4(octets: number[]): boolean {
  const [a, b] = octets as [number, number, number, number];
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224;
}

/** True only for globally routable unicast addresses. Blocks loopback, private, link-local, CGNAT, reserved and multicast ranges. */
export function isPublicAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return !blockedV4(address.split(".").map(Number));
  if (version === 6) {
    const value = address.toLowerCase();
    if (value === "::" || value === "::1") return false;
    if (value.startsWith("fe80") || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("ff")) return false;
    if (value.startsWith("::ffff:")) return false;
    if (value.startsWith("2001:db8") || value.startsWith("2001:0000")) return false;
    return true;
  }
  return false;
}

async function assertPublicHost(hostname: string, resolve: (host: string) => Promise<string[]>): Promise<void> {
  const addresses = await resolve(hostname);
  if (addresses.length === 0) throw new Error("URL host did not resolve");
  if (!addresses.every((address) => isPublicAddress(address))) throw new Error("URL host resolves to a non-public address");
}

/**
 * Fetches a user-supplied URL with SSRF protection: public-address resolution on every hop,
 * bounded redirects, no cookies or credentials, and strict size and time limits.
 * Intended to run in an isolated worker, never in the API process.
 */
export async function fetchUrlSafely(rawUrl: string, deps: SafeFetchDeps = {}): Promise<SafeFetchResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const resolve = deps.resolve ?? defaultResolve;
  const maxRedirects = deps.maxRedirects ?? 3;
  const maxBytes = deps.maxBytes ?? 512 * 1024;
  const maxChars = deps.maxChars ?? 200_000;
  const timeoutMs = deps.timeoutMs ?? 4_000;

  let current = new URL(rawUrl);
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    if (current.protocol !== "https:" && current.protocol !== "http:") throw new Error("Only HTTP and HTTPS URLs can be fetched");
    if (current.username || current.password) throw new Error("URLs with embedded credentials are rejected");
    await assertPublicHost(current.hostname, resolve);
    const response = await fetchImpl(current, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "text/html,text/plain,application/json;q=0.9,*/*;q=0.1", "user-agent": "ShieldScanner/1.0 (+https://shield.example)" }
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) throw new Error("Redirect response had no location");
      const next = new URL(location, current);
      if (next.protocol !== "https:" && next.protocol !== "http:") throw new Error("Redirected to an unsupported scheme");
      current = next;
      continue;
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    const truncated = buffer.length > maxBytes;
    return {
      url: current.toString(),
      status: response.status,
      contentType: response.headers.get("content-type") ?? "application/octet-stream",
      bytes: buffer.length,
      truncated,
      body: buffer.subarray(0, Math.min(maxBytes, maxChars)).toString("utf8")
    };
  }
  throw new Error("Too many redirects");
}
