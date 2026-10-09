// Dependency-free load runner for the scan API. Usage:
//   node scripts/load-test.mjs            (defaults: http://localhost:3001, 10s, 20 workers)
//   SHIELD_BASE_URL=http://localhost:3199 DURATION_MS=8000 WORKERS=24 node scripts/load-test.mjs
const base = process.env.SHIELD_BASE_URL ?? "http://localhost:3001";
const durationMs = Number(process.env.DURATION_MS ?? 10_000);
const workers = Number(process.env.WORKERS ?? 20);
const text = "Please send your OTP to 08029000000 urgently or your account will be blocked";

const latencies = [];
let ok = 0;
let throttled = 0;
let failed = 0;
const deadline = Date.now() + durationMs;

async function worker() {
  while (Date.now() < deadline) {
    const started = performance.now();
    try {
      const response = await fetch(`${base}/v1/scans`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, language: "en", mode: "fast" })
      });
      if (response.ok) { await response.arrayBuffer(); ok += 1; }
      else if (response.status === 429) { throttled += 1; }
      else { failed += 1; }
      latencies.push(performance.now() - started);
    } catch {
      failed += 1;
      latencies.push(performance.now() - started);
    }
  }
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[index];
}

const started = Date.now();
await Promise.all(Array.from({ length: workers }, worker));
const elapsed = (Date.now() - started) / 1000;
const total = ok + throttled + failed;
console.log(JSON.stringify({
  base,
  workers,
  duration_s: Number(elapsed.toFixed(2)),
  requests: total,
  ok,
  throttled,
  failed,
  error_rate: total ? Number((failed / total).toFixed(4)) : 0,
  rps: Number((total / elapsed).toFixed(1)),
  latency_ms: {
    p50: Number(percentile(latencies, 50).toFixed(1)),
    p95: Number(percentile(latencies, 95).toFixed(1)),
    p99: Number(percentile(latencies, 99).toFixed(1)),
    max: Number(Math.max(...latencies).toFixed(1))
  }
}, null, 2));