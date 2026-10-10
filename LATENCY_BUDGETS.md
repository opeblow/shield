# Latency budgets and enforcement

Date: 2026-10-10. These are initial product targets, not claimed measurements. No production SLO or representative deployment profile was provided. The targets below must be ratified against deployment topology and then measured on a Docker test stack and representative staging environment.

| Operation | Budget | Measurement needed | Current state |
|---|---:|---|---|
| Health/readiness GET | p95 < 150 ms | k6 `/readyz` | CI/local k6 configuration now gates p95 < 150 ms; no Docker-backed measurement yet |
| Simple API read/lookup | p95 < 300 ms | Per-route k6 `http_req_duration` | UNAVAILABLE |
| API writes (report, key, webhook) | p95 < 500 ms | Per-route k6 with seeded PostgreSQL and Redis | UNAVAILABLE |
| Rules-only scan | p95 < 500 ms | `POST /v1/scans` under representative text sizes, real PG/Redis | UNAVAILABLE; local process-only measurement is not representative |
| External-provider scan | p95 < 2 s, provider deadline <= 3.5 s | Include provider latency/failure profiles and report fallbacks separately | UNAVAILABLE |
| Long/deep operations | return initial response < 500 ms, progress event within 2 s | Queue wait and stage timing under multiple workers | UNAVAILABLE; Redis-backed product queue is implemented, but multi-worker timings have not run |
| Mobile web first content | LCP < 2.5 s on throttled mobile profile | Lighthouse CI on landing/auth/scanner | UNAVAILABLE |
| Front-end transfer size | JS <= 250 KiB compressed; CSS <= 100 KiB compressed | Lighthouse/bundle report | UNAVAILABLE |

## Instrumentation and gates

The API returns scan `latency_ms` and logs total request time. Scan paths now log fast assessment, PostgreSQL persist, Redis enqueue, worker queue wait, deep assessment and deep-result persistence. There are no database/cache/provider/render spans for all endpoints and no exported metrics/tracing endpoint. The current k6 runner still gates readiness p95 only; `.lighthouserc.json` adds mobile performance/LCP/transfer-size assertions but has not run. These do not enforce the operation budgets above.

Required follow-up: complete stage instrumentation for every endpoint; add seeded authenticated scan/read/write k6 scenarios with endpoint tags and simulated provider latency; export p50/p95/p99; enforce each budget in CI; and run Lighthouse. Full performance evidence is blocked by Docker absence and registry access described in `BLOCKERS.md`. Missing endpoint workloads and instrumentation are implementation gaps.
