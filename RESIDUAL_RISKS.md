# Residual risks and exact external actions

| Risk / gap | Evidence | Exact blocker or action needed |
|---|---|---|
| Docker full-stack results | No local Docker binary. GitHub Actions run `38038849232` failed starting API/web/worker services after PostgreSQL and migrations passed | Read `compose.log` and `compose-ps.txt` from the run's `shield-verification-reports` artifact; artifact access requires repository authentication unavailable to this session |
| PostgreSQL RLS and migration lifecycle | DB isolation and migration up/down integration cases exist; not executed | Run full Compose workflow; Docker unavailable locally |
| Product scan queue | `/v1/scans` deep path now uses Redis streams, worker process is `scripts/scan-worker.mjs`; tests cover kill/reclaim, idempotent final, retry/DLQ, queue bound, two APIs/workers and restart | Runtime evidence is unavailable until Docker/CI runs. Review worker DB, Redis and webhook failures in logs |
| Queue delivery semantics | Terminal result commit and persisted final event are atomic/idempotent; webhook delivery uses deterministic IDs | Exactly-once external side effects require receiver idempotency. No sandbox delivery test has run |
| Idempotency scope | Deep scans accept scoped `Idempotency-Key`; concurrent duplicate registration remains unique-index protected | Other state-changing endpoints have no general idempotency facility; define endpoint requirements and implement where retry-safe semantics are required |
| OpenAI fallback / recovery | Provider mock integration scenarios remain in the stack suite | Docker is absent; run timeout, error and recovery test and retain TAP output |
| Full feature E2E coverage | `FEATURE_MATRIX.md` maps routes/pages; browser suite covers primary consumer flow | Missing per-route browser/API positive and negative tests, offline/degraded flows and external integrations remain OPEN. Docker blocks DB-backed execution |
| Axe results | 15 axe checkpoints are in the browser suite, pinned axe install configured | Local npm registry metadata unavailable (`ENOTCACHED` offline); CI install has not run. Get registry access, run checks at both viewports, and remediate serious/critical findings |
| Lighthouse/mobile | `.lighthouserc.json` gates mobile performance, LCP, and transfer sizes | Tool install and Lighthouse run have not completed; run CI with npm registry access and fix assertion failures |
| API latency evidence | Request totals plus scan API/worker stage logs exist | k6 only targets readiness; endpoint workloads, per-endpoint p50/p95/p99, complete DB/cache/provider/render spans, and their CI budgets are missing. Add and run on stack/staging |
| DAST/scanners | On Actions run `38038849235`, dependency audit, CodeQL and Gitleaks passed; Semgrep and Trivy failed; ZAP was skipped because stack startup failed | Download `semgrep-report` and `trivy-reports` artifacts from Actions using an authenticated repo account, then fix their findings. This session cannot access the private artifact downloads |
| Backup/restore and chaos | Scripts and test cases are configured | Docker absent; no RTO/RPO or recovery evidence. Run full verification and record measurements |
| Missing product capabilities | No account deletion, scheduler, end-user notifications, payable billing, server-side media analysis, or live channel delivery | Define scope and implement before representing those features as supported |
| Clean checkout verification | CI checked `acc330b`; standard CI passed, full-stack/security have the failures listed above | Clear the reported workflow failures and rerun the full suite |
| Production capacity and controls | No production-like staging, KMS, monitoring, agreed RPO/RTO, or independent review | Provision and review staging. Local/CI test numbers do not establish production capacity |

The launch decision remains NO-GO until the unavailable gates pass and open implementation gaps are closed or removed from the supported feature scope.
