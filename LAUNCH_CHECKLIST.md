# Launch checklist

## Decision: NO-GO

| Gate | Go criterion | Current evidence | Decision |
|---|---|---|---|
| Code checks | Typecheck, lint, build, unit/security tests, eval pass | Typecheck/lint pass; build and 61/61 tests pass; 450 eval cases pass | PASS for local code checks |
| Verification harness | Compose/workflow and runners parse | Compose/workflow YAML and Bash/PowerShell scripts parse; Docker run unavailable | PASS for syntax only |
| Browser flow | Signup, scan, logout, developer page, mobile and keyboard-only flows pass | 10 functional assertions passed locally in development mode | PASS for covered paths only |
| Accessibility | Axe passes desktop/mobile pages with no serious/critical findings | 15 checkpoints exist; axe package install blocked locally and CI has no result | NO-GO |
| Feature matrix | Every supported feature has positive and failure-path E2E tests | Primary browser paths pass; matrix still contains partial/unavailable rows | NO-GO |
| PostgreSQL/Redis isolation and migrations | RLS and migration lifecycle pass on real services | Integration cases exist; no Docker run | NO-GO |
| Product scan queue | Redis queue passes kill/reclaim, retry, idempotency, replicas, restart and backpressure tests | Implementation and tests are in tree; runtime unverified because Docker is absent | NO-GO |
| DAST and security scans | ZAP, fresh npm/OSV, SAST, secrets and container scans have no unresolved high/critical findings | CI run `38038849235`: npm/OSV, CodeQL, and Gitleaks pass; Semgrep and Trivy fail; ZAP did not run because stack startup failed | NO-GO |
| Load, chaos and backup | Endpoint load budgets pass; dependencies recover; restore RTO/RPO measured | k6 only targets readiness; chaos and backup tools configured but not run | NO-GO |
| Latency and frontend performance | Per-endpoint p50/p95/p99 and Lighthouse mobile/bundle gates pass | Partial scan-stage logging and Lighthouse config added; no endpoint load or Lighthouse result | NO-GO |
| Production controls / external review | TLS/KMS/monitoring/rollback and legal/security/language reviews proven | Not provisioned or independently reviewed | NO-GO |

The full-stack runner is `bash scripts/verify-all.sh` or `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-all.ps1`. See `BLOCKERS.md` for exact external actions. Do not treat local readiness checks as production capacity evidence.
