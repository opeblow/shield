# Test report

Date: 2026-10-10. Working-tree checks; no clean checkout or production certification was performed.

## Recorded results

| Check | Result | Evidence |
|---|---|---|
| Typecheck | PASS, exit 0 | `npm.cmd run typecheck` after Redis queue implementation |
| Lint | PASS, exit 0 | `npm.cmd run lint` after Redis queue implementation |
| Build and unit/security tests | PASS, 61 passed / 0 failed | `npm.cmd test`; TypeScript build passed before tests |
| Evaluation | PASS, 450 cases; TP 300, FN 0, FP 0, TN 150; recall 1.00, FPR 0.00 | `npm.cmd run eval`; self-authored evaluation only |
| Browser E2E | PASS, 10 functional assertions | `python tests/e2e/browser_e2e.py` against local development-mode server; JSON and screenshots in ignored `reports/` |
| Accessibility | UNAVAILABLE, 15 axe checkpoints | The test defines desktop/mobile axe checkpoints, but `axe-core` is absent locally. Each checkpoint reported UNAVAILABLE; no violations were evaluated. |
| Docker/PostgreSQL/Redis integration | UNAVAILABLE | No Docker executable/daemon. Added queue reliability coverage has not run. |
| ZAP, k6, chaos, backup/restore, Lighthouse | UNAVAILABLE | Docker unavailable; no workflow run or reports artifact available |
| Clean checkout | UNAVAILABLE | Candidate worktree is uncommitted until this requested commit; no CI checkout has run |

The browser checks covered landing, desktop/mobile signup, session creation, scan result, developer-key page, logout, protected route, mobile overflow, keyboard-only signup and scan, keyboard focus, and uncaught page errors. The test fixes and re-runs the previously hidden developer dashboard sign-out control. This does not represent all matrix rows.

## Queue implementation and tests

The real progressive scan API now enqueues Redis Stream jobs consumed by `scripts/scan-worker.mjs`. Redis stores scan status and SSE events so separate API instances can serve progress. The integration suite now tests two API instances, two workers, worker SIGKILL and pending-job reclaim, exactly one final event, idempotent replay, whole-service/Redis restart recovery, transient retry, poison-message dead-lettering, bounded queue backpressure, and private stream ownership.

These are test definitions, not passing evidence: they require PostgreSQL and Redis containers and remain UNAVAILABLE on this machine.

## Feature coverage and latency

See [`FEATURE_MATRIX.md`](FEATURE_MATRIX.md) for route/page inventory and current coverage. Existing API/unit tests do not supply every requested browser happy/failure path. `LATENCY_BUDGETS.md` records initial targets. Request logs include total duration; scan API and worker now emit partial stage timing for fast assessment, enqueue, queue wait, deep assessment and persistence. k6 still exercises readiness only, so API endpoint percentiles, realistic provider-delay percentiles, and capacity are UNAVAILABLE.

Remaining absent product capabilities include account/data deletion, payable billing, server-side media analysis, scheduling and end-user notifications. Exact gaps are in [`BLOCKERS.md`](BLOCKERS.md).
