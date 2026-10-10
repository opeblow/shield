# Engineering decisions

- Keep launch status **NO-GO** because the README says production dependencies and runtime verification are absent; local tests cannot establish production behavior.
- Treat the existing 50 passing unit tests as component evidence only because they do not exercise every HTTP endpoint or production deployment boundary.
- Do not claim an npm dependency audit passed because the registry advisory endpoint was unreachable during this run.
- Do not claim capacity or resilience targets because there is no declared workload SLO or deployed production-like environment.
- Exclude payments from financial controls because billing is metered estimation only and the README states that payment processing is not implemented.
- Treat submitted message content and URLs as hostile, and treat model output as untrusted; this follows the scanner's public-input and optional OpenAI design.
- Require an explicit launch target workload before setting numerical capacity targets because “millions of users” does not specify concurrent traffic.
- Scope integration-key listing and revocation by the authenticated account email because the key table stores `created_by` and the prior global list/revoke methods enabled cross-user IDOR.
- Keep the production launch at NO-GO after the local security suite passes because local mocked dependencies do not prove database tenant isolation or production deployment controls.
- Use a separate verification Compose file and credentials because this harness creates seed/test rows and intentionally resets only its isolated volumes.
- Keep the Redis Streams worker limited to verification jobs because production scan jobs still use the in-process registry; the harness must not imply durable production queue behavior.
- Load-test `/readyz` for the generic stack profile because application scan requests have strict client throttles; report those numbers as readiness-endpoint behavior, not scan throughput.
- Require `FORCE ROW LEVEL SECURITY` on every table with a `tenant_id` column in the verification schema because table owners otherwise bypass ordinary RLS policies.
