# Runbook — incident response

Use this when production availability, integrity, or confidentiality may be at
risk. Severity is by customer impact, not by cause.

## Severities
- **SEV1** — Data exposure, auth bypass, or total outage. Page immediately.
- **SEV2** — Partial outage, wrong verdicts trending, or elevated error rate.
- **SEV3** — Degraded dependency handled correctly (see `DEGRADED_MATRIX.md`).

## First 15 minutes
1. **Declare** in the incident channel: severity, symptom, start time, commander.
2. **Stabilise**: if verdicts may be wrong or data may leak, stop the bleeding first.
   - Wrong verdicts → disable the affected model/config, force rules-only fallback.
   - Suspected key compromise → rotate (see `KEY_ROTATION.md`).
   - Data exposure → revoke the exposed credential and preserve logs before cleanup.
3. **Preserve evidence**: capture request IDs, `logEvent` output, and the deployment
   revision *before* redeploying. Logs are scrubbed of PII by `safe-log.ts`.
4. **Communicate**: post status to the status page; every 30 minutes for SEV1.

## Triage checklist
- `GET /healthz` (process) and `GET /readyz` (dependency mode).
- Recent failed executions and rate-limit `429`/`503` volume.
- Confirm the active `model_version` matches the intended rules/model path.
- Check `webhook_deliveries` for tenant-side failures.

## Containment levers
- Force rules-only: unset `OPENAI_MODEL` / `OPENAI_API_KEY` and restart.
- Raise the rate-limit floor to shed load rather than fail open.
- Scale away from a bad revision via the deploy target's rollback.

## After-action
- Write a blameless review within 5 business days: timeline, root cause,
  contributing factors, what worked, and dated action items.
- Add a regression test or eval case that would have caught the incident.
- Update this runbook and `DEGRADED_MATRIX.md` if the failure mode was new.

## Contacts
Fill in on deployment: on-call rotation, security lead, privacy counsel,
hosting provider, and the status-page owner. None are provisioned in this repo.
