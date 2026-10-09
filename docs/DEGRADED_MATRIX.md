# Degraded-dependency matrix

Shield is designed to fail closed: a missing dependency never yields a "safe"
verdict. This matrix is the contract for what each component does when a
dependency is unhealthy, how it is observed, and how it recovers.

| Dependency | Detection | Degraded behaviour | Customer signal | Recovery |
| --- | --- | --- | --- | --- |
| OpenAI (text/vision/transcription) | Missing key, timeout, retry exhausted, circuit open | Rules-only verdict; `model_version` reflects rules engine; no LLM claim | `mode` falls back to rules; no user-visible error | Circuit closes on next healthy call; set `OPENAI_API_KEY`/`OPENAI_MODEL` |
| OpenAI speech (TTS) | Missing `OPENAI_API_KEY` | `SimulatedSpeechProvider` returns deterministic audio marker | `/v1/voice/speak` returns `provider: "simulated"` | Credentials configured → `provider: "openai"` |
| PostgreSQL | `DATABASE_URL` unset or pool error | Development: scans returned but not persisted. Production: request fails `503` | `503 Storage unavailable` in production | Restore connectivity; migrations applied |
| Redis | `REDIS_URL` unset | Development: process-local rate limiter. Production: refuses to start | Readiness fails at boot | Restore Redis; shared limiter resumes |
| Progressive scan registry | Process restart or 2,000 retained/in-flight jobs | Completed results expire after 10 minutes; at capacity new scan jobs fail with `503` | `Scan capacity reached` | Reduce load or add durable shared job storage before multi-instance deployment |
| Webhook endpoint (tenant) | Non-2xx or timeout | Retried with exponential backoff, capped attempts; delivery recorded | `webhook_deliveries` row shows attempts/status | Tenant endpoint recovers; next event delivered |
| Object storage (artifacts) | Not configured | Image/document/voice artifact uploads rejected with `400` | `Unsupported or unrecognized file content` | Configure storage + signed URLs |
| SMS/USSD/IVR/WhatsApp | No provider credentials | Local simulators only; never contacts real subscribers | Simulator output clearly marked | Provision aggregator/Meta credentials |

## Invariants
- A rules-only fallback is always labelled; it is never presented as a model verdict.
- Missing encryption keys or keyring make the process fail to start rather than store plaintext.
- Rate limiting that cannot be evaluated fails the request closed (`503`), never open.
