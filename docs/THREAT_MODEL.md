# Shield threat model

## Assets

Submitted messages and uploads, regulated identifiers, scan results, API keys, tenant data, encryption keys, community reports, and audit records.

## Trust boundaries and actors

Unauthenticated consumers, tenant API clients, administrators/moderators, browser clients, OpenAI, database/cache/object-storage services, and channel providers are separate trust boundaries. Submitted content is hostile and may contain prompt injection, malformed files, private identifiers, forged payment alerts, or malicious URLs.

## Main threats and controls

- PII exposure through logs, model prompts, database dumps, or public reputation lookup: redact before model use; scrub logs; encrypt retained fields; use HMAC blind indexes; expose aggregates only.
- Prompt injection: scanned content is serialized as untrusted data; no tools are available to the model; validate structured output; deterministic rules and confirmed intelligence remain authoritative.
- Tenant data access: require tenant-scoped queries and PostgreSQL RLS; use tenant-bound AEAD associated data.
- SSRF and malicious uploads: do not fetch URLs in the API process; isolate fetch worker, validate each redirect and DNS result, limit content; sniff/re-encode files and scan for malware before storage.
- Credential theft/replay: store API-key HMAC only; scope and revoke keys; sign webhooks with timestamp and replay nonce; use secure cookies and CSRF protection for browser sessions.
- Abuse and availability: enforce request/file limits, rate limits by identity and network, queue backpressure, timeouts, circuit breakers, and rules-only degradation.
- Fraud false negatives/positives: measure with held-out, self-authored cases and per-language native-speaker-reviewed cases; provide feedback and dispute/takedown processes.

## Operational requirements

Production needs TLS 1.2+, strict CSP/HSTS, managed secrets/KMS, encrypted backups, verified restore drills, dependency and secret scanning, key rotation, alerting, incident response, and a privacy/legal review. These controls are release gates, not implied by local development configuration.
