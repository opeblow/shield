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

## STRIDE by component

| Component / boundary | Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation of privilege |
|---|---|---|---|---|---|---|
| Consumer auth and sessions (`apps/api/src/auth.ts`, auth routes) | Credential stuffing or stolen session | Session fixation/replay or forged cookie | Dispute over account action | Password/session leakage | Login flood or expensive hashing | User-to-moderator escalation |
| API routes and validators (`server.ts`, `validation.ts`) | Forged identity/API key | Mass assignment, malformed payload | Missing action audit | Cross-user/tenant response | Oversized or pathological requests | Route scope bypass |
| Integration keys (`integration.ts`) | Stolen or guessed key | Scope/key lifecycle mutation | Unattributed integration call | Raw key or tenant data leakage | Key-based flooding | Scope confusion or tenant substitution |
| Scan/risk engine and optional OpenAI provider | Spoofed provider/result | Prompt injection or crafted scan input | Untraceable decision | PII sent to provider or unsafe output rendered | ReDoS / provider exhaustion | Model output treated as trusted instruction |
| Link preview (`preview.ts`, `url-fetch.ts`) | DNS rebinding / redirect deception | Redirect or response manipulation | Untracked outbound request | SSRF reads private/metadata services | Slow/large remote response | Pivot from API process to internal network |
| Reputation, reports, certificates and waves | Fake reports/moderator identity | Report or certificate tampering | Moderator action disputes | Identifier inference or report evidence leak | Report floods | Moderator decision without moderator credential |
| PostgreSQL, Redis and migrations | Forged service/database identity | SQL/data/schema modification | Inadequate audit trail | At-rest or cross-tenant data access | Pool exhaustion / hot queries | Overprivileged DB role |
| Browser PWA, share target and extension | Malicious origin/extension caller | DOM/input manipulation | Client action ambiguity | XSS, browser history or key exposure | Resource exhaustion | Stored XSS or stolen integration key |
| Webhook and channel adapters | Forged webhook/signature | Replay or payload mutation | Missing delivery evidence | PII in webhook/log | Retry amplification | Provider response trusted as authority |

## Product-specific abuse cases and attack-test status

Attacker goals include stealing consumer sessions or integration keys; retrieving another tenant's reports, scans, usage, or certificates; poisoning reputation with coordinated false reports; probing private network services through link preview; exhausting model/API/database capacity; and convincing a user to trust a malicious message by exploiting unsafe rendering or model output.

The local suite now includes component and HTTP attack tests for SQL/NoSQL/command/template payload handling, strict-schema mass-assignment rejection, XSS escaping in signed certificate cards, private/link-local/redirect SSRF, malformed model output and prompt injection with deterministic fallback, artifact type/size/executable rejection, password/session checks, registration races, CSRF origin checks, credential rate limiting, session-based scan-certificate IDOR, integration-key owner-scoped listing/revocation, webhook signature/replay, ReDoS-sized inputs, path traversal attempts, request smuggling framing, and security headers. The integration-key IDOR was found by testing and fixed by adding owner predicates to memory and PostgreSQL key stores; PostgreSQL ownership predicates are parameterized and use `created_by`.

The full-stack harness adds non-superuser PostgreSQL tests that enumerate every `tenant_id` table and require both RLS and FORCE RLS, then attempt cross-tenant reads, writes, updates, and deletes against actual rows. It also includes Redis Streams worker claim/ack/dead-letter tests, concurrent registration against PostgreSQL, migration up/down/up, provider timeout/error/recovery, container chaos, load profiles and backup restore. These Docker-dependent tests are implemented but remain unrun on machines without Docker; see the readiness evidence for current status.

This local evidence does not cover SQL injection against a live database, cross-tenant API-key isolation/RLS, PostgreSQL races and double-submit behavior, Redis multi-instance rate-limit abuse, DNS rebinding at a real connection, file parser fuzzing, DAST crawler coverage, or exhaustive authorization on every route and role. The API does not implement NoSQL or command execution paths; payload tests show they remain input data in the scanner, not proof about hypothetical integrations. Exact remaining machine/tooling blockers are tracked in `RESIDUAL_RISKS.md`.

Uploads currently validate type/size and reject executables; the README says server-side media analysis and storage are not wired. No upload claim is made for malware scanning or safe rendering. SSRF protection has component tests, but a running-service DAST test and DNS-rebinding integration test are still required. No money-moving endpoint exists; billing is an estimate API only.
