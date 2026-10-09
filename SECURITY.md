# Security Policy

Shield handles fraud signals that may involve personal data. We take security
reports seriously and ask that you help us protect the people who use it.

## Supported versions

Shield is under active development and has not reached a launch release yet.
Security fixes target the latest commit on the default branch. There is no
support for older snapshots.

| Version | Supported |
| --- | --- |
| default branch (0.1.x) | yes |
| older commits | no |

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a security problem.

Report privately to the maintainers through the project's private security
contact. Use GitHub Security Advisories on this repository
([opeblow/shield](https://github.com/opeblow/shield/security/advisories/new)),
or email the maintainer address listed on the repository profile. Do not send
secrets over a channel you do not trust, and do not include real customer data in
your report.

Please include, where you can:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- Affected component (for example `apps/api`, `packages/shared/src/crypto.ts`).
- Any suggested fix or mitigation.

## What to expect

- We aim to acknowledge your report within 3 business days.
- We will investigate, keep you updated on progress, and agree a disclosure
  timeline with you.
- We will credit you in the fix notes unless you ask to remain anonymous.
- Please give us a reasonable window to ship a fix before any public disclosure.

## Scope

In scope:

- Authentication and API-key handling, tenant isolation, and row-level security.
- Cryptographic handling: keyring, field encryption, blind indexes, webhook
  signing, and secret rotation.
- Injection, SSRF, request smuggling, and unsafe deserialisation.
- Data exposure through logs, error messages, and prompts sent to model providers.
- Rate-limit and abuse-control bypasses.

Out of scope:

- Findings that require a compromised device, browser, or operator host.
- Denial of service from excessive volume without a specific bypass.
- Reports about third-party services we do not control.
- Missing hardening headers with no demonstrated impact.

## Safe harbour

We will not pursue or support legal action against researchers who make a good
faith effort to comply with this policy, avoid privacy violations and service
disruption, and report findings privately before disclosure.

## Handling secrets

This repository must never contain live credentials. If you believe a secret was
committed, report it privately and treat the credential as compromised: rotate it
first, then clean history. See `docs/runbooks/KEY_ROTATION.md`.
