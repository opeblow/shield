# Draft legal text — not approved for production

These draft clauses are internal working material only. Do not publish, present them as effective terms, or process customer data on their basis until Shield's legal entity details, processing roles, contact channels, lawful bases, cross-border transfer approach, and operational rights flows are confirmed by qualified Nigerian privacy counsel. This review must consider the Nigeria Data Protection Act 2023 and the NDPC General Application and Implementation Directive 2025.

## Draft terms of use

Shield provides indicators that may help a person pause and verify a suspicious communication. A scan is not a guarantee, a bank decision, or a determination that a person or account committed an offence. A result saying no signs were found does not prove the message is authentic. Users should confirm payment information using their bank's official app or independently verified contact details.

Do not submit PINs, passwords, one-time codes, or information you do not have permission to share. Do not use Shield to harass, expose, or make unsupported accusations about another person. Public reputation information, if enabled, must use moderated, factual report counts and an accessible dispute/takedown process.

## Draft privacy notice

**Controller identity and contact:** Must be completed with the actual Shield operating entity, address, privacy contact, and data-protection contact after legal review.

**Information and purpose:** A scan may contain messages, links, account/phone references, attachments, and the resulting risk assessment. The service uses submitted material to return a warning, protect the service, and—only after a separate affirmative choice—receive feedback or contribute a report. Avoid collecting information that is not needed for those purposes.

**Model provider:** When configured, Shield sends deterministically redacted scan text and rule signals to OpenAI for a structured assessment. Shield sets `store: false`; this is not a claim of Zero Data Retention. OpenAI's default API abuse-monitoring retention may be up to 30 days, and ZDR/Modified Abuse Monitoring requires eligibility and approval. See [Shield's AI data-handling note](../AI_DATA_HANDLING.md).

**Retention and security:** The current implementation does not retain submitted text. When PostgreSQL persistence is enabled, the current adapter stores a minimal scan summary and a content hash for 24 hours by default; it omits raw text, extracted identifiers, reason evidence, and model prompt. Upload storage and deletion workflows are not implemented. Do not state that a right-to-erasure request is fully automated until deletion is built and verified.

**Rights and complaints:** The final notice must explain how to request access, correction, objection/restriction, portability, deletion where applicable, and how to contact the Nigeria Data Protection Commission. A staffed and tested request process and current contact details must be supplied before publication.

**International processing:** Complete the recipient, country, transfer basis, safeguards, and retention details for each actual provider and deployment region before launch. The current deployment region is not configured.

## Draft data processing agreement outline

Complete and negotiate this agreement for each enterprise tenant. Identify controller and processor roles for each processing purpose, the documented instructions, data-subject categories, personal-data categories, duration, confidentiality commitments, security measures, subprocessors and locations, assistance with rights requests and breach response, deletion/return at termination, audit evidence, and transfer safeguards. Attach the active retention schedule and security controls. Do not claim controls that are not enabled in the deployment.

## Review sources

- [Nigeria Data Protection Act 2023 — Nigeria Computer Emergency Response Team resources](https://cert.gov.ng/resources)
- [NDP Act General Application and Implementation Directive 2025 — Nigeria Data Protection Commission](https://ndpc.gov.ng/wp-content/uploads/2025/07/NDP-ACT-GAID-2025-MARCH-20TH.pdf)
- [NDPC data-subject rights overview](https://ftp.ndpc.gov.ng/)
