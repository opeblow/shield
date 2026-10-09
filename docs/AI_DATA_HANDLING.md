# AI provider data handling

Shield sends only deterministic-redacted text and rule signals to the OpenAI Chat Completions API. The request sets `store: false`, exposes no tools, treats the message as untrusted data, and validates the structured response locally. Shield does not send unredacted account numbers, phone numbers, BVNs, NINs, card numbers, email addresses, PINs, OTPs, or passwords.

`store: false` is an application request setting; it does not establish that the account has Zero Data Retention. OpenAI's official documentation says abuse-monitoring logs may contain prompts and responses and are retained for up to 30 days by default; ZDR and Modified Abuse Monitoring require eligibility and prior approval. The organization/project controls must be checked by the account owner before any production customer data is processed. Shield has no access to those settings and makes no claim that the account is ZDR-enabled.

See [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) and [OpenAI API data controls](https://developers.openai.com/api/docs/guides/your-data).
