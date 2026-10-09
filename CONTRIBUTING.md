# Contributing to Shield

Thanks for helping improve Shield. This is a privacy-sensitive fraud-prevention
project, so a few rules are strict on purpose.

## Ground rules

- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Never commit real customer data, credentials, or secrets.
- Do not add emoji to source, docs, or commit messages. Keep the codebase plain text.
- Report security issues privately per [SECURITY.md](SECURITY.md), not in an issue or PR.

## Getting started

Requirements: Node.js 22 or newer and npm. No third-party account is needed for
the local rules-based scanner.

```
git clone https://github.com/opeblow/shield.git
cd shield
npm install
cp .env.example .env      # PowerShell: Copy-Item .env.example .env
npm run dev               # serves the API and PWA at http://localhost:3001
```

## Before you open a pull request

Run every check locally and make sure it is green:

```
npm run typecheck
npm run lint
npm test
npm run eval
```

CI runs the same commands (`.github/workflows/ci.yml`). A PR is not ready while any
of them fail, and eval metrics must not regress.

## Code conventions

- TypeScript, ESM, `NodeNext` resolution: relative imports must end in `.js`.
- The compiler runs with `strict`, `noUncheckedIndexedAccess`, and
  `exactOptionalPropertyTypes`. Prefer optional-property spreads over assigning
  `undefined`.
- Do not add new runtime dependencies. The project intentionally stays close to
  Node built-ins plus `zod`, `pg`, and `redis`. Discuss a new dependency in an
  issue first.
- Validation lives in `apps/api/src/validation.ts` using `zod`. Every new endpoint
  needs a schema and a negative test.
- Keep secrets out of code and logs. Redact via `packages/shared/src/redaction.ts`
  and log through `packages/shared/src/safe-log.ts`.
- Match the surrounding style. Do not reformat unrelated lines.

## Tests

- Add unit tests under `tests/` (compiled) or as `.mjs` where a browser API is
  required. New pure modules should get a focused test in `tests/platform.test.ts`
  or a new sibling file added to the `test` script.
- Cover the negative path, not just the happy path. For anything auth- or
  money-related, include the "must fail" case.

## Commits and pull requests

- One logical change per commit. Write an imperative subject line, for example
  "Add webhook replay guard".
- Describe what changed and why in the PR body, note any migration or config
  change, and link the relevant issue.
- Do not commit generated `dist/` output or `.env` files.

## Migrations and data

- Add a new numbered file in `infra/migrations/`; never edit an applied migration.
- Tenant-scoped tables must enable row-level security and a matching policy.
  Shared reference data (no personal data) may remain unscoped and documented as such.
