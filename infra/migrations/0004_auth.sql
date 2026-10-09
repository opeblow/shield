-- Consumer email/password authentication for the web app.
-- Kept separate from the tenant-scoped users table so consumer sign-ins do not
-- require a tenant. Access is server-only (no RLS): rows are reachable solely
-- through the API process, which never exposes password hashes or raw tokens.

CREATE TABLE accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);
CREATE UNIQUE INDEX accounts_email_lower_idx ON accounts (lower(email));

CREATE TABLE auth_sessions (
  token_hash text PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX auth_sessions_account_idx ON auth_sessions (account_id);
CREATE INDEX auth_sessions_expires_idx ON auth_sessions (expires_at);
