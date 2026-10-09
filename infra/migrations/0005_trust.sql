-- Trust layer: community reputation (works without the encrypted report pipeline)
-- and integration keys for bank/partner API access.

CREATE TABLE IF NOT EXISTS identifier_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('account', 'phone', 'url')),
  value_key text NOT NULL,
  value_label text NOT NULL,
  scam_type text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'rejected')),
  source text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz
);

CREATE INDEX IF NOT EXISTS identifier_reports_key_status ON identifier_reports (value_key, status, created_at);

CREATE TABLE IF NOT EXISTS integration_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  scopes text[] NOT NULL,
  key_hash text NOT NULL UNIQUE,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS integration_keys_hash ON integration_keys (key_hash);