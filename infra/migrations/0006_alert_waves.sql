-- Fraud-wave alerts: a durable ledger for detected surges of verified
-- reports against one identifier (wave detection also runs in memory).

CREATE TABLE IF NOT EXISTS fraud_waves (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('account', 'phone', 'url')),
  value_key text NOT NULL,
  label text NOT NULL,
  count integer NOT NULL,
  started_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'resolved'))
);

CREATE INDEX IF NOT EXISTS fraud_waves_key ON fraud_waves (value_key, status);
CREATE INDEX IF NOT EXISTS fraud_waves_seen ON fraud_waves (last_seen_at DESC);