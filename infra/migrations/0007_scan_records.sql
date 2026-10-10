-- Server-side scan records: the authoritative source for verifiable check
-- cards. A certificate can only be sealed from a record created here, so a
-- client can never mint a "safe" card for a scam message. Rows expire after
-- 48 hours (enforced on read by the store).

CREATE TABLE IF NOT EXISTS scan_records (
  scan_id uuid PRIMARY KEY,
  owner_id uuid,
  tenant_id uuid,
  verdict text NOT NULL CHECK (verdict IN ('safe', 'caution', 'likely_scam', 'scam')),
  risk_score integer NOT NULL,
  scam_types text[] NOT NULL DEFAULT '{}',
  language text NOT NULL,
  redacted_text text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_records_created ON scan_records (created_at DESC);
CREATE INDEX IF NOT EXISTS scan_records_owner ON scan_records (owner_id, created_at DESC);
ALTER TABLE scan_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_records FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_records_tenant_isolation ON scan_records
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
