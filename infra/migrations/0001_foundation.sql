CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  plan text NOT NULL DEFAULT 'free',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  data_sharing_opt_in boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  email_cipher jsonb,
  email_blind_index text UNIQUE,
  role text NOT NULL DEFAULT 'consumer' CHECK (role IN ('consumer','analyst','admin','owner')),
  language text NOT NULL DEFAULT 'en' CHECK (language IN ('en','pcm','yo','ha','ig')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  input_types text[] NOT NULL,
  verdict text NOT NULL CHECK (verdict IN ('safe','caution','likely_scam','scam')),
  risk_score smallint NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  confidence numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  scam_types text[] NOT NULL DEFAULT '{}',
  language text NOT NULL,
  latency_ms integer NOT NULL CHECK (latency_ms >= 0),
  model_version text NOT NULL,
  content_hash text NOT NULL,
  redacted_input_cipher jsonb,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX scans_tenant_created_idx ON scans (tenant_id, created_at DESC);
CREATE INDEX scans_hash_idx ON scans (content_hash, created_at DESC);
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
CREATE POLICY scans_tenant_isolation ON scans
  USING (tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key_id text NOT NULL UNIQUE, key_hash text NOT NULL, scopes text[] NOT NULL, expires_at timestamptz,
  revoked_at timestamptz, last_used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_keys_tenant_isolation ON api_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE ALL ON api_keys FROM PUBLIC;
CREATE FUNCTION resolve_api_key(p_key_id text)
RETURNS TABLE(tenant_id uuid, key_hash text, scopes text[])
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public.api_keys
  SET last_used_at = now()
  WHERE key_id = p_key_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
  RETURNING public.api_keys.tenant_id, public.api_keys.key_hash, public.api_keys.scopes
$$;
REVOKE ALL ON FUNCTION resolve_api_key(text) FROM PUBLIC;
CREATE TABLE entities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), type text NOT NULL CHECK (type IN ('url','phone','account','domain','brand')),
  blind_index text NOT NULL, pepper_version text NOT NULL, normalized_cipher jsonb,
  first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
  UNIQUE(type, blind_index, pepper_version)
);
CREATE TABLE scan_entities (scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE, entity_id uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE, PRIMARY KEY(scan_id, entity_id));
CREATE TABLE entity_reputation (
  entity_id uuid PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
  report_count integer NOT NULL DEFAULT 0 CHECK (report_count >= 0),
  verified_count integer NOT NULL DEFAULT 0 CHECK (verified_count >= 0 AND verified_count <= report_count),
  score numeric(5,2) NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
  last_computed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), entity_id uuid NOT NULL REFERENCES entities(id),
  reporter_blind_index text, scam_type text NOT NULL, description_cipher jsonb,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','rejected','disputed')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reports_pending_created_idx ON reports (created_at) WHERE status = 'pending';
CREATE INDEX reports_entity_created_idx ON reports (entity_id, created_at DESC);
CREATE TABLE feedback (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE, label text NOT NULL, comment_cipher jsonb, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE audit_logs (
  id bigserial PRIMARY KEY, tenant_id uuid REFERENCES tenants(id), actor text NOT NULL, action text NOT NULL,
  target text NOT NULL, prev_hash text NOT NULL, entry_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX audit_logs_entry_hash_unique ON audit_logs (entry_hash);
