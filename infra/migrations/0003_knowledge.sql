-- Milestone 8 knowledge base: shared, read-only reference data used by rules and lookups.
-- These tables hold no personal data, so they are not tenant-scoped or RLS-protected.

CREATE TABLE scam_templates (
  id text PRIMARY KEY,
  scam_type text NOT NULL,
  language text NOT NULL,
  phrase text NOT NULL,
  source text NOT NULL DEFAULT 'self-authored',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scam_templates_language_idx ON scam_templates (language, scam_type);

CREATE TABLE brand_registry (
  name text PRIMARY KEY,
  aliases text[] NOT NULL,
  official_domains text[] NOT NULL,
  sector text NOT NULL CHECK (sector IN ('bank','fintech','telco','regulator')),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE legitimate_patterns (
  id text PRIMARY KEY,
  description text NOT NULL,
  patterns text[] NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
