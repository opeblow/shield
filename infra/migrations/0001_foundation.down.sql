DROP FUNCTION IF EXISTS resolve_api_key(text);
DROP TABLE IF EXISTS api_keys, scans, users, tenants CASCADE;
DROP EXTENSION IF EXISTS pgcrypto;
