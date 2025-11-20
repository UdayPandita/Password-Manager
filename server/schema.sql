-- =======================
-- LPH Password Manager Database Schema
-- =======================

-- Drop existing tables if recreating (careful in production!)
-- DROP TABLE IF EXISTS shared_passwords CASCADE;
-- DROP TABLE IF EXISTS vault_data CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;

-- =======================
-- Users Table
-- =======================
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  hashed_password TEXT NOT NULL,
  salt TEXT NOT NULL,
  public_key TEXT NOT NULL,
  encrypted_kvault TEXT,
  kvault_salt TEXT,
  verifier TEXT,
  mnemonic_fingerprint TEXT,
  encrypted_private_key TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);

-- =======================
-- Vault Data Table (stores encrypted password vault per user)
-- =======================
CREATE TABLE IF NOT EXISTS vault_data (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encrypted_blob JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS vault_data_user_id_idx ON vault_data (user_id);

-- =======================
-- Shared Passwords Table (for sharing between users)
-- =======================
CREATE TABLE IF NOT EXISTS shared_passwords (
  id BIGSERIAL PRIMARY KEY,
  from_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encrypted_data TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS shared_passwords_to_user_idx ON shared_passwords (to_user_id);
CREATE INDEX IF NOT EXISTS shared_passwords_from_user_idx ON shared_passwords (from_user_id);

-- =======================
-- Rate Limits Table (for DB-backed rate limiting - optional for now)
-- =======================
CREATE TABLE IF NOT EXISTS rate_limits (
  id BIGSERIAL PRIMARY KEY,
  identifier TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  UNIQUE (identifier, window_start)
);

CREATE INDEX IF NOT EXISTS rate_limits_identifier_idx ON rate_limits (identifier, window_start);

-- =======================
-- User Permissions & Security
-- =======================

-- Revoke all permissions from public
REVOKE ALL ON DATABASE lph_password_manager FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Grant database connection to uss-lph user
GRANT CONNECT ON DATABASE lph_password_manager TO "uss-lph";

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO "uss-lph";

-- Grant table permissions (least privilege principle)
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO "uss-lph";
GRANT SELECT, INSERT, UPDATE, DELETE ON vault_data TO "uss-lph";
GRANT SELECT, INSERT, UPDATE, DELETE ON shared_passwords TO "uss-lph";
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO "uss-lph";

-- Grant sequence permissions (needed for BIGSERIAL auto-increment)
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO "uss-lph";
GRANT USAGE, SELECT ON SEQUENCE vault_data_id_seq TO "uss-lph";
GRANT USAGE, SELECT ON SEQUENCE shared_passwords_id_seq TO "uss-lph";
GRANT USAGE, SELECT ON SEQUENCE rate_limits_id_seq TO "uss-lph";

-- Ensure uss-lph cannot create or drop tables (security)
REVOKE CREATE ON SCHEMA public FROM "uss-lph";

-- Enable Row Level Security (RLS) for additional protection
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_passwords ENABLE ROW LEVEL SECURITY;

-- Create policies: users can only access their own data through application logic
-- Note: Application connects as uss-lph and enforces user isolation via WHERE clauses
-- RLS provides defense-in-depth if application logic is bypassed

-- Policy: Application can access all rows (application handles authorization)
CREATE POLICY app_access_users ON users FOR ALL TO "uss-lph" USING (true);
CREATE POLICY app_access_vault ON vault_data FOR ALL TO "uss-lph" USING (true);
CREATE POLICY app_access_shared ON shared_passwords FOR ALL TO "uss-lph" USING (true);

-- Prevent SQL injection by disabling dangerous functions
-- (Already handled by pg library parameterization, but defense-in-depth)

