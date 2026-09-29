CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL,
  display_name text NOT NULL DEFAULT '',
  email text NOT NULL DEFAULT '',
  role text NOT NULL DEFAULT 'USER' CHECK (role IN ('ADMIN','USER')),
  source text NOT NULL DEFAULT 'LOCAL' CHECK (source IN ('LOCAL','LDAP')),
  password_hash text,
  ldap_dn text,
  enabled boolean NOT NULL DEFAULT true,
  must_change_password boolean NOT NULL DEFAULT false,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((source='LOCAL' AND password_hash IS NOT NULL) OR (source='LDAP' AND ldap_dn IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users(lower(username));

CREATE TABLE IF NOT EXISTS user_sessions (
  token_hash bytea PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  remote_address text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS user_sessions_expiration_idx ON user_sessions(expires_at);
