-- 控制台会话由控制面集中核销，确保短时票据只能使用一次。
CREATE TABLE IF NOT EXISTS console_sessions (
  id text PRIMARY KEY,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  instance_id uuid NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
  domain text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('vnc', 'serial')),
  actor text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS console_sessions_expires_at_idx ON console_sessions(expires_at);
