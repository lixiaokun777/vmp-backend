CREATE INDEX IF NOT EXISTS instances_expiration_idx
ON instances(lifecycle_status, expires_at, retention_until);
