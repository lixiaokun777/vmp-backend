-- 登录计数使用数据库原子更新，多副本和重启共享限制。
CREATE TABLE login_attempt_buckets (
    bucket_key text PRIMARY KEY,
    attempts integer NOT NULL CHECK (attempts > 0),
    expires_at timestamptz NOT NULL
);
CREATE INDEX login_attempt_buckets_expiry ON login_attempt_buckets(expires_at);
