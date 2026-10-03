-- 完善审批超时、撤回、执行失败状态，并限制保留期恢复次数。
ALTER TABLE approval_requests
  DROP CONSTRAINT IF EXISTS approval_requests_status_check;

ALTER TABLE approval_requests
  ADD CONSTRAINT approval_requests_status_check
  CHECK (status IN ('PENDING','PROCESSING','APPROVED','APPROVED_FAILED','REJECTED','EXPIRED','WITHDRAWN','FAILED'));

ALTER TABLE approval_requests
  ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours');

CREATE INDEX IF NOT EXISTS approval_requests_pending_expiry_idx
ON approval_requests(expires_at)
WHERE status='PENDING';

ALTER TABLE instances
  ADD COLUMN IF NOT EXISTS restore_count integer NOT NULL DEFAULT 0 CHECK (restore_count BETWEEN 0 AND 1);
