-- 超过七天的创建、续期和保留期恢复统一进入审批，不提前预占资源。
CREATE TABLE IF NOT EXISTS approval_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_no text NOT NULL UNIQUE,
  request_type text NOT NULL CHECK (request_type IN ('CREATE', 'RENEW', 'RESTORE')),
  applicant text NOT NULL,
  instance_id uuid REFERENCES instances(id) ON DELETE SET NULL,
  requested_hours integer NOT NULL CHECK (requested_hours BETWEEN 1 AND 720),
  reason text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'APPROVED', 'REJECTED', 'FAILED')),
  reviewer text,
  review_comment text NOT NULL DEFAULT '',
  reviewed_at timestamptz,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS approval_requests_status_created_idx
ON approval_requests(status, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_pending_instance_idx
ON approval_requests(instance_id, request_type)
WHERE status IN ('PENDING', 'PROCESSING') AND instance_id IS NOT NULL;
