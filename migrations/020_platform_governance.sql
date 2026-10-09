-- 配额默认不限制，自动续期默认关闭；历史默认永久保留，升级不删除历史数据。
CREATE TABLE platform_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 max_instances integer NOT NULL DEFAULT 0 CHECK(max_instances>=0),
 max_cpu integer NOT NULL DEFAULT 0 CHECK(max_cpu>=0),
 max_memory_mb integer NOT NULL DEFAULT 0 CHECK(max_memory_mb>=0),
 max_disk_gb integer NOT NULL DEFAULT 0 CHECK(max_disk_gb>=0),
 max_future_lease_hours integer NOT NULL DEFAULT 0 CHECK(max_future_lease_hours BETWEEN 0 AND 876000),
 max_continuous_lease_hours integer NOT NULL DEFAULT 0 CHECK(max_continuous_lease_hours BETWEEN 0 AND 876000),
 auto_renew_enabled boolean NOT NULL DEFAULT false,
 auto_renew_max_count integer NOT NULL DEFAULT 3 CHECK(auto_renew_max_count BETWEEN 1 AND 100),
 auto_renew_hours integer NOT NULL DEFAULT 24 CHECK(auto_renew_hours BETWEEN 1 AND 168),
 audit_retention_days integer NOT NULL DEFAULT 0 CHECK(audit_retention_days=0 OR audit_retention_days>=180),
 notification_retention_days integer NOT NULL DEFAULT 0 CHECK(notification_retention_days=0 OR notification_retention_days>=30),
 approval_retention_days integer NOT NULL DEFAULT 0 CHECK(approval_retention_days=0 OR approval_retention_days>=90),
 updated_by text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO platform_policy(singleton) VALUES(true);
CREATE TABLE instance_auto_renew (
 instance_id uuid PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
 enabled boolean NOT NULL DEFAULT false,
 hours integer NOT NULL CHECK(hours BETWEEN 1 AND 168),
 max_renewals integer NOT NULL CHECK(max_renewals BETWEEN 1 AND 100),
 renewed_count integer NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE approval_delegations (
 owner_username text PRIMARY KEY,
 delegate_username text NOT NULL,
 starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL,
 CHECK(ends_at>starts_at AND ends_at<=starts_at+interval '90 days'),
 CHECK(owner_username<>delegate_username)
);
ALTER TABLE approval_requests ADD COLUMN assigned_reviewer text;
ALTER TABLE approval_requests ADD COLUMN delegated_from text;
CREATE INDEX approval_assignee_idx ON approval_requests(assigned_reviewer) WHERE status='PENDING';
-- 归档是有限大小、可下载并校验的压缩 NDJSON，清理源记录必须二次确认。
CREATE TABLE history_archives (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), category text NOT NULL CHECK(category IN ('audit','notifications','approvals')),
 checksum text NOT NULL, row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 5000),
 source_ids text[] NOT NULL, source_hashes text[] NOT NULL, data bytea NOT NULL, cutoff timestamptz NOT NULL,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 downloaded_at timestamptz, purged_at timestamptz
);
ALTER TABLE notification_settings ADD COLUMN notify_approvals boolean NOT NULL DEFAULT true;
ALTER TABLE notification_settings ADD COLUMN notify_failures boolean NOT NULL DEFAULT true;
ALTER TABLE notification_settings ADD COLUMN notify_host_alerts boolean NOT NULL DEFAULT true;
-- 与租期通知分开的平台事件队列，事件键去重，心跳只在异常/恢复边沿生成事件。
CREATE TABLE platform_notification_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_key text NOT NULL UNIQUE,
 kind text NOT NULL, resource_id text NOT NULL, title text NOT NULL, detail text NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','FAILED','CANCELLED')),
 attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
 last_error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz
);
CREATE TABLE host_notification_state (
 host_id uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
 offline boolean NOT NULL, transition_at timestamptz NOT NULL DEFAULT now()
);
