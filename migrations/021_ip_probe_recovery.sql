-- 隔离地址只能由一次新鲜、已认证的探测结果安全解除；不自动清空旧隔离记录。
ALTER TABLE ip_addresses ADD COLUMN last_probe_status text NOT NULL DEFAULT 'UNKNOWN' CHECK(last_probe_status IN ('UNKNOWN','PENDING','FREE','IN_USE','ERROR'));
ALTER TABLE ip_addresses ADD COLUMN last_probe_at timestamptz;
ALTER TABLE ip_addresses ADD COLUMN last_probe_message text NOT NULL DEFAULT '';
ALTER TABLE ip_addresses ADD COLUMN last_probe_host_id uuid REFERENCES hosts(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX tasks_one_active_ip_probe ON tasks(resource_id) WHERE task_type='PROBE_IP_ADDRESS' AND status IN ('PENDING','RUNNING');
ALTER TABLE tasks ADD COLUMN ip_conflict_count integer NOT NULL DEFAULT 0 CHECK(ip_conflict_count>=0);

-- 原失败实例的自动复核有有限候选集合；并发重试复用同一流程，不重复占预算。
ALTER TABLE instances ADD COLUMN ip_recovery_pending boolean NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN ip_recovery_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN ip_recovery_tried uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE instances ADD COLUMN ip_recovery_task_id uuid;
ALTER TABLE instances ADD COLUMN ip_recovery_message text NOT NULL DEFAULT '';

-- 恢复仅在真正启动成功后消耗恢复次数；失败仍回到原保留截止和原磁盘/IP。
ALTER TABLE instances ADD COLUMN restore_pending boolean NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN restore_previous_expires_at timestamptz;
