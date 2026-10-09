-- 分配快照不随管理员编辑规格而变化，旧实例优先从首次创建任务恢复实际资源。
ALTER TABLE instances ADD COLUMN allocated_cpu integer;
ALTER TABLE instances ADD COLUMN allocated_memory_mb integer;
ALTER TABLE instances ADD COLUMN allocated_disk_gb integer;
ALTER TABLE instances ADD COLUMN flavor_name_snapshot text;
ALTER TABLE instances ADD COLUMN allocation_snapshot_source text NOT NULL DEFAULT 'ALLOCATION';

UPDATE instances i SET
  allocated_cpu=coalesce((SELECT (t.payload->>'cpu')::integer FROM tasks t WHERE t.resource_id=i.id AND t.task_type='CREATE_INSTANCE' AND (t.payload->>'cpu') ~ '^[0-9]{1,8}$' ORDER BY t.created_at LIMIT 1),f.cpu),
  allocated_memory_mb=coalesce((SELECT (t.payload->>'memory_mb')::integer FROM tasks t WHERE t.resource_id=i.id AND t.task_type='CREATE_INSTANCE' AND (t.payload->>'memory_mb') ~ '^[0-9]{1,8}$' ORDER BY t.created_at LIMIT 1),f.memory_mb),
  allocated_disk_gb=coalesce((SELECT (t.payload->>'disk_gb')::integer FROM tasks t WHERE t.resource_id=i.id AND t.task_type='CREATE_INSTANCE' AND (t.payload->>'disk_gb') ~ '^[0-9]{1,8}$' ORDER BY t.created_at LIMIT 1),f.disk_gb),
  flavor_name_snapshot=f.name,
  allocation_snapshot_source=CASE WHEN EXISTS(SELECT 1 FROM tasks t WHERE t.resource_id=i.id AND t.task_type='CREATE_INSTANCE' AND (t.payload->>'cpu') ~ '^[0-9]{1,8}$' AND (t.payload->>'memory_mb') ~ '^[0-9]{1,8}$' AND (t.payload->>'disk_gb') ~ '^[0-9]{1,8}$') THEN 'CREATE_TASK' ELSE 'FLAVOR_FALLBACK' END
FROM applications a JOIN flavors f ON f.id=a.flavor_id WHERE a.id=i.application_id;

ALTER TABLE instances ALTER COLUMN allocated_cpu SET NOT NULL;
ALTER TABLE instances ALTER COLUMN allocated_memory_mb SET NOT NULL;
ALTER TABLE instances ALTER COLUMN allocated_disk_gb SET NOT NULL;
ALTER TABLE instances ALTER COLUMN flavor_name_snapshot SET NOT NULL;
ALTER TABLE instances ADD CONSTRAINT instances_allocation_positive CHECK (allocated_cpu>0 AND allocated_memory_mb>0 AND allocated_disk_gb>0);

-- 修复已发生的规格变更扣账错误；保留期和失败实例仍持有磁盘/IP，必须继续占用预算。
UPDATE hosts h SET reserved_cpu=coalesce(s.cpu,0),reserved_memory_mb=coalesce(s.memory_mb,0),reserved_disk_gb=coalesce(s.disk_gb,0),updated_at=now()
FROM (SELECT h2.id,sum(i.allocated_cpu)::integer AS cpu,sum(i.allocated_memory_mb)::integer AS memory_mb,sum(i.allocated_disk_gb)::integer AS disk_gb FROM hosts h2 LEFT JOIN instances i ON i.host_id=h2.id AND i.lifecycle_status<>'RELEASED' GROUP BY h2.id) s
WHERE h.id=s.id;

-- 领取令牌为每次尝试的隔离栅栏，过期旧尝试不得修改新任务和资源状态。
ALTER TABLE tasks ADD COLUMN claim_token text;
ALTER TABLE tasks ADD COLUMN lease_until timestamptz;
CREATE INDEX tasks_lease_expiry_idx ON tasks(lease_until) WHERE status='RUNNING';
UPDATE tasks SET lease_until=coalesce(claimed_at,updated_at)+interval '60 seconds' WHERE status='RUNNING';

-- 删除任务会随实例清除，独立确认回执用于安全接受上报重试，不保存密码或完整任务负载。
CREATE TABLE task_completion_receipts (
  task_id uuid NOT NULL,
  host_id uuid NOT NULL,
  claim_token_hash text NOT NULL,
  result_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(task_id,claim_token_hash)
);
CREATE INDEX task_completion_receipts_expiry_idx ON task_completion_receipts(created_at);

-- 旧版本 PROCESSING 无法证明续期等操作是否已经执行，绝不自动重放副作用。
UPDATE approval_requests SET status='FAILED',result=coalesce(result,'{}'::jsonb)||jsonb_build_object('execution_uncertain',true,'error','旧版本审批执行中断，结果不确定；请管理员核查关联实例和审计流水，不可直接重提'),updated_at=now() WHERE status='PROCESSING';
