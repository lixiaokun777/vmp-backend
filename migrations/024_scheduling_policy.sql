-- 升级继续使用剩余内存优先，不移动已有实例；轮询进度与资源预占同事务提交。
ALTER TABLE platform_policy ADD COLUMN scheduling_strategy text NOT NULL DEFAULT 'MOST_AVAILABLE'
 CHECK (scheduling_strategy IN ('MOST_AVAILABLE','ROUND_ROBIN','BALANCED'));
ALTER TABLE hosts ADD COLUMN last_scheduled_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN last_scheduled_at timestamptz;
ALTER TABLE instances ADD COLUMN scheduling_decision jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE TABLE scheduler_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 sequence bigint NOT NULL DEFAULT 0,
 last_host_id text NOT NULL DEFAULT '',
 last_host_name text NOT NULL DEFAULT '',
 last_host_created_at timestamptz NOT NULL DEFAULT 'epoch',
 last_scheduled_at timestamptz
);
INSERT INTO scheduler_state(singleton) VALUES(true);
