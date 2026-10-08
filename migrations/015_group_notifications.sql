-- 群机器人地址和签名密钥使用控制面的配置密钥加密保存。
CREATE TABLE notification_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled boolean NOT NULL DEFAULT false,
  webhook_ciphertext bytea,
  signature_ciphertext bytea,
  platform_url text NOT NULL DEFAULT '',
  reminder_hours integer[] NOT NULL DEFAULT '{24,1}',
  notify_retained boolean NOT NULL DEFAULT true,
  notify_retention_end boolean NOT NULL DEFAULT true,
  mention_owner boolean NOT NULL DEFAULT true,
  enabled_since timestamptz,
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO notification_settings(singleton) VALUES(true);

-- 每个实例的同一租期、同一提醒阶段只生成一条事件；发送状态跨重启保留。
CREATE TABLE notification_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  instance_id uuid,
  kind text NOT NULL,
  target_at timestamptz NOT NULL,
  instance_name text NOT NULL DEFAULT '',
  owner_username text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','SENT','FAILED','CANCELLED')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text NOT NULL DEFAULT '',
  message text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  UNIQUE(instance_id,kind,target_at)
);
CREATE INDEX notification_events_pending_idx ON notification_events(next_attempt_at) WHERE status='PENDING';
CREATE INDEX notification_events_created_idx ON notification_events(created_at DESC);
