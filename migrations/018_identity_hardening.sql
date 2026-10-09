-- 平台停用与目录存在状态相互独立，同步不能重新启用管理员停用的用户。
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_directory_present boolean NOT NULL DEFAULT true;

-- 每台宿主使用独立随机凭据；不导入旧全局令牌，升级时由管理员单独签发。
CREATE TABLE IF NOT EXISTS host_credentials (
  host_id uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 没有独立凭据的旧宿主禁止新增调度，重新签发、Agent 认证上报后再恢复。
UPDATE hosts SET status='CORDONED',updated_at=now()
WHERE NOT EXISTS (SELECT 1 FROM host_credentials c WHERE c.host_id=hosts.id);
