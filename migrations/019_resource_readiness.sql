-- 总预算、平台预留和实际可再分配余量相互独立，旧报告不能假定为新协议。
ALTER TABLE hosts ADD COLUMN budget_source text NOT NULL DEFAULT 'LEGACY';
ALTER TABLE hosts ADD COLUMN safe_available_memory_mb integer;
ALTER TABLE hosts ADD COLUMN safe_available_disk_gb integer;
ALTER TABLE hosts ADD COLUMN resource_measured_at timestamptz;

ALTER TABLE images ADD COLUMN generation integer NOT NULL DEFAULT 1 CHECK(generation>0);
ALTER TABLE images ADD COLUMN desired_enabled boolean NOT NULL DEFAULT true;
UPDATE images SET desired_enabled=enabled WHERE source_type='local' OR sync_status='READY';

CREATE TABLE host_images (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  image_id text NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  generation integer NOT NULL,
  file_name text NOT NULL,
  checksum text NOT NULL DEFAULT '',
  status text NOT NULL CHECK(status IN ('READY','MISSING','SYNCING','FAILED','STALE')),
  error text NOT NULL DEFAULT '',
  reported_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  PRIMARY KEY(host_id,image_id)
);
CREATE TABLE host_networks (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  network_id uuid NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  bridge text NOT NULL,
  ready boolean NOT NULL DEFAULT false,
  error text NOT NULL DEFAULT '',
  reported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(host_id,network_id)
);

ALTER TABLE instances ADD COLUMN network_id uuid REFERENCES networks(id);
UPDATE instances i SET network_id=coalesce(
  (SELECT ip.network_id FROM ip_addresses ip WHERE ip.instance_id=i.id ORDER BY ip.address LIMIT 1),
  (SELECT n.id FROM tasks t JOIN networks n ON n.id::text=t.payload->>'network_id' WHERE t.resource_id=i.id AND t.task_type='CREATE_INSTANCE' ORDER BY t.created_at LIMIT 1)
);
ALTER TABLE instances ADD COLUMN delivery_status text NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE instances ADD COLUMN delivery_message text NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN observed_domain_status text NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE instances ADD COLUMN last_domain_seen_at timestamptz;
ALTER TABLE instances ADD COLUMN domain_missing_since timestamptz;
ALTER TABLE instances ADD COLUMN domain_missing_scans integer NOT NULL DEFAULT 0;
CREATE INDEX users_source_role_enabled_idx ON users(source,role,enabled);
CREATE INDEX instances_host_state_idx ON instances(host_id,lifecycle_status);
CREATE INDEX approvals_type_state_created_idx ON approval_requests(request_type,status,created_at DESC);
