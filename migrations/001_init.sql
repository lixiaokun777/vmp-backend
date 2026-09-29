CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE hosts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  provider_type text NOT NULL DEFAULT 'kvm',
  agent_mode text NOT NULL DEFAULT 'mock',
  status text NOT NULL DEFAULT 'REGISTERING',
  management_ip inet,
  allocatable_cpu integer NOT NULL CHECK (allocatable_cpu >= 0),
  allocatable_memory_mb integer NOT NULL CHECK (allocatable_memory_mb >= 0),
  allocatable_disk_gb integer NOT NULL CHECK (allocatable_disk_gb >= 0),
  reserved_cpu integer NOT NULL DEFAULT 0,
  reserved_memory_mb integer NOT NULL DEFAULT 0,
  reserved_disk_gb integer NOT NULL DEFAULT 0,
  last_heartbeat_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE flavors (
  id text PRIMARY KEY,
  name text NOT NULL,
  cpu integer NOT NULL,
  memory_mb integer NOT NULL,
  disk_gb integer NOT NULL,
  enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE images (
  id text PRIMARY KEY,
  name text NOT NULL,
  os_family text NOT NULL,
  version text NOT NULL,
  enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_no text NOT NULL UNIQUE,
  applicant text NOT NULL,
  instance_name text NOT NULL,
  purpose text NOT NULL,
  flavor_id text NOT NULL REFERENCES flavors(id),
  image_id text NOT NULL REFERENCES images(id),
  lease_hours integer NOT NULL CHECK (lease_hours BETWEEN 1 AND 720),
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz
);

CREATE TABLE instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id uuid NOT NULL UNIQUE REFERENCES applications(id),
  host_id uuid REFERENCES hosts(id),
  name text NOT NULL UNIQUE,
  provider_ref text,
  provider_type text NOT NULL DEFAULT 'kvm',
  lifecycle_status text NOT NULL,
  provider_status text NOT NULL DEFAULT 'UNKNOWN',
  ip_address inet,
  username text NOT NULL DEFAULT 'ubuntu',
  expires_at timestamptz NOT NULL,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key text NOT NULL UNIQUE,
  task_type text NOT NULL,
  resource_id uuid NOT NULL,
  host_id uuid REFERENCES hosts(id),
  status text NOT NULL DEFAULT 'PENDING',
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  result jsonb,
  error_message text,
  attempt integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 3,
  available_at timestamptz NOT NULL DEFAULT now(),
  claimed_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX tasks_poll_idx ON tasks(host_id, status, available_at);
CREATE INDEX instances_status_idx ON instances(lifecycle_status);

CREATE TABLE audit_logs (
  id bigserial PRIMARY KEY,
  actor text NOT NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO flavors(id, name, cpu, memory_mb, disk_gb) VALUES
  ('c1m2', '轻量型 1C2G', 1, 2048, 40),
  ('c2m4', '标准型 2C4G', 2, 4096, 60),
  ('c4m8', '增强型 4C8G', 4, 8192, 100);

INSERT INTO images(id, name, os_family, version) VALUES
  ('ubuntu-2204', 'Ubuntu Server 22.04 LTS', 'ubuntu', '22.04'),
  ('ubuntu-2404', 'Ubuntu Server 24.04 LTS', 'ubuntu', '24.04');
