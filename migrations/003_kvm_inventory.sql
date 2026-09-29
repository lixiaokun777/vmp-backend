ALTER TABLE hosts ADD COLUMN IF NOT EXISTS facts jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_inventory_at timestamptz;

CREATE TABLE IF NOT EXISTS discovered_instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  provider_uuid text NOT NULL,
  name text NOT NULL,
  state text NOT NULL,
  vcpus integer NOT NULL DEFAULT 0,
  memory_mb integer NOT NULL DEFAULT 0,
  ownership text NOT NULL DEFAULT 'EXTERNAL' CHECK (ownership IN ('MANAGED','EXTERNAL','UNKNOWN')),
  platform_instance_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(host_id, provider_uuid)
);

CREATE INDEX IF NOT EXISTS discovered_instances_host_idx ON discovered_instances(host_id, ownership, state);
