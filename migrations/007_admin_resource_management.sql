ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_allocatable_cpu integer;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_allocatable_memory_mb integer;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_allocatable_disk_gb integer;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS quota_cpu integer;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS quota_memory_mb integer;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS quota_disk_gb integer;

UPDATE hosts SET
  agent_allocatable_cpu = coalesce(agent_allocatable_cpu, allocatable_cpu),
  agent_allocatable_memory_mb = coalesce(agent_allocatable_memory_mb, allocatable_memory_mb),
  agent_allocatable_disk_gb = coalesce(agent_allocatable_disk_gb, allocatable_disk_gb),
  quota_cpu = coalesce(quota_cpu, allocatable_cpu),
  quota_memory_mb = coalesce(quota_memory_mb, allocatable_memory_mb),
  quota_disk_gb = coalesce(quota_disk_gb, allocatable_disk_gb);

ALTER TABLE hosts ALTER COLUMN agent_allocatable_cpu SET NOT NULL;
ALTER TABLE hosts ALTER COLUMN agent_allocatable_memory_mb SET NOT NULL;
ALTER TABLE hosts ALTER COLUMN agent_allocatable_disk_gb SET NOT NULL;

ALTER TABLE images ADD COLUMN IF NOT EXISTS source_type text NOT NULL DEFAULT 'local';
ALTER TABLE images ADD COLUMN IF NOT EXISTS source_location text;
ALTER TABLE images ADD COLUMN IF NOT EXISTS checksum text;
ALTER TABLE images ADD COLUMN IF NOT EXISTS sync_status text NOT NULL DEFAULT 'READY';

UPDATE images SET source_location=file_name WHERE source_location IS NULL AND source_type='local';

ALTER TABLE images DROP CONSTRAINT IF EXISTS images_source_type_check;
ALTER TABLE images ADD CONSTRAINT images_source_type_check CHECK (source_type IN ('local','remote'));
ALTER TABLE images DROP CONSTRAINT IF EXISTS images_sync_status_check;
ALTER TABLE images ADD CONSTRAINT images_sync_status_check CHECK (sync_status IN ('READY','PENDING','SYNCING','FAILED'));
