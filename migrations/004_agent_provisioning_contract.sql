ALTER TABLE images ADD COLUMN IF NOT EXISTS file_name text;

UPDATE images
SET file_name = CASE id
  WHEN 'ubuntu-2204' THEN 'ubuntu-22.04.qcow2'
  WHEN 'ubuntu-2404' THEN 'ubuntu-24.04.qcow2'
  ELSE lower(regexp_replace(id, '[^a-zA-Z0-9._-]+', '-', 'g')) || '.qcow2'
END
WHERE file_name IS NULL;

ALTER TABLE images ALTER COLUMN file_name SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS images_file_name_unique_idx ON images(file_name);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'images_file_name_safe_check'
  ) THEN
    ALTER TABLE images
      ADD CONSTRAINT images_file_name_safe_check
      CHECK (file_name ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$');
  END IF;
END
$$;
