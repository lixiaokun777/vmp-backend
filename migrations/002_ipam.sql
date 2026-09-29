CREATE TABLE IF NOT EXISTS networks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  cidr cidr NOT NULL,
  gateway inet NOT NULL,
  dns_servers text[] NOT NULL DEFAULT '{}',
  bridge text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_addresses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  network_id uuid NOT NULL REFERENCES networks(id),
  address inet NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'FREE' CHECK (status IN ('FREE','RESERVED','ALLOCATED','QUARANTINED')),
  instance_id uuid UNIQUE REFERENCES instances(id),
  reserved_at timestamptz,
  allocated_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ip_addresses_allocate_idx ON ip_addresses(network_id, status, address);

UPDATE ip_addresses ip
SET status='ALLOCATED', instance_id=i.id, allocated_at=i.created_at, updated_at=now()
FROM instances i
WHERE i.ip_address=ip.address AND ip.instance_id IS NULL;
