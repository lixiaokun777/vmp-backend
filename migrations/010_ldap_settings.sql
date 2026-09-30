CREATE TABLE IF NOT EXISTS ldap_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  configured boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT false,
  url text NOT NULL DEFAULT '',
  start_tls boolean NOT NULL DEFAULT false,
  bind_dn text NOT NULL DEFAULT '',
  bind_password_ciphertext bytea,
  base_dn text NOT NULL DEFAULT '',
  login_filter text NOT NULL DEFAULT '(uid=%s)',
  sync_filter text NOT NULL DEFAULT '(objectClass=person)',
  username_attribute text NOT NULL DEFAULT 'uid',
  display_name_attribute text NOT NULL DEFAULT 'cn',
  email_attribute text NOT NULL DEFAULT 'mail',
  updated_by text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO ldap_settings(singleton) VALUES(true)
ON CONFLICT(singleton) DO NOTHING;
