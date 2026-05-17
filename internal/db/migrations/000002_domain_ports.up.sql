ALTER TABLE domain_chains
  DROP CONSTRAINT IF EXISTS domain_chains_domain_fkey;

ALTER TABLE domains
  ADD COLUMN IF NOT EXISTS port integer NOT NULL DEFAULT 443;

ALTER TABLE domains
  ADD CONSTRAINT domains_port_check CHECK (port BETWEEN 1 AND 65535);

ALTER TABLE domains
  DROP CONSTRAINT IF EXISTS domains_pkey;

ALTER TABLE domains
  ADD PRIMARY KEY (domain, port);

ALTER TABLE domain_chains
  ADD COLUMN IF NOT EXISTS port integer NOT NULL DEFAULT 443;

ALTER TABLE domain_chains
  ADD CONSTRAINT domain_chains_port_check CHECK (port BETWEEN 1 AND 65535);

ALTER TABLE domain_chains
  DROP CONSTRAINT IF EXISTS domain_chains_pkey;

ALTER TABLE domain_chains
  ADD PRIMARY KEY (domain, port, chain_hash);

ALTER TABLE domain_chains
  ADD CONSTRAINT domain_chains_domain_port_fkey
  FOREIGN KEY (domain, port) REFERENCES domains(domain, port) ON DELETE CASCADE;

COMMENT ON COLUMN domains.port IS 'TCP port used for TLS certificate observation. Defaults to 443.';
COMMENT ON COLUMN domain_chains.port IS 'TCP port used when this chain was observed for the domain.';
