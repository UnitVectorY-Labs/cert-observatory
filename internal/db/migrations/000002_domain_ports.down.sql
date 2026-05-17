ALTER TABLE domain_chains
  DROP CONSTRAINT IF EXISTS domain_chains_domain_port_fkey;

DELETE FROM domain_chains WHERE port <> 443;
DELETE FROM domains WHERE port <> 443;

ALTER TABLE domain_chains
  DROP CONSTRAINT IF EXISTS domain_chains_pkey;

ALTER TABLE domains
  DROP CONSTRAINT IF EXISTS domains_pkey;

ALTER TABLE domains
  ADD PRIMARY KEY (domain);

ALTER TABLE domain_chains
  ADD PRIMARY KEY (domain, chain_hash);

ALTER TABLE domain_chains
  ADD CONSTRAINT domain_chains_domain_fkey
  FOREIGN KEY (domain) REFERENCES domains(domain) ON DELETE CASCADE;

ALTER TABLE domain_chains
  DROP CONSTRAINT IF EXISTS domain_chains_port_check;

ALTER TABLE domain_chains
  DROP COLUMN IF EXISTS port;

ALTER TABLE domains
  DROP CONSTRAINT IF EXISTS domains_port_check;

ALTER TABLE domains
  DROP COLUMN IF EXISTS port;
