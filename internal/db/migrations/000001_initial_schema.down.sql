-- Drop all tables and types in reverse order of creation

DROP TABLE IF EXISTS root_source_certs;
DROP TABLE IF EXISTS root_sources;
DROP TABLE IF EXISTS domain_chain_states;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS chain_certs;
DROP TABLE IF EXISTS chains;
DROP TABLE IF EXISTS cert_signers;
DROP TABLE IF EXISTS certificates;

DROP TYPE IF EXISTS crawl_mode;
