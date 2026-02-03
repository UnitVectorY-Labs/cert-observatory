-- Drop all tables and types in reverse order of creation

DROP TABLE IF EXISTS domain_chains;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS chains;
DROP TABLE IF EXISTS certificates;

DROP TYPE IF EXISTS crawl_mode;
