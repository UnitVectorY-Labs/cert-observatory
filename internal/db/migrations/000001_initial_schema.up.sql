/*
cert-observatory Database Schema (PostgreSQL)

Purpose:
- Catalog TLS certificates (deduplicated by hash)
- Store exact peer-provided certificate chains (deduplicated)
- Track latest chain per domain plus historical unique chains ever observed
- Track rate limiting timestamps and basic failure/backoff for automated crawling

Non-goals:
- No trust validation or "is valid" computation
- No verified issuer graph building

Assumptions:
- Domain normalization occurs in the application layer (lowercase, no trailing dot)
- Crawling is TLS-only and SNI is always used
- Port is implicitly 443 for now
- Certificate hash is sha256 over DER bytes, stored as 32-byte bytea
- Chain hash is sha256 over the ordered list of certificate hashes (application-defined encoding)

Recommended transaction pattern:
- Insert missing certificates (upsert by hash)
- Insert missing chain (upsert by hash)
- Update domain current_chain_hash and timestamps
- Upsert domain_chains association
*/

----------------------------
-- Types
----------------------------

DO $$
BEGIN
  CREATE TYPE crawl_mode AS ENUM ('standard', 'forced', 'auto');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

COMMENT ON TYPE crawl_mode IS
'How a successful observation was triggered: standard UI fetch, forced refresh, or automated crawl.';


----------------------------
-- Certificates (immutable object store)
----------------------------

CREATE TABLE IF NOT EXISTS certificates (
  -- sha256(DER), always 32 bytes
  cert_hash     bytea PRIMARY KEY,

  -- First time this certificate was inserted into the catalog
  first_seen_at timestamptz NOT NULL DEFAULT now(),

  -- DER encoded certificate (canonical bytes that are hashed)
  der           bytea NOT NULL,

  -- Subject and Issuer distinguished names (RFC 2253 format)
  subject       text NOT NULL,
  issuer        text NOT NULL,

  -- Minimal indexed fields used for UI and operational queries
  not_before    timestamptz NULL,
  not_after     timestamptz NULL,

  -- Subject Key Identifier and Authority Key Identifier
  -- Stored as raw bytes. Length varies depending on encoding.
  ski           bytea NULL,
  aki           bytea NULL,

  CHECK (octet_length(cert_hash) = 32),
  CHECK (octet_length(der) > 0),
  CHECK (ski IS NULL OR octet_length(ski) BETWEEN 8 AND 64),
  CHECK (aki IS NULL OR octet_length(aki) BETWEEN 8 AND 64)
);

COMMENT ON TABLE certificates IS
'Immutable certificate catalog. One row per unique certificate. Keyed by sha256 of DER bytes.';
COMMENT ON COLUMN certificates.cert_hash IS 'sha256(DER) stored as 32-byte bytea.';
COMMENT ON COLUMN certificates.der IS 'DER encoded certificate bytes.';
COMMENT ON COLUMN certificates.subject IS 'Subject distinguished name in RFC 2253 format.';
COMMENT ON COLUMN certificates.issuer IS 'Issuer distinguished name in RFC 2253 format.';
COMMENT ON COLUMN certificates.not_before IS 'Certificate validity start time (from certificate).';
COMMENT ON COLUMN certificates.not_after IS 'Certificate validity end time (from certificate).';
COMMENT ON COLUMN certificates.ski IS 'Subject Key Identifier (raw bytes) if present.';
COMMENT ON COLUMN certificates.aki IS 'Authority Key Identifier (raw bytes) if present.';

-- Index for expiry queries
CREATE INDEX IF NOT EXISTS idx_cert_not_after
  ON certificates (not_after);

-- Index for issuer grouping and UI filters
CREATE INDEX IF NOT EXISTS idx_cert_issuer
  ON certificates (issuer);


----------------------------
-- Chains (exact peer-provided lists, deduplicated)
----------------------------

CREATE TABLE IF NOT EXISTS chains (
  -- sha256 of ordered certificate hash list, always 32 bytes
  chain_hash     bytea PRIMARY KEY,

  -- First time this chain was observed
  first_seen_at  timestamptz NOT NULL DEFAULT now(),

  -- Ordered array of certificate hashes (leaf-first)
  -- Note: PostgreSQL does not support foreign keys on array elements.
  -- Referential integrity is enforced by application logic: certificates
  -- are always inserted before chains within the same transaction.
  cert_hashes    bytea[] NOT NULL,

  -- Denormalized convenience columns (derived from cert_hashes)
  leaf_cert_hash bytea GENERATED ALWAYS AS (cert_hashes[1]) STORED,
  depth          integer GENERATED ALWAYS AS (array_length(cert_hashes, 1)) STORED,

  CHECK (octet_length(chain_hash) = 32),
  CHECK (array_length(cert_hashes, 1) >= 1)
);

COMMENT ON TABLE chains IS
'Deduplicated peer-provided chains. A chain is the ordered list returned by the server during TLS handshake.';
COMMENT ON COLUMN chains.chain_hash IS 'sha256 of the ordered list of cert_hash values using an application-defined encoding (version 1: 4-byte count + concatenated hashes).';
COMMENT ON COLUMN chains.cert_hashes IS 'Ordered array of certificate hashes, leaf-first.';
COMMENT ON COLUMN chains.leaf_cert_hash IS 'First certificate in the chain (derived from cert_hashes[1]).';
COMMENT ON COLUMN chains.depth IS 'Count of certificates in the chain (derived from array_length).';

-- GIN index for finding chains containing a specific certificate
CREATE INDEX IF NOT EXISTS idx_chains_cert_hashes
  ON chains USING GIN (cert_hashes);


----------------------------
-- Domains (crawl target identity and state)
----------------------------

CREATE TABLE IF NOT EXISTS domains (
  -- Normalized domain string as primary key
  domain text PRIMARY KEY,

  first_seen_at timestamptz NOT NULL DEFAULT now(),

  -- If the domain ever appeared in the imported toplist
  popular_domain boolean NOT NULL DEFAULT false,

  -- Whether automated crawler is allowed to crawl this domain
  auto_crawl boolean NOT NULL DEFAULT false,

  -- Latest successful observed chain for this domain
  current_chain_hash bytea NULL REFERENCES chains(chain_hash) ON DELETE SET NULL,
  current_chain_updated_at timestamptz NULL,

  -- Rate limiting timestamps:
  -- Standard and forced are tracked separately so forced refresh does not reset standard cadence.
  last_standard_attempt_at timestamptz NULL,
  last_standard_success_at timestamptz NULL,

  last_forced_attempt_at   timestamptz NULL,
  last_forced_success_at   timestamptz NULL,

  -- Convenience timestamps for UI
  last_success_at timestamptz NULL,
  last_failure_at timestamptz NULL,

  -- Automated crawl backoff only. Manual crawling ignores no_retry_before.
  consecutive_failures integer NOT NULL DEFAULT 0,
  no_retry_before timestamptz NULL,

  -- Light DB-side guards. Full validation and canonicalization occurs in the application.
  CHECK (domain = lower(domain)),
  CHECK (right(domain, 1) <> '.'),
  CHECK (length(domain) BETWEEN 1 AND 253)
);

COMMENT ON TABLE domains IS
'Normalized domain targets (TLS SNI). Stores latest chain pointer, rate limit timestamps, and automated backoff state.';
COMMENT ON COLUMN domains.domain IS 'Normalized domain (lowercase, no trailing dot). Primary key.';
COMMENT ON COLUMN domains.popular_domain IS 'True if the domain ever appeared on an imported popular list.';
COMMENT ON COLUMN domains.auto_crawl IS 'True if automated crawling is enabled for this domain.';
COMMENT ON COLUMN domains.current_chain_hash IS 'Latest successful chain_hash observed for this domain.';
COMMENT ON COLUMN domains.last_standard_attempt_at IS 'Last time a standard crawl attempt was made (success or failure).';
COMMENT ON COLUMN domains.last_forced_attempt_at IS 'Last time a forced refresh attempt was made (success or failure).';
COMMENT ON COLUMN domains.no_retry_before IS 'Automated crawling should not retry before this timestamp.';

CREATE INDEX IF NOT EXISTS idx_domains_popular
  ON domains (popular_domain)
  WHERE popular_domain = true;

CREATE INDEX IF NOT EXISTS idx_domains_auto_crawl
  ON domains (auto_crawl)
  WHERE auto_crawl = true;

CREATE INDEX IF NOT EXISTS idx_domains_no_retry_before
  ON domains (no_retry_before)
  WHERE no_retry_before IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_domains_current_chain
  ON domains (current_chain_hash)
  WHERE current_chain_hash IS NOT NULL;


----------------------------
-- Domain chain history (one row per unique chain ever observed for a domain)
----------------------------

CREATE TABLE IF NOT EXISTS domain_chains (
  -- Composite primary key: one row per (domain, chain) pair
  domain     text NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
  chain_hash bytea NOT NULL REFERENCES chains(chain_hash) ON DELETE RESTRICT,

  -- When this chain was first observed for this domain
  first_seen_at timestamptz NOT NULL,

  -- When this chain was last observed for this domain
  last_seen_at  timestamptz NOT NULL,

  -- Number of times this chain was observed for this domain
  seen_count    bigint NOT NULL DEFAULT 1,

  -- How the most recent observation was triggered
  last_mode     crawl_mode NOT NULL,

  PRIMARY KEY (domain, chain_hash),
  CHECK (octet_length(chain_hash) = 32),
  CHECK (last_seen_at >= first_seen_at),
  CHECK (seen_count >= 1)
);

COMMENT ON TABLE domain_chains IS
'One row per unique chain ever observed for a domain. No duplicates on oscillation between chains.';
COMMENT ON COLUMN domain_chains.first_seen_at IS 'When this chain was first observed for this domain.';
COMMENT ON COLUMN domain_chains.last_seen_at IS 'When this chain was last observed for this domain.';
COMMENT ON COLUMN domain_chains.seen_count IS 'Total number of successful observations of this chain for this domain.';
COMMENT ON COLUMN domain_chains.last_mode IS 'How the most recent observation was triggered.';

-- Reverse lookup: which domains have ever served this chain
CREATE INDEX IF NOT EXISTS idx_domain_chains_chain_hash
  ON domain_chains (chain_hash);
