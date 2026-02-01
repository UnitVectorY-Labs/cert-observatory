/*
cert-observatory Database Schema (PostgreSQL)

Purpose:
- Catalog TLS certificates (deduplicated by hash)
- Store exact peer-provided certificate chains (deduplicated)
- Track latest chain per domain plus historical unique chain states without per-crawl logs
- Track rate limiting timestamps and basic failure/backoff for automated crawling
- Track potential issuer relationships (supports cross-signing), independent of trust validation

Assumptions:
- Domain normalization occurs in the application layer (lowercase, no trailing dot)
- Crawling is TLS-only and SNI is always used
- Port is implicitly 443 for now
- Certificate hash is sha256 over DER bytes, stored as 32-byte bytea
- Chain hash is sha256 over the ordered list of certificate hashes (application-defined encoding)

Recommended transaction pattern:
- Insert missing certificates
- Insert missing chain and chain members
- Update domain pointers and timestamps
- Upsert or roll domain_chain_states current interval
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

  -- PEM encoding for display and export
  pem           text NOT NULL,

  -- Minimal indexed fields used for UI and operational queries
  not_before    timestamptz NULL,
  not_after     timestamptz NULL,

  -- Subject Key Identifier and Authority Key Identifier
  -- Stored as raw bytes. Length varies depending on encoding.
  ski           bytea NULL,
  aki           bytea NULL,

  CHECK (octet_length(cert_hash) = 32),
  CHECK (ski IS NULL OR octet_length(ski) BETWEEN 8 AND 64),
  CHECK (aki IS NULL OR octet_length(aki) BETWEEN 8 AND 64)
);

COMMENT ON TABLE certificates IS
'Immutable certificate catalog. One row per unique certificate. Keyed by sha256 of DER bytes.';
COMMENT ON COLUMN certificates.cert_hash IS 'sha256(DER) stored as 32-byte bytea.';
COMMENT ON COLUMN certificates.pem IS 'PEM encoded certificate as presented or reconstructed from DER.';
COMMENT ON COLUMN certificates.not_before IS 'Certificate validity start time (from certificate).';
COMMENT ON COLUMN certificates.not_after IS 'Certificate validity end time (from certificate).';
COMMENT ON COLUMN certificates.ski IS 'Subject Key Identifier (raw bytes) if present.';
COMMENT ON COLUMN certificates.aki IS 'Authority Key Identifier (raw bytes) if present.';

CREATE INDEX IF NOT EXISTS idx_cert_not_after
  ON certificates (not_after);

CREATE INDEX IF NOT EXISTS idx_cert_ski
  ON certificates (ski)
  WHERE ski IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cert_aki
  ON certificates (aki)
  WHERE aki IS NOT NULL;


----------------------------
-- Potential signer relationships (supports cross-signing)
----------------------------

CREATE TABLE IF NOT EXISTS cert_signers (
  subject_cert_hash bytea NOT NULL REFERENCES certificates(cert_hash) ON DELETE CASCADE,
  issuer_cert_hash  bytea NOT NULL REFERENCES certificates(cert_hash) ON DELETE CASCADE,

  first_seen_at     timestamptz NOT NULL DEFAULT now(),

  -- If the application verifies the signature, set true.
  is_verified       boolean NOT NULL DEFAULT false,

  PRIMARY KEY (subject_cert_hash, issuer_cert_hash),
  CHECK (octet_length(subject_cert_hash) = 32),
  CHECK (octet_length(issuer_cert_hash) = 32)
);

COMMENT ON TABLE cert_signers IS
'Many-to-many mapping of which certificates can sign which other certificates. Useful for cross-signing analysis.';
COMMENT ON COLUMN cert_signers.subject_cert_hash IS 'Certificate being signed.';
COMMENT ON COLUMN cert_signers.issuer_cert_hash IS 'Certificate that signs the subject certificate.';
COMMENT ON COLUMN cert_signers.is_verified IS 'True if signature was cryptographically verified by the application.';

CREATE INDEX IF NOT EXISTS idx_cert_signers_issuer
  ON cert_signers (issuer_cert_hash);


----------------------------
-- Chains (exact peer-provided lists, deduplicated)
----------------------------

CREATE TABLE IF NOT EXISTS chains (
  -- sha256 of ordered certificate hash list, always 32 bytes
  chain_hash     bytea PRIMARY KEY,

  created_at     timestamptz NOT NULL DEFAULT now(),

  -- Convenience pointer to the first certificate in the peer-provided list
  leaf_cert_hash bytea NOT NULL REFERENCES certificates(cert_hash) ON DELETE RESTRICT,

  -- Number of certificates in the peer-provided list
  depth          integer NOT NULL,

  CHECK (octet_length(chain_hash) = 32),
  CHECK (octet_length(leaf_cert_hash) = 32),
  CHECK (depth >= 1 AND depth <= 20)
);

COMMENT ON TABLE chains IS
'Deduplicated peer-provided chains. A chain is the ordered list returned by the server during TLS handshake.';
COMMENT ON COLUMN chains.chain_hash IS 'sha256 of the ordered list of cert_hash values using an application-defined encoding.';
COMMENT ON COLUMN chains.leaf_cert_hash IS 'First certificate in the peer-provided chain.';
COMMENT ON COLUMN chains.depth IS 'Count of certificates in the peer-provided chain.';

CREATE TABLE IF NOT EXISTS chain_certs (
  chain_hash bytea    NOT NULL REFERENCES chains(chain_hash) ON DELETE CASCADE,
  position   smallint NOT NULL,
  cert_hash  bytea    NOT NULL REFERENCES certificates(cert_hash) ON DELETE RESTRICT,

  PRIMARY KEY (chain_hash, position),
  CHECK (position >= 1),
  CHECK (octet_length(cert_hash) = 32)
);

COMMENT ON TABLE chain_certs IS
'Ordered chain membership. Stores the exact peer-provided chain order.';
COMMENT ON COLUMN chain_certs.position IS '1-based index into the chain, where 1 is the leaf certificate.';

-- Reverse lookup: which chains contain a given certificate
CREATE INDEX IF NOT EXISTS idx_chain_certs_cert
  ON chain_certs (cert_hash);


----------------------------
-- Domains (crawl target identity and state)
----------------------------

CREATE TABLE IF NOT EXISTS domains (
  domain_id bigserial PRIMARY KEY,

  -- Normalized domain string, unique. App layer enforces full validation.
  domain text NOT NULL UNIQUE,

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
COMMENT ON COLUMN domains.domain IS 'Normalized domain (lowercase, no trailing dot).';
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
-- Domain chain history (state intervals, no per-crawl logs)
----------------------------

CREATE TABLE IF NOT EXISTS domain_chain_states (
  state_id bigserial PRIMARY KEY,

  domain_id  bigint NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
  chain_hash bytea  NOT NULL REFERENCES chains(chain_hash) ON DELETE RESTRICT,

  -- Interval tracking for the period when this chain was current
  first_seen_at timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  ended_at      timestamptz NULL,

  -- Deduped observation counts for the interval
  seen_count bigint NOT NULL DEFAULT 1,

  -- How the most recent update to this interval was observed
  last_mode crawl_mode NOT NULL,

  CHECK (octet_length(chain_hash) = 32),
  CHECK (last_seen_at >= first_seen_at),
  CHECK (ended_at IS NULL OR ended_at >= last_seen_at)
);

COMMENT ON TABLE domain_chain_states IS
'History of unique chain states per domain stored as intervals. Avoids storing a row per crawl attempt.';
COMMENT ON COLUMN domain_chain_states.ended_at IS 'When this chain stopped being current for the domain. NULL means current.';
COMMENT ON COLUMN domain_chain_states.seen_count IS 'Number of successful observations that matched this chain during the interval.';
COMMENT ON COLUMN domain_chain_states.last_mode IS 'How the most recent observation in this interval was triggered.';

-- Enforce exactly one current interval per domain
CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_chain_current
  ON domain_chain_states (domain_id)
  WHERE ended_at IS NULL;

-- Fast fetch of current state
CREATE INDEX IF NOT EXISTS idx_domain_chain_current
  ON domain_chain_states (domain_id, last_seen_at DESC)
  WHERE ended_at IS NULL;

-- Reverse lookup: which domains ever served this chain
CREATE INDEX IF NOT EXISTS idx_domain_chain_chain_hash
  ON domain_chain_states (chain_hash);


----------------------------
-- Optional root source tracking (safe to include now, can remain unused)
----------------------------

CREATE TABLE IF NOT EXISTS root_sources (
  source_id bigserial PRIMARY KEY,
  source_name text NOT NULL UNIQUE,
  first_seen_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE root_sources IS
'Named sources for root certificate ingestion (optional). Examples: mozilla_nss, custom_bundle.';

CREATE TABLE IF NOT EXISTS root_source_certs (
  source_id bigint NOT NULL REFERENCES root_sources(source_id) ON DELETE CASCADE,
  cert_hash bytea  NOT NULL REFERENCES certificates(cert_hash) ON DELETE CASCADE,
  added_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_id, cert_hash),
  CHECK (octet_length(cert_hash) = 32)
);

COMMENT ON TABLE root_source_certs IS
'Optional mapping of certificates to a root source. Independent of chain validity.';
