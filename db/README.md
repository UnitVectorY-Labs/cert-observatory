# Database

The cert-observatory application uses PostgreSQL to store certificate data. This document serves as a quick reference for the database schema.

## Schema Overview

The schema is designed around these core principles:
- **Content-addressed storage**: Certificates and chains are keyed by SHA-256 hashes
- **Domain text as primary key**: Domains use the normalized domain string as the primary key (no surrogate IDs)
- **One row per unique observation**: Each unique chain observed for a domain has exactly one row, with timestamps and counts updated on oscillation
- **No trust validation**: The schema captures what servers present, not whether chains are trusted

## Tables

### certificates

Immutable certificate catalog. One row per unique certificate, keyed by SHA-256 of DER bytes.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `cert_hash` | bytea | NO (PK) | SHA-256 hash of DER-encoded certificate (32 bytes) |
| `first_seen_at` | timestamptz | NO | When this certificate was first seen |
| `der` | bytea | NO | DER-encoded certificate bytes |
| `subject` | text | NO | Subject distinguished name (RFC 2253 format) |
| `issuer` | text | NO | Issuer distinguished name (RFC 2253 format) |
| `not_before` | timestamptz | YES | Certificate validity start time |
| `not_after` | timestamptz | YES | Certificate validity end time |
| `ski` | bytea | YES | Subject Key Identifier (8-64 bytes if present) |
| `aki` | bytea | YES | Authority Key Identifier (8-64 bytes if present) |

**Constraints:**
- `octet_length(cert_hash) = 32`
- `octet_length(der) > 0`
- `ski IS NULL OR octet_length(ski) BETWEEN 8 AND 64`
- `aki IS NULL OR octet_length(aki) BETWEEN 8 AND 64`

**Indexes:**
- `idx_cert_not_after` on `not_after` - for expiry queries
- `idx_cert_issuer` on `issuer` - for issuer grouping and UI filters

### chains

Deduplicated peer-provided certificate chains. A chain is the ordered list returned by the server during TLS handshake.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `chain_hash` | bytea | NO (PK) | SHA-256 of the ordered cert_hash list (32 bytes) |
| `first_seen_at` | timestamptz | NO | When this chain was first observed |
| `cert_hashes` | bytea[] | NO | Ordered array of certificate hashes (leaf-first) |
| `leaf_cert_hash` | bytea | GENERATED | First certificate in the chain (computed from cert_hashes[1]) |
| `depth` | integer | GENERATED | Number of certificates in the chain (computed from array_length) |

**Constraints:**
- `octet_length(chain_hash) = 32`
- `array_length(cert_hashes, 1) >= 1`

**Indexes:**
- `idx_chains_cert_hashes` using GIN on `cert_hashes` - for finding chains containing a specific certificate

**Hash Encoding (Version 1):**
The chain_hash is computed from the ordered cert_hash list using this encoding:
- 4 bytes: number of certificates (big-endian uint32)
- For each certificate: 32 bytes of cert_hash
- SHA-256 of the concatenated bytes

### domains

Normalized domain targets (TLS SNI). Stores latest chain pointer, rate limit timestamps, and automated backoff state.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `domain` | text | NO (PK) | Normalized domain name (lowercase, no trailing dot) |
| `first_seen_at` | timestamptz | NO | When this domain was first seen |
| `popular_domain` | boolean | NO | True if domain appeared on imported popular list |
| `auto_crawl` | boolean | NO | True if automated crawling is enabled |
| `current_chain_hash` | bytea | YES | Latest successful chain_hash observed |
| `current_chain_updated_at` | timestamptz | YES | When current chain was last updated |
| `last_standard_attempt_at` | timestamptz | YES | Last standard crawl attempt time |
| `last_standard_success_at` | timestamptz | YES | Last successful standard crawl |
| `last_forced_attempt_at` | timestamptz | YES | Last forced refresh attempt time |
| `last_forced_success_at` | timestamptz | YES | Last successful forced refresh |
| `last_success_at` | timestamptz | YES | Last successful crawl (any mode) |
| `last_failure_at` | timestamptz | YES | Last failed crawl attempt |
| `consecutive_failures` | integer | NO | Count of consecutive failures (default: 0) |
| `no_retry_before` | timestamptz | YES | Automated crawling retry wait time |

**Constraints:**
- `domain = lower(domain)`
- `right(domain, 1) <> '.'`
- `length(domain) BETWEEN 1 AND 253`

**Foreign Keys:**
- `current_chain_hash` references `chains(chain_hash)` ON DELETE SET NULL

**Indexes:**
- `idx_domains_popular` (partial) where `popular_domain = true`
- `idx_domains_auto_crawl` (partial) where `auto_crawl = true`
- `idx_domains_no_retry_before` (partial) where `no_retry_before IS NOT NULL`
- `idx_domains_current_chain` (partial) where `current_chain_hash IS NOT NULL`

### domain_chains

One row per unique chain ever observed for a domain. No duplicates on oscillation between chains.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `domain` | text | NO (PK) | Reference to domains table |
| `chain_hash` | bytea | NO (PK) | Reference to chains table |
| `first_seen_at` | timestamptz | NO | When this chain was first observed for this domain |
| `last_seen_at` | timestamptz | NO | When this chain was last observed for this domain |
| `seen_count` | bigint | NO | Total number of successful observations (default: 1) |
| `last_mode` | crawl_mode | NO | How the most recent observation was triggered |

**Constraints:**
- `octet_length(chain_hash) = 32`
- `last_seen_at >= first_seen_at`
- `seen_count >= 1`

**Foreign Keys:**
- `domain` references `domains(domain)` ON DELETE CASCADE
- `chain_hash` references `chains(chain_hash)` ON DELETE RESTRICT

**Indexes:**
- `idx_domain_chains_chain_hash` on `chain_hash` - for reverse lookups (which domains served this chain)

## Types

### crawl_mode

Enum indicating how a crawl was triggered:
- `standard` - Normal UI fetch
- `forced` - Forced refresh by user
- `auto` - Automated background crawl

## Migrations

The migrations are embedded in the application binary and stored in the source code at `internal/db/migrations/`. They are applied by running the `migrate up` command.

See the [docs/DATABASE.md](../docs/DATABASE.md) for connection configuration and [docs/MIGRATE.md](../docs/MIGRATE.md) for migration management.

## Common Queries

### Get a domain's current chain with certificates

```sql
SELECT c.cert_hash, c.der, c.subject, c.issuer, c.not_before, c.not_after
FROM domains d
JOIN chains ch ON ch.chain_hash = d.current_chain_hash
JOIN certificates c ON c.cert_hash = ANY(ch.cert_hashes)
WHERE d.domain = 'example.com'
ORDER BY array_position(ch.cert_hashes, c.cert_hash);
```

### Find all domains that have ever served a specific chain

```sql
SELECT dc.domain, dc.first_seen_at, dc.last_seen_at, dc.seen_count
FROM domain_chains dc
WHERE dc.chain_hash = $1;
```

### Find all chains containing a specific certificate

```sql
SELECT chain_hash, first_seen_at, depth
FROM chains
WHERE $1 = ANY(cert_hashes);
```

### Get domains eligible for auto-crawl

```sql
SELECT domain
FROM domains
WHERE auto_crawl = true
  AND (no_retry_before IS NULL OR no_retry_before <= now())
  AND (last_success_at IS NULL OR last_success_at <= now() - interval '23 hours')
ORDER BY last_success_at NULLS FIRST
LIMIT 100;
```