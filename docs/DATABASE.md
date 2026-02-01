---
layout: default
title: Database
nav_order: 5
---

# Database Schema

The cert-observatory application uses PostgreSQL to store certificate data. This document describes the database tables and their relationships.

## Connection Parameters

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--db-host` | `DB_HOST` | `localhost` | PostgreSQL server hostname |
| `--db-port` | `DB_PORT` | `5432` | PostgreSQL server port |
| `--db-user` | `DB_USER` | `postgres` | Database user |
| `--db-password` | `DB_PASSWORD` | (empty) | Database password |
| `--db-name` | `DB_NAME` | `cert_observatory` | Database name |
| `--db-sslmode` | `DB_SSLMODE` | `disable` | SSL mode (`disable`, `require`, `verify-ca`, `verify-full`) |

Command-line flags take precedence over environment variables. If neither is specified, the default value is used.

## Tables

### certificates

Immutable certificate catalog. One row per unique certificate, keyed by SHA-256 of DER bytes.

| Column | Type | Description |
|--------|------|-------------|
| `cert_hash` | bytea (PK) | SHA-256 hash of DER-encoded certificate (32 bytes) |
| `first_seen_at` | timestamptz | When this certificate was first seen |
| `pem` | text | PEM-encoded certificate |
| `not_before` | timestamptz | Certificate validity start time |
| `not_after` | timestamptz | Certificate validity end time |
| `ski` | bytea | Subject Key Identifier (if present) |
| `aki` | bytea | Authority Key Identifier (if present) |

### cert_signers

Many-to-many mapping of which certificates can sign which other certificates. Supports cross-signing analysis.

| Column | Type | Description |
|--------|------|-------------|
| `subject_cert_hash` | bytea (PK) | Certificate being signed |
| `issuer_cert_hash` | bytea (PK) | Certificate that signs the subject certificate |
| `first_seen_at` | timestamptz | When this relationship was first observed |
| `is_verified` | boolean | True if signature was cryptographically verified |

### chains

Deduplicated peer-provided chains. A chain is the ordered list returned by the server during TLS handshake.

| Column | Type | Description |
|--------|------|-------------|
| `chain_hash` | bytea (PK) | SHA-256 of the ordered list of cert_hash values |
| `created_at` | timestamptz | When this chain was first observed |
| `leaf_cert_hash` | bytea | First certificate in the peer-provided chain |
| `depth` | integer | Number of certificates in the chain (1-20) |

### chain_certs

Ordered chain membership. Stores the exact peer-provided chain order.

| Column | Type | Description |
|--------|------|-------------|
| `chain_hash` | bytea (PK) | Reference to chains table |
| `position` | smallint (PK) | 1-based position in the chain (1 = leaf) |
| `cert_hash` | bytea | Reference to certificates table |

### domains

Normalized domain targets (TLS SNI). Stores latest chain pointer, rate limit timestamps, and automated backoff state.

| Column | Type | Description |
|--------|------|-------------|
| `domain_id` | bigserial (PK) | Auto-generated domain ID |
| `domain` | text (unique) | Normalized domain (lowercase, no trailing dot) |
| `first_seen_at` | timestamptz | When this domain was first seen |
| `popular_domain` | boolean | True if domain appeared on imported popular list |
| `auto_crawl` | boolean | True if automated crawling is enabled |
| `current_chain_hash` | bytea | Latest successful chain_hash observed |
| `current_chain_updated_at` | timestamptz | When current chain was last updated |
| `last_standard_attempt_at` | timestamptz | Last standard crawl attempt time |
| `last_standard_success_at` | timestamptz | Last successful standard crawl |
| `last_forced_attempt_at` | timestamptz | Last forced refresh attempt time |
| `last_forced_success_at` | timestamptz | Last successful forced refresh |
| `last_success_at` | timestamptz | Last successful crawl (any mode) |
| `last_failure_at` | timestamptz | Last failed crawl attempt |
| `consecutive_failures` | integer | Count of consecutive failures |
| `no_retry_before` | timestamptz | Automated crawling retry wait time |

### domain_chain_states

History of unique chain states per domain stored as intervals.

| Column | Type | Description |
|--------|------|-------------|
| `state_id` | bigserial (PK) | Auto-generated state ID |
| `domain_id` | bigint | Reference to domains table |
| `chain_hash` | bytea | Reference to chains table |
| `first_seen_at` | timestamptz | When this chain was first seen for this domain |
| `last_seen_at` | timestamptz | When this chain was last seen |
| `ended_at` | timestamptz | When this chain stopped being current (NULL = current) |
| `seen_count` | bigint | Number of successful observations |
| `last_mode` | crawl_mode | How the most recent observation was triggered |

### domain_locks

Advisory locks for preventing concurrent crawls of the same domain.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | text (PK) | Domain being locked |
| `locked_at` | timestamptz | When the lock was acquired |
| `locked_by` | text | Identifier of the lock holder |
| `expires_at` | timestamptz | When the lock automatically expires |

### root_sources (optional)

Named sources for root certificate ingestion.

| Column | Type | Description |
|--------|------|-------------|
| `source_id` | bigserial (PK) | Auto-generated source ID |
| `source_name` | text (unique) | Name of the root source |
| `first_seen_at` | timestamptz | When this source was first added |

### root_source_certs (optional)

Mapping of certificates to a root source.

| Column | Type | Description |
|--------|------|-------------|
| `source_id` | bigint (PK) | Reference to root_sources table |
| `cert_hash` | bytea (PK) | Reference to certificates table |
| `added_at` | timestamptz | When this certificate was added to this source |

## Types

### crawl_mode

Enum indicating how a crawl was triggered:
- `standard` - Normal UI fetch
- `forced` - Forced refresh by user
- `auto` - Automated background crawl
