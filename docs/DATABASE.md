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
| `der` | bytea | DER-encoded certificate bytes |
| `subject` | text | Subject distinguished name (RFC 2253 format) |
| `issuer` | text | Issuer distinguished name (RFC 2253 format) |
| `not_before` | timestamptz | Certificate validity start time |
| `not_after` | timestamptz | Certificate validity end time |
| `ski` | bytea | Subject Key Identifier (if present) |
| `aki` | bytea | Authority Key Identifier (if present) |

### chains

Deduplicated peer-provided chains. A chain is the ordered list returned by the server during TLS handshake.

| Column | Type | Description |
|--------|------|-------------|
| `chain_hash` | bytea (PK) | SHA-256 of the ordered list of cert_hash values |
| `first_seen_at` | timestamptz | When this chain was first observed |
| `cert_hashes` | bytea[] | Ordered array of certificate hashes (leaf-first) |
| `leaf_cert_hash` | bytea (GENERATED) | First certificate in the chain (derived from cert_hashes[1]) |
| `depth` | integer (GENERATED) | Number of certificates in the chain (derived from array_length) |

### domains

Normalized domain targets (TLS SNI plus TCP port). Stores latest chain pointer, rate limit timestamps, and automated backoff state.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | text (PK) | Normalized domain (lowercase, no trailing dot) |
| `port` | integer (PK) | TCP port used for TLS observation, defaults to 443 |
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

### domain_chains

One row per unique chain ever observed for a domain and port. No duplicates on oscillation between chains.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | text (PK) | Reference to domains table |
| `port` | integer (PK) | TCP port used when this chain was observed |
| `chain_hash` | bytea (PK) | Reference to chains table |
| `first_seen_at` | timestamptz | When this chain was first observed for this domain |
| `last_seen_at` | timestamptz | When this chain was last observed for this domain |
| `seen_count` | bigint | Total number of successful observations |
| `last_mode` | crawl_mode | How the most recent observation was triggered |

### certificate_distrust_rules

Independent CA platform distrust evidence; no foreign key to the observed certificate
catalog. Added in migration 3. A rule is unique by `(source, source_record_id, platform)`.

| Column | Type | Description |
|---|---|---|
| `id` | bigint identity (PK) | Internal identifier |
| `source` | text (FK) | `mozilla_onecrl` or `ccadb` |
| `source_record_id` | text | Upstream record identifier |
| `platform` | text | `mozilla`, `apple`, `chrome`, or `microsoft` |
| `status` | text | `blocked`, `disabled`, or `removed` |
| `match_type` | text | `certificate_sha256`, `issuer_serial`, or `subject_public_key_hash` |
| `certificate_sha256` | bytea, nullable | Exact certificate SHA-256 fingerprint |
| `issuer_name_der` | bytea, nullable | Encoded issuer distinguished name |
| `serial_number` | bytea, nullable | Unsigned big-endian serial number |
| `subject_name_der` | bytea, nullable | Encoded subject distinguished name |
| `public_key_hash` | bytea, nullable | SHA-256 of full DER SubjectPublicKeyInfo for OneCRL |
| `reason` | text | Source explanation, empty when unavailable |
| `reference_url` | text | Source/incident reference, empty when unavailable |
| `effective_at` | timestamptz, nullable | Effective date, if supplied |
| `first_seen_at` | timestamptz | First accepted observation |
| `last_seen_at` | timestamptz | Latest accepted observation |
| `withdrawn_at` | timestamptz, nullable | Source no longer publishes/enables this rule |

Constraints enforce exclusive matching fields and 32-byte hashes. A partial index
covers active rules. An absent rule never establishes trust or non-revocation.

### certificate_distrust_sources

| Column | Type | Description |
|---|---|---|
| `source` | text (PK) | Feed identifier |
| `last_attempted_at` | timestamptz | Latest recorded attempt |
| `last_successful_at` | timestamptz, nullable | Latest accepted complete snapshot |
| `active_rules` | integer | Active rules from the last accepted snapshot |
| `last_error` | text | Latest fetch/validation error, cleared on success |

See [ingest-distrust](INGEST-DISTRUST.md) for collection, atomic refresh behavior,
staleness, and coverage limitations. Only explicit platform actions are collected;
this does not add general trust/path validation.


## Types

### crawl_mode

Enum indicating how a crawl was triggered:
- `standard` - Normal UI fetch
- `forced` - Forced refresh by user
- `auto` - Automated background crawl

## Design Principles

### Storage Goals

- **Content-addressed keys**: Certificates and chains are keyed by SHA-256 hashes
- **Domain and port as primary key**: No surrogate integer IDs for crawl targets
- **One row per unique chain per domain and port**: No duplicates when oscillating between chains

### Non-goals

- No trust validation or "is valid" computation
- No verified issuer graph building
- No per-crawl logs (only timestamps and counts)
