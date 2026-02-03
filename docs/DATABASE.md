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

Normalized domain targets (TLS SNI). Stores latest chain pointer, rate limit timestamps, and automated backoff state.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | text (PK) | Normalized domain (lowercase, no trailing dot) |
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

One row per unique chain ever observed for a domain. No duplicates on oscillation between chains.

| Column | Type | Description |
|--------|------|-------------|
| `domain` | text (PK) | Reference to domains table |
| `chain_hash` | bytea (PK) | Reference to chains table |
| `first_seen_at` | timestamptz | When this chain was first observed for this domain |
| `last_seen_at` | timestamptz | When this chain was last observed for this domain |
| `seen_count` | bigint | Total number of successful observations |
| `last_mode` | crawl_mode | How the most recent observation was triggered |

## Types

### crawl_mode

Enum indicating how a crawl was triggered:
- `standard` - Normal UI fetch
- `forced` - Forced refresh by user
- `auto` - Automated background crawl

## Design Principles

### Storage Goals

- **Content-addressed keys**: Certificates and chains are keyed by SHA-256 hashes
- **Domain text as primary key**: No surrogate integer IDs for domains
- **One row per unique chain per domain**: No duplicates when oscillating between chains

### Non-goals

- No trust validation or "is valid" computation
- No verified issuer graph building
- No per-crawl logs (only timestamps and counts)
