---
layout: default
title: ingest-roots
nav_order: 6
---

# ingest-roots

Ingest root certificates from trusted sources into the certificate catalog.

## Synopsis

```bash
cert-observatory ingest-roots [options]
```

## Description

The `ingest-roots` command fetches and ingests root certificates (in PEM format) into the certificate catalog. This populates the database with trusted root certificates that can be used for chain validation analysis.

### Root Sources

The root sources are configured in an embedded `roots.yaml` file that is compiled into the binary. The following sources are currently included:

| Source | Name | Description |
|--------|------|-------------|
| Apple | `apple` | Apple root CA bundle |
| Google | `google` | Google root CA bundle |
| Microsoft | `microsoft` | Microsoft root CA bundle |
| Mozilla | `mozilla` | Mozilla root CA bundle |

The root certificate bundles are sourced from the [tls-inspector/rootca](https://github.com/tls-inspector/rootca) repository which maintains up-to-date copies of the trust stores from major platforms.

### Certificate Processing

For each certificate in the PEM bundle:

1. **Parse**: Decode PEM block and parse X.509 certificate
2. **Compute hash**: SHA-256 of DER bytes
3. **Insert**: Add to `certificates` table if not present

### Database Behavior

**For new certificates:**
- Inserted into `certificates` table with full details

**For existing certificates:**
- Skipped (no duplicate inserts)

Certificates are NOT associated with domains. This is expected as roots are trust anchors, not domain-specific.

## Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--verbose` | - | `false` | Enable verbose/debug logging |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Basic usage
cert-observatory ingest-roots

# With verbose logging
cert-observatory ingest-roots --verbose
```

## Logging Output

The command logs per-source statistics:
- Certificates parsed
- New certificates inserted
- Already existing (skipped)
- Parse failures

Example output:
```
INFO starting ingest-roots job
INFO fetching root certificates source=apple url=https://raw.githubusercontent.com/...
INFO parsed certificates source=apple count=150 parse_failures=0
INFO root source ingested source=apple parsed=150 inserted=150 already_exists=0 parse_failures=0
INFO fetching root certificates source=google url=https://raw.githubusercontent.com/...
...
```

On subsequent runs:
```
INFO root source ingested source=apple parsed=150 inserted=0 already_exists=150 parse_failures=0
```

## Idempotency

Running the ingest multiple times:
- Does NOT create duplicate certificates
- Results in zero inserts after first successful run
- Safe to run on a schedule to pick up new roots

## Database Tables Used

| Table | Purpose |
|-------|---------|
| `certificates` | Stores the actual certificate data |

## Configuration

The list of root sources is defined in `internal/roots/roots.yaml` and embedded into the binary at compile time. To add or modify root sources, update this file and rebuild the application.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (network error, database error, etc.) |
