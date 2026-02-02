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

Currently supported sources:

| Source | Name | URL |
|--------|------|-----|
| Mozilla CCADB | `mozilla_ccadb` | Included Roots with Websites trust bit |

The command is designed to be extensible for additional root sources in the future (e.g., Microsoft, Apple, custom bundles).

### Certificate Processing

For each certificate in the PEM bundle:

1. **Parse**: Decode PEM block and parse X.509 certificate
2. **Compute hash**: SHA-256 of DER bytes
3. **Insert**: Add to `certificates` table if not present
4. **Associate**: Link to root source in `root_source_certs`

### Database Behavior

**For new certificates:**
- Inserted into `certificates` table with full details
- Linked to the root source

**For existing certificates:**
- Skipped (no duplicate inserts)
- Still associated with the root source (idempotent)

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
INFO fetching root certificates source=mozilla_ccadb
INFO parsed certificates source=mozilla_ccadb count=147 parse_failures=0
INFO root source ingested source=mozilla_ccadb parsed=147 inserted=147 already_exists=0 parse_failures=0
```

On subsequent runs:
```
INFO root source ingested source=mozilla_ccadb parsed=147 inserted=0 already_exists=147 parse_failures=0
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
| `root_sources` | Tracks named sources (e.g., mozilla_ccadb) |
| `root_source_certs` | Links certificates to sources |

## Extensibility

The implementation is structured to support additional root sources:

```go
sources := []RootSource{
    {Name: "mozilla_ccadb", URL: "..."},
    {Name: "microsoft_roots", URL: "..."},  // Future
    {Name: "custom_bundle", URL: "..."},    // Custom
}
```

Each source can have a different URL and potentially different parsing logic (though currently only PEM bundle parsing is implemented).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (network error, database error, etc.) |
