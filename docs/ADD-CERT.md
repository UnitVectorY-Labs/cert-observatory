---
layout: default
title: add-cert
nav_order: 7
---

# add-cert

Add certificates from a PEM file to the certificate catalog.

## Synopsis

```bash
cert-observatory add-cert --pem-file <path> [options]
```

## Description

The `add-cert` command parses a PEM file containing one or more certificates and ingests them into the certificate catalog. This is useful for adding root or intermediate certificates that may not be returned by servers during TLS handshakes or are not included in the standard root stores ingested by `ingest-roots`.

### Use Cases

- **Root certificates**: Add root CA certificates from custom or internal PKIs
- **Intermediate certificates**: Add intermediate certificates that servers may not serve
- **Historical certificates**: Add expired or revoked certificates for research purposes
- **Cross-signed certificates**: Add alternative trust paths

### Certificate Processing

For each certificate in the PEM file:

1. **Parse**: Decode PEM block and parse X.509 certificate
2. **Compute hash**: SHA-256 of DER bytes
3. **Insert**: Add to `certificates` table if not present

### Database Behavior

**For new certificates:**
- Inserted into `certificates` table with full details

**For existing certificates:**
- Skipped (no duplicate inserts)

Certificates are NOT associated with domains. This command is for adding standalone certificates to the catalog.

## Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--pem-file` | - | (required) | Path to PEM file containing certificates |
| `--verbose` | - | `false` | Enable verbose/debug logging |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Add certificates from a PEM file
cert-observatory add-cert --pem-file /path/to/certificates.pem

# With verbose logging to see each certificate processed
cert-observatory add-cert --pem-file /path/to/certificates.pem --verbose

# Add a single root certificate
cert-observatory add-cert --pem-file my-root-ca.pem
```

## PEM File Format

The PEM file should contain one or more certificates in standard PEM format:

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcqg...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIJAMl3Mn2FnQgFMA0GCSq...
-----END CERTIFICATE-----
```

- Multiple certificates can be concatenated in a single file
- Non-certificate PEM blocks (e.g., private keys) are ignored
- Invalid certificates are counted as parse failures and skipped

## Logging Output

The command logs statistics after processing:

```
INFO starting add-cert pem_file=/path/to/certificates.pem
INFO parsed certificates count=5 parse_failures=0
INFO add-cert completed parsed=5 inserted=3 already_exists=2 parse_failures=0
```

With `--verbose`, each certificate operation is logged:

```
DEBUG certificate inserted subject=Example Root CA cert_hash=abc123...
DEBUG certificate already exists subject=Another CA cert_hash=def456...
```

## Idempotency

Running the command multiple times with the same PEM file:
- Does NOT create duplicate certificates
- Results in zero inserts after first successful run
- Safe to re-run when adding new certificates to an existing PEM file

## Database Tables Used

| Table | Purpose |
|-------|---------|
| `certificates` | Stores the actual certificate data |

## Comparison with Other Commands

| Command | Purpose |
|---------|---------|
| `add-cert` | Add certificates from a local PEM file |
| `ingest-roots` | Fetch and add root certificates from configured URLs |
| `crawl-domain` | Fetch certificates from a domain's TLS connection |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (at least one certificate was processed) |
| Non-zero | Error (file not found, no certificates, database error, etc.) |
