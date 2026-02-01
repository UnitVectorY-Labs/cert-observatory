---
layout: default
title: crawl-domain
nav_order: 3
---

# crawl-domain

Crawl a single domain to fetch its TLS certificate chain and store the results in the database.

## Synopsis

```bash
cert-observatory crawl-domain --url <domain> [options]
```

## Description

The `crawl-domain` command performs a TLS handshake to the specified domain on port 443, captures the peer-provided certificate chain, and stores the results in the database. The certificate chain is output to stdout in PEM format.

The command does NOT:
- Send HTTP requests or follow redirects
- Fetch OCSP/CRL or perform AIA fetching
- Require chain validation to succeed

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | (required) | Domain to crawl (hostname only, no scheme or port) |
| `--timeout` | `10s` | Timeout for connection and handshake |
| `--verbose` | `false` | Enable verbose/debug logging |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Basic usage
cert-observatory crawl-domain --url github.com

# With verbose logging
cert-observatory crawl-domain --url github.com --verbose

# Save certificates to a file
cert-observatory crawl-domain --url github.com > github-chain.pem
```

## Input Validation

The `--url` parameter must be a valid DNS hostname:
- Lowercase letters, numbers, and hyphens only
- No URL scheme, port specification, or path
- No trailing dot
- Length between 1 and 253 characters

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (invalid input, database error, or network failure) |
