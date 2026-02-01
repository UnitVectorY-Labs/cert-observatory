# crawl-domain

Crawl a single domain to fetch its TLS certificate chain and store the results in the database.

## Synopsis

```bash
cert-observatory crawl-domain --url <domain> [options]
```

## Description

The `crawl-domain` command performs a TLS handshake to the specified domain on port 443, captures the peer-provided certificate chain, and stores the results in the database.

This command:
- Opens a TCP connection to `<domain>:443`
- Performs a TLS handshake with SNI enabled
- Captures the exact peer-provided certificate chain
- Stores any new certificates in the database
- Updates the domain's current and historical chain state
- Outputs the certificate chain in PEM format to stdout

The command does NOT:
- Send HTTP requests
- Follow redirects
- Fetch OCSP/CRL
- Perform AIA fetching of intermediates
- Require chain validation to succeed

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | (required) | Domain to crawl. Must be a hostname only (no scheme, port, or path). |
| `--timeout` | `10s` | Timeout for connection and handshake. |
| `--verbose` | `false` | Enable verbose/debug logging. |

See [DATABASE.md](DATABASE.md) for database connection options.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success: crawl completed and database updated |
| Non-zero | Error: invalid input, database error, network/TLS failure, or internal error |

## Output

- **stdout**: Certificate chain in PEM format (on success)
- **stderr**: Logging messages and errors

## Examples

### Basic usage:

```bash
cert-observatory crawl-domain --url github.com
```

### With verbose logging:

```bash
cert-observatory crawl-domain --url github.com --verbose
```

### With custom timeout:

```bash
cert-observatory crawl-domain --url slow-server.example.com --timeout 30s
```

### Save certificates to a file:

```bash
cert-observatory crawl-domain --url github.com > github-chain.pem
```

### View only logs (discard PEM output):

```bash
cert-observatory crawl-domain --url github.com > /dev/null
```

## Input Validation

The `--url` parameter must be a valid DNS hostname:
- Lowercase letters, numbers, and hyphens only
- Labels separated by dots
- No trailing dot
- No URL scheme (e.g., `https://`)
- No port specification
- No path or query string
- Length between 1 and 253 characters
- Each label between 1 and 63 characters

Examples of valid input:
- `example.com`
- `www.example.com`
- `api.v2.example.com`
- `xn--nxasmq5b.com` (punycode)

Examples of invalid input:
- `https://example.com` (has scheme)
- `example.com:443` (has port)
- `example.com/path` (has path)
- `example.com.` (trailing dot)
- `EXAMPLE.COM` (will be normalized to lowercase)
- `  example.com  ` (whitespace will be trimmed)

## Logging Levels

### Info level (default):
- Normalized domain
- Whether domain row was inserted vs already existed
- Number of certificates in peer chain
- Whether the chain was newly inserted vs already existed
- Whether current chain changed for the domain

### Debug level (with `--verbose`):
- Certificate hashes
- Chain hash
- Parsed not_before/not_after
- SKI/AKI presence

PEM content is never logged.

## Database Behavior

On successful crawl:
1. Domain is inserted if not exists (first_seen_at = now)
2. All certificates in the chain are inserted if not exists
3. Chain is inserted if not exists
4. Domain's current_chain_hash is updated
5. Domain chain state interval is updated or created

On failed crawl:
1. Domain is inserted if not exists
2. Failure timestamps are updated
3. consecutive_failures is incremented
4. No chain or certificate data is modified

All database operations for a successful crawl are performed in a single transaction.
