---
layout: default
title: crawl-domains
nav_order: 4
---

# crawl-domains

A scheduled job that crawls domains from the database that are due for automated re-crawling.

## Synopsis

```bash
cert-observatory crawl-domains [options]
```

## Description

The `crawl-domains` command selects domains from the database that are due for re-crawl based on an age threshold, crawls them in parallel using a worker pool, and updates the database with any new certificate chains.

This command is designed to be run as a scheduled job (e.g., via cron or a Kubernetes CronJob) to keep the certificate data fresh.

### Domain Eligibility

A domain is eligible for crawling when:

1. **Auto-crawl enabled**: `auto_crawl = true`
2. **Not in backoff**: `no_retry_before` is NULL or in the past (unless `--ignore-errors` is set)
3. **Popular domain**: `popular_domain = true` (unless `--include-non-public` is set)
4. **Due by age**: `last_success_at` is NULL (never crawled) or older than the effective age threshold

### Effective Age Calculation

The effective threshold is calculated as: `(age_days × 24h) - 1h`

This creates an overlap window that ensures idempotency when the job runs multiple times:

| Age Days | Effective Age |
|----------|---------------|
| 1        | 23 hours      |
| 7        | 6 days 23 hours |
| 30       | 29 days 23 hours |

### Failure Handling

When a crawl fails, the command applies exponential backoff:

- Base delay: 1 hour
- Multiplier: 2× per consecutive failure
- Maximum per-retry cap: 7 days
- Maximum total backoff: 30 days (1 month)

On success, the failure counter is reset and backoff is cleared.

Use `--ignore-errors` to bypass the backoff mechanism and retry domains that are in backoff. This is useful for recovering from transient issues like DNS resolution problems caused by rate limiting.

### Rate Limiting

The `--rate` option controls the maximum number of crawls per second. This is useful when:

- DNS resolution errors occur due to upstream rate limiting
- You want to reduce load on network infrastructure
- Crawling a large number of domains causes issues

When rate limiting is enabled, domains are dispatched to workers at the specified rate regardless of the number of parallel workers. For example, with `--rate 1` and `--parallel 8`, only one new crawl will start per second even though 8 workers are available.

A value of `-1` (the default) means unlimited, where domains are dispatched as fast as workers can accept them.

## Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--age-days` | `CERT_OBS_CRAWL_AGE_DAYS` | `1` | Days since last crawl to qualify for re-crawl |
| `--parallel` | `CERT_OBS_CRAWL_PARALLEL` | `2` | Number of domains to crawl concurrently |
| `--rate` | `CERT_OBS_CRAWL_RATE` | `-1` | Maximum crawls per second, -1 for unlimited |
| `--timeout` | - | `10s` | Timeout for each crawl operation |
| `--verbose` | - | `false` | Enable verbose/debug logging |
| `--ignore-errors` | `CERT_OBS_CRAWL_IGNORE_ERRORS` | `false` | Ignore backoff errors and crawl domains anyway |
| `--include-non-public` | `CERT_OBS_CRAWL_INCLUDE_NON_PUBLIC` | `false` | Include non-public domains (manually submitted) |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Basic daily crawl with defaults
cert-observatory crawl-domains

# Weekly crawl with higher parallelism
cert-observatory crawl-domains --age-days 7 --parallel 8

# Rate-limited crawl (1 request per second)
cert-observatory crawl-domains --rate 1

# Using environment variables
export CERT_OBS_CRAWL_AGE_DAYS=1
export CERT_OBS_CRAWL_PARALLEL=4
cert-observatory crawl-domains

# With verbose logging for debugging
cert-observatory crawl-domains --verbose

# Ignore backoff errors and recrawl domains that previously failed
cert-observatory crawl-domains --ignore-errors

# Include non-public (manually submitted) domains
cert-observatory crawl-domains --include-non-public

# Combine options: ignore errors and include non-public domains with rate limiting
cert-observatory crawl-domains --ignore-errors --include-non-public --rate 5

# Using environment variables for all options
export CERT_OBS_CRAWL_IGNORE_ERRORS=true
export CERT_OBS_CRAWL_INCLUDE_NON_PUBLIC=true
export CERT_OBS_CRAWL_RATE=10
cert-observatory crawl-domains
```

## Logging

### Default Mode

- Does NOT log every successful domain crawl
- Logs periodic progress updates
- Always logs failures with:
  - Domain name
  - Error category (timeout, handshake_failure, dns_error, etc.)
  - Next retry time
  - Consecutive failure count
- Logs final summary:
  - Total eligible domains
  - Succeeded count
  - Failed count
  - Duration

### Verbose Mode

- Logs every domain with success/failure status
- Includes chain depth for successful crawls
- Debug-level information about processing

## Idempotency

The command is designed to be idempotent. When run twice back-to-back:

1. First run crawls all eligible domains
2. Second run finds few or no eligible domains because recently crawled domains are now younger than the effective age threshold

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (even if some individual crawls failed) |
| Non-zero | Fatal error (database connection, migration check, etc.) |
