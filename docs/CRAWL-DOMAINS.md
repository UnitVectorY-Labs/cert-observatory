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
2. **Not in backoff**: `no_retry_before` is NULL or in the past
3. **Due by age**: `last_success_at` is NULL (never crawled) or older than the effective age threshold

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

## Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--age-days` | `CERT_OBS_CRAWL_AGE_DAYS` | `1` | Days since last crawl to qualify for re-crawl |
| `--parallel` | `CERT_OBS_CRAWL_PARALLEL` | `4` | Number of domains to crawl concurrently |
| `--timeout` | - | `10s` | Timeout for each crawl operation |
| `--verbose` | - | `false` | Enable verbose/debug logging |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Basic daily crawl with defaults
cert-observatory crawl-domains

# Weekly crawl with higher parallelism
cert-observatory crawl-domains --age-days 7 --parallel 8

# Using environment variables
export CERT_OBS_CRAWL_AGE_DAYS=1
export CERT_OBS_CRAWL_PARALLEL=4
cert-observatory crawl-domains

# With verbose logging for debugging
cert-observatory crawl-domains --verbose
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
