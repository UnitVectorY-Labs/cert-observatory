---
layout: default
title: ingest-toplist
nav_order: 5
---

# ingest-toplist

Ingest domains from the Cloudflare Radar Top 10k list.

## Synopsis

```bash
cert-observatory ingest-toplist --cloudflare-token <token> [options]
```

## Description

The `ingest-toplist` command fetches the current top domain list from Cloudflare Radar and upserts domains into the database without crawling them. This seeds the database for future automated crawls by the `crawl-domains` command.

### Cloudflare Radar API

The command uses the Cloudflare Radar API endpoint:
```
https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000
```

This requires a Cloudflare API token with access to Radar datasets.

### Domain Processing

For each domain in the list:

1. **Normalize**: Convert to lowercase, trim whitespace
2. **Validate**: Ensure it's a valid hostname
3. **Upsert**: Insert or update in database

### Database Behavior

**For new domains:**
- `popular_domain = true`
- `auto_crawl = true`
- `first_seen_at = now()`
- No crawl timestamps set
- No chain fields set

**For existing domains:**
- Sets `popular_domain = true` if not already
- Sets `auto_crawl = true` if not already

The ingestion does NOT trigger any crawls.

## Options

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `--cloudflare-token` | `CLOUDFLARE_API_TOKEN` | (required) | Cloudflare API token |
| `--verbose` | - | `false` | Enable verbose/debug logging |

See [DATABASE.md](DATABASE.md) for database connection options.

## Examples

```bash
# Using flag
cert-observatory ingest-toplist --cloudflare-token your-api-token

# Using environment variable
export CLOUDFLARE_API_TOKEN=your-api-token
cert-observatory ingest-toplist

# With verbose logging
cert-observatory ingest-toplist --verbose
```

## Obtaining a Cloudflare API Token

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Go to **My Profile** → **API Tokens**
3. Create a token with access to the Radar API
4. Use the token with `--cloudflare-token` or `CLOUDFLARE_API_TOKEN`

## Logging Output

The command logs:
- Number of domains fetched from API
- Number of domains accepted (valid)
- Number of domains inserted (new)
- Number of domains updated (flags changed)
- Number of domains rejected (invalid format)

Example output:
```
INFO starting ingest-toplist job
INFO fetching domains from Cloudflare Radar
INFO fetched domains count=1000
INFO domain validation complete accepted=998 rejected=2
INFO ingest-toplist completed fetched=1000 accepted=998 inserted=950 updated=48 rejected=2
```

## Idempotency

Running the ingest multiple times:
- Does NOT create duplicate domains
- Results in minimal DB changes after first run
- Only updates domains whose flags need to change

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (missing token, API error, database error) |
