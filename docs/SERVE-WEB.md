---
layout: default
title: serve-web
nav_order: 2
---

# serve-web

Serve the web application for browsing and inspecting TLS certificate chains.

## Synopsis

```bash
cert-observatory serve-web [options]
```

## Description

The `serve-web` command starts an HTTP server that provides a web interface for inspecting TLS certificate chains. Users can enter a domain name to retrieve its certificate chain, view decoded certificate details, and inspect raw PEM content.

Features:
- Single-page dark-themed interface
- Real-time certificate chain retrieval via HTMX
- Two-pane layout with chain overview and certificate details
- Cached results with optional force refresh
- Rate limiting to prevent abuse
- Tailwind CSS-based styling with committed compiled assets

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | Address to listen on (host:port) |
| `--timeout` | `30s` | Timeout for outbound crawl operations |
| `--read-timeout` | `15s` | HTTP server read timeout |
| `--write-timeout` | `60s` | HTTP server write timeout |
| `--idle-timeout` | `120s` | HTTP server idle timeout |

See [DATABASE.md](DATABASE.md) for database connection options.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | Server listen address |
| `CRAWL_TIMEOUT` | `30s` | Timeout for TLS crawl operations |

## Examples

```bash
# Start with default settings
cert-observatory serve-web

# Listen on specific port
cert-observatory serve-web --listen :3000

# With database configuration
cert-observatory serve-web --db-host db.example.com --db-user certuser
```

## Frontend Asset Workflow

The web stylesheet is generated with the standalone Tailwind CLI and checked into source control:

```bash
# Build CSS once
just tailwind
```

Generated output: `internal/web/static/css/style.css`  
Tailwind source input: `internal/web/tailwind.css`

`go build` does not require Tailwind to run when compiled CSS is already present.

## Rate Limiting

The server enforces rate limiting to prevent abuse:

- **Standard refresh**: Returns cached data if the last successful crawl was within 23 hours
- **Force refresh**: Allows one forced refresh per 1-hour window when policy permits

Force refresh is only available when server-side policy allows it.

## Security

The web server includes security hardening:

- Input validation and normalization for domain names
- Port 443 is used by default. Supplying the `?port` query parameter to `/inspect` or `/refresh` enables `host:port` input such as `www.example.com:8443`.
- CSRF protection for state-changing operations
- SQL injection prevention via parameterized queries
- XSS prevention via HTML escaping
- Security headers (CSP, X-Content-Type-Options, etc.)
- IP literal blocking to prevent SSRF

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Server shut down gracefully |
| Non-zero | Error (database connection failed, port in use, etc.) |
