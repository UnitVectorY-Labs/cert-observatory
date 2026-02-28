[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active)
 [![Go Report Card](https://goreportcard.com/badge/github.com/UnitVectorY-Labs/cert-observatory)](https://goreportcard.com/report/github.com/UnitVectorY-Labs/cert-observatory)

# cert-observatory

A web-based TLS certificate observatory that fetches, stores, and visualizes the certificate chains presented by domains. Enter a domain and instantly see every certificate in the chain with decoded details, trust path diagrams, and raw PEM — all in a clean, dark-themed interface.

## Features

- **Certificate Chain Inspection** — View the full TLS certificate chain for any domain with decoded subject, issuer, validity dates, SANs, key usage, fingerprints, and more.
- **Trust Path Visualization** — Interactive Mermaid diagrams trace each certificate's path from leaf to root, highlighting intermediates, missing links, and expired certificates.
- **Automated Crawling** — Schedule background crawls of popular domains sourced from the Cloudflare Radar Top 10k list, with configurable parallelism, rate limiting, and exponential backoff on failures.
- **Root Store Ingestion** — Import trusted root certificates from Apple, Google, Microsoft, and Mozilla to enrich trust path analysis.
- **Single Binary, Zero Dependencies** — All HTML templates, CSS, JavaScript, and database migrations are embedded into one Go binary, deployed as a minimal distroless Docker image.
- **PostgreSQL Storage** — Content-addressed certificate and chain storage ensures deduplication across domains and crawls.

## Getting Started

The application is distributed as a Docker image and requires a PostgreSQL database.

```bash
# Apply database migrations
cert-observatory migrate up

# Start the web interface
cert-observatory serve-web
```

Visit `http://localhost:8080`, enter a domain, and inspect its certificate chain.

## Commands

| Command | Description |
|---------|-------------|
| `serve-web` | Serve the web interface for browsing certificate data |
| `crawl-domain` | Fetch and store the certificate chain for a single domain |
| `crawl-domains` | Batch crawl domains that are due for re-crawling |
| `ingest-toplist` | Seed the database with domains from the Cloudflare Radar Top 10k |
| `ingest-roots` | Import root certificates from major trust stores |
| `add-cert` | Add certificates from a local PEM file |
| `migrate` | Apply or check database schema migrations |

## Documentation

Full documentation for each command and the database schema is available in the [docs/](docs/) directory.
