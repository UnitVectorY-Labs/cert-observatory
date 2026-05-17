This is a Go application that provides multiple pieces of functionality through a single binary that is deployed via Docker. The main purpose of this application is to retrieve, store, and present the TLS certificate chains for individual domains. While the primary use case is focused on the web interface, an additional set of functionality is provided by the same binary.

## Technology Stack

- Go programming language
- Docker for containerization
- PostgreSQL for database storage
- HTMX for dynamic web components
- Tailwind CSS CLI for build-time stylesheet generation only (compiled CSS is committed and embedded)
- No additional JavaScript frameworks beyond HTMX (radical simplicity as design philosophy)

Minimize the use of external dependencies relying on the Go standard library as much as possible.

Tailwind is used for CSS on this project, but not as a JavaScript framework. The Tailwind CLI is used directly to compile the CSS into a single file that is committed to the repository and embedded in the binary. The use of Tailwind is purely for CSS utility classes and does not involve any JavaScript or runtime dependencies.

```
tailwindcss -i ./internal/web/tailwind.css -o ./internal/web/static/css/style.css
```

The icons used by this project are embedded SVGs taken from https://github.com/tabler/tabler-icons and are included as inline SVG in the HTML templates.

Always include the content such as HTML templates, CSS, and JavaScript as well as the database migrations within the single binary using Go's `embed` package allowing the single binary to be used without any additional files.

Environment variables are paired with command line flags for all configuration options to allow flexibility in deployment and usage. These are all clearly documented alongside the commands they apply to in `docs/`.

## Command Structure

This one binary exposes multiple commands to provide the different pieces of functionality:

- `serve-web` - Serve the web application for browsing and inspecting stored certificate data.
- `crawl-domain` - Manually crawl a single domain and store the results in the database.
- `crawl-domains` - Job to crawl domains that are due for re-crawling based on a schedule.
- `ingest-toplist` - Job to list of top domains from Cloudflare's Top 10k list to populate the database.
- `ingest-roots` - Job to ingest the set of trusted root certificates
- `migrate` - Apply database schema migrations.

The functionality is organized into internal packages including shared packages used by the separate commands.

## Testing

All testing utilizes mocks for external dependencies including interacting with PostgreSQL and making network requests to retrieve TLS certificates.

When an agent is developing and debugging it is allowed to use the Docker image `postgres:18` for testing and debugging against a real PostgreSQL instance, however access to retrieve real TLS certificates should be limited to domains like `github.com` and not be used for accessing arbitrary domains on the internet autonomously.

## Documentation

The main README.md file provides a minimal overview of the project. The majority of the documentation is contained within the docs/ directory with separate markdown files for different aspects of the project including one for each command as well as one for the database design, and additional files for each major component.

When screenshots are requested, use the Playwright MCP server to capture and post the images directly to the pull request — never commit screenshot files to the repository.

## Database Schema and Migrations

- SQL-first migrations: schema changes are authored as ordered SQL migrations in `db/migrations/` (the migration history is the source of truth, not an ORM).
- One tool: use `golang-migrate/migrate` with file-based migrations so containers and CI run the same thing.
- Explicit execution: production runs `cert-observatory migrate up` as a distinct step; application modes do not silently mutate schema by default.
- Fail fast on drift: `serve-web` (and all other commands that interact with the database) check the DB version at startup and refuse to run if migrations are pending and do not match expected version for the binary.
- Immutable history: never edit, renumber, or delete committed migrations **once a version is released**; new changes always go in a new migration to keep upgrades predictable.
- The `db/schema.sql` file contains the most recent schema for a new install and the state should match the state after applying all migrations in order including the initial schema setup and all subsequent migrations.
