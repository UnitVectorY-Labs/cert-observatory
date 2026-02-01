# Database

The most recent database schema for this application is stored in `schema.sql`.

The migrations are embedded in the application binary and stored in the source code at `internal/db/migrations/`. They are applied by running the `migrate up` command.

See the [docs/DATABASE.md](../docs/DATABASE.md) for connection configuration and [docs/migrate.md](../docs/migrate.md) for migration management.