# migrate

Manage database migrations for the cert-observatory application.

## Synopsis

```bash
cert-observatory migrate <subcommand> [options]
```

## Subcommands

### up

Apply all pending migrations.

```bash
cert-observatory migrate up [options]
```

### status

Show current migration status.

```bash
cert-observatory migrate status [options]
```

## Options

See [DATABASE.md](DATABASE.md) for database connection options.

## Description

The `migrate` command manages database schema migrations. Migrations are embedded in the binary and applied in order.

The application maintains an expected migration version. All commands that interact with the database check this version at startup and refuse to run if migrations are pending.

## Examples

### Apply migrations:

```bash
cert-observatory migrate up --db-host localhost --db-user postgres --db-password secret
```

### Check migration status:

```bash
cert-observatory migrate status --db-host localhost --db-user postgres --db-password secret
```

### Using environment variables:

```bash
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=secret
export DB_NAME=cert_observatory

cert-observatory migrate up
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (database connection failed, migration failed, dirty state) |

## Migration Files

Migrations are stored in `internal/db/migrations/` and embedded in the binary at build time. The migration format follows the golang-migrate convention:

- `NNNNNN_name.up.sql` - Forward migration
- `NNNNNN_name.down.sql` - Rollback migration

## Notes

- Migrations are applied in order by filename prefix (000001, 000002, etc.)
- Once a version is released, migration files must not be modified
- The database tracks the current version and dirty state
- If the database is in a dirty state, manual intervention is required
