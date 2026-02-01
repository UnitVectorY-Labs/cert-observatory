---
layout: default
title: migrate
nav_order: 4
---

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

The `migrate` command manages database schema migrations. Migrations are embedded in the binary and applied in order using [golang-migrate](https://github.com/golang-migrate/migrate).

All commands that interact with the database check the migration version at startup and refuse to run if migrations are pending.

## Examples

```bash
# Apply migrations
cert-observatory migrate up

# Check migration status
cert-observatory migrate status

# Using environment variables
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=secret
cert-observatory migrate up
```

## Migration Files

Migrations are stored in `internal/db/migrations/` and embedded in the binary. The format follows the golang-migrate convention:

- `NNNNNN_name.up.sql` - Forward migration
- `NNNNNN_name.down.sql` - Rollback migration

Once a version is released, migration files must not be modified. New changes always go in a new migration.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (database connection failed, migration failed, dirty state) |
