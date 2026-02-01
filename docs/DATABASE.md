# Database Connection

All commands that interact with the database share a common set of connection parameters. These can be specified either via command-line flags or environment variables.

## Connection Parameters

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--db-host` | `DB_HOST` | `localhost` | PostgreSQL server hostname |
| `--db-port` | `DB_PORT` | `5432` | PostgreSQL server port |
| `--db-user` | `DB_USER` | `postgres` | Database user |
| `--db-password` | `DB_PASSWORD` | (empty) | Database password |
| `--db-name` | `DB_NAME` | `cert_observatory` | Database name |
| `--db-sslmode` | `DB_SSLMODE` | `disable` | SSL mode (`disable`, `require`, `verify-ca`, `verify-full`) |

## Priority

Command-line flags take precedence over environment variables. If neither is specified, the default value is used.

## Connection String

The application constructs a PostgreSQL connection string using the provided parameters:

```
host=<host> port=<port> user=<user> password=<password> dbname=<database> sslmode=<sslmode>
```

## Example Usage

### Using environment variables:

```bash
export DB_HOST=db.example.com
export DB_PORT=5432
export DB_USER=certuser
export DB_PASSWORD=secret
export DB_NAME=cert_observatory

cert-observatory crawl-domain --url example.com
```

### Using command-line flags:

```bash
cert-observatory crawl-domain \
  --url example.com \
  --db-host db.example.com \
  --db-port 5432 \
  --db-user certuser \
  --db-password secret \
  --db-name cert_observatory
```

### Mixed usage (flags override environment variables):

```bash
export DB_HOST=default-db.example.com
export DB_USER=defaultuser

cert-observatory crawl-domain --url example.com --db-host override-db.example.com
# Uses override-db.example.com as host, but defaultuser as user
```

## Migrations

Before running commands that interact with the database, ensure the database schema is up to date. All commands that require database access will check the migration version at startup and refuse to run if migrations are pending.

The `migrate` command can be used to apply pending migrations:

```bash
cert-observatory migrate up
```

## Docker Compose Example

For local development, a PostgreSQL instance can be started with Docker:

```yaml
version: '3.8'
services:
  db:
    image: postgres:18
    environment:
      POSTGRES_DB: cert_observatory
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

Then configure the application:

```bash
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASSWORD=postgres
export DB_NAME=cert_observatory
```
