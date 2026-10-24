---
layout: default
title: ingest-distrust
nav_order: 9
---

# ingest-distrust

Collect explicit CA certificate distrust actions for display in the web interface.
This is independent of domain crawling and root certificate ingestion. Rendering
reads PostgreSQL only; it never contacts revocation services.

## Setup and scheduling

Apply migrations as a separate deployment step, then collect both sources:

```bash
cert-observatory migrate up
cert-observatory ingest-distrust
```

For recurring collection, run Mozilla OneCRL hourly and CCADB daily:

```cron
15 * * * * cert-observatory ingest-distrust --source=mozilla_onecrl
30 2 * * * cert-observatory ingest-distrust --source=ccadb
```

Provide database environment variables to the job as described in
[Database](DATABASE.md). Do not run the default `all` source hourly: CCADB recommends
a daily collection schedule. The application does not start an internal scheduler.

## Sources and meaning

- **Mozilla OneCRL**: public JSON from
  <https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records>.
  Enabled records are imported as **Blocked by Mozilla**. Matching preserves the
  upstream issuer/serial or subject/public-key-hash rule. The latter hashes the
  full DER SubjectPublicKeyInfo, as Mozilla does. Serial numbers are normalized to
  unsigned big-endian integers. Browser blocks are not automatically described as
  issuer revocations. See [Mozilla's documentation](https://wiki.mozilla.org/CA/Intermediate_Certificates)
  and [matching implementation](https://github.com/mozilla/gecko-dev/blob/master/security/certverifier/NSSCertDBTrustDomain.cpp).
- **CCADB**: the V5 All Certificate Information CSV linked from
  <https://www.ccadb.org/resources>. Only root records with an explicit `Blocked`,
  `Disabled`, or `Removed` status for Apple, Chrome, Microsoft, or Mozilla produce
  rules. Each platform action is stored separately and matched by certificate
  SHA-256 fingerprint. `Not Trusted`, `Not Included`, `NotBefore`, and other
  non-action values do not produce rules. Intermediate statuses can reflect
  inherited trust, so intermediate records are not imported as direct blocks.
  Observe the [CCADB Data Usage Terms](https://www.ccadb.org/resources).

A removed root is labeled **Removed from [platform] root store**, which does not
imply a compromise. These reports cover different platform purposes and do not
reproduce complete browser validation. Date restrictions and other platform
constraints are not evaluated. The feeds generally do not supply effective dates
or detailed incident reasons for every action; missing values remain unknown.

Both sources are fetched from fixed HTTPS URLs. Each response is bounded to
32 MiB and validated before rules can change. HTTP failures, invalid records,
duplicate identities, malformed CSV/JSON, unexpected CCADB root status values, and
OneCRL pagination fail the refresh. A new upstream schema or pagination mechanism
may require a software update. Complete, well-formed upstream snapshots are
trusted; the application cannot detect every upstream omission.

## Options

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--source` | `CERT_OBS_DISTRUST_SOURCE` | `all` | `all`, `mozilla_onecrl`, or `ccadb` |
| `--timeout` | `CERT_OBS_DISTRUST_TIMEOUT` | `2m` | Positive timeout for each source's HTTP fetch |
| `--verbose` | `CERT_OBS_DISTRUST_VERBOSE` | `false` | Enable debug logging |

Explicit flags override environment variables. Invalid environment durations and
booleans are errors. Database flags and environment variables are listed in
[DATABASE.md](DATABASE.md).

## Storage and refresh behavior

`certificate_distrust_rules` stores rules independently of the certificate catalog,
so a block can be collected before the certificate is observed. There is no foreign
key to `certificates`. Repeated imports update the same source record and platform;
they do not append full snapshots. Source record identifiers, matching fields,
status, optional reason/reference/effective date, first/last observation times, and
withdrawal time are retained. Binary identifiers are stored as `bytea`, not base64.

`certificate_distrust_sources` records each source's last attempt, last successful
refresh, active rule count, and last error. PostgreSQL transaction advisory locks
serialize each source's refresh, including its fetch. A concurrent refresh of the
same source exits with an error rather than overwriting a newer snapshot.

A successful refresh atomically upserts rules, withdraws absent/disabled rules,
and updates freshness. Reappearing rules are reactivated. Fetch and validation
failures preserve the last accepted rules and record a source error. Database
write failures roll back the entire refresh. Cancellation or database failure can
also prevent freshness/error recording. One source can succeed when the other
fails; any failure results in a nonzero exit code.

Rows withdrawn from a feed remain in the table but do not generate warnings.
This records current rule lifecycle timestamps, not a complete immutable history
of every status change. No raw downloads or unchanged periodic snapshots are stored.

For scale, a measurement on October 20, 2026 found 1,901 OneCRL records (802 KiB
JSON) and 10,344 CCADB catalog rows (10.44 MiB CSV). Only relevant fields/actions
are retained; the CCADB catalog includes substantial unrelated audit information.
Of those OneCRL records, 1,256 were enabled. Importing these plus 674 CCADB
platform actions into PostgreSQL 18 used 872 KiB for both new tables and their
indexes. This is a measurement of a fresh import, not a storage limit; withdrawn
rules and normal PostgreSQL maintenance can increase usage. Future feed sizes
and rule counts can change.

## Web behavior and limits

- The graph marks affected CA certificates with `⚠` and a dashed, thicker border.
  Certificate details show the platform action, source, last observed time, and
  available reference/reason. Alternative paths remain visible.
- Current stored evidence is applied to cached chains, fresh crawls, and manual
  certificate inspection. A new rule can flag an existing chain without recrawling.
- Source refresh status is not displayed in search results. Previously accepted
  blocks remain visible even when a source refresh fails or data becomes stale.
- Warnings are applied only to certificates with CA basic constraints. Leaf
  certificates are not checked, even if a feed contains an exceptional leaf block.
- No issuer CRL downloads, OCSP checks, Chrome CRLSet ingestion, general trust
  validation, or global "not revoked"/"trusted" verdict is performed. Absence of a
  warning is not evidence of trust or non-revocation.

## Tests

`go test ./...` includes mocked HTTP ingestion, source selection and partial
failures, SQL transaction/failure tests, matching tests (including reissued and
cross-signed certificates), freshness tests, and HTML/graph rendering tests.
Network certificate retrieval is not used by these tests.
