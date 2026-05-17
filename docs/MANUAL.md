---
layout: default
title: manual
nav_order: 10
---

# Manual Certificate Import

The `serve-web` command includes a hidden **manual import** mode that allows a trusted certificate to be pasted directly as PEM text, bypassing the normal domain-lookup flow.

## Activating Manual Mode

Navigate to the application with the `?manual` query parameter appended to the root URL:

```
http://localhost:8080/?manual
```

The standard domain-lookup form is replaced with a PEM text area. Paste a single PEM-encoded certificate into the text area and click **Import**.

## Behavior

1. The submitted PEM block is decoded and parsed as a single X.509 certificate.
2. The certificate's signature is validated against certificates already stored in the database (matched via the Authority Key Identifier ↔ Subject Key Identifier relationship, followed by a cryptographic signature check).
3. If the signature is valid, the certificate is inserted into the `certificates` table (idempotent — re-uploading the same certificate is safe).
4. The full trust path for the uploaded certificate is built and rendered exactly as it would be for a certificate retrieved from a live server, using all CA certificates present in the database.

## Constraints

- **One certificate only.** Submitting a PEM bundle containing multiple `CERTIFICATE` blocks is rejected.
- **No self-signed certificates.** The uploaded certificate must be issued by an issuer whose certificate is already in the database. Uploading a new root CA directly is not supported through this interface.
- **Valid signature required.** Unlike the domain-crawl flow, which captures and displays invalid or expired certificates returned by a server, manual import requires the certificate to be cryptographically valid before it is accepted.

## Use Cases

- Manually adding a newly-issued intermediate CA certificate so that its trust path and chain relationships are visible in the application before any server has deployed it.
- Importing a certificate of interest that is not directly accessible via a live TLS endpoint.
- Verifying the trust path of any certificate against the set of roots and intermediaries already ingested into the database.

## Example

```bash
# Activate the manual import page
open "http://localhost:8080/?manual"
```

Paste the PEM certificate (including the `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` delimiters) into the text area and click **Import**. The resulting page shows the certificate's decoded details and its full trust path in the same graph view used by the standard domain-lookup flow.

## Security Notes

The manual import endpoint (`POST /manual`) is protected by the same cross-origin request checks applied to all state-changing endpoints. Only same-origin requests (matching `Origin` header or `Sec-Fetch-Site: same-origin`) are accepted.

This feature is intentionally undiscoverable from the standard UI — it is activated only by adding `?manual` to the URL — which is why it is referred to as a "secret" feature.
