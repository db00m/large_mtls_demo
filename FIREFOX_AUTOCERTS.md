# Automatic Cert Enrollment Flow
## Current Header Format For Testing

The currently implemented trigger is a response header:

```http
Client-Cert-Enrollment: https://example.com/enroll; token="opaque-one-time-token"; https://example.com/enroll/complete
```

Header fields are currently interpreted as:

- the enrollment CSR endpoint URL
- an optional `token="..."`
- a bare completion URL for the browser to load after enrollment finishes

Current enforced constraints:

- Response must be a top-level HTTPS document load.
- TLS connection must be trustworthy.
- Enrollment URL must be HTTPS.
- Enrollment URL must currently be same-origin with the response URL.
- Pref must be enabled:

```text
security.tls.client_certificate_enrollment.enabled = true
```

## Current CSR Request Format

Once the user approves enrollment, Firefox sends a CSR to the enrollment URL as
an HTTPS `POST`.

Current request shape:

```http
POST /enroll HTTP/1.1
Host: example.com
Accept: application/json, application/pkix-cert, application/pkcs7-mime, application/x-pem-file, application/pem-certificate-chain, text/plain
Content-Type: application/pkcs10
Authorization: Bearer opaque-one-time-token
```

Request body:

```pem
-----BEGIN CERTIFICATE REQUEST-----
MIIB...
-----END CERTIFICATE REQUEST-----
```

Notes:

- The `Authorization` header is only sent if the `Client-Cert-Enrollment`
  header included a `token="..."` parameter.
- The request body is a PEM-encoded PKCS#10 CSR.
- The CSR is generated from a newly-created persistent NSS token key pair.
- The CSR currently uses a P-256 key.
- The CSR subject is currently `CN=<requesting host>`.

## Current CSR Response Formats

The enrollment endpoint must return an HTTP `2xx` response. Any non-OK response
is treated as enrollment failure.

Firefox currently accepts either JSON or raw certificate bytes.

### 1. JSON response

Recommended shape:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "encoding": "pem"
}
```

Supported JSON encodings:

- `encoding: "pem"`
- `encoding: "base64"`
- `encoding: "base64-der"`
- no `encoding`, which is treated the same as base64/base64-der
- if the `certificate` string contains `-----BEGIN`, it is treated as PEM even
  without `encoding: "pem"`

### 2. Raw response body

If the response `Content-Type` is not JSON, Firefox reads the response body as
raw bytes and passes it directly to `nsIX509CertDB.importUserCertificate()`.

Example:

```http
HTTP/1.1 200 OK
Content-Type: application/pkix-cert
Cache-Control: no-store
```

```text
...raw DER certificate bytes...
```
