# Project State

## Purpose

This repository is building a demo for browser-to-edge mTLS in standard web
sessions, with special focus on Firefox automatic client certificate
enrollment.

The demo is intended to show:

- a browser reaching a load balancer over TLS
- the load balancer validating client certificates
- a normal application consuming trusted identity from the LB
- a separate signing service issuing client certificates from CSRs

The project is not trying to demonstrate backend service-to-service mTLS.

## Core Design

The agreed architecture is documented in [ARCHITECTURE.md](./ARCHITECTURE.md).

Current service model:

1. `lb`
2. `app`
3. `signer`

Trust model:

- The LB authenticates the client certificate.
- The application authorizes the user.
- The signer issues certificates only after app-approved enrollment.

Important design decisions:

- The signer acts as the client CA.
- Certificates should carry a stable internal user identifier.
- Certificate fingerprint is for audit/device tracking, not primary user ID.
- User access is revoked at the application level, not by certificate
  revocation.
- The backend network is intentionally trusted for this demo.

## Firefox Integration Notes

Firefox-specific behavior is documented in
[FIREFOX_AUTOCERTS.md](./FIREFOX_AUTOCERTS.md).

Key points already captured there:

- Enrollment trigger header:
  `Client-Cert-Enrollment: https://example.com/enroll; token="..."`
- Enrollment currently requires:
  - top-level HTTPS document load
  - trustworthy TLS
  - HTTPS enrollment endpoint
  - same-origin enrollment URL
  - Firefox pref:
    `security.tls.client_certificate_enrollment.enabled = true`
- CSR request details:
  - `POST` to the enrollment endpoint
  - `Content-Type: application/pkcs10`
  - optional `Authorization: Bearer <token>`
  - PEM PKCS#10 CSR body

## Current Implementation

The repository now contains a Compose scaffold with local HTTPS termination at
the load balancer using mkcert-generated development certificates.

Implemented files:

- [docker-compose.yml](./docker-compose.yml)
- [lb/nginx.conf](./lb/nginx.conf)
- [app/Dockerfile](./app/Dockerfile)
- [app/server.py](./app/server.py)
- [signer/Dockerfile](./signer/Dockerfile)
- [signer/server.py](./signer/server.py)
- [tests/test_compose_stack.py](./tests/test_compose_stack.py)
- [README.md](./README.md)

What works today:

- `docker compose` starts three containers
- only the LB is exposed on host ports
- `http://localhost:8080` is available for LB health checks and HTTP-to-HTTPS
  redirects
- `https://localhost:8443` terminates TLS at the LB with local certs mounted
  from `./certs`
- `https://localhost:9443` terminates TLS at the LB and requires a verified
  client certificate signed by the demo client CA
- the LB routes:
  - `/` and `/whoami` to `app`
  - `/enroll/start` and `/enroll/complete` to `app`
  - `/enroll` and `/signer/*` to `signer`
- the app serves a minimal HTML landing page at `/`
- the app exposes an enroll button and a top-level HTTPS enrollment trigger page
- the enrollment trigger page emits the Firefox
  `Client-Cert-Enrollment` header with a dummy token, a CSR endpoint on `8443`,
  and a completion URL on the mTLS listener at `9443`
- the signer accepts a real PEM CSR at `POST /enroll` and returns a PEM client
  certificate in JSON
- the LB enforces client certificate verification on `9443`
- the LB injects trusted-proxy headers and forwards certificate verification
  metadata to the app on the mTLS listener
- all three services emit request logs to stdout
- integration tests verify the baseline network behavior

What does **not** exist yet:

- real enrollment token flow
- certificate fingerprint forwarding
- user/session model in the application
- application-side authorization decisions based on the verified certificate

## How To Run

Start the stack:

```bash
./scripts/generate-local-certs.sh
docker compose up --build -d
```

Useful endpoints:

- `https://127.0.0.1:8443/`
- `https://127.0.0.1:8443/whoami`
- `https://localhost:9443/enroll/complete`
- `https://localhost:9443/whoami`
- `http://127.0.0.1:8080/` (redirects to HTTPS except health)
- `http://127.0.0.1:8080/lb/healthz`

Example signer request:

```bash
curl -X POST https://127.0.0.1:8443/enroll \
  -H 'Authorization: Bearer test-token' \
  -H 'Content-Type: application/pkcs10' \
  --data-binary $'-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n'
```

Stop the stack:

```bash
docker compose down -v
```

## Logs

To follow logs for a single service:

```bash
docker compose logs -f lb
docker compose logs -f app
docker compose logs -f signer
```

Current logging behavior:

- `lb` logs request method, path, status, and upstream target
- `app` logs method, path, status, and forwarded LB headers
- `signer` logs method, path, status, auth header, and forwarded LB headers

## Tests

Run the integration test suite with:

```bash
python -m unittest tests/test_compose_stack.py
```

The test suite currently verifies:

- LB health endpoint
- HTTP redirect behavior at the LB
- delivery of the app HTML page over HTTPS
- delivery of the Firefox enrollment trigger page and header over HTTPS
- routing to the app diagnostics endpoint over HTTPS
- routing to the signer enrollment endpoint over HTTPS
- rejection of unauthenticated traffic on the mTLS listener
- delivery of the enrollment completion page over mTLS
- forwarding of verified client identity headers over mTLS
- backend services are not reachable directly from host ports
- LB can reach backend services on the internal Compose network

Recent test-hardening changes:

- the test suite now tears down stale Compose state before startup
- Compose errors are surfaced with stdout/stderr rather than hidden behind a
  generic subprocess failure

## Environment Notes

This repo has already hit one important Fedora-specific behavior:

- the bind-mounted NGINX config required SELinux relabeling
- this is handled in `docker-compose.yml` with the `:Z` mount option

Docker access may depend on local host configuration. If `docker compose`
fails with socket permission errors, that is a host setup issue rather than a
repo code issue.

## Recommended Next Steps

The next implementation milestones should be:

1. Add enrollment token issuance and validation beyond the current dummy token.
2. Add certificate fingerprint and full certificate forwarding where needed.
3. Add application-side user lookup and authorization behavior.
4. Add demo cases for:
   - valid cert + active user
   - valid cert + disabled user
   - invalid/untrusted cert

## Suggested Starting Point For Future Agents

If continuing implementation, read files in this order:

1. [PROJECT_STATE.md](./PROJECT_STATE.md)
2. [ARCHITECTURE.md](./ARCHITECTURE.md)
3. [FIREFOX_AUTOCERTS.md](./FIREFOX_AUTOCERTS.md)
4. [README.md](./README.md)
5. [docker-compose.yml](./docker-compose.yml)
6. [lb/nginx.conf](./lb/nginx.conf)
7. [app/server.py](./app/server.py)
8. [signer/server.py](./signer/server.py)
9. [tests/test_compose_stack.py](./tests/test_compose_stack.py)
