# Large mTLS Demo

This repository contains a browser-to-edge mTLS demo with user-bound client
certificate enrollment.

## Current Stack

- `lb`: NGINX reverse proxy on `https://localhost:8443` and `https://localhost:9443`
- `app`: Python HTTP service that owns demo users and enrollment requests
- `signer`: Python HTTP service that signs client CSRs from trusted enrollment
  claims

The stack now terminates TLS at the load balancer with local development
certificates. Backend traffic remains plain HTTP on the internal Compose
network, while the app and signer share a SQLite database volume for user and
enrollment state.

The app now exposes a browser-visible enrollment flow:

- `/` serves demo users with active or disabled enrollment status
- `/enroll/start?user=<user-id>` creates an enrollment request, generates a
  short-lived token, and emits the Firefox `Client-Cert-Enrollment` header on
  the bootstrap HTTPS listener at `8443`
- `/enroll/complete` is the post-enrollment completion page served on the mTLS
  listener at `9443`
- `POST /enroll` validates the token, ignores CSR identity claims, and returns
  a PEM certificate in JSON
- all traffic on `9443` requires a client certificate signed by the demo client
  CA
- the issued certificate subject contains the user display name and a stable
  `serialNumber` mapped back to the user account

## Run

```bash
./scripts/generate-local-certs.sh
docker compose up --build
```

If you hit the stack over HTTP on `http://localhost:8080`, the LB redirects
application traffic to `https://localhost:8443`.

After enrollment, use the mTLS port:

- `https://localhost:9443/enroll/complete`
- `https://localhost:9443/whoami`

Demo users:

- `user-alice` -> active
- `user-bob` -> active
- `user-eve` -> disabled

## Test

```bash
python -m unittest tests/test_compose_stack.py
```

## Logs

Each service writes request logs to stdout. To follow one service:

```bash
docker compose logs -f lb
docker compose logs -f app
docker compose logs -f signer
```

The integration test will:

- verify the LB health endpoint
- verify HTTP requests redirect to HTTPS
- verify the app serves a minimal HTML page through the LB over HTTPS
- verify the enrollment trigger page emits the Firefox enrollment header
- verify enrollment is tied to specific demo users
- verify app diagnostics traffic routes through the LB over HTTPS
- verify `/enroll` reaches the signer through the LB over HTTPS and the signer
  overwrites certificate identity from trusted user data
- verify the mTLS port rejects requests without a client certificate
- verify the enrollment completion page is reachable with an enrolled client
  certificate
- verify verified client identity headers and resolved user identity reach the
  app through the mTLS port
- verify `app` and `signer` are not published to the host
- verify internal service-to-service networking on the compose network
