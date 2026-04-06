# Large mTLS Demo

This repository contains the first scaffold for a browser-to-edge mTLS demo.

## Current Stack

- `lb`: NGINX reverse proxy on `https://localhost:8443` and `https://localhost:9443`
- `app`: minimal Python HTTP service
- `signer`: Python HTTP service that signs demo client CSRs

The stack now terminates TLS at the load balancer with local development
certificates. Backend traffic remains plain HTTP on the internal Compose
network.

The app now exposes a browser-visible enrollment flow:

- `/` serves an enroll button
- `/enroll/start` emits the Firefox `Client-Cert-Enrollment` header on the
  bootstrap HTTPS listener at `8443`
- `/enroll/complete` is the post-enrollment completion page served on the mTLS
  listener at `9443`
- `POST /enroll` signs a real CSR and returns a PEM certificate in JSON
- all traffic on `9443` requires a client certificate signed by the demo client
  CA

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
- verify app diagnostics traffic routes through the LB over HTTPS
- verify `/enroll` reaches the signer through the LB over HTTPS
- verify the mTLS port rejects requests without a client certificate
- verify the enrollment completion page is reachable with an enrolled client
  certificate
- verify verified client identity headers reach the app through the mTLS port
- verify `app` and `signer` are not published to the host
- verify internal service-to-service networking on the compose network
