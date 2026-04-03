# Large mTLS Demo

This repository contains the first scaffold for a browser-to-edge mTLS demo.

## Current Stack

- `lb`: NGINX reverse proxy on `https://localhost:8443`
- `app`: minimal Python HTTP service
- `signer`: minimal Python HTTP service

The stack now terminates TLS at the load balancer with local development
certificates. Backend traffic remains plain HTTP on the internal Compose
network.

## Run

```bash
./scripts/generate-local-certs.sh
docker compose up --build
```

If you hit the stack over HTTP on `http://localhost:8080`, the LB redirects
application traffic to `https://localhost:8443`.

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
- verify app diagnostics traffic routes through the LB over HTTPS
- verify `/enroll` reaches the signer through the LB over HTTPS
- verify `app` and `signer` are not published to the host
- verify internal service-to-service networking on the compose network
