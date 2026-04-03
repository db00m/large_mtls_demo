# Large mTLS Demo

This repository contains the first scaffold for a browser-to-edge mTLS demo.

## Current Stack

- `lb`: NGINX reverse proxy on `localhost:8080`
- `app`: minimal Python HTTP service
- `signer`: minimal Python HTTP service

This first pass validates container layout, routing, and internal network
assumptions before adding TLS termination, client certificate validation, and
real certificate issuance.

## Run

```bash
docker compose up --build
```

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
- verify app traffic routes through the LB
- verify `/enroll` reaches the signer through the LB
- verify `app` and `signer` are not published to the host
- verify internal service-to-service networking on the compose network
