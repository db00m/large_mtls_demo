#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
CERT_FILE="${CERT_DIR}/localhost.pem"
KEY_FILE="${CERT_DIR}/localhost-key.pem"

if ! command -v mkcert >/dev/null 2>&1; then
  echo "mkcert is required to generate local HTTPS certs" >&2
  exit 1
fi

mkdir -p "${CERT_DIR}"

mkcert -install
mkcert \
  -cert-file "${CERT_FILE}" \
  -key-file "${KEY_FILE}" \
  localhost 127.0.0.1 ::1

echo "Generated ${CERT_FILE} and ${KEY_FILE}"
