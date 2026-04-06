import json
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


STATE_DIR = Path("/srv/signer/state")
CA_KEY_FILE = STATE_DIR / "demo-client-ca.key"
CA_CERT_FILE = STATE_DIR / "demo-client-ca.pem"
CA_SERIAL_FILE = STATE_DIR / "demo-client-ca.srl"


def run_openssl(*args, input_text=None):
    result = subprocess.run(
        ["openssl", *args],
        input=input_text,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl {' '.join(args)} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def ensure_demo_ca():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists():
        return
    run_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(CA_KEY_FILE),
        "-out",
        str(CA_CERT_FILE),
        "-days",
        "30",
        "-subj",
        "/CN=large-mtls-demo-client-ca",
    )


def sign_csr(csr_pem):
    ensure_demo_ca()
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        csr_file = tmp_dir / "request.csr"
        cert_file = tmp_dir / "issued.pem"
        csr_file.write_text(csr_pem, encoding="utf-8")
        args = [
            "x509",
            "-req",
            "-in",
            str(csr_file),
            "-CA",
            str(CA_CERT_FILE),
            "-CAkey",
            str(CA_KEY_FILE),
            "-CAserial",
            str(CA_SERIAL_FILE),
            "-CAcreateserial",
            "-out",
            str(cert_file),
            "-days",
            "7",
            "-sha256",
        ]
        run_openssl(*args)
        return cert_file.read_text(encoding="utf-8")


class SignerHandler(BaseHTTPRequestHandler):
    ENROLLMENT_TOKEN = "Bearer demo-enrollment-token"
    ENROLLMENT_COMPLETE_URL = "https://localhost:9443/enroll/complete"

    def _log_request(self, status_code):
        if urlsplit(self.path).path == "/healthz":
            return
        sys.stdout.write(
            "[signer] "
            f"client={self.client_address[0]} "
            f'method={self.command} path="{self.path}" '
            f"status={status_code} "
            f'authorization="{self.headers.get("Authorization", "-")}" '
            f'content_type="{self.headers.get("Content-Type", "-")}" '
            f'x_demo_trusted_proxy="{self.headers.get("X-Demo-Trusted-Proxy", "-")}" '
            f'x_forwarded_proto="{self.headers.get("X-Forwarded-Proto", "-")}"\n'
        )
        sys.stdout.flush()

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        self._log_request(status_code)

    def _external_base_url(self):
        scheme = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "localhost")
        return f"{scheme}://{host}"

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"service": "signer", "status": "ok"})
            return

        if self.path == "/ca.pem":
            body = CA_CERT_FILE.read_text(encoding="utf-8")
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)
            self._log_request(200)
            return

        self._send_json(
            200,
            {
                "service": "signer",
                "message": "signer container reachable through load balancer",
                "path": self.path,
            },
        )

    def do_POST(self):
        if self.path != "/enroll":
            self._send_json(404, {"service": "signer", "error": "not found"})
            return

        authorization = self.headers.get("Authorization")
        if authorization != self.ENROLLMENT_TOKEN:
            self._send_json(
                401,
                {
                    "service": "signer",
                    "error": "invalid enrollment token",
                    "expected": self.ENROLLMENT_TOKEN,
                },
            )
            return

        if self.headers.get("Content-Type") != "application/pkcs10":
            self._send_json(
                415,
                {"service": "signer", "error": "expected Content-Type application/pkcs10"},
            )
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        if "BEGIN CERTIFICATE REQUEST" not in body:
            self._send_json(
                400,
                {"service": "signer", "error": "request body did not contain a PEM CSR"},
            )
            return

        try:
            certificate_pem = sign_csr(body)
        except RuntimeError as exc:
            self._send_json(
                400,
                {"service": "signer", "error": "failed to sign CSR", "details": str(exc)},
            )
            return

        payload = {
            "service": "signer",
            "path": self.path,
            "method": "POST",
            "headers": {
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "x_demo_trusted_proxy": self.headers.get("X-Demo-Trusted-Proxy"),
                "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            },
            "csr_received": True,
            "certificate": certificate_pem,
            "encoding": "pem",
            "redirect_url": self.ENROLLMENT_COMPLETE_URL,
        }
        self._send_json(200, payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ensure_demo_ca()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), SignerHandler)
    print("[signer] listening on 0.0.0.0:8000", flush=True)
    server.serve_forever()
