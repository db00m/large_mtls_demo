import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SignerHandler(BaseHTTPRequestHandler):
    def _log_request(self, status_code):
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
        self.end_headers()
        self.wfile.write(body)
        self._log_request(status_code)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"service": "signer", "status": "ok"})
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

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

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
            "csr_received": "BEGIN CERTIFICATE REQUEST" in body,
        }
        self._send_json(200, payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8000), SignerHandler)
    print("[signer] listening on 0.0.0.0:8000", flush=True)
    server.serve_forever()
