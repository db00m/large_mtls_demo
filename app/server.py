import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class AppHandler(BaseHTTPRequestHandler):
    def _log_request(self, status_code):
        sys.stdout.write(
            "[app] "
            f"client={self.client_address[0]} "
            f'method={self.command} path="{self.path}" '
            f"status={status_code} "
            f'host="{self.headers.get("Host", "-")}" '
            f'x_demo_trusted_proxy="{self.headers.get("X-Demo-Trusted-Proxy", "-")}" '
            f'x_forwarded_for="{self.headers.get("X-Forwarded-For", "-")}" '
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
            self._send_json(200, {"service": "app", "status": "ok"})
            return

        if self.path == "/whoami":
            payload = {
                "service": "app",
                "path": self.path,
                "headers": {
                    "host": self.headers.get("Host"),
                    "x_demo_trusted_proxy": self.headers.get("X-Demo-Trusted-Proxy"),
                    "x_forwarded_for": self.headers.get("X-Forwarded-For"),
                    "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                    "x_forwarded_host": self.headers.get("X-Forwarded-Host"),
                },
            }
            self._send_json(200, payload)
            return

        self._send_json(
            200,
            {
                "service": "app",
                "message": "app container reachable through load balancer",
                "path": self.path,
            },
        )

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8000), AppHandler)
    print("[app] listening on 0.0.0.0:8000", flush=True)
    server.serve_forever()
