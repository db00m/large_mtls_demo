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

    def _send_html(self, status_code, body):
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        self._log_request(status_code)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"service": "app", "status": "ok"})
            return

        if self.path == "/":
            self._send_html(
                200,
                """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Large mTLS Demo</title>
  </head>
  <body>
    <main>
      <h1>Large mTLS Demo</h1>
      <p>This app is reachable through the HTTPS load balancer.</p>
      <p>Current phase: local TLS termination is active, but client certificate enrollment is not implemented yet.</p>
      <ul>
        <li><a href="/whoami">Inspect forwarded headers</a></li>
        <li><code>POST /enroll</code> is routed to the signer service through the load balancer.</li>
      </ul>
    </main>
  </body>
</html>
""",
            )
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

        self._send_json(404, {"service": "app", "error": "not found", "path": self.path})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8000), AppHandler)
    print("[app] listening on 0.0.0.0:8000", flush=True)
    server.serve_forever()
