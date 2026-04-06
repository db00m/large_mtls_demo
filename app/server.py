import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class AppHandler(BaseHTTPRequestHandler):
    ENROLLMENT_TOKEN = "demo-enrollment-token"
    ENROLLMENT_COMPLETE_URL = "https://localhost:9443/enroll/complete"

    def _log_request(self, status_code):
        if urlsplit(self.path).path == "/healthz":
            return
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

    def _external_base_url(self):
        scheme = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "localhost")
        return f"{scheme}://{host}"

    def _send_enrollment_page(self):
        base_url = self._external_base_url()
        csr_url = f"{base_url}/enroll"
        complete_url = self.ENROLLMENT_COMPLETE_URL
        enrollment_header = f'{csr_url}; token="{self.ENROLLMENT_TOKEN}"; {complete_url}'
        body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Enroll Client Certificate</title>
    <meta http-equiv="refresh" content="3; url={complete_url}">
  </head>
  <body>
    <main>
      <h1>Client Certificate Enrollment</h1>
      <p>This top-level HTTPS page emits the Firefox <code>Client-Cert-Enrollment</code> header.</p>
      <p>If Firefox auto enrollment is enabled, the browser should now generate a CSR and <code>POST</code> it to <code>{csr_url}</code>.</p>
      <p>You will be redirected to the completion page shortly.</p>
      <p><a href="{complete_url}">Continue to the completion page</a></p>
    </main>
  </body>
</html>
"""
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Client-Cert-Enrollment", enrollment_header)
        self.end_headers()
        self.wfile.write(encoded)
        self._log_request(200)

    def do_GET(self):
        request_path = urlsplit(self.path).path

        if request_path == "/healthz":
            self._send_json(200, {"service": "app", "status": "ok"})
            return

        if request_path == "/":
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
      <p>Current phase: Firefox enrollment scaffolding is active and the mTLS edge now requires a verified client certificate on port 9443.</p>
      <p><a href="/enroll/start">Enroll Client Certificate</a></p>
      <ul>
        <li><a href="/enroll/start">Trigger Firefox auto enrollment</a></li>
        <li><a href="https://localhost:9443/enroll/complete">Enrollment completion page on the mTLS port</a></li>
        <li><a href="/whoami">Inspect forwarded headers</a></li>
        <li><a href="https://localhost:9443/whoami">Inspect verified client identity on the mTLS port</a></li>
        <li><code>POST /enroll</code> is routed to the signer service through the load balancer.</li>
      </ul>
    </main>
  </body>
</html>
""",
            )
            return

        if request_path == "/enroll/start":
            self._send_enrollment_page()
            return

        if request_path == "/enroll/complete":
            self._send_html(
                200,
                """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Enrollment Complete</title>
  </head>
  <body>
    <main>
      <h1>Enrollment Completion</h1>
      <p>This is the real redirect target for the enrollment flow on the mTLS port.</p>
      <p>If this page loaded successfully, the client certificate was presented and verified at the load balancer.</p>
      <p><a href="/">Return to the demo home page</a></p>
      <p><a href="/whoami">Inspect the verified client identity headers</a></p>
    </main>
  </body>
</html>
""",
            )
            return

        if request_path == "/whoami":
            payload = {
                "service": "app",
                "path": request_path,
                "headers": {
                    "host": self.headers.get("Host"),
                    "x_demo_trusted_proxy": self.headers.get("X-Demo-Trusted-Proxy"),
                    "x_forwarded_for": self.headers.get("X-Forwarded-For"),
                    "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                    "x_forwarded_host": self.headers.get("X-Forwarded-Host"),
                    "x_client_verify": self.headers.get("X-Client-Verify"),
                    "x_client_subject": self.headers.get("X-Client-Subject"),
                    "x_client_issuer": self.headers.get("X-Client-Issuer"),
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
