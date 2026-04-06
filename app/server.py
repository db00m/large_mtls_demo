import json
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


DB_PATH = Path(os.environ.get("DEMO_DB_PATH", "/srv/demo-data/demo.db"))
ENROLLMENT_COMPLETE_URL = "https://localhost:9443/enroll/complete"
ENROLLMENT_TTL_MINUTES = 10
SEEDED_USERS = (
    {
        "id": "user-alice",
        "display_name": "Alice Admin",
        "email": "alice@example.test",
        "status": "active",
    },
    {
        "id": "user-bob",
        "display_name": "Bob Builder",
        "email": "bob@example.test",
        "status": "active",
    },
    {
        "id": "user-eve",
        "display_name": "Eve Example",
        "email": "eve@example.test",
        "status": "disabled",
    },
)


def utc_now():
    return datetime.now(timezone.utc)


def utc_timestamp(value):
    return value.replace(microsecond=0).isoformat()


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db():
    with connect_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                cert_identifier TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enrollment_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                issued_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

        created_at = utc_timestamp(utc_now())
        for user in SEEDED_USERS:
            connection.execute(
                """
                INSERT INTO users (id, display_name, email, status, cert_identifier, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    display_name = excluded.display_name,
                    email = excluded.email,
                    status = excluded.status,
                    cert_identifier = excluded.cert_identifier
                """,
                (
                    user["id"],
                    user["display_name"],
                    user["email"],
                    user["status"],
                    user["id"],
                    created_at,
                ),
            )


def row_to_user(row):
    if row is None:
        return None
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "email": row["email"],
        "status": row["status"],
        "cert_identifier": row["cert_identifier"],
    }


def get_users():
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT id, display_name, email, status, cert_identifier FROM users ORDER BY display_name"
        ).fetchall()
    return [row_to_user(row) for row in rows]


def get_user_by_id(user_id):
    with connect_db() as connection:
        row = connection.execute(
            "SELECT id, display_name, email, status, cert_identifier FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return row_to_user(row)


def get_user_by_cert_identifier(cert_identifier):
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT id, display_name, email, status, cert_identifier
            FROM users
            WHERE cert_identifier = ?
            """,
            (cert_identifier,),
        ).fetchone()
    return row_to_user(row)


def create_enrollment_request(user_id):
    token = secrets.token_urlsafe(24)
    request_id = f"enr_{secrets.token_hex(8)}"
    created_at = utc_now()
    expires_at = created_at + timedelta(minutes=ENROLLMENT_TTL_MINUTES)
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO enrollment_requests (id, user_id, token, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                user_id,
                token,
                "pending",
                utc_timestamp(created_at),
                utc_timestamp(expires_at),
            ),
        )
    return {"id": request_id, "token": token, "expires_at": utc_timestamp(expires_at)}


def extract_cert_user_id(subject):
    if not subject:
        return None

    for separator in (",", "/"):
        for part in subject.split(separator):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key.strip().lower() == "serialnumber" and value.strip():
                return value.strip()
    return None


class AppHandler(BaseHTTPRequestHandler):
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
            f'x_forwarded_proto="{self.headers.get("X-Forwarded-Proto", "-")}" '
            f'x_client_cert_user_id="{self.headers.get("X-Client-Cert-User-Id", "-")}"\n'
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

    def _send_html(self, status_code, body):
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)
        self._log_request(status_code)

    def _external_base_url(self):
        scheme = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "localhost")
        return f"{scheme}://{host}"

    def _request_target(self):
        parsed = urlsplit(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _current_certificate_identity(self):
        subject = self.headers.get("X-Client-Subject")
        cert_user_id = self.headers.get("X-Client-Cert-User-Id") or extract_cert_user_id(subject)
        verify = self.headers.get("X-Client-Verify")
        user = get_user_by_cert_identifier(cert_user_id) if cert_user_id else None
        return {
            "verify": verify,
            "subject": subject,
            "issuer": self.headers.get("X-Client-Issuer"),
            "cert_user_id": cert_user_id,
            "user": user,
        }

    def _send_home_page(self):
        users = get_users()
        identity = self._current_certificate_identity()
        base_url = self._external_base_url()
        current_user_markup = ""
        if identity["verify"] == "SUCCESS" and identity["user"]:
            current_user_markup = f"""
      <section>
        <h2>Current Certificate Identity</h2>
        <p>This browser is presenting a verified certificate for <strong>{identity["user"]["display_name"]}</strong> ({identity["user"]["id"]}).</p>
        <p><a href="{base_url}/whoami">Inspect trusted identity headers</a></p>
      </section>
"""

        user_items = []
        for user in users:
            if user["status"] == "active":
                action = f'<a href="/enroll/start?user={user["id"]}">Enroll certificate as {user["display_name"]}</a>'
            else:
                action = "Enrollment disabled"
            user_items.append(
                f"<li><strong>{user['display_name']}</strong> ({user['email']})"
                f" status={user['status']} cert_id={user['cert_identifier']}<br>{action}</li>"
            )

        self._send_html(
            200,
            f"""<!doctype html>
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
      <p>The app now owns demo users and stores enrollment requests in a shared SQLite database.</p>
{current_user_markup}      <section>
        <h2>Demo Users</h2>
        <p>Choose an active user to mint a short-lived enrollment request and hand Firefox a user-bound token.</p>
        <ul>
          {''.join(user_items)}
        </ul>
      </section>
      <section>
        <h2>Diagnostics</h2>
        <ul>
          <li><a href="/whoami">Inspect forwarded headers</a></li>
          <li><a href="https://localhost:9443/whoami">Inspect verified client identity on the mTLS port</a></li>
          <li><a href="https://localhost:9443/enroll/complete">Visit the mTLS completion page</a></li>
        </ul>
      </section>
    </main>
  </body>
</html>
""",
        )

    def _send_enrollment_page(self, user):
        base_url = self._external_base_url()
        csr_url = f"{base_url}/enroll"
        request_record = create_enrollment_request(user["id"])
        complete_url = ENROLLMENT_COMPLETE_URL
        enrollment_header = f'{csr_url}; token="{request_record["token"]}"; {complete_url}'
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
      <p>Enrollment request <code>{request_record["id"]}</code> was created for <strong>{user["display_name"]}</strong> ({user["id"]}).</p>
      <p>This page emits the Firefox <code>Client-Cert-Enrollment</code> header with a short-lived token linked to that user.</p>
      <p>If Firefox auto enrollment is enabled, the browser should now generate a CSR and <code>POST</code> it to <code>{csr_url}</code>.</p>
      <p>The signer will ignore CSR identity fields, populate the response <code>name</code> from the user record, and embed <code>{user["cert_identifier"]}</code> into the certificate subject.</p>
      <p>This request expires at <code>{request_record["expires_at"]}</code>.</p>
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
        request_path, query = self._request_target()

        if request_path == "/healthz":
            init_db()
            self._send_json(200, {"service": "app", "status": "ok"})
            return

        if request_path == "/":
            self._send_home_page()
            return

        if request_path == "/enroll/start":
            user_id = query.get("user", ["user-alice"])[0]
            user = get_user_by_id(user_id)
            if user is None:
                self._send_json(404, {"service": "app", "error": "unknown user", "user": user_id})
                return
            if user["status"] != "active":
                self._send_json(
                    403,
                    {
                        "service": "app",
                        "error": "user is not allowed to enroll",
                        "user": user,
                    },
                )
                return
            self._send_enrollment_page(user)
            return

        if request_path == "/enroll/complete":
            identity = self._current_certificate_identity()
            user_markup = "<p>No verified client certificate was forwarded to the app.</p>"
            if identity["verify"] == "SUCCESS" and identity["user"]:
                user_markup = (
                    f"<p>This browser is authenticated as <strong>{identity['user']['display_name']}</strong> "
                    f"with certificate user id <code>{identity['cert_user_id']}</code>.</p>"
                )
            self._send_html(
                200,
                f"""<!doctype html>
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
      {user_markup}
      <p><a href="/">Return to the demo home page</a></p>
      <p><a href="/whoami">Inspect the verified client identity headers</a></p>
    </main>
  </body>
</html>
""",
            )
            return

        if request_path == "/whoami":
            identity = self._current_certificate_identity()
            payload = {
                "service": "app",
                "path": request_path,
                "headers": {
                    "host": self.headers.get("Host"),
                    "x_demo_trusted_proxy": self.headers.get("X-Demo-Trusted-Proxy"),
                    "x_forwarded_for": self.headers.get("X-Forwarded-For"),
                    "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                    "x_forwarded_host": self.headers.get("X-Forwarded-Host"),
                    "x_client_verify": identity["verify"],
                    "x_client_subject": identity["subject"],
                    "x_client_issuer": identity["issuer"],
                    "x_client_cert_user_id": identity["cert_user_id"],
                },
                "user": identity["user"],
            }
            self._send_json(200, payload)
            return

        self._send_json(404, {"service": "app", "error": "not found", "path": self.path})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), AppHandler)
    print(f"[app] listening on 0.0.0.0:8000 using db={DB_PATH}", flush=True)
    server.serve_forever()
