import json
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


DB_PATH = Path(os.environ.get("DEMO_DB_PATH", "/srv/demo-data/demo.db"))
ENROLLMENT_COMPLETE_URL = "https://localhost:9443/enroll/complete"
ENROLLMENT_TTL_MINUTES = 10
SESSION_TTL_HOURS = 8
SESSION_COOKIE_NAME = "demo_session"
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

            CREATE TABLE IF NOT EXISTS app_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
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


def create_session(user_id):
    session_id = f"sess_{secrets.token_hex(8)}"
    token = secrets.token_urlsafe(24)
    created_at = utc_now()
    expires_at = created_at + timedelta(hours=SESSION_TTL_HOURS)
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO app_sessions (id, user_id, token, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                user_id,
                token,
                utc_timestamp(created_at),
                utc_timestamp(expires_at),
            ),
        )
    return token


def get_session_user(session_token):
    if not session_token:
        return None
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT u.id, u.display_name, u.email, u.status, u.cert_identifier
            FROM app_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (session_token, utc_timestamp(utc_now())),
        ).fetchone()
    return row_to_user(row)


def delete_session(session_token):
    if not session_token:
        return
    with connect_db() as connection:
        connection.execute("DELETE FROM app_sessions WHERE token = ?", (session_token,))


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


def html_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


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

    def _write_response(self, status_code, content_type, body, extra_headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        for header_name, header_value in extra_headers or ():
            self.send_header(header_name, header_value)
        self.end_headers()
        self.wfile.write(encoded)
        self._log_request(status_code)

    def _send_json(self, status_code, payload, extra_headers=None):
        self._write_response(
            status_code,
            "application/json",
            json.dumps(payload),
            extra_headers=extra_headers,
        )

    def _send_html(self, status_code, body, extra_headers=None):
        self._write_response(
            status_code,
            "text/html; charset=utf-8",
            body,
            extra_headers=extra_headers,
        )

    def _redirect(self, location, extra_headers=None):
        headers = [("Location", location)]
        if extra_headers:
            headers.extend(extra_headers)
        self._write_response(303, "text/plain; charset=utf-8", "redirecting", extra_headers=headers)

    def _external_base_url(self):
        scheme = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "localhost")
        return f"{scheme}://{host}"

    def _request_target(self):
        parsed = urlsplit(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _read_form(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        return parse_qs(raw_body)

    def _safe_next_path(self, next_value, fallback):
        if not next_value or not next_value.startswith("/") or next_value.startswith("//"):
            return fallback
        return next_value

    def _session_token(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        morsel = cookies.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel else None

    def _session_cookie_header(self, token):
        return f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax"

    def _clear_session_cookie_header(self):
        return f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"

    def _current_session_user(self):
        return get_session_user(self._session_token())

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

    def _page_shell(self, title, content):
        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html_escape(title)}</title>
  </head>
  <body>
    <main>
      {content}
    </main>
  </body>
</html>
"""

    def _send_home_page(self):
        session_user = self._current_session_user()
        mtls_identity = self._current_certificate_identity()
        login_section = """
      <section>
        <h2>Standard TLS Session</h2>
        <p>You are not logged in. The standard TLS protected page and certificate enrollment flow require an app login first.</p>
        <p><a href="/login">Go to the login page</a></p>
      </section>
"""
        if session_user:
            enroll_markup = "<p>This user cannot enroll for a client certificate.</p>"
            if session_user["status"] == "active":
                enroll_markup = '<p><a href="/enroll/start">Enroll a client certificate for this logged-in user</a></p>'
            login_section = f"""
      <section>
        <h2>Standard TLS Session</h2>
        <p>You are logged in as <strong>{html_escape(session_user["display_name"])}</strong> ({html_escape(session_user["id"])}).</p>
        <p><a href="/protected">Visit the standard TLS protected page</a></p>
        {enroll_markup}
        <p><a href="/logout">Log out</a></p>
      </section>
"""

        mtls_section = """
      <section>
        <h2>mTLS Session</h2>
        <p>No verified client certificate is currently attached to this request.</p>
        <p><a href="https://localhost:9443/protected/mtls">Open the mTLS protected page</a></p>
      </section>
"""
        if mtls_identity["verify"] == "SUCCESS" and mtls_identity["user"]:
            mtls_section = f"""
      <section>
        <h2>mTLS Session</h2>
        <p>This browser is presenting a verified certificate for <strong>{html_escape(mtls_identity["user"]["display_name"])}</strong> ({html_escape(mtls_identity["user"]["id"])}).</p>
        <p><a href="https://localhost:9443/protected/mtls">Open the mTLS protected page</a></p>
      </section>
"""

        self._send_html(
            200,
            self._page_shell(
                "Large mTLS Demo",
                f"""
      <h1>Large mTLS Demo</h1>
      <p>This site now separates standard login protection from certificate-based mTLS protection.</p>
      {login_section}
      {mtls_section}
      <section>
        <h2>Diagnostics</h2>
        <p><a href="/whoami">Inspect forwarded identity details</a></p>
        <p><a href="https://localhost:9443/whoami">Inspect verified mTLS identity details</a></p>
      </section>
""",
            ),
        )

    def _send_login_page(self, next_path="/protected", message=None):
        users_markup = []
        for user in get_users():
            users_markup.append(
                f'<option value="{html_escape(user["id"])}">{html_escape(user["display_name"])} ({html_escape(user["status"])})</option>'
            )
        message_markup = ""
        if message:
            message_markup = f"<p><strong>{html_escape(message)}</strong></p>"
        body = self._page_shell(
            "Login",
            f"""
      <h1>Login</h1>
      <p>Choose a demo user to create a standard TLS application session.</p>
      {message_markup}
      <form method="post" action="/login">
        <input type="hidden" name="next" value="{html_escape(next_path)}">
        <label for="user_id">Demo user</label>
        <select id="user_id" name="user_id">
          {''.join(users_markup)}
        </select>
        <button type="submit">Log in</button>
      </form>
      <p><a href="/">Return to the home page</a></p>
""",
        )
        self._send_html(200, body)

    def _send_protected_login_required(self, next_path):
        encoded_next = urlencode({"next": next_path})
        self._send_html(
            401,
            self._page_shell(
                "Login Required",
                f"""
      <h1>Protected Standard TLS Page</h1>
      <p>This page is protected by the application and requires a standard login session.</p>
      <p>You must log in before accessing this protected content.</p>
      <p><a href="/login?{encoded_next}">Log in to continue</a></p>
""",
            ),
        )

    def _send_standard_protected_page(self, session_user):
        enroll_markup = "<p>This user cannot enroll for a client certificate.</p>"
        if session_user["status"] == "active":
            enroll_markup = '<p><a href="/enroll/start">Start client certificate enrollment</a></p>'
        self._send_html(
            200,
            self._page_shell(
                "Protected Standard TLS Page",
                f"""
      <h1>Protected Standard TLS Page</h1>
      <p>This page is protected by the application login layer and is intended for authenticated users over standard TLS.</p>
      <p>The logged-in user is <strong>{html_escape(session_user["display_name"])}</strong> ({html_escape(session_user["id"])}).</p>
      {enroll_markup}
      <p><a href="/">Return to the home page</a></p>
""",
            ),
        )

    def _send_mtls_protected_page(self, mtls_identity):
        if mtls_identity["verify"] != "SUCCESS" or not mtls_identity["user"]:
            self._send_html(
                403,
                self._page_shell(
                    "mTLS Required",
                    """
      <h1>Protected mTLS Page</h1>
      <p>This page is protected by mutual TLS and requires a verified client certificate.</p>
      <p>Connect on the mTLS listener with an enrolled certificate to access this protected content.</p>
""",
                ),
            )
            return

        self._send_html(
            200,
            self._page_shell(
                "Protected mTLS Page",
                f"""
      <h1>Protected mTLS Page</h1>
      <p>This page is protected by mutual TLS. Access is only granted when a verified client certificate is presented.</p>
      <p>The connected certificate belongs to <strong>{html_escape(mtls_identity["user"]["display_name"])}</strong> ({html_escape(mtls_identity["user"]["id"])}).</p>
      <p>The stable certificate user identifier is <code>{html_escape(mtls_identity["cert_user_id"])}</code>.</p>
      <p><a href="https://localhost:9443/whoami">Inspect the forwarded mTLS identity headers</a></p>
""",
            ),
        )

    def _send_enrollment_page(self, user):
        base_url = self._external_base_url()
        csr_url = f"{base_url}/enroll"
        request_record = create_enrollment_request(user["id"])
        complete_url = ENROLLMENT_COMPLETE_URL
        enrollment_header = f'{csr_url}; token="{request_record["token"]}"; {complete_url}'
        body = self._page_shell(
            "Enroll Client Certificate",
            f"""
      <h1>Client Certificate Enrollment</h1>
      <p>Enrollment request <code>{html_escape(request_record["id"])}</code> was created for <strong>{html_escape(user["display_name"])}</strong> ({html_escape(user["id"])}).</p>
      <p>This page is protected behind the application login flow and emits the Firefox <code>Client-Cert-Enrollment</code> header with a short-lived token linked to that logged-in user.</p>
      <p>If Firefox auto enrollment is enabled, the browser should now generate a CSR and <code>POST</code> it to <code>{html_escape(csr_url)}</code>.</p>
      <p>The signer will ignore CSR identity fields, populate the response <code>name</code> from the user record, and embed <code>{html_escape(user["cert_identifier"])}</code> into the certificate subject.</p>
      <p>This request expires at <code>{html_escape(request_record["expires_at"])}</code>.</p>
      <p><a href="{html_escape(complete_url)}">Continue to the completion page</a></p>
""",
        )
        self._send_html(200, body, extra_headers=[("Client-Cert-Enrollment", enrollment_header)])

    def do_GET(self):
        request_path, query = self._request_target()

        if request_path == "/healthz":
            init_db()
            self._send_json(200, {"service": "app", "status": "ok"})
            return

        if request_path == "/":
            self._send_home_page()
            return

        if request_path == "/login":
            next_path = self._safe_next_path(query.get("next", ["/protected"])[0], "/protected")
            self._send_login_page(next_path=next_path)
            return

        if request_path == "/logout":
            delete_session(self._session_token())
            self._redirect("/", extra_headers=[("Set-Cookie", self._clear_session_cookie_header())])
            return

        if request_path == "/protected":
            session_user = self._current_session_user()
            if session_user is None:
                self._send_protected_login_required("/protected")
                return
            self._send_standard_protected_page(session_user)
            return

        if request_path == "/protected/mtls":
            self._send_mtls_protected_page(self._current_certificate_identity())
            return

        if request_path == "/enroll/start":
            session_user = self._current_session_user()
            if session_user is None:
                self._send_protected_login_required("/enroll/start")
                return
            if session_user["status"] != "active":
                self._send_json(
                    403,
                    {
                        "service": "app",
                        "error": "user is not allowed to enroll",
                        "user": session_user,
                    },
                )
                return
            self._send_enrollment_page(session_user)
            return

        if request_path == "/enroll/complete":
            identity = self._current_certificate_identity()
            user_markup = "<p>No verified client certificate was forwarded to the app.</p>"
            if identity["verify"] == "SUCCESS" and identity["user"]:
                user_markup = (
                    f"<p>This browser is authenticated as <strong>{html_escape(identity['user']['display_name'])}</strong> "
                    f"with certificate user id <code>{html_escape(identity['cert_user_id'])}</code>.</p>"
                )
            self._send_html(
                200,
                self._page_shell(
                    "Enrollment Complete",
                    f"""
      <h1>Enrollment Completion</h1>
      <p>This is the real redirect target for the enrollment flow on the mTLS port.</p>
      {user_markup}
      <p><a href="/">Return to the demo home page</a></p>
      <p><a href="/whoami">Inspect the verified client identity headers</a></p>
""",
                ),
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
                "session_user": self._current_session_user(),
                "certificate_user": identity["user"],
            }
            self._send_json(200, payload)
            return

        self._send_json(404, {"service": "app", "error": "not found", "path": self.path})

    def do_POST(self):
        request_path, _ = self._request_target()

        if request_path != "/login":
            self._send_json(404, {"service": "app", "error": "not found", "path": self.path})
            return

        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            self._send_json(
                415,
                {"service": "app", "error": "expected Content-Type application/x-www-form-urlencoded"},
            )
            return

        form = self._read_form()
        next_path = self._safe_next_path(form.get("next", ["/protected"])[0], "/protected")
        user_id = form.get("user_id", [""])[0]
        user = get_user_by_id(user_id)
        if user is None:
            self._send_login_page(next_path=next_path, message="Unknown user selected.")
            return

        session_token = create_session(user["id"])
        self._redirect(
            next_path,
            extra_headers=[("Set-Cookie", self._session_cookie_header(session_token))],
        )

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), AppHandler)
    print(f"[app] listening on 0.0.0.0:8000 using db={DB_PATH}", flush=True)
    server.serve_forever()
