import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


STATE_DIR = Path("/srv/signer/state")
DB_PATH = Path(os.environ.get("DEMO_DB_PATH", "/srv/demo-data/demo.db"))
CA_KEY_FILE = STATE_DIR / "demo-client-ca.key"
CA_CERT_FILE = STATE_DIR / "demo-client-ca.pem"
CA_SERIAL_FILE = STATE_DIR / "demo-client-ca.srl"
ENROLLMENT_COMPLETE_URL = "https://localhost:9443/enroll/complete"
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


def row_to_enrollment(row):
    if row is None:
        return None
    return {
        "request_id": row["request_id"],
        "status": row["request_status"],
        "expires_at": row["expires_at"],
        "user": {
            "id": row["user_id"],
            "display_name": row["display_name"],
            "email": row["email"],
            "status": row["user_status"],
            "cert_identifier": row["cert_identifier"],
        },
    }


def get_enrollment_by_token(token):
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT
                er.id AS request_id,
                er.status AS request_status,
                er.expires_at,
                u.id AS user_id,
                u.display_name,
                u.email,
                u.status AS user_status,
                u.cert_identifier
            FROM enrollment_requests er
            JOIN users u ON u.id = er.user_id
            WHERE er.token = ?
            """,
            (token,),
        ).fetchone()
    return row_to_enrollment(row)


def mark_enrollment_issued(request_id):
    with connect_db() as connection:
        connection.execute(
            """
            UPDATE enrollment_requests
            SET status = ?, issued_at = ?
            WHERE id = ?
            """,
            ("issued", utc_timestamp(utc_now()), request_id),
        )


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


def extract_csr_subject(csr_pem):
    with tempfile.NamedTemporaryFile(dir=STATE_DIR, suffix=".csr", mode="w", delete=False) as csr_file:
        csr_file.write(csr_pem)
        csr_path = Path(csr_file.name)
    try:
        result = run_openssl("req", "-in", str(csr_path), "-subject", "-noout", "-nameopt", "RFC2253")
        return result.stdout.strip().removeprefix("subject=")
    finally:
        csr_path.unlink(missing_ok=True)


def certificate_subject_for_user(user):
    return f"/CN={user['display_name']}/serialNumber={user['cert_identifier']}"


def sign_csr(csr_pem, user):
    ensure_demo_ca()
    certificate_subject = certificate_subject_for_user(user)
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        csr_file = tmp_dir / "request.csr"
        cert_file = tmp_dir / "issued.pem"
        ext_file = tmp_dir / "extensions.cnf"
        csr_file.write_text(csr_pem, encoding="utf-8")
        ext_file.write_text(
            "\n".join(
                (
                    "[extensions]",
                    "basicConstraints=CA:FALSE",
                    "keyUsage=digitalSignature",
                    "extendedKeyUsage=clientAuth",
                    f"subjectAltName=URI:urn:large-mtls-demo:user:{user['cert_identifier']}",
                )
            ),
            encoding="utf-8",
        )
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
            "-set_subject",
            certificate_subject,
            "-clrext",
            "-extfile",
            str(ext_file),
            "-extensions",
            "extensions",
        ]
        run_openssl(*args)
        return {
            "certificate": cert_file.read_text(encoding="utf-8"),
            "certificate_subject": certificate_subject,
        }


class SignerHandler(BaseHTTPRequestHandler):
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

    def do_GET(self):
        if self.path == "/healthz":
            init_db()
            self._send_json(200, {"service": "signer", "status": "ok"})
            return

        if self.path == "/ca.pem":
            ensure_demo_ca()
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

        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            self._send_json(
                401,
                {
                    "service": "signer",
                    "error": "missing bearer enrollment token",
                },
            )
            return

        enrollment = get_enrollment_by_token(authorization.removeprefix("Bearer ").strip())
        if enrollment is None:
            self._send_json(401, {"service": "signer", "error": "invalid enrollment token"})
            return

        if enrollment["status"] != "pending":
            self._send_json(409, {"service": "signer", "error": "enrollment token already used"})
            return

        if enrollment["user"]["status"] != "active":
            self._send_json(403, {"service": "signer", "error": "user is not eligible for enrollment"})
            return

        if datetime.fromisoformat(enrollment["expires_at"]) <= utc_now():
            self._send_json(401, {"service": "signer", "error": "enrollment token expired"})
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
            csr_subject = extract_csr_subject(body)
            issuance = sign_csr(body, enrollment["user"])
            mark_enrollment_issued(enrollment["request_id"])
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
                "authorization": authorization,
                "content_type": self.headers.get("Content-Type"),
                "x_demo_trusted_proxy": self.headers.get("X-Demo-Trusted-Proxy"),
                "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            },
            "csr_received": True,
            "csr_subject": csr_subject,
            "name": enrollment["user"]["display_name"],
            "user": enrollment["user"],
            "enrollment_request_id": enrollment["request_id"],
            "certificate_subject": issuance["certificate_subject"],
            "certificate_identity": {
                "user_id": enrollment["user"]["id"],
                "cert_identifier": enrollment["user"]["cert_identifier"],
                "subject_alt_name_uri": f"urn:large-mtls-demo:user:{enrollment['user']['cert_identifier']}",
            },
            "certificate": issuance["certificate"],
            "encoding": "pem",
            "redirect_url": ENROLLMENT_COMPLETE_URL,
        }
        self._send_json(200, payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    init_db()
    ensure_demo_ca()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), SignerHandler)
    print(f"[signer] listening on 0.0.0.0:8000 using db={DB_PATH}", flush=True)
    server.serve_forever()
