import http.cookiejar
import json
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_CMD = ["docker", "compose"]
CERT_DIR = ROOT / "certs"
CERT_FILE = CERT_DIR / "localhost.pem"
KEY_FILE = CERT_DIR / "localhost-key.pem"


def docker_available():
    return shutil.which("docker") is not None


def mkcert_available():
    return shutil.which("mkcert") is not None


def openssl_available():
    return shutil.which("openssl") is not None


def run_compose(*args, check=True):
    result = subprocess.run(
        [*COMPOSE_CMD, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "docker compose command failed: "
            f"{' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def run_command(*args):
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )


def create_client_key_and_csr(output_dir, common_name="firefox-demo-client"):
    if not openssl_available():
        raise AssertionError("openssl is required to generate a demo CSR for enrollment tests")
    filename_prefix = common_name.replace("/", "-")
    key_file = output_dir / f"{filename_prefix}.key"
    csr_file = output_dir / f"{filename_prefix}.csr"
    run_command(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_file),
        "-out",
        str(csr_file),
        "-subj",
        f"/CN={common_name}",
    )
    return key_file, csr_file.read_bytes()


def read_certificate_subject(cert_file):
    result = run_command(
        "openssl",
        "x509",
        "-in",
        str(cert_file),
        "-subject",
        "-noout",
        "-nameopt",
        "RFC2253",
    )
    return result.stdout.strip().removeprefix("subject=")


def ensure_local_tls_material():
    CERT_DIR.mkdir(exist_ok=True)

    if CERT_FILE.exists() and KEY_FILE.exists():
        return False

    if mkcert_available():
        run_command(
            "mkcert",
            "-cert-file",
            str(CERT_FILE),
            "-key-file",
            str(KEY_FILE),
            "localhost",
            "127.0.0.1",
            "::1",
        )
        return True

    if openssl_available():
        run_command(
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(KEY_FILE),
            "-out",
            str(CERT_FILE),
            "-days",
            "7",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        )
        return True

    raise AssertionError("mkcert or openssl is required to provision local TLS material")


def maybe_cleanup_generated_tls_material(created):
    if not created:
        return
    for path in (CERT_FILE, KEY_FILE):
        if path.exists():
            path.unlink()


def https_context():
    if mkcert_available():
        result = subprocess.run(
            ["mkcert", "-CAROOT"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            ca_file = Path(result.stdout.strip()) / "rootCA.pem"
            if ca_file.exists():
                return ssl.create_default_context(cafile=str(ca_file))
    return ssl._create_unverified_context()


def client_https_context(cert_file, key_file):
    context = https_context()
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def get_response(url, method="GET", body=None, headers=None, context=None):
    request = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    return urllib.request.urlopen(request, timeout=2, context=context)


def get_json(url, method="GET", body=None, headers=None, context=None):
    with get_response(url, method=method, body=body, headers=headers, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def opener_with_context(context):
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookie_jar),
    )
    return opener


def open_with_opener(opener, url, method="GET", body=None, headers=None):
    request = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    return opener.open(request, timeout=2)


def get_json_with_opener(opener, url, method="GET", body=None, headers=None):
    with open_with_opener(opener, url, method=method, body=body, headers=headers) as response:
        return json.loads(response.read().decode("utf-8"))


def login_as(user_id, context, next_path="/protected"):
    opener = opener_with_context(context)
    body = urllib.parse.urlencode({"user_id": user_id, "next": next_path}).encode("utf-8")
    with open_with_opener(
        opener,
        "https://localhost:8443/login",
        method="POST",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ) as response:
        page = response.read().decode("utf-8")
    return opener, page


def parse_enrollment_token(enrollment_header):
    match = re.fullmatch(
        r'https://localhost:8443/enroll; token="([^"]+)"; https://localhost:9443/enroll/complete',
        enrollment_header,
    )
    if not match:
        raise AssertionError(f"unexpected Client-Cert-Enrollment header: {enrollment_header}")
    return match.group(1)


def start_enrollment(opener):
    with open_with_opener(opener, "https://localhost:8443/enroll/start") as response:
        enrollment_header = response.headers.get("Client-Cert-Enrollment")
        body = response.read().decode("utf-8")
    return {
        "token": parse_enrollment_token(enrollment_header),
        "header": enrollment_header,
        "body": body,
    }


@unittest.skipUnless(docker_available(), "docker is required for compose integration tests")
class ComposeStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._generated_tls_material = ensure_local_tls_material()
        cls._https_context = https_context()
        run_compose("down", "-v", "--remove-orphans", check=False)
        run_compose("up", "--build", "-d")
        cls._wait_for_stack()
        cls._client_tmp_dir = tempfile.TemporaryDirectory()
        client_dir = Path(cls._client_tmp_dir.name)
        alice_opener, _ = login_as("user-alice", cls._https_context, next_path="/protected")
        enrollment = start_enrollment(alice_opener)
        cls._client_key_file, client_csr = create_client_key_and_csr(
            client_dir,
            common_name="csr-tries-to-be-mallory",
        )
        cls._initial_enrollment_payload = get_json(
            "https://127.0.0.1:8443/enroll",
            method="POST",
            body=client_csr,
            headers={
                "Authorization": f"Bearer {enrollment['token']}",
                "Content-Type": "application/pkcs10",
            },
            context=cls._https_context,
        )
        cls._client_cert_file = client_dir / "client.pem"
        cls._client_cert_file.write_text(
            cls._initial_enrollment_payload["certificate"],
            encoding="utf-8",
        )
        cls._client_cert_subject = read_certificate_subject(cls._client_cert_file)
        cls._mtls_context = client_https_context(cls._client_cert_file, cls._client_key_file)

    @classmethod
    def tearDownClass(cls):
        run_compose("down", "-v", "--remove-orphans", check=False)
        cls._client_tmp_dir.cleanup()
        maybe_cleanup_generated_tls_material(cls._generated_tls_material)

    @classmethod
    def _wait_for_stack(cls):
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                payload = get_json("http://127.0.0.1:8080/lb/healthz")
                if payload["service"] == "lb":
                    return
            except Exception:
                time.sleep(1)
        raise AssertionError("stack did not become healthy within 60 seconds")

    def test_lb_health_endpoint(self):
        payload = get_json("http://127.0.0.1:8080/lb/healthz")
        self.assertEqual(payload["service"], "lb")
        self.assertEqual(payload["status"], "ok")

    def test_http_redirects_to_https_for_app_routes(self):
        with get_response("http://127.0.0.1:8080/", context=self._https_context) as response:
            final_url = urlparse(response.geturl())
            self.assertEqual(final_url.scheme, "https")
            self.assertEqual(final_url.port, 8443)
            self.assertEqual(response.headers.get_content_type(), "text/html")
            body = response.read().decode("utf-8")
        self.assertIn("Large mTLS Demo", body)

    def test_app_root_serves_html_over_https(self):
        with get_response("https://127.0.0.1:8443/", context=self._https_context) as response:
            self.assertEqual(response.headers.get_content_type(), "text/html")
            body = response.read().decode("utf-8")
        self.assertIn("Large mTLS Demo", body)
        self.assertIn("not logged in", body)
        self.assertIn("login page", body)
        self.assertIn("mTLS protected page", body)

    def test_login_page_lists_demo_users(self):
        with get_response("https://localhost:8443/login", context=self._https_context) as response:
            self.assertEqual(response.headers.get_content_type(), "text/html")
            body = response.read().decode("utf-8")
        self.assertIn("Login", body)
        self.assertIn("Alice Admin", body)
        self.assertIn("Bob Builder", body)
        self.assertIn("Eve Example", body)

    def test_standard_tls_protected_page_requires_login(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            get_response("https://localhost:8443/protected", context=self._https_context)
        self.assertEqual(context.exception.code, 401)
        body = context.exception.read().decode("utf-8")
        context.exception.close()
        self.assertIn("Protected Standard TLS Page", body)
        self.assertIn("requires a standard login session", body)

    def test_standard_tls_protected_page_is_available_after_login(self):
        opener, page = login_as("user-bob", self._https_context, next_path="/protected")
        self.assertIn("Protected Standard TLS Page", page)
        self.assertIn("Bob Builder", page)
        payload = get_json_with_opener(opener, "https://localhost:8443/whoami")
        self.assertEqual(payload["session_user"]["id"], "user-bob")
        self.assertIsNone(payload["certificate_user"])

    def test_enrollment_trigger_page_emits_firefox_header_for_logged_in_user(self):
        opener, _ = login_as("user-bob", self._https_context, next_path="/protected")
        enrollment = start_enrollment(opener)
        self.assertTrue(enrollment["token"])
        self.assertIn("Bob Builder", enrollment["body"])
        self.assertIn("logged-in user", enrollment["body"])
        self.assertIn("Client Certificate Enrollment", enrollment["body"])
        self.assertIn("name", enrollment["body"])

    def test_app_diagnostics_route_through_lb_over_https(self):
        payload = get_json("https://127.0.0.1:8443/whoami", context=self._https_context)
        self.assertEqual(payload["service"], "app")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "https")
        self.assertEqual(payload["headers"]["x_forwarded_host"], "127.0.0.1:8443")
        self.assertIsNone(payload["headers"]["x_client_cert_user_id"])
        self.assertIsNone(payload["session_user"])
        self.assertIsNone(payload["certificate_user"])

    def test_signer_enroll_route_through_lb_over_https(self):
        client_dir = Path(self._client_tmp_dir.name)
        opener, _ = login_as("user-bob", self._https_context, next_path="/protected")
        enrollment = start_enrollment(opener)
        _, body = create_client_key_and_csr(client_dir, common_name="mallory-requested-name")
        payload = get_json(
            "https://127.0.0.1:8443/enroll",
            method="POST",
            body=body,
            headers={
                "Authorization": f"Bearer {enrollment['token']}",
                "Content-Type": "application/pkcs10",
            },
            context=self._https_context,
        )
        self.assertEqual(payload["service"], "signer")
        self.assertEqual(payload["headers"]["authorization"], f"Bearer {enrollment['token']}")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "https")
        self.assertTrue(payload["csr_received"])
        self.assertIn("CN=mallory-requested-name", payload["csr_subject"])
        self.assertEqual(payload["name"], "Bob Builder")
        self.assertEqual(payload["user"]["id"], "user-bob")
        self.assertEqual(payload["certificate_identity"]["user_id"], "user-bob")
        self.assertEqual(payload["certificate_identity"]["cert_identifier"], "user-bob")
        self.assertEqual(
            payload["certificate_identity"]["subject_alt_name_uri"],
            "urn:large-mtls-demo:user:user-bob",
        )
        self.assertIn("/CN=Bob Builder/serialNumber=user-bob", payload["certificate_subject"])
        self.assertEqual(payload["encoding"], "pem")
        self.assertEqual(payload["redirect_url"], "https://localhost:9443/enroll/complete")
        self.assertIn("BEGIN CERTIFICATE", payload["certificate"])

    def test_initial_certificate_subject_uses_trusted_user_identity(self):
        self.assertIn("serialNumber=user-alice", self._client_cert_subject)
        self.assertIn("CN=Alice Admin", self._client_cert_subject)
        self.assertNotIn("csr-tries-to-be-mallory", self._client_cert_subject)

    def test_mtls_protected_page_on_standard_tls_port_requires_certificate(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            get_response("https://localhost:8443/protected/mtls", context=self._https_context)
        self.assertEqual(context.exception.code, 403)
        body = context.exception.read().decode("utf-8")
        context.exception.close()
        self.assertIn("Protected mTLS Page", body)
        self.assertIn("requires a verified client certificate", body)

    def test_mtls_port_rejects_requests_without_client_certificate(self):
        try:
            get_response("https://localhost:9443/enroll/complete", context=self._https_context)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            exc.close()
        except (urllib.error.URLError, ssl.SSLError, ConnectionResetError, TimeoutError):
            pass
        else:
            self.fail("expected the mTLS port to reject requests without a client certificate")

    def test_enrollment_completion_page_is_reachable_over_mtls(self):
        with get_response(
            "https://localhost:9443/enroll/complete?state=installed",
            context=self._mtls_context,
        ) as response:
            self.assertEqual(response.headers.get_content_type(), "text/html")
            body = response.read().decode("utf-8")
        self.assertIn("Enrollment Completion", body)
        self.assertIn("Alice Admin", body)
        self.assertIn("user-alice", body)

    def test_mtls_protected_page_shows_connected_user(self):
        with get_response("https://localhost:9443/protected/mtls", context=self._mtls_context) as response:
            self.assertEqual(response.headers.get_content_type(), "text/html")
            body = response.read().decode("utf-8")
        self.assertIn("Protected mTLS Page", body)
        self.assertIn("Alice Admin", body)
        self.assertIn("user-alice", body)
        self.assertIn("protected by mutual TLS", body)

    def test_mtls_whoami_shows_verified_client_identity(self):
        payload = get_json("https://localhost:9443/whoami", context=self._mtls_context)
        self.assertEqual(payload["service"], "app")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "https")
        self.assertEqual(payload["headers"]["x_forwarded_host"], "localhost:9443")
        self.assertEqual(payload["headers"]["x_client_verify"], "SUCCESS")
        self.assertEqual(payload["headers"]["x_client_cert_user_id"], "user-alice")
        self.assertIn("serialNumber=user-alice", payload["headers"]["x_client_subject"])
        self.assertIn("CN=Alice Admin", payload["headers"]["x_client_subject"])
        self.assertIn("CN=large-mtls-demo-client-ca", payload["headers"]["x_client_issuer"])
        self.assertIsNone(payload["session_user"])
        self.assertEqual(payload["certificate_user"]["id"], "user-alice")
        self.assertEqual(payload["certificate_user"]["display_name"], "Alice Admin")

    def test_disabled_user_cannot_start_enrollment(self):
        opener, _ = login_as("user-eve", self._https_context, next_path="/protected")
        with self.assertRaises(urllib.error.HTTPError) as context:
            open_with_opener(opener, "https://localhost:8443/enroll/start")
        self.assertEqual(context.exception.code, 403)
        body = context.exception.read().decode("utf-8")
        context.exception.close()
        self.assertIn("not allowed to enroll", body)

    def test_backend_services_are_not_published_to_host(self):
        with self.assertRaises((urllib.error.URLError, ConnectionError, TimeoutError)):
            urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=1)
        with self.assertRaises((urllib.error.URLError, ConnectionError, TimeoutError)):
            urllib.request.urlopen("http://127.0.0.1:8001/healthz", timeout=1)

    def test_internal_service_networking_is_available(self):
        app_result = run_compose(
            "exec",
            "-T",
            "lb",
            "wget",
            "-q",
            "-O",
            "-",
            "http://app:8000/healthz",
        )
        signer_result = run_compose(
            "exec",
            "-T",
            "lb",
            "wget",
            "-q",
            "-O",
            "-",
            "http://signer:8000/healthz",
        )
        self.assertIn('"service": "app"', app_result.stdout)
        self.assertIn('"service": "signer"', signer_result.stdout)


if __name__ == "__main__":
    unittest.main()
