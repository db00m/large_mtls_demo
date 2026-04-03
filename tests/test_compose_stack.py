import json
import shutil
import ssl
import subprocess
import time
import unittest
import urllib.error
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


def get_response(url, method="GET", body=None, headers=None, context=None):
    request = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    return urllib.request.urlopen(request, timeout=2, context=context)


def get_json(url, method="GET", body=None, headers=None, context=None):
    with get_response(url, method=method, body=body, headers=headers, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


@unittest.skipUnless(docker_available(), "docker is required for compose integration tests")
class ComposeStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._generated_tls_material = ensure_local_tls_material()
        cls._https_context = https_context()
        run_compose("down", "-v", "--remove-orphans", check=False)
        run_compose("up", "--build", "-d")
        cls._wait_for_stack()

    @classmethod
    def tearDownClass(cls):
        run_compose("down", "-v", "--remove-orphans", check=False)
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
        self.assertIn("HTTPS load balancer", body)

    def test_app_diagnostics_route_through_lb_over_https(self):
        payload = get_json("https://127.0.0.1:8443/whoami", context=self._https_context)
        self.assertEqual(payload["service"], "app")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "https")

    def test_signer_enroll_route_through_lb_over_https(self):
        body = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
        payload = get_json(
            "https://127.0.0.1:8443/enroll",
            method="POST",
            body=body,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/pkcs10",
            },
            context=self._https_context,
        )
        self.assertEqual(payload["service"], "signer")
        self.assertEqual(payload["headers"]["authorization"], "Bearer test-token")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "https")
        self.assertTrue(payload["csr_received"])

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
