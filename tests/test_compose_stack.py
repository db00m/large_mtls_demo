import json
import shutil
import subprocess
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_CMD = ["docker", "compose"]


def docker_available():
    return shutil.which("docker") is not None


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


def get_json(url, method="GET", body=None, headers=None):
    request = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


@unittest.skipUnless(docker_available(), "docker is required for compose integration tests")
class ComposeStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_compose("down", "-v", "--remove-orphans", check=False)
        run_compose("up", "--build", "-d")
        cls._wait_for_stack()

    @classmethod
    def tearDownClass(cls):
        run_compose("down", "-v", "--remove-orphans", check=False)

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

    def test_app_traffic_routes_through_lb(self):
        payload = get_json("http://127.0.0.1:8080/whoami")
        self.assertEqual(payload["service"], "app")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
        self.assertEqual(payload["headers"]["x_forwarded_proto"], "http")

    def test_signer_enroll_route_through_lb(self):
        body = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
        payload = get_json(
            "http://127.0.0.1:8080/enroll",
            method="POST",
            body=body,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/pkcs10",
            },
        )
        self.assertEqual(payload["service"], "signer")
        self.assertEqual(payload["headers"]["authorization"], "Bearer test-token")
        self.assertEqual(payload["headers"]["x_demo_trusted_proxy"], "lb")
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
