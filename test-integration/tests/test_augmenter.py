"""
Tests for the metadata augmenter (augmenter/app.py). No Docker, no IAM: a stub
"IAM" runs in-process and the augmenter is pointed at it.

  python -m unittest test-integration/tests/test_augmenter.py -v
"""
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Load by path under a unique name: fake-rs/app.py is also called "app", and the
# two test modules may share one interpreter.
_spec = importlib.util.spec_from_file_location(
    "augmenter_app", Path(__file__).resolve().parent.parent / "augmenter" / "app.py")
aug = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aug)

OIDC_DOC = {
    "issuer": "https://iam.local.io/",
    "token_endpoint": "https://iam.local.io/token",
    "device_authorization_endpoint": "https://iam.local.io/devicecode",
    "jwks_uri": "https://iam.local.io/jwk",
}


class StubIam:
    """A fake IAM: serves whatever is in `docs`, counts requests per path."""

    def __init__(self, docs):
        self.docs, self.hits, self.hosts = docs, {}, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                outer.hosts.append(self.headers.get("Host"))
                doc = outer.docs.get(self.path)
                body = json.dumps(doc if doc is not None else {}).encode()
                self.send_response(200 if doc is not None else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_port

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class AugmenterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp.name) / "protected_resources.json"
        self.cfg.write_text(json.dumps({"protected_resources": ["https://src.local.io"]}))
        aug.CONFIG = str(self.cfg)
        aug.CACHE_SECONDS = 60
        aug._cache.clear()
        self.iam = None
        self.front = None

    def tearDown(self):
        if self.iam:
            self.iam.close()
        if self.front:
            self.front.shutdown()
            self.front.server_close()
        self.tmp.cleanup()

    def start(self, docs):
        """Start the stub IAM and the augmenter in front of it."""
        self.iam = StubIam(docs)
        aug.UPSTREAM = self.iam.url
        self.front = HTTPServer(("127.0.0.1", 0), aug.Handler)
        threading.Thread(target=self.front.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.front.server_port

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    # -- the core behaviour ---------------------------------------------------

    def test_adds_protected_resources_and_changes_nothing_else(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})
        status, doc = self.get(aug.OIDC_PATH)
        self.assertEqual(status, 200)
        self.assertEqual(doc.pop("protected_resources"), ["https://src.local.io"])
        self.assertEqual(doc, OIDC_DOC)            # issuer & endpoints untouched

    def test_rfc8414_path_is_derived_from_oidc_when_iam_lacks_it(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})       # no RFC 8414 doc upstream
        status, doc = self.get(aug.AS_PATH)
        self.assertEqual(status, 200)
        self.assertEqual(doc["issuer"], OIDC_DOC["issuer"])
        self.assertEqual(doc["protected_resources"], ["https://src.local.io"])

    def test_native_rfc8414_document_is_used_when_present(self):
        native = dict(OIDC_DOC, grant_types_supported=["device_code"])
        self.start({aug.AS_PATH: native, aug.OIDC_PATH: OIDC_DOC})
        _, doc = self.get(aug.AS_PATH)
        self.assertIn("grant_types_supported", doc)

    def test_upstream_protected_resources_wins(self):
        self.start({aug.OIDC_PATH: dict(OIDC_DOC, protected_resources=["https://native"])})
        _, doc = self.get(aug.OIDC_PATH)
        self.assertEqual(doc["protected_resources"], ["https://native"])

    def test_iam_sees_the_public_host(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.get(aug.OIDC_PATH)
        self.assertEqual(self.iam.hosts, ["iam.local.io"])

    # -- the config file (drives the negative tests) --------------------------

    def test_member_omitted_when_key_missing(self):
        self.cfg.write_text("{}")
        self.start({aug.OIDC_PATH: OIDC_DOC})
        _, doc = self.get(aug.OIDC_PATH)
        self.assertNotIn("protected_resources", doc)

    def test_member_omitted_when_file_missing_or_malformed(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.cfg.unlink()
        self.assertNotIn("protected_resources", self.get(aug.OIDC_PATH)[1])
        self.cfg.write_text("not json")
        self.assertNotIn("protected_resources", self.get(aug.OIDC_PATH)[1])

    def test_empty_list_is_published_as_empty(self):
        self.cfg.write_text(json.dumps({"protected_resources": []}))
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.assertEqual(self.get(aug.OIDC_PATH)[1]["protected_resources"], [])

    # -- caching ----------------------------------------------------------------

    def test_upstream_cached_but_config_read_every_time(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.get(aug.OIDC_PATH)
        self.cfg.write_text(json.dumps({"protected_resources": ["https://other"]}))
        _, doc = self.get(aug.OIDC_PATH)
        self.assertEqual(doc["protected_resources"], ["https://other"])   # edit is live
        self.assertEqual(self.iam.hits[aug.OIDC_PATH], 1)                 # IAM hit once

    def test_cache_expires(self):
        aug.CACHE_SECONDS = 0
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.get(aug.OIDC_PATH)
        self.get(aug.OIDC_PATH)
        self.assertEqual(self.iam.hits[aug.OIDC_PATH], 2)

    # -- everything else ----------------------------------------------------------

    def test_other_paths_are_404(self):
        self.start({aug.OIDC_PATH: OIDC_DOC})
        self.assertEqual(self.get("/token")[0], 404)
        self.assertEqual(self.get("/.well-known/oauth-protected-resource")[0], 404)

    def test_bad_gateway_when_iam_has_nothing(self):
        self.start({})
        self.assertEqual(self.get(aug.OIDC_PATH)[0], 502)
        self.assertEqual(self.get(aug.AS_PATH)[0], 502)

    def test_healthz(self):
        self.start({})
        self.assertEqual(self.get("/healthz")[0], 200)


if __name__ == "__main__":
    unittest.main()
