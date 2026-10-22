"""
Offline tests for the demo drivers (demo/*.py). No Docker, no network.

  pip install requests
  python -m unittest test-integration/tests/test_demos_offline.py -v

  * the shared checks (demo/authvo_checks.py) against the same coverage vectors
    the real clients use;
  * each Python demo, run against a canned "evil" resource, must abort with exit
    code 2 at the resource check -- and must have POSTed nothing, i.e. never
    requested a device code or asked for a login.
"""
import builtins
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
DEMO = HERE.parent / "demo"
sys.path.insert(0, str(DEMO))
import authvo_checks as chk  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location("demo_" + name, DEMO / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VECTORS = json.loads((HERE / "coverage_vectors.json").read_text())

ISSUER = "https://iam.local.io/"
AS_URL = "https://iam.local.io/.well-known/oauth-authorization-server"
OIDC_URL = "https://iam.local.io/.well-known/openid-configuration"


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.text = json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError
        return self._body


class FakeSession:
    """GETs from a table, POSTs forbidden; shaped like requests.Session."""
    routes = {}
    posts = []

    def __init__(self):
        self.verify = None
        self.headers = {}

    def get(self, url, **kw):
        assert kw.get("allow_redirects") is False, f"GET {url} must not follow redirects"
        return self.routes.get(url, Resp(404))

    def post(self, url, **kw):
        FakeSession.posts.append(url)
        raise AssertionError(f"POST {url}: the demo must abort before this")


def evil_routes():
    """evil.local.io: a well-formed PRM naming the REAL IAM, which does not list it."""
    return {
        "https://evil.local.io/vo-resource": Resp(401, "x", {
            "WWW-Authenticate": 'Bearer resource_metadata="https://evil.local.io/.well-known/oauth-protected-resource"'}),
        "https://evil.local.io/.well-known/oauth-protected-resource": Resp(200, {
            "resource": "https://evil.local.io", "authorization_servers": [ISSUER]}),
        AS_URL: Resp(200, {"issuer": ISSUER, "protected_resources": ["https://src.local.io"],
                           "token_endpoint": "https://iam.local.io/token",
                           "device_authorization_endpoint": "https://iam.local.io/devicecode"}),
    }


class SharedChecks(unittest.TestCase):
    def test_coverage_vectors(self):
        for url, rid, expected in VECTORS["covered"]:
            with self.subTest(url=url, resource=rid):
                self.assertEqual(chk.is_covered(url, rid), expected)

    def test_most_specific_vectors(self):
        for url, ids, expected in VECTORS["most_specific"]:
            with self.subTest(url=url, ids=ids):
                self.assertEqual(chk.most_specific_cover(url, ids), expected)

    def test_absent_list_is_a_failure(self):
        with self.assertRaisesRegex(chk.Abort, "no protected_resources"):
            chk.check_b({"issuer": ISSUER}, "https://src.local.io/vo")

    def test_redirect_is_refused(self):
        FakeSession.routes = {AS_URL: Resp(302, None, {"Location": OIDC_URL})}
        with self.assertRaisesRegex(chk.Abort, "redirect"):
            chk.get_json(FakeSession(), AS_URL, "RFC 8414 metadata")

    def test_aud_of_is_display_only(self):
        self.assertIsNone(chk.aud_of("opaque-token"))


class DemoAbortsOnEvil(unittest.TestCase):
    def setUp(self):
        FakeSession.routes = evil_routes()
        FakeSession.posts = []

    def run_demo(self, name, argv, **patches):
        mod = load(name)
        with mock.patch.object(mod.requests, "Session", FakeSession), \
                mock.patch.object(sys, "argv", [name + ".py", "--resource",
                                                "https://evil.local.io/vo-resource"] + argv), \
                mock.patch.object(builtins, "input", lambda *a: ""):
            with mock.patch("builtins.print") as pr:
                rc = mod.main()
        printed = "\n".join(str(c.args[0]) for c in pr.call_args_list if c.args)
        return rc, printed

    def check(self, rc, printed):
        self.assertEqual(rc, 2)
        self.assertIn("check (b)", printed)
        self.assertEqual(FakeSession.posts, [], "must abort before any device request")

    def test_demo_py(self):
        self.check(*self.run_demo("demo", []))

    def test_auto_demo_py(self):
        self.check(*self.run_demo("auto_demo", []))

    def test_human_demo_py(self):
        self.check(*self.run_demo("human_demo", ["--no-browser"]))


if __name__ == "__main__":
    unittest.main()
