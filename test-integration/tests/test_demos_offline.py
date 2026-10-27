"""
Offline tests for the demo drivers (demo/*.py). No Docker, no network.

  pip install requests
  python -m unittest test-integration/tests/test_demos_offline.py -v

  * the shared checks (demo/authvo_checks.py) against the same vectors the real
    clients use (coverage, the exact PRM match, resource indicators);
  * each Python demo, run against a canned "evil" resource, must abort with exit
    code 2 at the resource check -- and must have POSTed nothing, i.e. never
    requested a device code or asked for a login;
  * the same for a PRM that merely COVERS the requested URL: abort at step 2.
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
EVIL_URL = "https://evil.local.io/vo/resource"
EVIL_PRM = "https://evil.local.io/.well-known/oauth-protected-resource/vo/resource"
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
        EVIL_URL: Resp(401, "x", {"WWW-Authenticate": f'Bearer resource_metadata="{EVIL_PRM}"'}),
        # RFC 9728 3.3: the PRM names EXACTLY the requested URL
        EVIL_PRM: Resp(200, {"resource": EVIL_URL, "authorization_servers": [ISSUER]}),
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

    def test_exact_vectors(self):
        for requested, resource, expected, why in VECTORS["exact"]:
            with self.subTest(why=why, requested=requested, resource=resource):
                self.assertIs(chk.urls_match_exactly(requested, resource), expected)

    def test_indicator_vectors(self):
        for url, expected, why in VECTORS["indicator"]:
            with self.subTest(why=why, url=url):
                self.assertIs(chk.is_valid_indicator(url), expected)

    def test_check_prm_is_an_exact_match(self):
        url = "https://src.local.io/vo/resource?ID=1"
        prm = {"resource": url, "authorization_servers": [ISSUER]}
        self.assertEqual(chk.check_prm(url, prm), [ISSUER])
        for bad in ("https://src.local.io/vo", "https://src.local.io/vo/resource",
                    "https://src.local.io/vo/resource?ID=2"):
            with self.subTest(prm_resource=bad), self.assertRaisesRegex(chk.Abort, "not identical"):
                chk.check_prm(url, dict(prm, resource=bad))

    def test_audience_comes_from_the_issuers_list(self):
        doc = {"protected_resources": ["https://src.local.io/datalink", "https://src.local.io/vo",
                                       "https://src.local.io/x#frag", "not-a-uri",
                                       "https://src.local.io/vo"]}
        vo = "https://src.local.io/vo"
        self.assertEqual(chk.audience_entries(doc, vo), [vo])
        self.assertEqual(chk.audience_entries(doc, vo, chk.AUDIENCE_DOMAIN),
                         [vo, "https://src.local.io/datalink"])
        with self.assertRaisesRegex(ValueError, "audience must be"):
            chk.audience_entries(doc, vo, "everything")

    def test_resource_is_repeated_once_per_entry(self):
        self.assertEqual(chk.resource_params(["a", "b"]), [("resource", "a"), ("resource", "b")])

    def test_a_covering_entry_that_is_not_an_indicator_aborts(self):
        with self.assertRaisesRegex(chk.Abort, "not a valid RFC 8707"):
            chk.check_b({"protected_resources": ["https://src.local.io/vo#frag"]},
                        "https://src.local.io/vo/resource")

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
                                                EVIL_URL] + argv), \
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


class DemoAbortsOnCoveringPrm(DemoAbortsOnEvil):
    """The pre-review profile accepted a PRM that COVERS the URL; RFC 9728 3.3 does not."""

    def setUp(self):
        super().setUp()
        FakeSession.routes[EVIL_PRM] = Resp(200, {"resource": "https://evil.local.io/vo",
                                                  "authorization_servers": [ISSUER]})

    def check(self, rc, printed):
        self.assertEqual(rc, 2)
        self.assertIn("not identical", printed)
        self.assertNotIn("check (b)", printed)          # stopped at step 2, before the issuer was asked
        self.assertEqual(FakeSession.posts, [], "must abort before any device request")


if __name__ == "__main__":
    unittest.main()
