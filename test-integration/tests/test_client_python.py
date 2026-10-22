"""
Offline tests for the Python client (authvo_client.py). No Docker, no network:
the client's HTTP session is replaced by a canned fake.

  pip install requests
  python -m unittest test-integration/tests/test_client_python.py -v

What is covered:
  * the URL-coverage helpers, against tests/coverage_vectors.json (the same
    vectors the Java client is tested with);
  * steps 1-3 of the flow -- probe, PRM, resource check -- including every way
    they must ABORT. Each abort test also asserts that nothing was POSTed, i.e.
    that the client stopped before requesting a device code / asking for a login.
"""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "authvo_client", HERE.parent.parent / "authvo_client.py")
ac = importlib.util.module_from_spec(_spec)
sys.modules["authvo_client"] = ac      # dataclasses look the module up by name
_spec.loader.exec_module(ac)

VECTORS = json.loads((HERE / "coverage_vectors.json").read_text())

RES_URL = "https://src.local.io/vo-resource"
PRM_URL = "https://src.local.io/.well-known/oauth-protected-resource"
ISSUER = "https://iam.local.io/"
AS_URL = "https://iam.local.io/.well-known/oauth-authorization-server"
OIDC_URL = "https://iam.local.io/.well-known/openid-configuration"

PRM = {"resource": "https://src.local.io", "authorization_servers": [ISSUER]}
AS_DOC = {
    "issuer": ISSUER,
    "token_endpoint": "https://iam.local.io/token",
    "device_authorization_endpoint": "https://iam.local.io/devicecode",
    "registration_endpoint": "https://iam.local.io/register",
    "protected_resources": ["https://src.local.io"],
}
CHALLENGE = 'Bearer resource_metadata="%s"' % PRM_URL


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body) if body is not None else ""
        self.content = self.text.encode()

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    """Answers GETs from a {url: FakeResponse} table; refuses any POST."""

    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.gets, self.posts = [], []

    def get(self, url, **kw):
        assert kw.get("allow_redirects") is False, "discovery GET must not follow redirects"
        self.gets.append(url)
        return self.routes.get(url, FakeResponse(404))

    def post(self, url, **kw):
        self.posts.append(url)
        raise AssertionError("POST %s: the client must abort before this point" % url)


def client_with(routes, **kw):
    c = ac.AuthVoClient(client_id="authvo-client", **kw)
    c.http = FakeSession(routes)
    return c


def good_routes(**override):
    routes = {
        RES_URL: FakeResponse(401, headers={"WWW-Authenticate": CHALLENGE}),
        PRM_URL: FakeResponse(200, PRM),
        AS_URL: FakeResponse(200, AS_DOC),
    }
    routes.update(override)
    return routes


class Coverage(unittest.TestCase):
    def test_covered_vectors(self):
        for url, rid, expected in VECTORS["covered"]:
            with self.subTest(url=url, resource=rid):
                self.assertEqual(ac.is_covered(url, rid), expected)

    def test_most_specific_vectors(self):
        for url, ids, expected in VECTORS["most_specific"]:
            with self.subTest(url=url, ids=ids):
                self.assertEqual(ac.most_specific_cover(url, ids), expected)


class Step1Probe(unittest.TestCase):
    def test_extracts_pointer(self):
        self.assertEqual(client_with(good_routes())._step1_probe(RES_URL), PRM_URL)

    def test_bare_pointer_form(self):
        self.assertEqual(ac.AuthVoClient._parse_resource_metadata(
            "Bearer resource_metadata=" + PRM_URL), PRM_URL)

    def test_not_401_aborts(self):
        c = client_with(good_routes(**{RES_URL: FakeResponse(200)}))
        with self.assertRaisesRegex(ac.SecurityError, "got 200"):
            c._step1_probe(RES_URL)

    def test_redirect_from_resource_is_not_followed_and_aborts(self):
        c = client_with(good_routes(**{RES_URL: FakeResponse(302, headers={"Location": "https://x"})}))
        with self.assertRaisesRegex(ac.SecurityError, "got 302"):
            c._step1_probe(RES_URL)

    def test_missing_pointer_aborts(self):
        c = client_with(good_routes(**{RES_URL: FakeResponse(401, headers={"WWW-Authenticate": "Bearer"})}))
        with self.assertRaisesRegex(ac.SecurityError, "resource_metadata"):
            c._step1_probe(RES_URL)


class Step2Prm(unittest.TestCase):
    def test_ok(self):
        prm = client_with(good_routes())._step2_prm(RES_URL, PRM_URL)
        self.assertEqual((prm.resource, prm.authorization_servers),
                         ("https://src.local.io", [ISSUER]))

    def test_resource_not_covering_requested_url_aborts(self):
        routes = good_routes(**{PRM_URL: FakeResponse(200, dict(PRM, resource="https://src.local.io/other"))})
        c = client_with(routes)
        with self.assertRaisesRegex(ac.SecurityError, "STEP 2 FAILED"):
            c._step2_prm(RES_URL, PRM_URL)
        self.assertEqual(c.http.posts, [])

    def test_prm_about_another_origin_aborts(self):
        routes = good_routes(**{PRM_URL: FakeResponse(200, dict(PRM, resource="https://evil.local.io"))})
        with self.assertRaisesRegex(ac.SecurityError, "STEP 2 FAILED"):
            client_with(routes)._step2_prm(RES_URL, PRM_URL)

    def test_redirect_on_prm_fetch_is_refused(self):
        routes = good_routes(**{PRM_URL: FakeResponse(302, headers={"Location": PRM_URL + "2"}),
                                PRM_URL + "2": FakeResponse(200, PRM)})
        c = client_with(routes)
        with self.assertRaisesRegex(ac.SecurityError, "redirect"):
            c._step2_prm(RES_URL, PRM_URL)
        self.assertEqual(c.http.gets, [PRM_URL])       # never fetched the target

    def test_plain_http_pointer_aborts(self):
        with self.assertRaisesRegex(ac.SecurityError, "HTTPS"):
            client_with(good_routes())._step2_prm(RES_URL, PRM_URL.replace("https", "http"))

    def test_prm_without_servers_aborts(self):
        routes = good_routes(**{PRM_URL: FakeResponse(200, {"resource": "https://src.local.io"})})
        with self.assertRaisesRegex(ac.SecurityError, "authorization_servers"):
            client_with(routes)._step2_prm(RES_URL, PRM_URL)

    def test_non_json_object_aborts(self):
        routes = good_routes(**{PRM_URL: FakeResponse(200, ["not", "an", "object"])})
        with self.assertRaisesRegex(ac.SecurityError, "not a JSON object"):
            client_with(routes)._step2_prm(RES_URL, PRM_URL)


class Step3ResourceCheck(unittest.TestCase):
    def prm(self, *servers):
        return ac.ProtectedResourceMetadata(PRM_URL, "https://src.local.io", list(servers or [ISSUER]))

    def check(self, routes, *servers):
        c = client_with(routes)
        return c, c._step3_resource_check(RES_URL, self.prm(*servers))

    def test_passes_and_returns_matched_id_and_endpoints(self):
        _, chk = self.check(good_routes())
        self.assertEqual(chk.resource_id, "https://src.local.io")
        self.assertEqual(chk.meta.token_endpoint, "https://iam.local.io/token")
        self.assertEqual(chk.meta.issuer, ISSUER)

    def test_most_specific_listed_resource_is_chosen(self):
        doc = dict(AS_DOC, protected_resources=["https://src.local.io", "https://src.local.io/vo-resource"])
        _, chk = self.check(good_routes(**{AS_URL: FakeResponse(200, doc)}))
        self.assertEqual(chk.resource_id, "https://src.local.io/vo-resource")

    def assertAborts(self, routes, pattern, *servers):
        c = client_with(routes)
        with self.assertRaisesRegex(ac.SecurityError, pattern):
            c._step3_resource_check(RES_URL, self.prm(*servers))
        self.assertEqual(c.http.posts, [], "must abort before any device request")

    def test_issuer_mismatch_aborts(self):          # check (a)
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, dict(AS_DOC, issuer="https://evil.example/"))}),
                          r"check \(a\)")

    def test_absent_protected_resources_aborts(self):   # absence is a failure
        doc = {k: v for k, v in AS_DOC.items() if k != "protected_resources"}
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, doc)}), r"check \(b\).*no protected_resources")

    def test_empty_protected_resources_aborts(self):
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, dict(AS_DOC, protected_resources=[]))}),
                          r"check \(b\).*not covered")

    def test_resource_not_listed_aborts(self):       # the "evil service" case
        doc = dict(AS_DOC, protected_resources=["https://src.local.io/other", "https://elsewhere.example"])
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, doc)}), r"check \(b\).*not covered")

    def test_malformed_list_aborts(self):
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, dict(AS_DOC, protected_resources="https://src.local.io"))}),
                          r"not a list of strings")

    def test_redirect_on_as_metadata_is_refused(self):
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(301, headers={"Location": OIDC_URL})}), "redirect")

    def test_oidc_document_never_substitutes_for_the_check(self):
        # RFC 8414 document missing; an OIDC doc WITH the list exists. Still abort.
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(404), OIDC_URL: FakeResponse(200, AS_DOC)}),
                          "HTTP 404")

    def test_oidc_used_only_to_read_missing_endpoints(self):
        slim = {"issuer": ISSUER, "protected_resources": ["https://src.local.io"]}
        c, chk = self.check(good_routes(**{AS_URL: FakeResponse(200, slim), OIDC_URL: FakeResponse(200, AS_DOC)}))
        self.assertIn(OIDC_URL, c.http.gets)
        self.assertEqual(chk.meta.device_authorization_endpoint, "https://iam.local.io/devicecode")

    def test_oidc_fallback_issuer_must_match_too(self):
        slim = {"issuer": ISSUER, "protected_resources": ["https://src.local.io"]}
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, slim),
                                         OIDC_URL: FakeResponse(200, dict(AS_DOC, issuer="https://evil.example/"))}),
                          "OIDC discovery issuer")

    def test_first_issuer_that_passes_is_used(self):
        other = "https://other.example/"
        other_as = "https://other.example/.well-known/oauth-authorization-server"
        routes = good_routes(**{other_as: FakeResponse(200, dict(AS_DOC, issuer=other, protected_resources=[]))})
        _, chk = self.check(routes, other, ISSUER)
        self.assertEqual(chk.meta.issuer, ISSUER)

    def test_every_issuer_failing_aborts_listing_reasons(self):
        other = "https://other.example/"
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, dict(AS_DOC, protected_resources=[]))}),
                          r"other\.example.*HTTP 404.*iam\.local\.io", other, ISSUER)

    def test_non_https_issuer_is_rejected(self):
        self.assertAborts(good_routes(), "HTTPS", "http://iam.local.io/")


class MetadataUrls(unittest.TestCase):
    def test_issuer_with_and_without_path(self):
        f = ac.AuthVoClient._as_metadata_urls
        self.assertEqual(f("https://iam.local.io/"), (AS_URL, OIDC_URL))
        self.assertEqual(f("https://h/iam"), ("https://h/.well-known/oauth-authorization-server/iam",
                                              "https://h/iam/.well-known/openid-configuration"))


if __name__ == "__main__":
    unittest.main()
