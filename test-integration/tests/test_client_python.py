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
import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from unittest import mock

from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "authvo_client", HERE.parent.parent / "authvo_client.py")
ac = importlib.util.module_from_spec(_spec)
sys.modules["authvo_client"] = ac      # dataclasses look the module up by name
_spec.loader.exec_module(ac)

VECTORS = json.loads((HERE / "coverage_vectors.json").read_text())

RES_URL = "https://src.local.io/vo/resource"
# RFC 9728 3.1: the PRM URL is derived from the REQUESTED URL (suffix between host and path)
PRM_URL = "https://src.local.io/.well-known/oauth-protected-resource/vo/resource"
SERVICE = "https://src.local.io/vo"           # the entry the IAM lists for the service
DATALINK = "https://src.local.io/datalink"    # a second entry, listed but not the one requested
ISSUER = "https://iam.local.io/"
AS_URL = "https://iam.local.io/.well-known/oauth-authorization-server"
OIDC_URL = "https://iam.local.io/.well-known/openid-configuration"

# the PRM names EXACTLY the URL that was requested (RFC 9728 3.3)
PRM = {"resource": RES_URL, "authorization_servers": [ISSUER]}
AS_DOC = {
    "issuer": ISSUER,
    "token_endpoint": "https://iam.local.io/token",
    "device_authorization_endpoint": "https://iam.local.io/devicecode",
    "registration_endpoint": "https://iam.local.io/register",
    "protected_resources": [SERVICE, DATALINK],
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


class ExactMatch(unittest.TestCase):
    """Step 2 (RFC 9728 3.3): the PRM `resource` must be IDENTICAL to the requested URL,
    query included. Same vectors as the Java client."""

    def test_exact_vectors(self):
        for requested, resource, expected, why in VECTORS["exact"]:
            with self.subTest(requested=requested, resource=resource, why=why):
                self.assertEqual(ac.urls_match_exactly(requested, resource), expected, why)

    def test_is_symmetric_apart_from_the_fragment_rule(self):
        # (a fragment is dropped on the requested side only, so symmetry is checked without)
        for requested, resource, expected, why in VECTORS["exact"]:
            if "#" in requested + resource:
                continue
            with self.subTest(requested=requested, resource=resource):
                self.assertEqual(ac.urls_match_exactly(resource, requested), expected, why)

    def test_unparseable_input_is_a_mismatch_not_a_crash(self):
        for bad in ("https://[::1", "https://h:99999999/", "http://h:abc/x"):
            self.assertFalse(ac.urls_match_exactly(bad, "https://h/x"))
            self.assertFalse(ac.urls_match_exactly("https://h/x", bad))


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
        self.assertEqual((prm.resource, prm.authorization_servers), (RES_URL, [ISSUER]))

    def step2(self, requested, resource, pointer=PRM_URL):
        routes = {pointer: FakeResponse(200, dict(PRM, resource=resource))}
        c = client_with(routes)
        prm = c._step2_prm(requested, pointer)
        self.assertEqual(c.http.posts, [])
        return prm

    def assertStep2Aborts(self, requested, resource):
        c = client_with({PRM_URL: FakeResponse(200, dict(PRM, resource=resource))})
        with self.assertRaisesRegex(ac.SecurityError, "STEP 2 FAILED"):
            c._step2_prm(requested, PRM_URL)
        self.assertEqual(c.http.posts, [], "must abort before any device request")

    def test_a_different_resource_aborts(self):
        self.assertStep2Aborts(RES_URL, "https://src.local.io/other")

    def test_a_prm_that_merely_COVERS_the_request_aborts(self):
        # The pre-review profile accepted this (the service identifier covers the URL);
        # RFC 9728 3.3 does not: the resource must be the requested URL itself.
        self.assertStep2Aborts(RES_URL, SERVICE)
        self.assertStep2Aborts(RES_URL, "https://src.local.io")

    def test_a_longer_resource_aborts(self):
        self.assertStep2Aborts(SERVICE, RES_URL)

    def test_the_query_is_part_of_the_identity(self):
        with_query = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy&b=2"
        self.step2(with_query, with_query, pointer=PRM_URL + "?ID=ivo%3A%2F%2Fx%2Fy&b=2")
        self.assertStep2Aborts(with_query, RES_URL)                       # PRM drops the query
        self.assertStep2Aborts(RES_URL, with_query)                       # PRM adds one
        self.assertStep2Aborts(with_query, RES_URL + "?ID=other&b=2")     # a different query
        self.assertStep2Aborts(RES_URL + "?a=1&b=2", RES_URL + "?b=2&a=1")  # order: no normalisation

    def test_cosmetic_differences_are_tolerated_but_only_those(self):
        self.step2("https://SRC.local.io:443/vo/resource/", RES_URL)      # host case, default port, 1 slash
        self.assertStep2Aborts(RES_URL + "//", RES_URL)                   # two slashes are not one

    def test_a_fragment_on_the_requested_url_is_dropped_but_not_on_the_resource(self):
        self.step2(RES_URL + "#top", RES_URL)
        self.assertStep2Aborts(RES_URL, RES_URL + "#top")

    def test_prm_about_another_origin_aborts(self):
        self.assertStep2Aborts(RES_URL, "https://evil.local.io/vo/resource")

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
        routes = good_routes(**{PRM_URL: FakeResponse(200, {"resource": RES_URL})})
        with self.assertRaisesRegex(ac.SecurityError, "authorization_servers"):
            client_with(routes)._step2_prm(RES_URL, PRM_URL)

    def test_non_json_object_aborts(self):
        routes = good_routes(**{PRM_URL: FakeResponse(200, ["not", "an", "object"])})
        with self.assertRaisesRegex(ac.SecurityError, "not a JSON object"):
            client_with(routes)._step2_prm(RES_URL, PRM_URL)


class Step3ResourceCheck(unittest.TestCase):
    def prm(self, *servers):
        return ac.ProtectedResourceMetadata(PRM_URL, RES_URL, list(servers or [ISSUER]))

    def check(self, routes, *servers):
        c = client_with(routes)
        return c, c._step3_resource_check(RES_URL, self.prm(*servers))

    def test_passes_and_returns_the_covering_entry_and_endpoints(self):
        _, chk = self.check(good_routes())
        # the audience entry comes from the IAM's list (the one that covers the URL),
        # NOT from the PRM resource; the other listed entry does not cover the request
        self.assertEqual(chk.resource_id, SERVICE)
        self.assertEqual(chk.meta.token_endpoint, "https://iam.local.io/token")
        self.assertEqual(chk.meta.issuer, ISSUER)

    def test_most_specific_listed_resource_is_chosen(self):
        doc = dict(AS_DOC, protected_resources=[SERVICE, RES_URL])
        _, chk = self.check(good_routes(**{AS_URL: FakeResponse(200, doc)}))
        self.assertEqual(chk.resource_id, RES_URL)

    def test_only_ONE_entry_has_to_cover_the_request(self):
        # DATALINK is listed first but does not cover /vo/resource; SERVICE does
        doc = dict(AS_DOC, protected_resources=[DATALINK, SERVICE])
        _, chk = self.check(good_routes(**{AS_URL: FakeResponse(200, doc)}))
        self.assertEqual(chk.resource_id, SERVICE)

    def test_coverage_ignores_the_query_of_the_requested_url(self):
        with_query = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy"
        c = client_with(good_routes())
        prm = ac.ProtectedResourceMetadata(PRM_URL, with_query, [ISSUER])
        self.assertEqual(c._step3_resource_check(with_query, prm).resource_id, SERVICE)

    def test_a_query_cannot_smuggle_a_listed_prefix_in(self):
        doc = dict(AS_DOC, protected_resources=[SERVICE])
        c = client_with(good_routes(**{AS_URL: FakeResponse(200, doc)}))
        other = "https://src.local.io/other?next=/vo/x"
        with self.assertRaisesRegex(ac.SecurityError, r"check \(b\).*not covered"):
            c._step3_resource_check(other, ac.ProtectedResourceMetadata(PRM_URL, other, [ISSUER]))

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
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(200, dict(AS_DOC, protected_resources=SERVICE))}),
                          r"not a list of strings")

    def test_redirect_on_as_metadata_is_refused(self):
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(301, headers={"Location": OIDC_URL})}), "redirect")

    def test_oidc_document_never_substitutes_for_the_check(self):
        # RFC 8414 document missing; an OIDC doc WITH the list exists. Still abort.
        self.assertAborts(good_routes(**{AS_URL: FakeResponse(404), OIDC_URL: FakeResponse(200, AS_DOC)}),
                          "HTTP 404")

    def test_oidc_used_only_to_read_missing_endpoints(self):
        slim = {"issuer": ISSUER, "protected_resources": [SERVICE]}
        c, chk = self.check(good_routes(**{AS_URL: FakeResponse(200, slim), OIDC_URL: FakeResponse(200, AS_DOC)}))
        self.assertIn(OIDC_URL, c.http.gets)
        self.assertEqual(chk.meta.device_authorization_endpoint, "https://iam.local.io/devicecode")

    def test_oidc_fallback_issuer_must_match_too(self):
        slim = {"issuer": ISSUER, "protected_resources": [SERVICE]}
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


class BearerCheck(unittest.TestCase):
    """The AuthVO draft (5.4.5): the client MUST verify the response carries an access
    token and that it is of type Bearer (RFC 6749 7.1: the type is case-insensitive)."""

    def check(self, doc):
        ac.AuthVoClient._require_bearer(doc, "access token")

    def test_accepts_bearer_in_any_case(self):
        for t in ("Bearer", "bearer", "BEARER"):
            self.check({"access_token": "abc", "token_type": t})

    def test_rejects_other_token_types(self):
        for t in ("DPoP", "mac", "N_A", "", None, 123):
            with self.subTest(token_type=t):
                with self.assertRaisesRegex(ac.SecurityError, "token_type"):
                    self.check({"access_token": "abc", "token_type": t})

    def test_rejects_a_missing_token_type(self):
        with self.assertRaisesRegex(ac.SecurityError, "token_type"):
            self.check({"access_token": "abc"})

    def test_rejects_a_missing_or_empty_access_token(self):
        for doc in ({"token_type": "Bearer"}, {"access_token": "", "token_type": "Bearer"},
                    {"access_token": None, "token_type": "Bearer"}):
            with self.subTest(doc=doc):
                with self.assertRaisesRegex(ac.SecurityError, "no access_token"):
                    self.check(doc)


class IndicatorVectors(unittest.TestCase):
    """RFC 8707 2: a resource indicator is an absolute URI without a fragment.
    The same vectors drive the Java client's tests."""

    def test_vectors(self):
        vectors = json.loads((Path(__file__).parent / "coverage_vectors.json").read_text())["indicator"]
        self.assertGreater(len(vectors), 5)
        for url, expected, why in vectors:
            with self.subTest(url=url, why=why):
                self.assertIs(ac.is_valid_indicator(url), expected)


class AudienceOption(unittest.TestCase):
    """The token's audience comes from the issuer's `protected_resources`, never from the
    PRM `resource`: the covering entry by default, every entry with audience="domain"."""

    def check_for(self, listed, url=RES_URL, **kw):
        doc = dict(AS_DOC, protected_resources=listed)
        c = client_with(good_routes(**{AS_URL: FakeResponse(200, doc)}), **kw)
        prm = ac.ProtectedResourceMetadata(PRM_URL, url, [ISSUER])
        return c, c._step3_resource_check(url, prm)

    def test_default_is_covering(self):
        self.assertEqual(ac.AuthVoClient().audience, "covering")

    def test_an_unknown_audience_mode_is_refused(self):
        with self.assertRaisesRegex(ValueError, "audience must be"):
            ac.AuthVoClient(audience="everything")

    def test_covering_requests_only_the_entry_that_covered_the_url(self):
        c, chk = self.check_for([DATALINK, SERVICE])
        self.assertEqual(c._audience_ids(chk), [SERVICE])

    def test_domain_requests_every_entry_covering_one_first(self):
        c, chk = self.check_for([DATALINK, SERVICE], audience="domain")
        self.assertEqual(chk.domain_ids, [SERVICE, DATALINK])
        self.assertEqual(c._audience_ids(chk), [SERVICE, DATALINK])

    def test_domain_does_not_repeat_an_entry(self):
        c, chk = self.check_for([SERVICE, DATALINK, SERVICE], audience="domain")
        self.assertEqual(c._audience_ids(chk), [SERVICE, DATALINK])

    def test_entries_that_are_not_valid_indicators_are_skipped(self):
        # RFC 8707 2: an absolute URI WITHOUT a fragment
        c, chk = self.check_for([SERVICE, "https://src.local.io/x#frag", "not-a-uri", DATALINK],
                                audience="domain")
        self.assertEqual(c._audience_ids(chk), [SERVICE, DATALINK])

    def test_a_covering_entry_that_is_not_a_valid_indicator_aborts(self):
        # (an entry with a fragment still COVERS the URL, since coverage ignores fragments)
        with self.assertRaisesRegex(ac.SecurityError, "not a valid RFC 8707"):
            self.check_for(["https://src.local.io/vo#frag"])

    def test_the_audience_never_comes_from_the_prm_resource(self):
        with_query = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy"
        c, chk = self.check_for([SERVICE, DATALINK], url=with_query, audience="domain")
        self.assertNotIn(with_query, c._audience_ids(chk))
        self.assertEqual(c._audience_ids(chk), [SERVICE, DATALINK])


class AudShortfall(unittest.TestCase):
    """The user is told when the issuer narrowed a multi-entry audience (INDIGO 1.15 takes
    only the first repeated `resource`); never a trust decision."""

    AUD = [SERVICE, DATALINK]

    @staticmethod
    def doc(aud):
        import base64
        seg = base64.urlsafe_b64encode(json.dumps({"aud": aud}).encode()).decode().rstrip("=")
        return {"access_token": "h.%s.s" % seg}

    def test_nothing_missing_when_one_entry_was_requested(self):
        self.assertEqual(ac.aud_shortfall(SERVICE, [SERVICE]), [])
        self.assertEqual(ac.aud_shortfall("https://elsewhere.example", [SERVICE]), [])

    def test_a_string_aud_names_only_one_of_two(self):
        self.assertEqual(ac.aud_shortfall(SERVICE, self.AUD), [DATALINK])

    def test_a_list_aud_naming_both_is_complete(self):
        self.assertEqual(ac.aud_shortfall([SERVICE, DATALINK], self.AUD), [])
        self.assertEqual(ac.aud_shortfall([DATALINK, SERVICE, "x"], self.AUD), [])

    def test_the_note_is_logged_for_a_narrowed_token(self):
        with self.assertLogs(ac.log, level="WARNING") as cm:
            ac.AuthVoClient._log_aud(self.doc(SERVICE), "access token", self.AUD)
        self.assertIn("narrowed the audience", cm.output[0])
        self.assertIn(DATALINK, cm.output[0])

    def test_no_note_when_nothing_was_narrowed(self):
        with self.assertNoLogs(ac.log, level="WARNING"):
            ac.AuthVoClient._log_aud(self.doc([SERVICE, DATALINK]), "access token", self.AUD)


class Recorder:
    """A session that records every POST and answers from a script."""

    def __init__(self, *responses):
        self.responses, self.posts, self.headers = list(responses), [], {}

    def post(self, url, data=None, **kw):
        self.posts.append((url, data, kw))
        return self.responses.pop(0)


META = ac.ASMetadata(issuer=ISSUER, token_endpoint="https://iam.local.io/token",
                     device_authorization_endpoint="https://iam.local.io/devicecode",
                     registration_endpoint="https://iam.local.io/register")


def resources_of(data):
    """The values of every `resource` field of a form (a list of (name, value) pairs)."""
    return [v for k, v in data if k == "resource"]


class ResourceOnBothDeviceRequests(unittest.TestCase):
    """RFC 8707: `resource` goes on the device authorization request AND the token request,
    repeated once per entry; `requests` needs a list of pairs for that (a dict cannot)."""

    AUD = [SERVICE, DATALINK]

    def test_device_authorization_request_carries_the_resources(self):
        c = ac.AuthVoClient(client_id="cid")
        c.http = Recorder(FakeResponse(200, {"device_code": "dc", "user_code": "UC"}))
        c._step5a_device_authorization(META, "cid", self.AUD)
        url, data, _ = c.http.posts[0]
        self.assertEqual(url, META.device_authorization_endpoint)
        self.assertIsInstance(data, list)
        self.assertEqual(resources_of(data), self.AUD)
        self.assertIn(("client_id", "cid"), data)

    def test_every_token_poll_carries_the_resources(self):
        c = ac.AuthVoClient(client_id="cid")
        c.http = Recorder(FakeResponse(400, {"error": "authorization_pending"}),
                          FakeResponse(200, {"access_token": "t", "token_type": "Bearer"}))
        with mock.patch.object(ac.time, "sleep", lambda s: None):
            c._step5c_poll_token(META, "cid", {"device_code": "dc", "interval": 1, "expires_in": 60}, self.AUD)
        self.assertEqual(len(c.http.posts), 2)
        for url, data, kw in c.http.posts:
            self.assertEqual(url, META.token_endpoint)
            self.assertEqual(resources_of(data), self.AUD)
            self.assertIn(("device_code", "dc"), data)
            self.assertIs(kw["allow_redirects"], False)

    def test_the_token_exchange_uses_the_same_audience_list(self):
        c = ac.AuthVoClient(client_id="cid", token_exchange=True)
        c.http = Recorder(FakeResponse(200, {"access_token": "t2", "token_type": "Bearer"}))
        c._step5d_token_exchange(META, "cid", {"access_token": "t1"}, self.AUD)
        data = c.http.posts[0][1]
        self.assertEqual([v for k, v in data if k == "audience"], self.AUD)
        self.assertEqual(resources_of(data), self.AUD)

    def test_a_single_entry_is_sent_once(self):
        c = ac.AuthVoClient(client_id="cid")
        c.http = Recorder(FakeResponse(200, {"device_code": "dc"}))
        c._step5a_device_authorization(META, "cid", [SERVICE])
        self.assertEqual(resources_of(c.http.posts[0][1]), [SERVICE])

    def test_the_wire_encoding_repeats_the_parameter(self):
        body = requests.models.RequestEncodingMixin._encode_params(
            ac.AuthVoClient._resource_params(self.AUD))
        self.assertEqual(body, "resource=https%3A%2F%2Fsrc.local.io%2Fvo&"
                               "resource=https%3A%2F%2Fsrc.local.io%2Fdatalink")


class Prompt(unittest.TestCase):
    """Step 5b: the user must SEE what the token is for, every entry, and who issues it."""

    def banner(self, audience):
        c = ac.AuthVoClient()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c._step5b_prompt_user({"verification_uri": "https://iam.local.io/device", "user_code": "WDJB"},
                                  RES_URL + "?ID=1", ISSUER, audience)
        return out.getvalue()

    def test_shows_the_requested_url_the_issuer_and_the_one_entry(self):
        text = self.banner([SERVICE])
        self.assertIn(RES_URL + "?ID=1", text)
        self.assertIn(ISSUER, text)
        self.assertIn(SERVICE, text)
        self.assertNotIn(DATALINK, text)

    def test_shows_every_entry_of_a_domain_wide_token(self):
        text = self.banner([SERVICE, DATALINK])
        self.assertIn(SERVICE, text)
        self.assertIn(DATALINK, text)
        self.assertEqual(text.count("Token is for"), 1)           # one label, several lines


class Cli(unittest.TestCase):
    def run_main(self, env):
        seen = {}

        class FakeClient:
            def __init__(self, **kw):
                seen.update(kw)

            def access(self, url):
                raise ac.SecurityError("stop here")

        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch.object(ac, "AuthVoClient", FakeClient):
            if "AUTHVO_AUDIENCE" not in env:          # ignore the caller's own environment
                os.environ.pop("AUTHVO_AUDIENCE", None)
            rc = ac.main(["authvo_client.py", RES_URL])
        return rc, seen

    def test_audience_defaults_to_covering(self):
        self.assertEqual(self.run_main({})[1]["audience"], "covering")

    def test_audience_comes_from_the_environment(self):
        self.assertEqual(self.run_main({"AUTHVO_AUDIENCE": "domain"})[1]["audience"], "domain")

    def test_a_bad_audience_is_a_usage_error_not_a_traceback(self):
        with mock.patch.dict(os.environ, {"AUTHVO_AUDIENCE": "everything"}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = ac.main(["authvo_client.py", RES_URL])
        self.assertEqual(rc, 2)
        self.assertIn("audience must be", err.getvalue())


class TokenExchangeOptional(unittest.TestCase):
    """Token exchange (RFC 8693) is opt-in; DCR only asks for grants it will use."""

    META = ac.ASMetadata(issuer=ISSUER, token_endpoint="https://iam.local.io/token",
                         device_authorization_endpoint="https://iam.local.io/devicecode",
                         registration_endpoint="https://iam.local.io/register")

    class Recorder:
        """Records the registration POST and answers it."""
        headers = {}

        def __init__(self):
            self.body = None

        def post(self, url, json=None, **kw):
            self.body = json
            return FakeResponse(201, {"client_id": "dyn-1"})

    def register(self, **kw):
        c = ac.AuthVoClient(**kw)            # no client_id -> must register
        c.http = self.Recorder()
        self.assertEqual(c._step4_register(self.META), "dyn-1")
        return c.http.body

    def test_off_by_default(self):
        self.assertFalse(ac.AuthVoClient().token_exchange)

    def test_dcr_requests_only_the_device_grant_by_default(self):
        body = self.register()
        self.assertEqual(body["grant_types"], [ac.GRANT_DEVICE_CODE])
        self.assertEqual(body["scope"], "openid vo.read")

    def test_dcr_adds_the_exchange_grant_only_when_enabled(self):
        body = self.register(token_exchange=True)
        self.assertEqual(body["grant_types"], [ac.GRANT_DEVICE_CODE, ac.GRANT_TOKEN_EXCHANGE])


class MetadataUrls(unittest.TestCase):
    def test_issuer_with_and_without_path(self):
        f = ac.AuthVoClient._as_metadata_urls
        self.assertEqual(f("https://iam.local.io/"), (AS_URL, OIDC_URL))
        self.assertEqual(f("https://h/iam"), ("https://h/.well-known/oauth-authorization-server/iam",
                                              "https://h/iam/.well-known/openid-configuration"))


if __name__ == "__main__":
    unittest.main()
