"""
Unit tests for the fake resource server (fake-rs/app.py). No Docker needed.

  pip install flask "pyjwt[crypto]==2.7.0" requests
  python -m unittest test-integration/tests/test_fake_rs.py -v

Groups:

  * the six token-validation cases the harness has always promised -- valid,
    wrong audience, missing vo.read, rogue issuer, expired, unauthenticated --
    on the pure validate_token() helper and through the HTTP route (so status
    codes and WWW-Authenticate headers are checked too); `aud` is checked when
    present but not required, and (after the PR #23 review) a present `aud` must
    name an accepted identifier that COVERS the request, with several entries
    allowed;

  * the RFC 9728 Protected Resource Metadata, GENERATED PER REQUEST: one handler
    answers every URL of the service; `resource` is the requested URL, query
    included, byte for byte (RFC 9728 3.3); 404 for paths the service does not own;

  * the 401 pointer, derived from the requested URL (RFC 9728 3.1, 5.1);

  * the deliberately broken discovery fixtures behind the negative scenarios.
"""
import importlib.util
import json
import os
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
RS_DIR = HERE.parent / "fake-rs"

# The module reads its configuration at import time, so pin it first.
os.environ.update({
    "RS_RESOURCE_ID": "https://src.local.io/vo",      # the SERVICE identifier
    "RS_ISSUER": "https://iam.local.io/",
    "RS_REQUIRED_SCOPE": "vo.read",
    "RS_PAYLOAD_FILE": str(RS_DIR / "protected_resource.txt"),
    "RS_TEST_FAULTS": "1",
})
for name in ("RS_PRM_URL", "RS_SERVICE_PATH", "RS_AUDIENCE_IDS"):
    os.environ.pop(name, None)
# Load by path under a unique name: augmenter/app.py is also called "app", and
# the two test modules may share one interpreter.
_spec = importlib.util.spec_from_file_location("fake_rs_app", RS_DIR / "app.py")
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

SERVICE = "https://src.local.io/vo"
DATALINK = "https://src.local.io/datalink"
ISSUER = "https://iam.local.io/"
WK = "/.well-known/oauth-protected-resource"
REQUEST = "https://src.local.io/vo/resource"          # a URL the service owns

VECTORS = json.loads((HERE / "coverage_vectors.json").read_text())

# One throwaway RSA key signs every test token.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
_PUB = _KEY.public_key()


def make_token(**override):
    """A valid token (claims in `override` replace/extend the defaults)."""
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": SERVICE, "scope": "openid vo.read",
              "sub": "vouser", "iat": now, "exp": now + 300}
    claims.update(override)
    # A claim set to None means "leave it out".
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, _PEM, algorithm="RS256", headers={"kid": "rsa1"})


class _StubJwks:
    """Stands in for PyJWKClient so the route needs no network."""

    class _Key:
        key = _PUB

    def get_signing_key_from_jwt(self, token):
        return self._Key()


class AcceptDomainAudience:
    """Context manager: make the server accept the whole domain's identifiers."""

    def __enter__(self):
        self.saved = rs.AUDIENCE_IDS
        rs.AUDIENCE_IDS = [SERVICE, DATALINK]
        return self

    def __exit__(self, *exc):
        rs.AUDIENCE_IDS = self.saved


class Coverage(unittest.TestCase):
    """rs.covers is a copy of the clients' is_covered: same shared vectors."""

    def test_covered_vectors(self):
        for url, rid, expected in VECTORS["covered"]:
            with self.subTest(url=url, resource=rid):
                self.assertEqual(rs.covers(url, rid), expected)


class ValidateToken(unittest.TestCase):
    """The pure validation helper."""

    def validate(self, tok, url=REQUEST):
        return rs.validate_token(tok, _PUB, url)

    def test_valid(self):
        self.assertEqual(self.validate(make_token())["aud"], SERVICE)

    def test_wrong_audience(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            self.validate(make_token(aud="https://other.example"))

    def test_missing_scope(self):
        with self.assertRaises(PermissionError):
            self.validate(make_token(scope="openid"))

    # aud is checked when present, not required (token exchange is optional)
    def test_no_aud_claim_is_accepted(self):
        self.assertNotIn("aud", self.validate(make_token(aud=None)))

    def test_aud_list_including_us_is_accepted(self):
        self.validate(make_token(aud=["https://other.example", SERVICE]))

    def test_aud_list_without_us_is_refused(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            self.validate(make_token(aud=["https://other.example"]))

    def test_empty_aud_is_refused(self):
        # present-but-empty is not "absent": it names nobody, so it is not for us
        with self.assertRaises(jwt.InvalidAudienceError):
            self.validate(make_token(aud=[]))

    def test_rogue_issuer(self):
        with self.assertRaises(jwt.InvalidIssuerError):
            self.validate(make_token(iss="https://evil.example/"))

    def test_expired(self):
        with self.assertRaises(jwt.ExpiredSignatureError):
            self.validate(make_token(exp=int(time.time()) - 10))

    # --- PR #23: the audience comes from protected_resources, several entries allowed
    def test_domain_wide_audience_is_accepted_when_one_entry_qualifies(self):
        with AcceptDomainAudience():
            self.validate(make_token(aud=[SERVICE, DATALINK]))        # a domain-wide token

    def test_audience_naming_only_another_entry_is_refused(self):
        # DATALINK is an identifier this server accepts, but it does not COVER the request
        with AcceptDomainAudience():
            with self.assertRaises(jwt.InvalidAudienceError):
                self.validate(make_token(aud=[DATALINK]))

    def test_audience_naming_an_identifier_we_do_not_accept_is_refused(self):
        # the origin covers the request, but it is not one of RS_AUDIENCE_IDS
        with self.assertRaises(jwt.InvalidAudienceError):
            self.validate(make_token(aud=["https://src.local.io"]))

    def test_audience_is_judged_against_the_request(self):
        with AcceptDomainAudience():
            self.validate(make_token(aud=[DATALINK]), "https://src.local.io/datalink/x")
            with self.assertRaises(jwt.InvalidAudienceError):
                self.validate(make_token(aud=[SERVICE]), "https://src.local.io/datalink/x")

    def test_query_of_the_request_is_ignored_by_coverage(self):
        self.validate(make_token(), "https://src.local.io/vo/datalink?ID=1")


class Routes(unittest.TestCase):
    """The same cases through HTTP: the protected URLs and their 401 pointer."""

    def setUp(self):
        rs._jwks = lambda: _StubJwks()
        self.c = rs.app.test_client()

    def get(self, token=None, path="/vo/resource"):
        h = {"Authorization": "Bearer " + token} if token else {}
        return self.c.get(path, headers=h)

    # --- the 401 pointer is derived from the REQUESTED URL ------------------
    def test_unauthenticated_gets_the_pointer_for_the_requested_url(self):
        r = self.get()
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers["WWW-Authenticate"],
                         f'Bearer resource_metadata="https://src.local.io{WK}/vo/resource"')

    def test_pointer_follows_a_variable_path(self):
        r = self.get(path="/vo/tap/async/8f3a")
        self.assertEqual(r.headers["WWW-Authenticate"],
                         f'Bearer resource_metadata="https://src.local.io{WK}/vo/tap/async/8f3a"')

    def test_pointer_keeps_the_query_at_the_end(self):
        r = self.get(path="/vo/datalink?ID=ivo%3A%2F%2Fx%2Fy&b=2")
        self.assertEqual(r.headers["WWW-Authenticate"],
                         f'Bearer resource_metadata="https://src.local.io{WK}/vo/datalink?ID=ivo%3A%2F%2Fx%2Fy&b=2"')

    def test_the_service_root_is_protected_too(self):
        r = self.get(path="/vo")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers["WWW-Authenticate"],
                         f'Bearer resource_metadata="https://src.local.io{WK}/vo"')

    # --- paths the service does not own -----------------------------------------
    def test_a_path_outside_the_service_is_404_with_no_challenge(self):
        for path in ("/other/x", "/", "/datalink/x"):
            with self.subTest(path=path):
                r = self.get(path=path)
                self.assertEqual(r.status_code, 404)
                self.assertNotIn("WWW-Authenticate", r.headers)

    def test_a_prefix_that_is_not_a_segment_boundary_is_404(self):
        self.assertEqual(self.get(path="/vocab").status_code, 404)

    # --- the six validation cases through HTTP ------------------------------------
    def test_valid_token_gets_payload(self):
        r = self.get(make_token())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data)

    def test_token_without_aud_gets_payload(self):
        self.assertEqual(self.get(make_token(aud=None)).status_code, 200)

    def test_wrong_audience_is_401(self):
        self.assertEqual(self.get(make_token(aud="https://other.example")).status_code, 401)

    def test_domain_wide_audience_is_200_when_accepted(self):
        with AcceptDomainAudience():
            self.assertEqual(self.get(make_token(aud=[SERVICE, DATALINK])).status_code, 200)

    def test_audience_of_another_entry_only_is_401(self):
        with AcceptDomainAudience():
            self.assertEqual(self.get(make_token(aud=[DATALINK])).status_code, 401)

    def test_bad_token_401_points_at_the_prm_for_the_requested_url(self):
        r = self.get(make_token(aud="https://other.example"), path="/vo/datalink?ID=1")
        self.assertIn('error="invalid_token"', r.headers["WWW-Authenticate"])
        self.assertIn(f'resource_metadata="https://src.local.io{WK}/vo/datalink?ID=1"',
                      r.headers["WWW-Authenticate"])

    def test_missing_scope_is_403(self):
        r = self.get(make_token(scope="openid"))
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_scope", r.headers["WWW-Authenticate"])

    def test_rogue_issuer_is_401(self):
        self.assertEqual(self.get(make_token(iss="https://evil.example/")).status_code, 401)

    def test_expired_is_401(self):
        self.assertEqual(self.get(make_token(exp=int(time.time()) - 10)).status_code, 401)

    def test_foreign_signature_is_401(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = other.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
        now = int(time.time())
        tok = jwt.encode({"iss": ISSUER, "aud": SERVICE, "scope": "vo.read",
                          "exp": now + 300}, pem, algorithm="RS256")
        self.assertEqual(self.get(tok).status_code, 401)


class ProtectedResourceMetadata(unittest.TestCase):
    """RFC 9728: the PRM is generated per request, by the resource server itself."""

    def setUp(self):
        self.c = rs.app.test_client()

    def prm(self, suffix_and_query, **kw):
        return self.c.get(WK + suffix_and_query, **kw)

    def test_document_for_the_service_root(self):
        r = self.prm("/vo")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/json")
        self.assertEqual(r.get_json(), {
            "resource": SERVICE,
            "authorization_servers": [ISSUER],
            "scopes_supported": ["vo.read"],
            "bearer_methods_supported": ["header"],
        })

    def test_same_members_for_every_url_only_resource_differs(self):
        docs = [self.prm(s).get_json() for s in ("/vo", "/vo/resource", "/vo/tap/async/1",
                                                  "/vo/datalink?ID=1")]
        for d in docs:
            self.assertEqual({k: v for k, v in d.items() if k != "resource"},
                             {k: v for k, v in docs[0].items() if k != "resource"})
        self.assertEqual(len({d["resource"] for d in docs}), 4)

    def test_resource_is_the_requested_url_for_a_variable_path(self):
        self.assertEqual(self.prm("/vo/tap/async/8f3a").get_json()["resource"],
                         "https://src.local.io/vo/tap/async/8f3a")

    def test_resource_keeps_the_query_byte_for_byte(self):
        q = "?ID=ivo%3A%2F%2Fx%2Fy&b=2&a=1"       # no re-ordering, no re-encoding
        self.assertEqual(self.prm("/vo/datalink" + q).get_json()["resource"],
                         "https://src.local.io/vo/datalink" + q)

    def test_query_needing_json_escaping_is_escaped_not_concatenated(self):
        raw = '/vo/x?q="a"&r=\\z'
        r = self.c.get(WK + "/vo/x", environ_overrides={"RAW_URI": WK + raw})
        self.assertEqual(r.status_code, 200)
        doc = json.loads(r.get_data(as_text=True))        # still valid JSON ...
        self.assertEqual(doc["resource"], "https://src.local.io" + raw)   # ... and exact
        self.assertEqual(set(doc), {"resource", "authorization_servers",
                                    "scopes_supported", "bearer_methods_supported"})

    def test_percent_encoded_path_is_preserved(self):
        for kw in ({}, {"environ_overrides": {"RAW_URI": WK + "/vo/a%20b"}}):
            with self.subTest(raw_uri=bool(kw)):
                self.assertEqual(self.prm("/vo/a%20b", **kw).get_json()["resource"],
                                 "https://src.local.io/vo/a%20b")

    def test_double_slash_is_not_merged(self):
        self.assertEqual(self.prm("/vo//x").get_json()["resource"], "https://src.local.io/vo//x")

    def test_trailing_slash_is_preserved(self):
        self.assertEqual(self.prm("/vo/").get_json()["resource"], "https://src.local.io/vo/")

    # --- paths the service does not own ----------------------------------------------
    def test_404_outside_the_service_path(self):
        for suffix in ("/other", "/other/vo", "/vocab", "/datalink/x", ""):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.prm(suffix).status_code, 404)

    def test_404_when_the_prefix_runs_on(self):
        self.assertEqual(self.c.get(WK + "X/vo").status_code, 404)

    def test_a_service_at_the_root_owns_everything(self):
        saved = rs.SERVICE_PATH
        rs.SERVICE_PATH = "/"
        try:
            self.assertEqual(self.prm("/anything/at/all").status_code, 200)
            self.assertEqual(self.prm("").get_json()["resource"], "https://src.local.io")
        finally:
            rs.SERVICE_PATH = saved

    # --- RFC 9728 3.1: where the suffix goes -----------------------------------------------
    def test_prm_url_derivation(self):
        f = rs.prm_url_for
        self.assertEqual(f("/vo"), "https://src.local.io" + WK + "/vo")
        self.assertEqual(f("/vo/tap/async/7"), "https://src.local.io" + WK + "/vo/tap/async/7")
        self.assertEqual(f("/vo/datalink", "ID=1"), "https://src.local.io" + WK + "/vo/datalink?ID=1")
        self.assertEqual(f("/"), "https://src.local.io" + WK)          # slash after the host dropped
        self.assertEqual(f("/", "q=1"), "https://src.local.io" + WK + "?q=1")


class Ownership(unittest.TestCase):
    def test_owns_at_segment_boundaries(self):
        self.assertTrue(rs.owns("/vo"))
        self.assertTrue(rs.owns("/vo/"))
        self.assertTrue(rs.owns("/vo/tap/async/1"))
        self.assertFalse(rs.owns("/vocab"))
        self.assertFalse(rs.owns("/"))
        self.assertFalse(rs.owns("/other/vo"))


class Faults(unittest.TestCase):
    """The deliberately broken discovery fixtures behind the negative scenarios."""

    def setUp(self):
        self.c = rs.app.test_client()

    def test_each_fault_has_its_own_protected_url_pointing_at_its_own_prm(self):
        for name in ("prm-not-covering", "prm-covering", "prm-redirect"):
            r = self.c.get(f"/vo/faults/{name}/resource")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.headers["WWW-Authenticate"],
                             f'Bearer resource_metadata="https://src.local.io/vo/faults/{name}/prm"')

    def test_prm_not_covering_describes_a_different_resource(self):
        doc = self.c.get("/vo/faults/prm-not-covering/prm").get_json()
        self.assertEqual(doc["resource"], "https://src.local.io/some-other-service")
        self.assertEqual(doc["authorization_servers"], [ISSUER])

    def test_prm_covering_names_the_service_which_covers_but_is_not_the_requested_url(self):
        doc = self.c.get("/vo/faults/prm-covering/prm").get_json()
        requested = "https://src.local.io/vo/faults/prm-covering/resource"
        self.assertEqual(doc["resource"], SERVICE)
        self.assertTrue(rs.covers(requested, doc["resource"]))     # the OLD rule would pass it
        self.assertNotEqual(doc["resource"], requested)             # RFC 9728 3.3 does not

    def test_prm_redirect_redirects_to_a_prm_that_would_pass(self):
        r = self.c.get("/vo/faults/prm-redirect/prm")
        self.assertEqual(r.status_code, 302)
        target = r.headers["Location"]
        self.assertEqual(target, f"https://src.local.io{WK}/vo/faults/prm-redirect/resource")
        # ... and that target is a PRM naming exactly the URL that was requested
        doc = self.c.get(target.replace("https://src.local.io", "")).get_json()
        self.assertEqual(doc["resource"], "https://src.local.io/vo/faults/prm-redirect/resource")

    def test_unknown_fault_is_404(self):
        self.assertEqual(self.c.get("/vo/faults/nope/resource").status_code, 404)
        self.assertEqual(self.c.get("/vo/faults/nope/prm").status_code, 404)


if __name__ == "__main__":
    unittest.main()
