"""
Unit tests for the fake resource server (fake-rs/app.py). No Docker needed.

  pip install flask "pyjwt[crypto]==2.7.0" requests
  python -m unittest test-integration/tests/test_fake_rs.py -v

Two groups:

  * the six token-validation cases the harness has always promised -- valid,
    wrong audience, missing vo.read, rogue issuer, expired, unauthenticated --
    (plus: `aud` is checked when present but no longer required) --
    exercised both on the pure validate_token() helper and through the HTTP
    route (so the status codes and WWW-Authenticate headers are checked too);

  * the RFC 9728 Protected Resource Metadata endpoint (PRM URL derivation per
    section 3.1, document contents per section 2).
"""
import importlib.util
import os
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

RS_DIR = Path(__file__).resolve().parent.parent / "fake-rs"

# The module reads its configuration at import time, so pin it first.
os.environ.update({
    "RS_RESOURCE_ID": "https://src.local.io",
    "RS_ISSUER": "https://iam.local.io/",
    "RS_REQUIRED_SCOPE": "vo.read",
    "RS_PAYLOAD_FILE": str(RS_DIR / "protected_resource.txt"),
    "RS_TEST_FAULTS": "1",
})
os.environ.pop("RS_PRM_URL", None)
# Load by path under a unique name: augmenter/app.py is also called "app", and
# the two test modules may share one interpreter.
_spec = importlib.util.spec_from_file_location("fake_rs_app", RS_DIR / "app.py")
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

RESOURCE = "https://src.local.io"
ISSUER = "https://iam.local.io/"

# One throwaway RSA key signs every test token; "rogue" is a second key pair.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
_PUB = _KEY.public_key()


def make_token(**override):
    """A valid token (claims in `override` replace/extend the defaults)."""
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": RESOURCE, "scope": "openid vo.read",
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


class ValidateToken(unittest.TestCase):
    """The pure validation helper."""

    def test_valid(self):
        claims = rs.validate_token(make_token(), _PUB)
        self.assertEqual(claims["aud"], RESOURCE)

    def test_wrong_audience(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            rs.validate_token(make_token(aud="https://other.example"), _PUB)

    def test_missing_scope(self):
        with self.assertRaises(PermissionError):
            rs.validate_token(make_token(scope="openid"), _PUB)

    # aud is checked when present, not required (token exchange is optional now)
    def test_no_aud_claim_is_accepted(self):
        claims = rs.validate_token(make_token(aud=None), _PUB)
        self.assertNotIn("aud", claims)

    def test_aud_list_including_us_is_accepted(self):
        rs.validate_token(make_token(aud=["https://other.example", RESOURCE]), _PUB)

    def test_aud_list_without_us_is_refused(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            rs.validate_token(make_token(aud=["https://other.example"]), _PUB)

    def test_empty_aud_is_refused(self):
        # present-but-empty is not "absent": it names nobody, so it is not for us
        with self.assertRaises(jwt.InvalidAudienceError):
            rs.validate_token(make_token(aud=[]), _PUB)

    def test_rogue_issuer(self):
        with self.assertRaises(jwt.InvalidIssuerError):
            rs.validate_token(make_token(iss="https://evil.example/"), _PUB)

    def test_expired(self):
        with self.assertRaises(jwt.ExpiredSignatureError):
            rs.validate_token(make_token(exp=int(time.time()) - 10), _PUB)


class Routes(unittest.TestCase):
    """The same cases through HTTP, plus the PRM document."""

    def setUp(self):
        rs._jwks = lambda: _StubJwks()
        self.c = rs.app.test_client()

    def get(self, token=None):
        h = {"Authorization": "Bearer " + token} if token else {}
        return self.c.get("/vo-resource", headers=h)

    def test_unauthenticated_gets_pointer_to_own_prm(self):
        r = self.get()
        self.assertEqual(r.status_code, 401)
        self.assertEqual(
            r.headers["WWW-Authenticate"],
            'Bearer resource_metadata="https://src.local.io/.well-known/oauth-protected-resource"')

    def test_valid_token_gets_payload(self):
        r = self.get(make_token())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data)

    def test_token_without_aud_gets_payload(self):
        self.assertEqual(self.get(make_token(aud=None)).status_code, 200)

    def test_wrong_audience_is_401(self):
        self.assertEqual(self.get(make_token(aud="https://other.example")).status_code, 401)

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
        tok = jwt.encode({"iss": ISSUER, "aud": RESOURCE, "scope": "vo.read",
                          "exp": now + 300}, pem, algorithm="RS256")
        self.assertEqual(self.get(tok).status_code, 401)


class ProtectedResourceMetadata(unittest.TestCase):
    """RFC 9728: the PRM is served by the resource server itself."""

    def test_document(self):
        r = rs.app.test_client().get("/.well-known/oauth-protected-resource")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/json")
        self.assertEqual(r.get_json(), {
            "resource": RESOURCE,
            "authorization_servers": [ISSUER],
            "scopes_supported": ["vo.read"],
            "bearer_methods_supported": ["header"],
        })

    def test_well_known_url_derivation(self):
        # RFC 9728 3.1: the suffix goes between host and path.
        f = rs.prm_well_known_url
        self.assertEqual(f("https://src.local.io"),
                         "https://src.local.io/.well-known/oauth-protected-resource")
        self.assertEqual(f("https://src.local.io/"),
                         "https://src.local.io/.well-known/oauth-protected-resource")
        self.assertEqual(f("https://src.local.io/vo"),
                         "https://src.local.io/.well-known/oauth-protected-resource/vo")

    def test_no_document_at_unrelated_suffix(self):
        r = rs.app.test_client().get("/.well-known/oauth-protected-resource/elsewhere")
        self.assertEqual(r.status_code, 404)


class Faults(unittest.TestCase):
    """The deliberately broken discovery fixtures behind the negative scenarios."""

    def setUp(self):
        self.c = rs.app.test_client()

    def test_each_fault_has_its_own_protected_url_pointing_at_its_own_prm(self):
        for name in ("prm-not-covering", "prm-redirect"):
            r = self.c.get(f"/faults/{name}/vo-resource")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.headers["WWW-Authenticate"],
                             f'Bearer resource_metadata="https://src.local.io/faults/{name}/prm"')

    def test_prm_not_covering_describes_a_different_resource(self):
        doc = self.c.get("/faults/prm-not-covering/prm").get_json()
        self.assertEqual(doc["resource"], "https://src.local.io/some-other-service")
        self.assertEqual(doc["authorization_servers"], [ISSUER])

    def test_prm_redirect_redirects_to_the_good_prm(self):
        r = self.c.get("/faults/prm-redirect/prm")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"],
                         "https://src.local.io/.well-known/oauth-protected-resource")

    def test_unknown_fault_is_404(self):
        self.assertEqual(self.c.get("/faults/nope/vo-resource").status_code, 404)
        self.assertEqual(self.c.get("/faults/nope/prm").status_code, 404)


if __name__ == "__main__":
    unittest.main()
