"""
Unit tests for the fake resource server (fake-rs/app.py). No Docker needed.

  pip install flask "pyjwt[crypto]==2.7.0" requests
  python -m unittest test-integration/tests/test_fake_rs.py -v

Two groups:

  * the six token-validation cases the harness has always promised -- valid,
    wrong audience, missing vo.read, rogue issuer, expired, unauthenticated --
    exercised both on the pure validate_token() helper and through the HTTP
    route (so the status codes and WWW-Authenticate headers are checked too);

  * the RFC 9728 Protected Resource Metadata endpoint (PRM URL derivation per
    section 3.1, document contents per section 2).
"""
import os
import sys
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
})
os.environ.pop("RS_PRM_URL", None)
sys.path.insert(0, str(RS_DIR))
import app as rs  # noqa: E402  (import after the environment is set)

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


if __name__ == "__main__":
    unittest.main()
