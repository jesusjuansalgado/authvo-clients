"""
Fake VO resource server (TAP / DataLink / SODA stand-in).

Implements the bearer mechanism from the AuthVO "Security Challenges" talk:

  - Unauthenticated request  -> 401 with a WWW-Authenticate: Bearer challenge
    carrying ONLY a `resource_metadata` pointer to the PRM sidecar at the IAM
    origin. The resource server never serves the authoritative descriptor
    itself (slides 14/16/17): it just emits the untrusted pointer.

  - Authenticated request -> the access token is validated and must:
        * be a JWT signed by the IAM (signature checked against IAM JWKS),
        * have `iss` == the configured IAM issuer,
        * have `aud` == this resource's own id  (RS verifies aud, slide 21/11),
        * carry scope/context `vo.read`,
        * be unexpired.
    On success it returns the ASCII payload "protected resource data".
    Missing/insufficient scope -> 403 insufficient_scope.

All knobs are environment variables so the same image works in the compose
stack and in a unit test.
"""
import os
import time

import jwt  # PyJWT
import requests
from flask import Flask, Response, request

# --- configuration (env-driven) ---------------------------------------------
RESOURCE_ID = os.environ.get("RS_RESOURCE_ID", "https://src.local.io")
ISSUER = os.environ.get("RS_ISSUER", "https://iam.local.io/")
PRM_URL = os.environ.get(
    "RS_PRM_URL",
    "https://iam.local.io/.well-known/oauth-protected-resource",
)
REQUIRED_SCOPE = os.environ.get("RS_REQUIRED_SCOPE", "vo.read")
# Path to a CA bundle so we trust the harness's self-signed origin, or "0" to
# disable verification in throwaway local demos.
CA_BUNDLE = os.environ.get("RS_CA_BUNDLE", "")
PAYLOAD_FILE = os.environ.get("RS_PAYLOAD_FILE", "protected_resource.txt")

app = Flask(__name__)
_jwks_client = None


def _verify_tls():
    if CA_BUNDLE == "0":
        return False
    return CA_BUNDLE or True


def _jwks():
    """Lazily build a PyJWKClient pointed at the IAM's JWKS endpoint.

    The endpoint is read from the AS metadata so we don't hard-code it.
    """
    global _jwks_client
    if _jwks_client is None:
        meta_url = ISSUER.rstrip("/") + "/.well-known/openid-configuration"
        meta = requests.get(meta_url, verify=_verify_tls(), timeout=10).json()
        _jwks_client = jwt.PyJWKClient(meta["jwks_uri"])
    return _jwks_client


def _challenge():
    """RFC 9728 / RFC 6750 style challenge: only a pointer, never the descriptor."""
    return f'Bearer resource_metadata="{PRM_URL}"'


def _scopes(claims):
    """INDIGO IAM puts scopes in the space-delimited `scope` claim."""
    raw = claims.get("scope", "")
    if isinstance(raw, (list, tuple)):
        return set(raw)
    return set(raw.split())


def validate_token(token, signing_key):
    """Pure validation helper (kept separate so it is unit-testable).

    Returns the decoded claims. Raises jwt exceptions or PermissionError.
    """
    claims = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        audience=RESOURCE_ID,   # RS verifies aud == its own id
        issuer=ISSUER,
        options={"require": ["exp", "aud", "iss"]},
    )
    if REQUIRED_SCOPE not in _scopes(claims):
        raise PermissionError("insufficient_scope")
    return claims


def _payload():
    with open(PAYLOAD_FILE, "rb") as fh:
        return fh.read()


@app.get("/vo-resource")
@app.get("/datalink/download/<path:anything>")  # dynamic DataLink-style URLs
def protected(anything=None):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Step 2 of the flow: 401 "token not found" -> untrusted pointer only.
        return Response(
            "token not found",
            status=401,
            headers={"WWW-Authenticate": _challenge()},
            mimetype="text/plain",
        )

    token = auth[len("Bearer ") :].strip()
    try:
        signing_key = _jwks().get_signing_key_from_jwt(token).key
        validate_token(token, signing_key)
    except PermissionError:
        return Response(
            "insufficient scope",
            status=403,
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="insufficient_scope", scope="{REQUIRED_SCOPE}"'
                )
            },
            mimetype="text/plain",
        )
    except Exception as exc:  # signature / aud / iss / exp failures
        return Response(
            "invalid token",
            status=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer error="invalid_token", '
                    f'error_description="{type(exc).__name__}", '
                    f'resource_metadata="{PRM_URL}"'
                )
            },
            mimetype="text/plain",
        )

    # Token good, audience-bound to us, has vo.read -> hand over the file.
    return Response(
        _payload(),
        status=200,
        mimetype="text/plain; charset=us-ascii",
        headers={"Content-Disposition": 'attachment; filename="protected_resource.txt"'},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "resource": RESOURCE_ID, "ts": int(time.time())}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
