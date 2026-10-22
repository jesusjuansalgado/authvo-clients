"""
Fake VO resource server (TAP / DataLink / SODA stand-in).

Implements the bearer mechanism from the AuthVO "Security Challenges" talk:

  - Unauthenticated request  -> 401 with a WWW-Authenticate: Bearer challenge
    carrying a `resource_metadata` pointer (RFC 9728 section 5) to this
    resource server's own Protected Resource Metadata (PRM). The pointer is
    UNTRUSTED: the client decides whether to believe the document it leads to.

  - GET /.well-known/oauth-protected-resource  -> the PRM itself (RFC 9728
    section 3), built from this server's environment: its own resource id, the
    authorization server(s) it accepts tokens from, the scopes it understands.
    Per RFC 9728 the PRM belongs to the RESOURCE SERVER, not to the IAM. What
    ties a resource to an issuer is the issuer's `protected_resources` metadata
    member (see ../augmenter/), which the client checks separately.

  - Authenticated request -> the access token is validated and must:
        * be a JWT signed by the IAM (signature checked against IAM JWKS),
        * have `iss` == the configured IAM issuer,
        * if it carries an `aud`, that must include this resource's own id.
          `aud` is checked WHEN PRESENT but not required: a token requested with
          the RFC 8707 `resource` indicator may come back without one if the
          issuer does not bind audiences (INDIGO IAM 1.10 does not honour it),
          and the client no longer needs an RFC 8693 exchange to get one,
        * carry scope/context `vo.read`,
        * be unexpired.
    On success it returns the ASCII payload "protected resource data".
    Missing/insufficient scope -> 403 insufficient_scope.

All knobs are environment variables so the same image works in the compose
stack and in a unit test.
"""
import json
import os
import time
from urllib.parse import urlsplit

import jwt  # PyJWT
import requests
from flask import Flask, Response, request

PRM_WELL_KNOWN = "/.well-known/oauth-protected-resource"


def prm_well_known_url(resource_id):
    """The URL at which the PRM for `resource_id` is published (RFC 9728 3.1).

    The well-known suffix is INSERTED between the host and the path of the
    resource identifier (any trailing slash on the path is dropped first):

        https://src.local.io        -> https://src.local.io/.well-known/oauth-protected-resource
        https://src.local.io/vo     -> https://src.local.io/.well-known/oauth-protected-resource/vo
    """
    p = urlsplit(resource_id)
    return f"{p.scheme}://{p.netloc}{PRM_WELL_KNOWN}{p.path.rstrip('/')}"


# --- configuration (env-driven) ---------------------------------------------
RESOURCE_ID = os.environ.get("RS_RESOURCE_ID", "https://src.local.io")
ISSUER = os.environ.get("RS_ISSUER", "https://iam.local.io/")
# Where the 401 challenge points the client. Defaults to this server's own PRM
# (RFC 9728 3.1); the env var exists so a test can point it somewhere else.
PRM_URL = os.environ.get("RS_PRM_URL", prm_well_known_url(RESOURCE_ID))
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
    """RFC 6750 / RFC 9728 section 5 challenge: a `resource_metadata` pointer."""
    return f'Bearer resource_metadata="{PRM_URL}"'


def prm_document():
    """This server's Protected Resource Metadata (RFC 9728 section 2).

    Everything is derived from the environment so the same image can play the
    real resource server or the "evil" one in the negative tests:

      resource                  who we are (what a token's `aud` should name)
      authorization_servers     issuers we accept tokens from
      scopes_supported          scopes we understand
      bearer_methods_supported  how a token may be presented (header only)
    """
    return {
        "resource": RESOURCE_ID,
        "authorization_servers": [ISSUER],
        "scopes_supported": [REQUIRED_SCOPE],
        "bearer_methods_supported": ["header"],
    }


@app.get(PRM_WELL_KNOWN)
@app.get(PRM_WELL_KNOWN + "/<path:suffix>")
def prm(suffix=None):
    """Serve the PRM at its RFC 9728 3.1 well-known URL, and only there.

    For a path-bearing resource id the document lives at /<well-known>/<path>,
    so the route accepts a suffix but answers 404 unless the request path is
    exactly the one derived from RESOURCE_ID (no document at unrelated URLs).
    """
    if request.path != urlsplit(prm_well_known_url(RESOURCE_ID)).path:
        return Response("not found", status=404, mimetype="text/plain")
    return Response(json.dumps(prm_document(), indent=2) + "\n",
                    mimetype="application/json")


def _scopes(claims):
    """INDIGO IAM puts scopes in the space-delimited `scope` claim."""
    raw = claims.get("scope", "")
    if isinstance(raw, (list, tuple)):
        return set(raw)
    return set(raw.split())


def validate_token(token, signing_key):
    """Pure validation helper (kept separate so it is unit-testable).

    Checks signature, `iss`, `exp` and the required scope, and `aud` WHEN THE
    TOKEN HAS ONE: a present `aud` must include RESOURCE_ID (a token minted for
    another service is refused), an absent one is accepted. Returns the decoded
    claims. Raises jwt exceptions or PermissionError.
    """
    claims = jwt.decode(
        token,
        signing_key,
        algorithms=["RS256"],
        issuer=ISSUER,
        # PyJWT would insist on an `aud` the moment we hand it an audience, so
        # `aud` is checked by hand below, and only when present.
        options={"require": ["exp", "iss"], "verify_aud": False},
    )
    if "aud" in claims:
        aud = claims["aud"]
        audiences = [aud] if isinstance(aud, str) else list(aud or [])
        if RESOURCE_ID not in audiences:
            raise jwt.InvalidAudienceError("Invalid audience")
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

    # Token good (and, if it names an audience, that is us), has vo.read -> file.
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
