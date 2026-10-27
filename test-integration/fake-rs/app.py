"""
Fake VO resource server (TAP / DataLink / SODA stand-in).

Implements the bearer mechanism from the AuthVO "Security Challenges" talk:

  - Unauthenticated request  -> 401 with a WWW-Authenticate: Bearer challenge
    carrying a `resource_metadata` pointer (RFC 9728 section 5) to the Protected
    Resource Metadata (PRM) for THE URL THAT WAS REQUESTED. The pointer is
    UNTRUSTED: the client decides whether to believe the document it leads to.

  - GET /.well-known/oauth-protected-resource/<path>[?<query>]  -> the PRM for
    the resource <scheme>://<host>/<path>[?<query>] (RFC 9728 section 3.1: the
    well-known suffix is inserted between the host and the path, and the query
    stays at the end). It is GENERATED PER REQUEST, because a service whose
    paths vary (TAP async jobs, DataLink ?ID=...) cannot publish one static file.
    Every PRM carries the same members; only `resource` changes, and it is the
    requested URL, query included, byte for byte. That is what RFC 9728 section
    3.3 requires when the PRM URL came from a WWW-Authenticate challenge: the
    `resource` value must be identical to the URL the client requested.
    Nothing is registered per URL.

  - Which URLs does this service own? Those at or below RS_SERVICE_PATH (a
    path-segment boundary, so /vo owns /vo and /vo/tap but not /vocab). Anything
    else answers 404, including its PRM, so the handler does not claim URLs that
    belong to another service on a shared host.

  - What ties a resource to an issuer is NOT this server's say-so but the
    issuer's own `protected_resources` metadata member (see ../augmenter/), which
    the client checks separately (Step 3). The audience a token is for also comes
    from there, never from the PRM `resource`.

  - Authenticated request -> the access token is validated and must:
        * be a JWT signed by the IAM (signature checked against IAM JWKS),
        * have `iss` == the configured IAM issuer,
        * if it carries an `aud`, that must include an identifier this service
          accepts (RS_AUDIENCE_IDS, default: the service identifier) which also
          COVERS the requested URL. `aud` is checked WHEN PRESENT but not
          required: INDIGO IAM 1.10 issues tokens without one,
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
from urllib.parse import quote, unquote, urlsplit

import jwt  # PyJWT
import requests
from flask import Flask, Response, request

PRM_WELL_KNOWN = "/.well-known/oauth-protected-resource"

# --- configuration (env-driven) ---------------------------------------------
# The SERVICE identifier: what the IAM lists in `protected_resources` for this
# service, e.g. https://src.local.io/vo . Its origin is the origin of every URL
# this server answers for.
RESOURCE_ID = os.environ.get("RS_RESOURCE_ID", "https://src.local.io")
_RID = urlsplit(RESOURCE_ID)
ORIGIN = f"{_RID.scheme}://{_RID.netloc}"
# The path this service owns. Defaults to the path of the service identifier
# ("/" when it has none).
SERVICE_PATH = os.environ.get("RS_SERVICE_PATH", _RID.path or "/")
# Identifiers a token's `aud` may name (space-separated), at least one of which must
# cover the request. Defaults to the service identifier; list several to accept
# domain-wide tokens (an audience made of every entry of `protected_resources`).
AUDIENCE_IDS = os.environ.get("RS_AUDIENCE_IDS", RESOURCE_ID).split()
ISSUER = os.environ.get("RS_ISSUER", "https://iam.local.io/")
REQUIRED_SCOPE = os.environ.get("RS_REQUIRED_SCOPE", "vo.read")
# Path to a CA bundle so we trust the harness's self-signed origin, or "0" to
# disable verification in throwaway local demos.
CA_BUNDLE = os.environ.get("RS_CA_BUNDLE", "")
PAYLOAD_FILE = os.environ.get("RS_PAYLOAD_FILE", "protected_resource.txt")
# Test fixtures: when "1", serve deliberately broken discovery under
# <service path>/faults/... (see the end of this file). Off unless the harness
# turns it on.
TEST_FAULTS = os.environ.get("RS_TEST_FAULTS") == "1"

app = Flask(__name__)
# (The `path` converters below keep "//" as it was sent; the exact-match rule compares
# URLs byte for byte, and test_double_slash_is_not_merged holds that property.)
_jwks_client = None


# --- URLs: what was asked for, and what it maps to --------------------------

def _raw_target():
    """The request target exactly as the client sent it: (raw path, raw query).

    Werkzeug decodes `request.path`, which would turn /vo/a%20b into /vo/a b and
    then fail the byte-for-byte comparison a client makes. gunicorn and the dev
    server both expose the raw request line as RAW_URI; if neither does (the Flask
    test client), the path is re-encoded, which round-trips ordinary input.
    """
    raw = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI")
    if raw:
        path, _, query = raw.partition("?")
        return path, query
    path = quote(request.path, safe="/:@!$&'()*+,;=-._~")
    return path, request.query_string.decode("utf-8", errors="strict")


def prm_url_for(raw_path, raw_query=""):
    """The PRM URL for the resource at `raw_path` (+ `raw_query`) (RFC 9728 3.1).

    The well-known suffix is INSERTED between the host and the path; the query
    stays at the end. A bare "/" path is dropped (the slash right after the host
    is removed), so:

        /vo                 -> /.well-known/oauth-protected-resource/vo
        /vo/tap/async/7     -> /.well-known/oauth-protected-resource/vo/tap/async/7
        /vo/datalink?ID=1   -> /.well-known/oauth-protected-resource/vo/datalink?ID=1
        /                   -> /.well-known/oauth-protected-resource
    """
    path = "" if raw_path == "/" else raw_path
    return ORIGIN + PRM_WELL_KNOWN + path + (("?" + raw_query) if raw_query else "")


def owns(path):
    """Is `path` at or below this service's path, at a path-SEGMENT boundary?

    /vo owns /vo and /vo/tap/async/1 but not /vocab. A service path of "/" owns
    everything. Used for the PRM as well as the protected URLs, so a shared host
    can give each service its own subtree (and its own well-known prefix).
    """
    base = SERVICE_PATH.rstrip("/")
    return base == "" or path == base or path.startswith(base + "/")


def covers(url, identifier):
    """Is `url` covered by the resource identifier `identifier`?

    The same rule the clients apply to the entries of `protected_resources`
    (AuthVO draft 3.3.1): same origin, and a path equal to the identifier's or
    extending it AT A PATH-SEGMENT BOUNDARY; any query or fragment is ignored and
    dot-segments are resolved first (so /vo/../x is not under /vo). A deliberate
    COPY of authvo_client.is_covered (this image cannot import it); both are tested
    against tests/coverage_vectors.json.
    """
    def parts(u):
        p = urlsplit(u)
        scheme, host = (p.scheme or "").lower(), (p.hostname or "").lower()
        default = {"https": 443, "http": 80}.get(scheme)
        netloc = host if p.port in (None, default) else f"{host}:{p.port}"
        segs = []
        for seg in (p.path or "/").split("/"):
            s = seg.lower()
            if s in (".", "%2e"):
                continue
            if s in ("..", ".%2e", "%2e.", "%2e%2e"):
                if len(segs) > 1:
                    segs.pop()
                continue
            segs.append(seg)
        return f"{scheme}://{netloc}", "/".join(segs).rstrip("/")

    (uo, up), (io, ip) = parts(url), parts(identifier)
    return uo == io and (ip == "" or up == ip or up.startswith(ip + "/"))


# --- TLS / JWKS --------------------------------------------------------------

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


# --- the 401 challenge and the PRM -------------------------------------------

def _challenge(raw_path, raw_query=""):
    """RFC 6750 / RFC 9728 section 5 challenge: a `resource_metadata` pointer.

    The pointer is the PRM URL derived from the URL that was REQUESTED, query
    included, so the PRM it leads to can name exactly that URL.
    """
    return f'Bearer resource_metadata="{prm_url_for(raw_path, raw_query)}"'


def prm_document(resource):
    """The Protected Resource Metadata for the resource URL `resource` (RFC 9728 s.2).

    Every PRM has the same members; only `resource` varies, and it is the
    requested URL. Built with json (never by string concatenation), so a query
    containing quotes or backslashes is escaped safely.

      resource                  the requested URL, exactly (RFC 9728 3.3)
      authorization_servers     issuers we accept tokens from
      scopes_supported          scopes we understand
      bearer_methods_supported  how a token may be presented (header only)
    """
    return {
        "resource": resource,
        "authorization_servers": [ISSUER],
        "scopes_supported": [REQUIRED_SCOPE],
        "bearer_methods_supported": ["header"],
    }


def _json(doc):
    return Response(json.dumps(doc, indent=2) + "\n", mimetype="application/json")


@app.get(PRM_WELL_KNOWN)
@app.get(PRM_WELL_KNOWN + "/<path:suffix>")
def prm(suffix=None):
    """Generate the PRM for the URL named by the well-known request (RFC 9728 3.1).

    The requested resource is whatever follows the well-known prefix, with the
    query kept: .../oauth-protected-resource/vo/datalink?ID=1 is the PRM of
    <origin>/vo/datalink?ID=1. If this service does not own that path the answer
    is 404, so the handler never speaks for another service on the same host.
    """
    raw_path, raw_query = _raw_target()
    rest = raw_path[len(PRM_WELL_KNOWN):]
    if rest and not rest.startswith("/"):                  # .../oauth-protected-resourceX
        return Response("not found", status=404, mimetype="text/plain")
    if not owns(unquote(rest or "/")):
        return Response("not found", status=404, mimetype="text/plain")
    return _json(prm_document(ORIGIN + rest + (("?" + raw_query) if raw_query else "")))


# --- token validation ---------------------------------------------------------

def _scopes(claims):
    """INDIGO IAM puts scopes in the space-delimited `scope` claim."""
    raw = claims.get("scope", "")
    if isinstance(raw, (list, tuple)):
        return set(raw)
    return set(raw.split())


def validate_token(token, signing_key, request_url=None):
    """Pure validation helper (kept separate so it is unit-testable).

    Checks signature, `iss`, `exp` and the required scope, and `aud` WHEN THE
    TOKEN HAS ONE: a present `aud` must name at least one identifier from
    AUDIENCE_IDS that COVERS `request_url` (a token minted for another service,
    or for a part of this domain that does not contain the request, is refused;
    an audience with several entries is fine if one of them qualifies). An absent
    `aud` is accepted. `request_url` defaults to the service identifier. Returns
    the decoded claims. Raises jwt exceptions or PermissionError.
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
        url = request_url or RESOURCE_ID
        if not any(a in AUDIENCE_IDS and covers(url, a) for a in audiences):
            raise jwt.InvalidAudienceError("Invalid audience")
    if REQUIRED_SCOPE not in _scopes(claims):
        raise PermissionError("insufficient_scope")
    return claims


def _payload():
    with open(PAYLOAD_FILE, "rb") as fh:
        return fh.read()


# --- the protected URLs ---------------------------------------------------------

@app.get("/")
@app.get("/<path:anything>")
def protected(anything=None):
    """Any URL at or below the service path is protected; anything else is 404."""
    raw_path, raw_query = _raw_target()
    if not owns(unquote(raw_path)):
        return Response("not found", status=404, mimetype="text/plain")

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Step 1 of the flow: 401 "token not found" -> untrusted pointer only. RFC
        # 6750 3.1: no error code when the request carried no credentials.
        return Response(
            "token not found",
            status=401,
            headers={"WWW-Authenticate": _challenge(raw_path, raw_query)},
            mimetype="text/plain",
        )

    token = auth[len("Bearer "):].strip()
    try:
        signing_key = _jwks().get_signing_key_from_jwt(token).key
        validate_token(token, signing_key, ORIGIN + raw_path)
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
                    f'resource_metadata="{prm_url_for(raw_path, raw_query)}"'
                )
            },
            mimetype="text/plain",
        )

    # Token good (and, if it names an audience, one we accept that covers this
    # request), has vo.read -> hand over the file.
    return Response(
        _payload(),
        status=200,
        mimetype="text/plain; charset=us-ascii",
        headers={"Content-Disposition": 'attachment; filename="protected_resource.txt"'},
    )


# --- test fixtures (RS_TEST_FAULTS=1) ----------------------------------------
# Deliberately broken discovery set-ups, so the clients' Step 2 refusals can be
# exercised against the real stack. They live UNDER the service path (so a router
# that sends the service's subtree here needs no special case). Each fault has a
# protected URL (<service path>/faults/<name>/resource) whose 401 points at its own
# PRM (<service path>/faults/<name>/prm):
#
#   prm-not-covering  the PRM describes a DIFFERENT resource entirely -> Step 2 abort
#   prm-covering      the PRM names the SERVICE identifier, which COVERS the requested
#                     URL but is not equal to it. The pre-review profile accepted that;
#                     RFC 9728 3.3 does not -> Step 2 abort
#   prm-redirect      the PRM URL answers 302 to a perfectly good PRM (one that WOULD
#                     pass Step 2); a client that followed it would succeed, so
#                     refusing is the whole test
FAULT_NAMES = ("prm-not-covering", "prm-covering", "prm-redirect")
FAULT_PREFIX = SERVICE_PATH.rstrip("/") + "/faults"

if TEST_FAULTS:
    @app.get(FAULT_PREFIX + "/<name>/resource")
    def fault_resource(name):
        if name not in FAULT_NAMES:
            return Response("not found", status=404, mimetype="text/plain")
        pointer = f"{ORIGIN}{FAULT_PREFIX}/{name}/prm"
        return Response("token not found", status=401, mimetype="text/plain",
                        headers={"WWW-Authenticate": f'Bearer resource_metadata="{pointer}"'})

    @app.get(FAULT_PREFIX + "/<name>/prm")
    def fault_prm(name):
        if name == "prm-redirect":
            # a PRM that is perfectly valid for the requested URL, behind a redirect
            return Response(status=302, headers={
                "Location": prm_url_for(f"{FAULT_PREFIX}/{name}/resource")})
        if name == "prm-not-covering":
            return _json(prm_document(ORIGIN + "/some-other-service"))
        if name == "prm-covering":
            return _json(prm_document(RESOURCE_ID))
        return Response("not found", status=404, mimetype="text/plain")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "resource": RESOURCE_ID, "ts": int(time.time())}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
