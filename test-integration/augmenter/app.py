"""
Authorization-server metadata AUGMENTER  --  an INTERIM emulation.
===================================================================

What it is
----------
A tiny reverse proxy that sits in front of the IAM's two discovery documents,

    /.well-known/oauth-authorization-server     (RFC 8414)
    /.well-known/openid-configuration           (OpenID Connect Discovery)

and returns the IAM's LIVE metadata with exactly one extra member added:

    "protected_resources": [ "https://src.local.io", ... ]

Everything else -- above all `issuer` -- is passed through untouched.

Why it exists
-------------
RFC 9728 section 4 defines `protected_resources` as an (optional) member of the
authorization server's RFC 8414 metadata: the list of resource identifiers the
server is willing to issue tokens for. That list is what binds a RESOURCE to an
ISSUER, and so what lets a client refuse the "evil service" (a resource server
that names a real issuer in ITS OWN protected-resource metadata, hoping to make
the client hand over a token minted by that issuer). A client trusts the
binding only if the ISSUER itself vouches for the resource.

INDIGO IAM does not publish `protected_resources` yet, and we must not modify
INDIGO. So this proxy emulates the member: Traefik routes the two metadata
paths on the IAM origin here (at higher priority than the IAM router), and
every other path still goes straight to the IAM. To a client the result is
indistinguishable from native support.

    >>> This is the interim emulation described in the AuthVO draft's
    >>> implementation note. DELETE this service (and its Traefik router) as soon
    >>> as INDIGO IAM publishes `protected_resources` natively. <<<

If the upstream document ever already contains `protected_resources`, it is
left alone: native support wins over the emulation.

Behaviour, precisely
--------------------
* The IAM's metadata is fetched over the internal network (AUGMENTER_UPSTREAM),
  presenting the public Host / X-Forwarded-* headers so the IAM generates its
  public URLs. It is cached for AUGMENTER_CACHE_SECONDS (default 60).
* If the IAM has no RFC 8414 document, one is DERIVED from its OIDC discovery
  document (the two share the members we care about, notably `issuer`).
* The resource list is read from AUGMENTER_CONFIG on EVERY request (it is tiny),
  so editing the file takes effect at once -- the negative tests rely on this.
  The file is a JSON object:   {"protected_resources": ["https://src.local.io"]}
  If the file or that key is missing/unreadable the member is simply omitted
  (a client must treat an absent list as a failure, so this fails closed).
* Anything other than GET of the two metadata paths (and /healthz) is a 404.

Standard library only (no pip install in the image).
"""
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AS_PATH = "/.well-known/oauth-authorization-server"      # RFC 8414
OIDC_PATH = "/.well-known/openid-configuration"          # OIDC Discovery

# --- configuration (env-driven; module globals so tests can override) -------
UPSTREAM = os.environ.get("AUGMENTER_UPSTREAM", "http://iam:8080")
# The Host the IAM must believe it was called with, so that the URLs inside its
# metadata are its PUBLIC ones rather than http://iam:8080/...
UPSTREAM_HOST = os.environ.get("AUGMENTER_UPSTREAM_HOST", "iam.local.io")
CONFIG = os.environ.get("AUGMENTER_CONFIG", "/config/protected_resources.json")
CACHE_SECONDS = float(os.environ.get("AUGMENTER_CACHE_SECONDS", "60"))
PORT = int(os.environ.get("PORT", "8080"))

log = logging.getLogger("augmenter")

_cache = {}                       # requested path -> (expires_at, document)
_cache_lock = threading.Lock()


class UpstreamError(Exception):
    """The IAM could not be reached or returned something unusable."""


def _fetch_upstream(path):
    """GET `path` from the IAM; return (status, parsed-JSON-or-None).

    A 404 is returned as (404, None) rather than raised: it is an expected
    answer when the IAM has no RFC 8414 document. Any other failure raises.
    """
    req = urllib.request.Request(UPSTREAM + path, headers={
        "Host": UPSTREAM_HOST,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": UPSTREAM_HOST,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, None
        raise UpstreamError(f"IAM answered {e.code} for {path}") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpstreamError(f"cannot read {path} from the IAM: {e}") from e


def upstream_metadata(requested_path):
    """The IAM's live metadata for `requested_path`, cached ~60 s.

    For the RFC 8414 path the IAM may have no document at all; in that case the
    OIDC discovery document is used in its place (same `issuer`, same endpoint
    members) -- the "derive it" fallback.
    """
    now = time.time()
    with _cache_lock:
        hit = _cache.get(requested_path)
        if hit and hit[0] > now:
            return hit[1]

    status, doc = _fetch_upstream(requested_path)
    if status == 404 and requested_path == AS_PATH:
        log.info("IAM has no %s; deriving it from %s", AS_PATH, OIDC_PATH)
        status, doc = _fetch_upstream(OIDC_PATH)
    if doc is None:
        raise UpstreamError(f"IAM has no metadata document for {requested_path}")

    with _cache_lock:
        _cache[requested_path] = (now + CACHE_SECONDS, doc)
    return doc


def load_protected_resources():
    """The resource identifiers to publish, or None if there are none.

    Read fresh on every call. Any problem (no file, bad JSON, wrong shape) is
    logged and yields None, so the member is omitted -- clients reject that.
    """
    try:
        with open(CONFIG, encoding="utf-8") as fh:
            value = json.load(fh).get("protected_resources")
    except (OSError, ValueError, AttributeError) as e:
        log.warning("no usable resource list in %s: %s", CONFIG, e)
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        log.warning("%s: 'protected_resources' must be a list of strings", CONFIG)
        return None
    return value


def augment(doc):
    """Return a copy of `doc` with `protected_resources` added (see module doc)."""
    out = dict(doc)
    if "protected_resources" in out:
        log.info("upstream already publishes protected_resources; passing through")
        return out
    resources = load_protected_resources()
    if resources is not None:
        out["protected_resources"] = resources
    return out


class Handler(BaseHTTPRequestHandler):
    """GET the two metadata paths (+ /healthz); everything else is a 404."""

    def _send(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 (http.server naming)
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, {"status": "ok"})
        if path not in (AS_PATH, OIDC_PATH):
            return self._send(404, {"error": "not found"})
        try:
            doc = augment(upstream_metadata(path))
        except UpstreamError as e:
            log.error("%s", e)
            return self._send(502, {"error": "bad_gateway", "detail": str(e)})
        log.info("GET %s -> 200 (protected_resources=%s)", path,
                 doc.get("protected_resources", "absent"))
        self._send(200, doc)

    def log_message(self, fmt, *args):   # route http.server's chatter via logging
        log.debug(fmt, *args)


def main():
    logging.basicConfig(level=logging.INFO, format="augmenter: %(message)s")
    log.info("fronting %s (Host %s), resources from %s, cache %ss",
             UPSTREAM, UPSTREAM_HOST, CONFIG, CACHE_SECONDS)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
