#!/usr/bin/env python3
"""
Reference VO client for the unified AuthVO bearer-token flow.
================================================================

This is a *reference implementation*, written to be read. It walks the complete
AuthVO bearer-token flow described in the IVOA DSP "Bearer Tokens — open issues"
deck, end to end, with copious logging so you can watch each step happen.

WHY THIS EXISTS (the threat it defends against)
-----------------------------------------------
In plain OAuth2 a client that hits a protected service is told "go get a token
from issuer X". But nothing ties issuer X to the service that named it. A
*malicious* service (the "evil service") can therefore point the client at a
spoofed metadata document and harvest a real token that was minted for it.

AuthVO closes that hole with two ideas, both implemented below:

  1. The resource server's 401 hands back ONLY a *pointer* to a metadata
     document (the "sidecar"), never the authoritative descriptor itself. The
     pointer is UNTRUSTED until it passes the domain-proxy check.

  2. The DOMAIN-PROXY CHECK (step 4) refuses to trust the issuer named in that
     document unless (a) the document is served from the SAME origin as the
     issuer it names, and (b) the resource we actually called is one the
     document is authoritative for. Co-locating the sidecar and the issuer on
     one origin is what makes a forged `evil.com` descriptor fail gate (a).

Once the issuer is trusted, the token we obtain is narrowed (its `aud` claim is
bound) to exactly the target resource, so even if it leaked it could not be
replayed against a different service.

THE FLOW, STEP BY STEP (numbers match the slide deck and the methods below)
---------------------------------------------------------------------------
  1  GET the protected resource anonymously
  2  401 "token not found" -> sidecar location (an UNTRUSTED pointer)
  3  GET the sidecar at the IAM proxy -> issuer URL + protected-resources list
  4  DOMAIN PROXY CHECK (two gates, ABORT on failure):
        (a) the sidecar and the issuer it names share the same origin/proxy
        (b) the redirecting service is in the sidecar's list (path-prefix match)
  5  GET the Authorization Server metadata (RFC 8414) from the named issuer
  6  Dynamic client registration (RFC 7591) -> client_id        [if needed]
  7  Device authorization request (RFC 8628)
  8  User authenticates and grants (we show the service + issuer)
  9  Poll the token endpoint (RFC 8628) with resource indicator (RFC 8707)
 10  Token exchange (RFC 8693): audience=<resource> -> narrowed, aud-bound token
 11  Access the resource with the narrowed token (RS verifies aud server-side)
 12  (optional) refresh + re-exchange per resource

The token requested in steps 9-10 is bound to the *service-level* resource id
that matched in gate (b), not to the dynamic deep URL the client started from.
(So a DataLink deep link like .../download/obs123/file456 yields a token scoped
to the whole service, e.g. https://src.example.org, which is what the resource
server checks its own `aud` against.)

RELEVANT STANDARDS
------------------
  RFC 6750  Bearer Token usage + the WWW-Authenticate challenge
  RFC 8414  Authorization Server Metadata (the /.well-known document)
  RFC 9728  Protected Resource Metadata (the "sidecar")
  RFC 7591  Dynamic Client Registration
  RFC 8628  Device Authorization Grant
  RFC 8707  Resource Indicators (the `resource` parameter)
  RFC 8693  OAuth 2.0 Token Exchange (narrowing the audience)
  RFC 9207  Authorization Server Issuer Identification (the `iss` check)

Dependency:  requests   ->   pip install requests
Usage:       python authvo_client.py https://src.example.org/datalink/download/obs123/file456
"""

# `from __future__ import annotations` lets us write modern type hints (e.g.
# `list[str]`) on older Python versions by treating annotations as strings.
from __future__ import annotations

import logging
import os
import re
import sys
import time
import json
import base64
import webbrowser
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests

# A single module-level logger. main() configures it to print plain messages so
# the step-by-step trace reads like a narrative of the flow.
log = logging.getLogger("authvo")

# The two well-known paths we try when discovering Authorization Server metadata.
# RFC 8414 defines the first; the OpenID Connect discovery document is the second
# and many issuers (including INDIGO IAM) serve it.
WELL_KNOWN_AS = "/.well-known/oauth-authorization-server"
WELL_KNOWN_OIDC = "/.well-known/openid-configuration"

# OAuth grant-type / token-type URNs used in the form posts below. Spelled out as
# constants so the wire values are unmistakable and typo-proof.
GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"


class SecurityError(Exception):
    """Raised when a mandatory security check fails -> the flow MUST abort.

    This is deliberately its own exception type so callers can distinguish a
    *security* stop (we refuse to continue) from an ordinary network/HTTP error.
    The whole client is "fail closed": if anything about the discovery or the
    issuer looks wrong, we raise this and never send a token anywhere.
    """


# --------------------------------------------------------------------------- #
#  URL / origin helpers                                                       #
#                                                                             #
#  The domain-proxy check is entirely about comparing ORIGINS and PATHS, so   #
#  these small, well-defined helpers are the security-critical core. Keep     #
#  them simple and obviously correct.                                         #
# --------------------------------------------------------------------------- #

def normalize_origin(url: str) -> str:
    """Return scheme://host[:port] with default ports dropped, lower-cased.

    "Origin" = scheme + host + port. We normalise so that cosmetic differences
    (upper/lower case, an explicit :443 on https) do not cause a false mismatch
    in same_origin(). Anything else about the URL (path, query) is ignored here.
    """
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    # Drop the port if it is the scheme's default (443 for https, 80 for http),
    # so "https://h" and "https://h:443" compare equal.
    default = {"https": 443, "http": 80}.get(scheme)
    port = p.port
    netloc = host if (port is None or port == default) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def same_origin(a: str, b: str) -> bool:
    """True iff two URLs share scheme+host+port. The heart of gate (a)."""
    return normalize_origin(a) == normalize_origin(b)


def is_under(resource_url: str, listed_id: str) -> bool:
    """Path-prefix membership at a path-segment boundary, same origin required.

    This implements gate (b): is the resource we called covered by an id the
    sidecar declares it is authoritative for? Matching is done on whole path
    SEGMENTS so a listed `/datalink` covers `/datalink/...` but never the
    unrelated `/datalinkX`.

    `https://src.example.org`            covers any path on that origin.
    `https://src.example.org/datalink`   covers `/datalink` and `/datalink/...`
                                          but NOT `/datalinkX`.
    """
    # Origin must match first — a path prefix on a different host means nothing.
    if not same_origin(resource_url, listed_id):
        return False
    rp = urlsplit(resource_url).path or "/"
    lp = urlsplit(listed_id).path or "/"
    # A listed id with an empty / root path covers the whole origin.
    if lp in ("", "/"):
        return True
    lp = lp.rstrip("/")
    # Exact match, or a match at a segment boundary (note the trailing "/").
    return rp == lp or rp.startswith(lp + "/")


def require_https(url: str, what: str) -> None:
    """Refuse to talk to a non-HTTPS endpoint for any security-relevant URL.

    Bearer tokens and the discovery they depend on must travel over TLS; plain
    http anywhere in the chain is an immediate abort.
    """
    if urlsplit(url).scheme.lower() != "https":
        raise SecurityError(f"{what} must be served over HTTPS: {url!r}")


def jwt_payload(token: str) -> Optional[dict]:
    """Best-effort decode of a JWT payload (NO signature verification).

    IMPORTANT: this does NOT verify the signature and must never be used to make
    a trust decision. It exists only so the client can log/sanity-check claims
    like `aud` and `iss`. The authoritative verification of the token is done by
    the RESOURCE SERVER, server-side. Returns None for opaque (non-JWT) tokens.
    """
    parts = token.split(".")
    if len(parts) != 3:  # a JWT is header.payload.signature
        return None
    try:
        # base64url-decode the middle segment, re-padding to a multiple of 4.
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Discovery results                                                          #
#                                                                             #
#  Tiny typed value objects for the two documents we discover, so the rest of #
#  the code reads `sidecar.issuer` / `meta.token_endpoint` instead of poking  #
#  at raw dicts.                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class Sidecar:
    """The parsed RFC 9728 Protected-Resource-Metadata document."""
    url: str                                    # where we fetched it (for gate a)
    issuer: str                                 # the AS it names
    protected_resources: list[str] = field(default_factory=list)  # gate (b) list


@dataclass
class ASMetadata:
    """The bits of the Authorization Server metadata we actually use."""
    issuer: str
    token_endpoint: str
    device_authorization_endpoint: str
    registration_endpoint: Optional[str] = None
    scopes_supported: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  The client                                                                 #
# --------------------------------------------------------------------------- #

class AuthVoClient:
    """Drives the whole flow. Construct it, then call .access(resource_url).

    Each numbered _stepN_* method below is one step of the flow and is meant to
    be read in order; access() simply calls them in sequence.
    """

    def __init__(self, scope: str = "openid vo.read",
                 client_id: Optional[str] = None,
                 exchange_scope: str = "vo.read",
                 timeout: int = 30,
                 open_browser: bool = False) -> None:
        # `scope`          : requested at the device grant (step 7).
        # `client_id`      : if given, we skip dynamic registration (step 6).
        # `exchange_scope` : scope asked for on the narrowed token (step 10).
        # `open_browser`   : auto-open the verification URL for the user (step 8).
        self.scope = scope
        self.client_id = client_id
        self.exchange_scope = exchange_scope
        self.timeout = timeout
        self.open_browser = open_browser
        # One requests.Session reused for connection pooling and a stable UA.
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "authvo-reference-client/1.0"

    # -- public entry point ------------------------------------------------- #

    def access(self, resource_url: str) -> requests.Response:
        """Run the full flow for one resource URL and return the final response.

        Reads top-to-bottom as the 11 steps of the flow. Any security stop along
        the way raises SecurityError and nothing further happens.
        """
        # The resource itself must be HTTPS before we even knock on its door.
        require_https(resource_url, "Protected resource")

        challenge = self._step1_probe(resource_url)                       # 1 + 2
        sidecar_url = self._step2_pointer(challenge)                      # 2
        sidecar = self._step3_fetch_sidecar(sidecar_url)                  # 3
        # Step 4 returns the *service-level* resource id our URL matched; that id
        # (not the deep URL) is what the token will be bound to.
        resource_id = self._step4_domain_proxy_check(resource_url, sidecar_url, sidecar)
        meta = self._step5_as_metadata(sidecar.issuer)                   # 5
        client_id = self._step6_register(meta)                           # 6
        device = self._step7_device_authorization(meta, client_id)       # 7
        self._step8_prompt_user(device, resource_url, sidecar.issuer)    # 8
        token = self._step9_poll_token(meta, client_id, device, resource_id)      # 9
        narrowed = self._step10_token_exchange(meta, client_id, token, resource_id)  # 10
        return self._step11_access(resource_url, narrowed, resource_id)  # 11

    # -- step 1 ------------------------------------------------------------- #

    def _step1_probe(self, resource_url: str) -> str:
        """Knock on the resource with no credentials and expect a 401 challenge.

        A real client starts knowing only the resource URL. We send no token and
        REFUSE to follow redirects (a redirect could itself be a spoofing trick);
        the only thing we accept here is a 401 that carries a discovery pointer.
        """
        log.info("STEP 1  GET %s  (anonymous)", resource_url)
        r = self.http.get(resource_url, timeout=self.timeout, allow_redirects=False)
        if r.status_code != 401:
            # Already accessible, or some other status — nothing to discover.
            raise SecurityError(
                f"Expected 401 with a discovery pointer, got {r.status_code}")
        www = r.headers.get("WWW-Authenticate", "")
        log.info("STEP 2  401  WWW-Authenticate: %s", www or "(missing)")
        return www

    # -- step 2 ------------------------------------------------------------- #

    @staticmethod
    def _step2_pointer(www_authenticate: str) -> str:
        """Extract the sidecar location. It is an UNTRUSTED pointer at this stage.

        The 401's WWW-Authenticate looks like:
            Bearer resource_metadata="https://iam.example/.well-known/..."
        We pull out that URL. We do NOT trust it yet — it is just where to look;
        step 4 decides whether to believe what we find there. We accept both the
        quoted and bare forms of the parameter for robustness.
        """
        m = re.search(r'resource_metadata\s*=\s*"([^"]+)"', www_authenticate)
        if not m:
            m = re.search(r'resource_metadata\s*=\s*([^,\s]+)', www_authenticate)
        if not m:
            raise SecurityError("401 did not carry a resource_metadata pointer")
        url = m.group(1)
        log.info("        -> sidecar pointer (untrusted): %s", url)
        return url

    # -- step 3 ------------------------------------------------------------- #

    def _step3_fetch_sidecar(self, sidecar_url: str) -> Sidecar:
        """Fetch and parse the RFC 9728 descriptor the pointer led us to.

        It tells us which Authorization Server (issuer) governs this resource and
        which resource ids that descriptor is authoritative for. Still untrusted
        until step 4 — here we only parse it.
        """
        require_https(sidecar_url, "Sidecar (protected-resource metadata)")
        log.info("STEP 3  GET sidecar %s", sidecar_url)
        doc = self._get_json(sidecar_url)

        # `authorization_servers` is required; we use the first issuer it names.
        issuers = doc.get("authorization_servers") or []
        if not issuers:
            raise SecurityError("sidecar did not list any authorization_servers")
        issuer = issuers[0]

        # `protected_resources` is the authoritative allow-list (IVOA extension);
        # fall back to the standard single `resource` value if absent.
        listed = doc.get("protected_resources")
        if not listed:
            single = doc.get("resource")
            listed = [single] if single else []
        log.info("        issuer=%s  protected_resources=%s", issuer, listed)
        return Sidecar(url=sidecar_url, issuer=issuer, protected_resources=listed)

    # -- step 4: the two gates --------------------------------------------- #

    def _step4_domain_proxy_check(self, resource_url: str, sidecar_url: str,
                                  sidecar: Sidecar) -> str:
        """THE security crux. Two gates; either failing aborts the whole flow.

        Returns the resource id (from the sidecar's list) that our URL matched —
        this is what the token will be requested and bound for.
        """
        log.info("STEP 4  DOMAIN PROXY CHECK")

        # Gate (a): the sidecar and the issuer it names must share the origin.
        # This is what a forged descriptor on evil.com cannot satisfy: it would
        # have to be served from the real issuer's origin to pass.
        if not same_origin(sidecar_url, sidecar.issuer):
            raise SecurityError(
                "GATE (a) FAILED: sidecar origin %s != issuer origin %s"
                % (normalize_origin(sidecar_url), normalize_origin(sidecar.issuer)))
        log.info("        gate (a) OK: sidecar & issuer share origin %s",
                 normalize_origin(sidecar.issuer))

        # Gate (b): the redirecting service must itself be in the sidecar's list.
        # i.e. the descriptor must actually claim authority over the resource we
        # called — not merely be a valid descriptor for some other resource.
        matched = next((rid for rid in sidecar.protected_resources
                        if is_under(resource_url, rid)), None)
        if matched is None:
            raise SecurityError(
                "GATE (b) FAILED: %s is not covered by any listed resource %s"
                % (resource_url, sidecar.protected_resources))
        log.info("        gate (b) OK: %s is under listed resource %s",
                 resource_url, matched)
        log.info("        -> token will be requested for resource id: %s", matched)
        return matched

    # -- step 5 ------------------------------------------------------------- #

    def _step5_as_metadata(self, issuer: str) -> ASMetadata:
        """Now that the issuer is trusted, discover its endpoints (RFC 8414/OIDC).

        We try the RFC 8414 URL first, then the OIDC discovery URL. Crucially we
        verify that the document's own `issuer` value equals the issuer we asked
        for — a mismatch means the metadata is not really this issuer's, abort.
        """
        require_https(issuer, "Issuer")
        for url in self._as_metadata_urls(issuer):
            try:
                log.info("STEP 5  GET AS metadata %s", url)
                doc = self._get_json(url)
            except requests.HTTPError:
                # This well-known variant 404'd; try the next candidate URL.
                continue
            if doc.get("issuer") != issuer:
                raise SecurityError(
                    "AS metadata issuer %r does not match expected %r"
                    % (doc.get("issuer"), issuer))
            return ASMetadata(
                issuer=issuer,
                token_endpoint=doc["token_endpoint"],
                device_authorization_endpoint=doc["device_authorization_endpoint"],
                registration_endpoint=doc.get("registration_endpoint"),
                scopes_supported=doc.get("scopes_supported", []),
            )
        raise SecurityError("could not retrieve AS metadata for %s" % issuer)

    @staticmethod
    def _as_metadata_urls(issuer: str) -> list[str]:
        """Build the two candidate metadata URLs for an issuer.

        The subtlety is WHERE the well-known suffix goes when the issuer has a
        path component (e.g. https://host/iam):
          * RFC 8414 inserts it between host and path  -> https://host/.well-known/oauth-authorization-server/iam
          * OIDC appends it after the issuer path       -> https://host/iam/.well-known/openid-configuration
        """
        p = urlsplit(issuer)
        base = p.path.rstrip("/")
        # RFC 8414: insert the well-known suffix between host and path.
        rfc8414 = urlunsplit((p.scheme, p.netloc, WELL_KNOWN_AS + base, "", ""))
        # OIDC style: append discovery doc after the issuer path.
        oidc = urlunsplit((p.scheme, p.netloc, base + WELL_KNOWN_OIDC, "", ""))
        return [rfc8414, oidc]

    # -- step 6 ------------------------------------------------------------- #

    def _step6_register(self, meta: ASMetadata) -> str:
        """Obtain a client_id: reuse a preconfigured one, else self-register.

        Dynamic Client Registration (RFC 7591) lets a brand-new client mint its
        own id with no prior setup. We register as a PUBLIC client (no secret —
        appropriate for the device flow on a native app) declaring the two grants
        we need: device_code and token-exchange.

        NB: some IAMs (e.g. INDIGO) forbid self-registered clients from requesting
        token-exchange. Against those, pass a preconfigured client_id instead, or
        use the `aud` request parameter on the device grant (see human_demo.py).
        """
        if self.client_id:
            log.info("STEP 6  using preconfigured client_id=%s", self.client_id)
            return self.client_id
        if not meta.registration_endpoint:
            raise SecurityError("no client_id and the IAM offers no registration endpoint")
        log.info("STEP 6  POST register (RFC 7591) %s", meta.registration_endpoint)
        body = {
            "client_name": "authvo-reference-client",
            "grant_types": [GRANT_DEVICE_CODE, GRANT_TOKEN_EXCHANGE],
            "token_endpoint_auth_method": "none",   # public client
            "application_type": "native",
        }
        doc = self._post_json(meta.registration_endpoint, body)
        self.client_id = doc["client_id"]
        log.info("        -> client_id=%s", self.client_id)
        return self.client_id

    # -- step 7 ------------------------------------------------------------- #

    def _step7_device_authorization(self, meta: ASMetadata, client_id: str) -> dict:
        """Start the Device Authorization Grant (RFC 8628).

        We send our client_id and the scopes we want; the IAM returns a
        device_code (which we poll with) plus a user_code and verification URL
        (which the human uses). This grant suits CLIs/headless clients because
        the user authenticates in a normal browser, not in our process.
        """
        log.info("STEP 7  POST device_authorization (RFC 8628)")
        doc = self._post_form(meta.device_authorization_endpoint, {
            "client_id": client_id,
            "scope": self.scope,
        })
        if "device_code" not in doc:
            raise SecurityError("device authorization response missing device_code")
        return doc

    # -- step 8 ------------------------------------------------------------- #

    def _step8_prompt_user(self, device: dict, resource_url: str, issuer: str) -> None:
        """Tell the human where to go and what they are authorizing.

        We show BOTH the resource and the identity provider so the user can
        sanity-check that they are logging in to the expected IAM for the
        expected service. The client never sees the user's credentials — they are
        typed into the IAM's own page.
        """
        # verification_uri_complete embeds the user_code; prefer it when present.
        uri = device.get("verification_uri_complete") or device["verification_uri"]
        log.info("STEP 8  user action required")
        print("\n" + "=" * 64)
        print("  Authorize access to : %s" % resource_url)
        print("  Identity provider   : %s" % issuer)
        print("  Open                : %s" % uri)
        # Only print the code separately if it is not already baked into the URL.
        if "user_code" not in (device.get("verification_uri_complete") or ""):
            print("  Enter code          : %s" % device.get("user_code", ""))
        print("=" * 64 + "\n")
        if self.open_browser:
            try:
                webbrowser.open(uri)
            except Exception:
                pass  # headless box / no browser — the printed URL still works

    # -- step 9 ------------------------------------------------------------- #

    def _step9_poll_token(self, meta: ASMetadata, client_id: str,
                          device: dict, resource_id: str) -> dict:
        """Poll the token endpoint until the user approves (or we time out).

        Per RFC 8628 we poll at `interval` seconds and handle two non-error
        signals: `authorization_pending` (keep waiting) and `slow_down` (back off
        by 5s). We also pass the RFC 8707 `resource` indicator so a cooperating
        IAM can already scope the broad token toward the target.
        """
        interval = int(device.get("interval", 5))
        deadline = time.time() + int(device.get("expires_in", 300))
        log.info("STEP 9  polling token endpoint (resource=%s)", resource_id)
        while time.time() < deadline:
            time.sleep(interval)  # RFC 8628: wait BEFORE each poll
            resp = self.http.post(meta.token_endpoint, data={
                "grant_type": GRANT_DEVICE_CODE,
                "device_code": device["device_code"],
                "client_id": client_id,
                "resource": resource_id,          # RFC 8707 resource indicator
            }, timeout=self.timeout)
            doc = resp.json()
            if resp.status_code == 200:
                # Got a token. Sanity-check the issuer before using it (step 11).
                self._validate_issuer(doc, meta.issuer, "access token")
                log.info("        -> access token acquired")
                return doc
            err = doc.get("error")
            if err == "authorization_pending":
                continue                          # user hasn't approved yet
            if err == "slow_down":
                interval += 5                     # IAM asks us to poll less often
                continue
            # Any other error is terminal (expired_token, access_denied, ...).
            raise SecurityError("token endpoint error: %s (%s)"
                                % (err, doc.get("error_description", "")))
        raise SecurityError("device authorization timed out")

    # -- step 10 ------------------------------------------------------------ #

    def _step10_token_exchange(self, meta: ASMetadata, client_id: str,
                               token: dict, resource_id: str) -> dict:
        """Exchange the broad token for one narrowed to exactly this resource.

        RFC 8693 token exchange: we hand in the access token from step 9 and ask
        for a new token whose `audience` is the target resource id. The result is
        an `aud`-bound token — if it leaked, it could not be replayed against any
        other service, because that other service's `aud` check would reject it.
        We send both `audience` (RFC 8693) and `resource` (RFC 8707) for breadth.
        """
        log.info("STEP 10  token exchange (RFC 8693)  audience=%s", resource_id)
        doc = self._post_form(meta.token_endpoint, {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "client_id": client_id,
            "subject_token": token["access_token"],
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "audience": resource_id,             # narrow to the target service
            "resource": resource_id,             # RFC 8707, belt-and-braces
            "scope": self.exchange_scope,
        })
        self._validate_issuer(doc, meta.issuer, "narrowed token")
        # Decode (without verifying) just to log the resulting aud for the trace.
        payload = jwt_payload(doc["access_token"])
        if payload and "aud" in payload:
            log.info("        -> narrowed token aud=%s", payload["aud"])
        return doc

    # -- step 11 ------------------------------------------------------------ #

    def _step11_access(self, resource_url: str, narrowed: dict,
                       resource_id: str) -> requests.Response:
        """Retry the original request, now presenting the narrowed bearer token.

        This is where it pays off: the resource server independently verifies the
        token's signature against the IAM's JWKS and checks iss / aud (== itself)
        / scope / expiry. We just present the token and report the outcome.
        """
        log.info("STEP 11  GET %s  with narrowed bearer token", resource_url)
        r = self.http.get(resource_url, timeout=self.timeout, headers={
            "Authorization": "Bearer " + narrowed["access_token"],
        })
        if r.status_code == 200:
            log.info("        -> SUCCESS (%d bytes)", len(r.content))
        else:
            log.warning("        -> resource returned %d", r.status_code)
        return r

    # -- shared HTTP / validation helpers ----------------------------------- #

    def _validate_issuer(self, token_doc: dict, issuer: str, what: str) -> None:
        """Client-side `iss` cross-check (RFC 9207 spirit).

        If either the token RESPONSE or the JWT itself names an issuer, it MUST
        equal the issuer we discovered and trusted. This catches a token that was
        somehow minted by the wrong party. (The resource server does the binding
        verification; this is a cheap early sanity check on our side.)
        """
        if token_doc.get("iss") and token_doc["iss"] != issuer:
            raise SecurityError("%s iss %r != expected %r"
                                % (what, token_doc["iss"], issuer))
        payload = jwt_payload(token_doc.get("access_token", ""))
        if payload and payload.get("iss") and payload["iss"] != issuer:
            raise SecurityError("%s JWT iss %r != expected %r"
                                % (what, payload["iss"], issuer))

    # --- thin wrappers around requests, with consistent error handling ----- #

    def _get_json(self, url: str) -> dict:
        """GET a URL and parse JSON, raising on any HTTP error status."""
        r = self.http.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post_json(self, url: str, body: dict) -> dict:
        """POST a JSON body (used for dynamic client registration)."""
        r = self.http.post(url, json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post_form(self, url: str, form: dict) -> dict:
        """POST a form-encoded body (used for the OAuth token/device endpoints).

        OAuth endpoints expect application/x-www-form-urlencoded. We surface a
        400+ as a SecurityError with a trimmed body so failures are legible.
        """
        r = self.http.post(url, data=form, timeout=self.timeout)
        if r.status_code >= 400:
            raise SecurityError("POST %s -> %d: %s" % (url, r.status_code, r.text[:300]))
        return r.json()


def main(argv: list[str]) -> int:
    """CLI entry point: take a resource URL (arg or AUTHVO_RESOURCE) and run it.

    Environment variables:
      AUTHVO_RESOURCE      the protected-resource URL (if not passed as argv[1])
      AUTHVO_CLIENT_ID     a preconfigured client_id (skips dynamic registration)
      AUTHVO_OPEN_BROWSER  "1" to auto-open the device verification URL
    """
    # Log as plain lines so the STEP trace reads as a clean narrative.
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    resource = (argv[1] if len(argv) > 1 else os.environ.get("AUTHVO_RESOURCE"))
    if not resource:
        print(__doc__)
        print("error: pass the protected-resource URL as the first argument",
              file=sys.stderr)
        return 2
    client = AuthVoClient(
        client_id=os.environ.get("AUTHVO_CLIENT_ID"),
        open_browser=os.environ.get("AUTHVO_OPEN_BROWSER") == "1",
    )
    try:
        resp = client.access(resource)
    except SecurityError as e:
        # Any failed gate / check lands here: print why and exit non-zero.
        log.error("ABORT: %s", e)
        return 1
    print("\n--- resource response ---")
    print(resp.text[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
