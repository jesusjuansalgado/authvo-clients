#!/usr/bin/env python3
"""
Reference VO client for the AuthVO bearer-token flow (RFC 9728-conformant).
===========================================================================

This is a *reference implementation*, written to be read. It walks the complete
AuthVO bearer-token flow end to end, with copious logging so you can watch each
step happen. (Java twin: AuthVoClient.java -- the two behave identically.)

WHY THIS EXISTS (the threat it defends against)
-----------------------------------------------
In plain OAuth2 a client that hits a protected service is told "go get a token
from issuer X". But nothing ties issuer X to the service that named it. A
*malicious* service (the "evil service") can therefore name a REAL issuer and
harvest a real token that the user was tricked into obtaining for it.

AuthVO closes that hole with two independent checks, both implemented below:

  1. The resource server publishes Protected Resource Metadata (PRM, RFC 9728)
     at ITS OWN well-known URL, and the 401 challenge only POINTS at it. The
     pointer is UNTRUSTED. The PRM must describe the resource we actually asked
     for: its `resource` identifier must COVER the requested URL (step 2).

  2. But a resource server can say anything about itself, including "my issuer
     is the real IAM". So the binding is checked from the OTHER side (step 3):
     the AUTHORIZATION SERVER's own RFC 8414 metadata must (a) carry the very
     issuer the PRM named, and (b) list the requested resource in its
     `protected_resources` member (RFC 9728 section 4). Only the issuer can vouch
     for which resources it serves; a resource claiming an issuer that does not
     list it is refused BEFORE the user is asked to log in. An issuer that
     publishes no such list is refused too: absence is a failure, not a pass.

Once both hold, the user logs in (device grant) and the token request carries the
matched resource as an RFC 8707 `resource` indicator, so a cooperating issuer
can bind the token's audience to it. (Optionally the token can be narrowed
further by RFC 8693 token exchange -- OFF by default, enable it with
AuthVoClient(token_exchange=True) or AUTHVO_TOKEN_EXCHANGE=1.)

THE FLOW, STEP BY STEP (numbers match the methods below)
--------------------------------------------------------
  1  GET the protected resource anonymously (NO redirects). Expect
     401 + WWW-Authenticate: Bearer resource_metadata="<url>"   (UNTRUSTED pointer)
  2  GET the PRM at that pointer over HTTPS (NO redirects). ABORT unless the
     PRM `resource` covers the URL we asked for.                 (RFC 9728 3, 3.3)
  3  RESOURCE CHECK (ABORT before any login on failure). For an issuer named in
     the PRM, GET its RFC 8414 metadata (NO redirects) and require
        (a) metadata `issuer` == the issuer the PRM named        (RFC 8414 3.3)
        (b) `protected_resources` present AND covering our URL   (RFC 9728 4)
     The first listed issuer that passes both is the one we use.
  4  Client registration: preconfigured client_id, else RFC 7591 DCR.
  5  Token: device authorization (RFC 8628) -> the user logs in and approves
     (we show the resource AND the issuer) -> poll the token endpoint, sending
     resource=<matched resource id> (RFC 8707). Optional RFC 8693 exchange
     (off by default).
  6  Present the token to the resource; the RS validates signature, iss, scope,
     expiry, and aud when present.
  7  (refresh would re-send the same `resource`; not implemented here)

"Covered" (steps 2 and 3b) means: equal to the identifier, or the same scheme,
host and port with a path that extends it at a path-SEGMENT boundary. So
https://src.example.org/vo covers https://src.example.org/vo/tap/async/1 but NOT
https://src.example.org/vocab; a root identifier covers its whole origin.

The token is requested for the resource id that matched in step 3(b), not for
the dynamic deep URL the client started from. (So a DataLink deep link like
.../download/obs123/file456 yields a token for the whole service, e.g.
https://src.example.org, which is what the resource server expects.)

RELEVANT STANDARDS
------------------
  RFC 6750  Bearer Token usage + the WWW-Authenticate challenge
  RFC 8414  Authorization Server Metadata (the /.well-known document)
  RFC 9728  Protected Resource Metadata (sections 3, 3.3, 4, 5)
  RFC 7591  Dynamic Client Registration
  RFC 8628  Device Authorization Grant
  RFC 8707  Resource Indicators (the `resource` parameter)
  RFC 8693  OAuth 2.0 Token Exchange (optional narrowing of the audience)
  RFC 9207  Authorization Server Issuer Identification (the `iss` check)

Dependency:  requests   ->   pip install requests
Usage:       python authvo_client.py https://src.example.org/datalink/download/obs123/file456
TLS:         requests honours REQUESTS_CA_BUNDLE (handy for a local test CA).
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

# The two well-known paths we use when discovering Authorization Server metadata.
# RFC 8414 defines the first; the OpenID Connect discovery document is the second
# and many issuers (including INDIGO IAM) serve it. The RFC 8414 document is the
# one the resource check (step 3) is performed on; OIDC discovery is only ever a
# fallback for READING ENDPOINTS, never a way around check (b).
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
#  Steps 2 and 3 are entirely about comparing ORIGINS and PATHS, so these     #
#  small, well-defined helpers are the security-critical core. Keep them      #
#  simple and obviously correct. (AuthVoClient.java has the same helpers and  #
#  both are tested against tests/coverage_vectors.json.)                      #
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
    """True iff two URLs share scheme+host+port."""
    return normalize_origin(a) == normalize_origin(b)


def _normalized_path(url: str) -> str:
    """The URL's path with dot-segments resolved (RFC 3986 5.2.4), no trailing '/'.

    Resolving "." and ".." (also when percent-encoded) matters for security:
    without it https://h/vo/../other would look as if it were "under" /vo while
    the server would actually serve /other. The root path comes back as "".
    """
    out: list[str] = []
    for seg in (urlsplit(url).path or "/").split("/"):
        s = seg.lower()
        if s in (".", "%2e"):
            continue
        if s in ("..", ".%2e", "%2e.", "%2e%2e"):
            if len(out) > 1:          # never pop the leading empty segment
                out.pop()
            continue
        out.append(seg)
    return "/".join(out).rstrip("/")


def is_covered(url: str, resource_id: str) -> bool:
    """Is `url` covered by the resource identifier `resource_id`?

    Covered means: the same origin (scheme, host, port), and a path that is equal
    to the identifier's or extends it AT A PATH-SEGMENT BOUNDARY (RFC 9728 3.3
    compares a resource with the URL it was found for; AuthVO extends that to
    deep URLs under one service-level identifier).

        https://src.example.org            covers every path on that origin
        https://src.example.org/vo         covers /vo and /vo/tap/async/1,
                                           but NOT /vocab and NOT /vo/../other
    """
    # Origin must match first -- a path prefix on a different host means nothing.
    if not same_origin(url, resource_id):
        return False
    up, rp = _normalized_path(url), _normalized_path(resource_id)
    if rp == "":                       # a root identifier covers the whole origin
        return True
    return up == rp or up.startswith(rp + "/")


def most_specific_cover(url: str, resource_ids: list[str]) -> Optional[str]:
    """Of the identifiers that cover `url`, the most specific (longest path).

    If an issuer lists both https://h and https://h/vo, a request under /vo
    should get a token for the narrower one. Ties keep list order. None if no
    identifier covers the URL.
    """
    covering = [r for r in resource_ids if is_covered(url, r)]
    return max(covering, key=lambda r: len(_normalized_path(r)), default=None)


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
#  Tiny typed value objects for the documents we discover, so the rest of the #
#  code reads `prm.resource` / `meta.token_endpoint` instead of poking at raw #
#  dicts.                                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class ProtectedResourceMetadata:
    """The parsed RFC 9728 Protected Resource Metadata (PRM) document."""
    url: str                                    # where we fetched it
    resource: str                               # what the RS says it is
    authorization_servers: list[str] = field(default_factory=list)


@dataclass
class ASMetadata:
    """The bits of the Authorization Server metadata we actually use."""
    issuer: str
    token_endpoint: str
    device_authorization_endpoint: str
    registration_endpoint: Optional[str] = None
    scopes_supported: list[str] = field(default_factory=list)


@dataclass
class ResourceCheck:
    """What a passed resource check (step 3) hands to the rest of the flow."""
    meta: ASMetadata       # the trusted issuer's endpoints
    resource_id: str       # the protected_resources entry that covered our URL


# --------------------------------------------------------------------------- #
#  The client                                                                 #
# --------------------------------------------------------------------------- #

class AuthVoClient:
    """Drives the whole flow. Construct it, then call .access(resource_url).

    Each _stepN_* method below is one step of the flow and is meant to be read
    in order; access() simply calls them in sequence.
    """

    def __init__(self, scope: str = "openid vo.read",
                 client_id: Optional[str] = None,
                 exchange_scope: str = "vo.read",
                 timeout: int = 30,
                 open_browser: bool = False,
                 token_exchange: bool = False) -> None:
        # `scope`          : requested at the device grant (step 5).
        # `client_id`      : if given, we skip dynamic registration (step 4).
        # `exchange_scope` : scope asked for on an exchanged token (step 5d).
        # `open_browser`   : auto-open the verification URL for the user (step 5b).
        # `token_exchange` : also run the RFC 8693 narrowing exchange (step 5d).
        #                    OFF by default: the `resource` indicator on the token
        #                    request (RFC 8707) is the primary audience mechanism.
        self.scope = scope
        self.client_id = client_id
        self.exchange_scope = exchange_scope
        self.timeout = timeout
        self.open_browser = open_browser
        self.token_exchange = token_exchange
        # One requests.Session reused for connection pooling and a stable UA.
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "authvo-reference-client/2.0"

    # -- public entry point ------------------------------------------------- #

    def access(self, resource_url: str) -> requests.Response:
        """Run the full flow for one resource URL and return the final response.

        Reads top-to-bottom as the steps of the flow. Any security stop along the
        way raises SecurityError and nothing further happens -- in particular,
        steps 1-3 involve no user interaction and no credentials, so a failed
        check costs the user nothing.
        """
        # The resource itself must be HTTPS before we even knock on its door.
        require_https(resource_url, "Protected resource")

        pointer = self._step1_probe(resource_url)                         # 1
        prm = self._step2_prm(resource_url, pointer)                      # 2
        # Step 3 returns the trusted issuer's metadata plus the resource id our
        # URL matched; that id (not the deep URL) is what the token is for.
        check = self._step3_resource_check(resource_url, prm)             # 3
        meta, resource_id = check.meta, check.resource_id
        client_id = self._step4_register(meta)                            # 4
        device = self._step5a_device_authorization(meta, client_id)       # 5
        self._step5b_prompt_user(device, resource_url, meta.issuer, resource_id)
        token = self._step5c_poll_token(meta, client_id, device, resource_id)
        if self.token_exchange:
            token = self._step5d_token_exchange(meta, client_id, token, resource_id)
        return self._step6_access(resource_url, token)                    # 6

    # -- step 1 ------------------------------------------------------------- #

    def _step1_probe(self, resource_url: str) -> str:
        """Knock on the resource with no credentials; return the PRM pointer.

        A real client starts knowing only the resource URL. We send no token and
        REFUSE to follow redirects (a redirect could itself be a spoofing trick);
        the only thing we accept here is a 401 whose WWW-Authenticate carries a
        `resource_metadata` pointer (RFC 9728 section 5). The pointer is UNTRUSTED:
        it is just where to look, and step 2 decides whether to believe it.
        """
        log.info("STEP 1  GET %s  (anonymous, no redirects)", resource_url)
        r = self.http.get(resource_url, timeout=self.timeout, allow_redirects=False)
        if r.status_code != 401:
            # Already accessible, redirected, or some other status: nothing to
            # discover (and a redirect is never followed).
            raise SecurityError(
                f"Expected 401 with a discovery pointer, got {r.status_code}")
        www = r.headers.get("WWW-Authenticate", "")
        log.info("        401  WWW-Authenticate: %s", www or "(missing)")
        pointer = self._parse_resource_metadata(www)
        log.info("        -> PRM pointer (untrusted): %s", pointer)
        return pointer

    @staticmethod
    def _parse_resource_metadata(www_authenticate: str) -> str:
        """Extract the `resource_metadata` URL from a Bearer challenge.

        The header looks like:
            Bearer resource_metadata="https://src.example/.well-known/..."
        We accept both the quoted and bare forms of the parameter for robustness.
        """
        m = re.search(r'resource_metadata\s*=\s*"([^"]+)"', www_authenticate)
        if not m:
            m = re.search(r'resource_metadata\s*=\s*([^,\s]+)', www_authenticate)
        if not m:
            raise SecurityError("401 did not carry a resource_metadata pointer")
        return m.group(1)

    # -- step 2 ------------------------------------------------------------- #

    def _step2_prm(self, resource_url: str, pointer: str) -> ProtectedResourceMetadata:
        """Fetch the PRM and require that it describes the resource we asked for.

        RFC 9728 section 3: the PRM is a JSON document published BY THE RESOURCE
        SERVER. We fetch it over HTTPS and refuse redirects. Then, per section 3.3,
        the `resource` it declares must be consistent with the resource we are
        accessing -- here, it must COVER the URL we asked for (see is_covered). A
        PRM about some other resource is useless to us and is a sign of spoofing,
        so we abort.
        """
        require_https(pointer, "PRM pointer")
        log.info("STEP 2  GET PRM %s  (no redirects)", pointer)
        doc = self._get_json(pointer, "Protected Resource Metadata")

        resource = doc.get("resource")
        if not isinstance(resource, str) or not resource:
            raise SecurityError("PRM has no `resource` member")
        require_https(resource, "PRM resource identifier")
        servers = doc.get("authorization_servers")
        if (not isinstance(servers, list) or not servers
                or not all(isinstance(s, str) for s in servers)):
            raise SecurityError("PRM did not list any authorization_servers")
        log.info("        resource=%s  authorization_servers=%s", resource, servers)

        if not is_covered(resource_url, resource):
            raise SecurityError(
                "STEP 2 FAILED: the PRM's resource %s does not cover the requested URL %s"
                % (resource, resource_url))
        log.info("        OK: PRM resource covers the requested URL")
        return ProtectedResourceMetadata(url=pointer, resource=resource,
                                         authorization_servers=servers)

    # -- step 3: the resource check ---------------------------------------- #

    def _step3_resource_check(self, resource_url: str,
                              prm: ProtectedResourceMetadata) -> ResourceCheck:
        """THE security crux. Ask the ISSUER whether it really serves this resource.

        The PRM came from the resource server, which can claim any issuer it
        likes. So for each issuer the PRM names we fetch ITS OWN RFC 8414 metadata
        and require, before any user login:
          (a) metadata `issuer` == the issuer the PRM named (RFC 8414 3.3), and
          (b) `protected_resources` is present and one entry covers our URL
              (RFC 9728 4).
        The first issuer that passes both is used; if none does we abort with
        every reason. An ABSENT `protected_resources` is a failure, never a pass.
        """
        log.info("STEP 3  RESOURCE CHECK")
        failures = []
        for issuer in prm.authorization_servers:
            try:
                check = self._check_issuer(resource_url, issuer)
            except SecurityError as e:
                log.info("        issuer %s REJECTED: %s", issuer, e)
                failures.append(f"{issuer}: {e}")
                continue
            log.info("        issuer %s ACCEPTED", issuer)
            log.info("        -> token will be requested for resource id: %s",
                     check.resource_id)
            return check
        raise SecurityError("STEP 3 FAILED: no authorization server vouches for %s (%s)"
                            % (resource_url, "; ".join(failures)))

    def _check_issuer(self, resource_url: str, issuer: str) -> ResourceCheck:
        """Run checks (a) and (b) against ONE issuer, then read its endpoints."""
        require_https(issuer, "Issuer")
        as_url, oidc_url = self._as_metadata_urls(issuer)
        log.info("        GET AS metadata %s  (RFC 8414, no redirects)", as_url)
        doc = self._get_json(as_url, "RFC 8414 metadata")

        # (a) The document must really be this issuer's. RFC 8414 3.3: the
        # `issuer` value MUST be identical to the one used to build the URL.
        if doc.get("issuer") != issuer:
            raise SecurityError("check (a): metadata issuer %r != the issuer %r named by the PRM"
                                % (doc.get("issuer"), issuer))
        log.info("        check (a) OK: metadata issuer == %s", issuer)

        # (b) The issuer must list the resource. Absent list == failure.
        listed = doc.get("protected_resources")
        if listed is None:
            raise SecurityError("check (b): the issuer publishes no protected_resources "
                                "(an absent list is a failure)")
        if not isinstance(listed, list) or not all(isinstance(x, str) for x in listed):
            raise SecurityError("check (b): protected_resources is not a list of strings")
        matched = most_specific_cover(resource_url, listed)
        if matched is None:
            raise SecurityError("check (b): %s is not covered by the issuer's protected_resources %s"
                                % (resource_url, listed))
        log.info("        check (b) OK: %s is covered by listed resource %s",
                 resource_url, matched)

        return ResourceCheck(meta=self._endpoints(doc, issuer, oidc_url), resource_id=matched)

    def _endpoints(self, doc: dict, issuer: str, oidc_url: str) -> ASMetadata:
        """Read the endpoints we need from the (already vetted) RFC 8414 document.

        If the RFC 8414 document lacks an endpoint we need, fall back to the OIDC
        discovery document -- but ONLY to read endpoints (its issuer must match
        too). This never substitutes for the checks done on the RFC 8414 document.
        """
        needed = ["token_endpoint", "device_authorization_endpoint"]
        if self.client_id is None:
            needed.append("registration_endpoint")
        if any(not doc.get(k) for k in needed):
            log.info("        endpoints missing from the RFC 8414 document; "
                     "reading OIDC discovery %s (endpoints only)", oidc_url)
            oidc = self._get_json(oidc_url, "OIDC discovery")
            if oidc.get("issuer") != issuer:
                raise SecurityError("OIDC discovery issuer %r != %r"
                                    % (oidc.get("issuer"), issuer))
            doc = {**oidc, **{k: v for k, v in doc.items() if v}}
        for k in ("token_endpoint", "device_authorization_endpoint"):
            if not doc.get(k):
                raise SecurityError(f"the issuer's metadata has no {k}")
        return ASMetadata(
            issuer=issuer,
            token_endpoint=doc["token_endpoint"],
            device_authorization_endpoint=doc["device_authorization_endpoint"],
            registration_endpoint=doc.get("registration_endpoint"),
            scopes_supported=doc.get("scopes_supported", []),
        )

    @staticmethod
    def _as_metadata_urls(issuer: str) -> tuple[str, str]:
        """Build the (RFC 8414, OIDC) metadata URLs for an issuer.

        The subtlety is WHERE the well-known suffix goes when the issuer has a
        path component (e.g. https://host/iam):
          * RFC 8414 inserts it between host and path  -> https://host/.well-known/oauth-authorization-server/iam
          * OIDC appends it after the issuer path       -> https://host/iam/.well-known/openid-configuration
        """
        p = urlsplit(issuer)
        base = p.path.rstrip("/")
        rfc8414 = urlunsplit((p.scheme, p.netloc, WELL_KNOWN_AS + base, "", ""))
        oidc = urlunsplit((p.scheme, p.netloc, base + WELL_KNOWN_OIDC, "", ""))
        return rfc8414, oidc

    # -- step 4 ------------------------------------------------------------- #

    def _step4_register(self, meta: ASMetadata) -> str:
        """Obtain a client_id: reuse a preconfigured one, else self-register.

        Dynamic Client Registration (RFC 7591) lets a brand-new client mint its
        own id with no prior setup. We register as a PUBLIC client (no secret --
        appropriate for the device flow on a native app) declaring the device_code
        grant, plus token-exchange only if we will actually use it.

        NB: some IAMs (e.g. INDIGO) forbid self-registered clients from requesting
        token-exchange. Against those, leave token exchange off (it is optional)
        or pass a preconfigured client_id.
        """
        if self.client_id:
            log.info("STEP 4  using preconfigured client_id=%s", self.client_id)
            return self.client_id
        if not meta.registration_endpoint:
            raise SecurityError("no client_id and the IAM offers no registration endpoint")
        log.info("STEP 4  POST register (RFC 7591) %s", meta.registration_endpoint)
        grants = [GRANT_DEVICE_CODE] + ([GRANT_TOKEN_EXCHANGE] if self.token_exchange else [])
        body = {
            "client_name": "authvo-reference-client",
            "grant_types": grants,
            "token_endpoint_auth_method": "none",   # public client
            "application_type": "native",
            "scope": self.scope,
        }
        doc = self._post_json(meta.registration_endpoint, body)
        self.client_id = doc["client_id"]
        log.info("        -> client_id=%s", self.client_id)
        return self.client_id

    # -- step 5 ------------------------------------------------------------- #

    def _step5a_device_authorization(self, meta: ASMetadata, client_id: str) -> dict:
        """Start the Device Authorization Grant (RFC 8628).

        We send our client_id and the scopes we want; the IAM returns a
        device_code (which we poll with) plus a user_code and verification URL
        (which the human uses). This grant suits CLIs/headless clients because
        the user authenticates in a normal browser, not in our process.
        """
        log.info("STEP 5  POST device_authorization (RFC 8628)")
        doc = self._post_form(meta.device_authorization_endpoint, {
            "client_id": client_id,
            "scope": self.scope,
        })
        if "device_code" not in doc:
            raise SecurityError("device authorization response missing device_code")
        return doc

    def _step5b_prompt_user(self, device: dict, resource_url: str, issuer: str,
                            resource_id: str) -> None:
        """Tell the human where to go and what they are authorizing.

        We show the resource, the resource id the token will be for, AND the
        identity provider, so the user can sanity-check that they are logging in
        to the expected IAM for the expected service. The client never sees the
        user's credentials -- they are typed into the IAM's own page.
        """
        # verification_uri_complete embeds the user_code; prefer it when present.
        uri = device.get("verification_uri_complete") or device["verification_uri"]
        log.info("        user action required")
        print("\n" + "=" * 64)
        print("  Authorize access to : %s" % resource_url)
        print("  Token is for        : %s" % resource_id)
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
                pass  # headless box / no browser -- the printed URL still works

    def _step5c_poll_token(self, meta: ASMetadata, client_id: str,
                           device: dict, resource_id: str) -> dict:
        """Poll the token endpoint until the user approves (or we time out).

        Per RFC 8628 we poll at `interval` seconds and handle two non-error
        signals: `authorization_pending` (keep waiting) and `slow_down` (back off
        by 5s). Every poll carries the RFC 8707 `resource` indicator -- the id
        that matched in step 3(b) -- so a cooperating issuer can bind the token's
        audience to exactly that resource. If the token is a JWT we log its `aud`
        for information only: the resource server, not we, enforces it.
        """
        interval = int(device.get("interval", 5))
        deadline = time.time() + int(device.get("expires_in", 300))
        log.info("        polling token endpoint (resource=%s)", resource_id)
        while time.time() < deadline:
            time.sleep(interval)  # RFC 8628: wait BEFORE each poll
            resp = self.http.post(meta.token_endpoint, data={
                "grant_type": GRANT_DEVICE_CODE,
                "device_code": device["device_code"],
                "client_id": client_id,
                "resource": resource_id,          # RFC 8707 resource indicator
            }, timeout=self.timeout, allow_redirects=False)
            doc = resp.json()
            if resp.status_code == 200:
                # Got a token. Sanity-check the issuer before using it (step 6).
                self._validate_issuer(doc, meta.issuer, "access token")
                log.info("        -> access token acquired")
                self._log_aud(doc, "access token")
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

    def _step5d_token_exchange(self, meta: ASMetadata, client_id: str,
                               token: dict, resource_id: str) -> dict:
        """Optional: exchange the token for one narrowed to exactly this resource.

        RFC 8693 token exchange: we hand in the access token from step 5c and ask
        for a new token whose `audience` is the target resource id. The result is
        an `aud`-bound token that cannot be replayed against any other service.
        Off by default (the `resource` indicator on the token request is the
        primary mechanism); it needs a client the IAM allows to use this grant.
        We send both `audience` (RFC 8693) and `resource` (RFC 8707).
        """
        log.info("STEP 5d token exchange (RFC 8693)  audience=%s", resource_id)
        doc = self._post_form(meta.token_endpoint, {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "client_id": client_id,
            "subject_token": token["access_token"],
            "subject_token_type": TOKEN_TYPE_ACCESS,
            "audience": resource_id,             # narrow to the target service
            "resource": resource_id,             # RFC 8707, belt-and-braces
            "scope": self.exchange_scope,
        })
        self._validate_issuer(doc, meta.issuer, "exchanged token")
        self._log_aud(doc, "exchanged token")
        return doc

    # -- step 6 ------------------------------------------------------------- #

    def _step6_access(self, resource_url: str, token: dict) -> requests.Response:
        """Retry the original request, now presenting the bearer token.

        This is where it pays off: the resource server independently verifies the
        token's signature against the IAM's JWKS and checks iss / scope / expiry,
        and `aud` (== itself) whenever the token carries one. We just present the
        token and report the outcome. Redirects are not followed: a redirect must
        never carry our bearer token to a place the resource did not name.
        """
        log.info("STEP 6  GET %s  with bearer token", resource_url)
        r = self.http.get(resource_url, timeout=self.timeout, allow_redirects=False,
                          headers={"Authorization": "Bearer " + token["access_token"]})
        if r.status_code == 200:
            log.info("        -> SUCCESS (%d bytes)", len(r.content))
        else:
            log.warning("        -> resource returned %d", r.status_code)
        return r

    # -- shared HTTP / validation helpers ----------------------------------- #

    @staticmethod
    def _log_aud(token_doc: dict, what: str) -> None:
        """Log a JWT token's `aud` for information. Never fails, never decides."""
        payload = jwt_payload(token_doc.get("access_token", ""))
        if payload is None:
            log.info("        (%s is opaque; aud not inspectable)", what)
        else:
            log.info("        %s aud=%s (informational; the resource server enforces it)",
                     what, payload.get("aud", "<absent>"))

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

    def _get_json(self, url: str, what: str) -> dict:
        """GET a discovery document and parse JSON -- NEVER following redirects.

        Fail closed: a redirect (3xx), any non-200 status, or a body that is not
        a JSON object raises SecurityError. Refusing redirects matters because a
        hostile server could bounce us to a document it does not control the
        origin of, defeating the origin/path reasoning of steps 2 and 3.
        """
        r = self.http.get(url, timeout=self.timeout, allow_redirects=False,
                          headers={"Accept": "application/json"})
        if 300 <= r.status_code < 400:
            raise SecurityError("%s at %s redirected (%d -> %s); refusing to follow redirects"
                                % (what, url, r.status_code, r.headers.get("Location", "?")))
        if r.status_code != 200:
            raise SecurityError("%s at %s returned HTTP %d" % (what, url, r.status_code))
        try:
            doc = r.json()
        except ValueError:
            raise SecurityError("%s at %s is not valid JSON" % (what, url))
        if not isinstance(doc, dict):
            raise SecurityError("%s at %s is not a JSON object" % (what, url))
        return doc

    def _post_json(self, url: str, body: dict) -> dict:
        """POST a JSON body (used for dynamic client registration)."""
        r = self.http.post(url, json=body, timeout=self.timeout, allow_redirects=False)
        if r.status_code >= 300:
            raise SecurityError("POST %s -> %d: %s" % (url, r.status_code, r.text[:300]))
        return r.json()

    def _post_form(self, url: str, form: dict) -> dict:
        """POST a form-encoded body (used for the OAuth token/device endpoints).

        OAuth endpoints expect application/x-www-form-urlencoded. We surface a
        3xx/4xx/5xx as a SecurityError with a trimmed body so failures are legible.
        """
        r = self.http.post(url, data=form, timeout=self.timeout, allow_redirects=False)
        if r.status_code >= 300:
            raise SecurityError("POST %s -> %d: %s" % (url, r.status_code, r.text[:300]))
        return r.json()


def main(argv: list[str]) -> int:
    """CLI entry point: take a resource URL (arg or AUTHVO_RESOURCE) and run it.

    Exit status: 0 = the resource returned 200; 1 = a check failed, the network
    failed, or the resource answered with anything else; 2 = usage error.

    Environment variables:
      AUTHVO_RESOURCE        the protected-resource URL (if not passed as argv[1])
      AUTHVO_CLIENT_ID       a preconfigured client_id (skips dynamic registration)
      AUTHVO_OPEN_BROWSER    "1" to auto-open the device verification URL
      AUTHVO_TOKEN_EXCHANGE  "1" to ALSO run the RFC 8693 token exchange (off by
                             default; needs a client the IAM lets use that grant)
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
        token_exchange=os.environ.get("AUTHVO_TOKEN_EXCHANGE") == "1",
    )
    try:
        resp = client.access(resource)
    except SecurityError as e:
        # Any failed check lands here: print why and exit non-zero.
        log.error("ABORT: %s", e)
        return 1
    except requests.RequestException as e:
        # Network trouble (DNS, TLS, timeout) is not a security verdict, but we
        # still stop and send nothing.
        log.error("ERROR: network failure: %s", e)
        return 1
    print("\n--- resource response ---")
    print(resp.text[:2000])
    # Exit non-zero unless the resource actually handed over its data (a 403 for
    # a missing scope, say, is a failure even though no check was violated).
    return 0 if resp.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
