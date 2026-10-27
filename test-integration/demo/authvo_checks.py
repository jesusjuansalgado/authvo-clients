"""
The discovery checks of the AuthVO flow, in one small place, for the demo drivers.

demo.py, auto_demo.py and human_demo.py each walk the flow step by step so you can
read it; the checks they share live here so the three cannot drift apart. They
are a deliberately plain port of the checks in the real client (authvo_client.py,
which is the reference): same rules, same RFC references.

  Step 1  probe: 401 + a `resource_metadata` pointer (UNTRUSTED)       RFC 9728 s5
  Step 2  the PRM's `resource` must be IDENTICAL to the requested URL  RFC 9728 s3.3
            (query included; no "covered by" relaxation any more)
  Step 3  resource check on the ISSUER's own RFC 8414 metadata:
            (a) its `issuer` == the issuer the PRM named               RFC 8414 s3.3
            (b) `protected_resources` present AND covering the URL     RFC 9728 s4; AuthVO 3.3.1
  Step 5  the token's AUDIENCE is taken from `protected_resources` (never from the PRM
          `resource`) and sent as RFC 8707 `resource` parameters       RFC 8707 s2
  Every metadata fetch refuses redirects. COVERAGE (a path-segment prefix rule) applies
ONLY to the entries of `protected_resources`; a MANDATORY protected_resources is the
AuthVO draft's profile (RFC 9728 4 makes it optional).

Anything that fails raises Abort: the demo prints the reason and stops, before the
user is ever asked to log in.
"""
import re
from urllib.parse import urlsplit, urlunsplit

WELL_KNOWN_AS = "/.well-known/oauth-authorization-server"
WELL_KNOWN_OIDC = "/.well-known/openid-configuration"

# Which `protected_resources` entries the token is requested for (step 5).
AUDIENCE_COVERING = "covering"      # only the entry that covered the requested URL
AUDIENCE_DOMAIN = "domain"          # every entry: a domain-wide token


class Abort(Exception):
    """A mandatory check failed: stop, send no token, ask for no login."""


# --- Step 2: the EXACT match of the PRM `resource` (RFC 9728 3.3) --------------

def _exact_parts(url):
    """The parts the exact comparison uses: (key, has_fragment); (None, False) if unparseable.

    Scheme and host are lower-cased and a default port is dropped; the path is kept as
    is apart from ONE trailing slash; the query is kept byte for byte ("?" is not "");
    the fragment is split off. Same rules as authvo_client.py (the reference).
    """
    before, hash_, _frag = url.partition("#")
    try:
        p = urlsplit(before)
        port = p.port
    except ValueError:
        return None, False
    scheme = (p.scheme or "").lower()
    userinfo, at, _hostport = p.netloc.rpartition("@")
    path = p.path[:-1] if p.path.endswith("/") else p.path
    default = {"https": 443, "http": 80}.get(scheme)
    key = (scheme, userinfo if at else None, (p.hostname or "").lower(),
           None if port == default else port, path, "?" in before, p.query)
    return key, bool(hash_)


def urls_match_exactly(requested_url, prm_resource):
    """Is the PRM's `resource` IDENTICAL to the URL we requested? (RFC 9728 3.3)

    When the PRM URL came from a WWW-Authenticate `resource_metadata` pointer, its
    `resource` MUST be identical to the requested URL, query included; otherwise the PRM
    MUST NOT be used. A PRM that merely COVERS the URL is refused: the service itself
    must say which URL it is describing. No normalisation beyond case of scheme/host,
    the default port and one trailing slash; a PRM `resource` with a fragment never
    matches (RFC 9728 1.2). Tested against the `exact` vectors shared with both clients.
    """
    requested, _ = _exact_parts(requested_url)
    resource, resource_has_fragment = _exact_parts(prm_resource)
    if requested is None or resource is None or resource_has_fragment:
        return False
    return requested == resource


def is_valid_indicator(identifier):
    """May `identifier` be sent as an RFC 8707 `resource` value? An absolute URI, no fragment."""
    p = urlsplit(identifier)
    return bool(p.scheme and p.netloc) and "#" not in identifier


# --- Step 3: "covered" -- ONLY for the entries of protected_resources ----------

# (Coverage ignores any query of the requested URL: _path() looks at the path only.)

def _origin(url):
    p = urlsplit(url)
    scheme, host = (p.scheme or "").lower(), (p.hostname or "").lower()
    default = {"https": 443, "http": 80}.get(scheme)
    port = p.port
    return f"{scheme}://{host if port in (None, default) else f'{host}:{port}'}"


def _path(url):
    """Path with dot-segments resolved (RFC 3986 5.2.4) and no trailing slash."""
    out = []
    for seg in (urlsplit(url).path or "/").split("/"):
        s = seg.lower()
        if s in (".", "%2e"):
            continue
        if s in ("..", ".%2e", "%2e.", "%2e%2e"):
            if len(out) > 1:
                out.pop()
            continue
        out.append(seg)
    return "/".join(out).rstrip("/")


def is_covered(url, resource_id):
    """Equal to the identifier, or same origin and a path extending it at a
    path-SEGMENT boundary: https://h/vo covers /vo/tap/async/1, not /vocab; a
    root identifier covers the whole origin."""
    if _origin(url) != _origin(resource_id):
        return False
    up, rp = _path(url), _path(resource_id)
    return rp == "" or up == rp or up.startswith(rp + "/")


def most_specific_cover(url, resource_ids):
    """Of the identifiers covering `url`, the one with the longest path (or None)."""
    covering = [r for r in resource_ids if is_covered(url, r)]
    return max(covering, key=lambda r: len(_path(r)), default=None)


# --- fetching ----------------------------------------------------------------

def parse_pointer(www_authenticate):
    """The `resource_metadata` URL from a Bearer challenge (UNTRUSTED)."""
    m = (re.search(r'resource_metadata\s*=\s*"([^"]+)"', www_authenticate)
         or re.search(r'resource_metadata\s*=\s*([^,\s]+)', www_authenticate))
    if not m:
        raise Abort("the 401 carried no resource_metadata pointer")
    return m.group(1)


def require_https(url, what):
    if urlsplit(url).scheme.lower() != "https":
        raise Abort(f"{what} must be served over HTTPS: {url}")


def get_json(session, url, what):
    """GET a discovery document, NEVER following redirects, expecting a JSON object.

    A hostile server could bounce us to a document whose origin it does not
    control; refusing every redirect keeps the origin/path reasoning honest.
    """
    r = session.get(url, allow_redirects=False)
    if 300 <= r.status_code < 400:
        raise Abort(f"{what} at {url} redirected ({r.status_code} -> "
                    f"{r.headers.get('Location', '?')}); refusing to follow redirects")
    if r.status_code != 200:
        raise Abort(f"{what} at {url} returned HTTP {r.status_code}")
    try:
        doc = r.json()
    except ValueError:
        raise Abort(f"{what} at {url} is not valid JSON")
    if not isinstance(doc, dict):
        raise Abort(f"{what} at {url} is not a JSON object")
    return doc


def as_metadata_urls(issuer):
    """(RFC 8414 URL, OIDC URL) for an issuer. RFC 8414 INSERTS the well-known
    suffix between host and path; OIDC appends it after the path."""
    p = urlsplit(issuer)
    base = p.path.rstrip("/")
    return (urlunsplit((p.scheme, p.netloc, WELL_KNOWN_AS + base, "", "")),
            urlunsplit((p.scheme, p.netloc, base + WELL_KNOWN_OIDC, "", "")))


# --- the checks ----------------------------------------------------------------

def check_prm(resource_url, prm):
    """Step 2: the PRM must describe EXACTLY the URL we asked for (RFC 9728 3.3).

    Returns the issuers it names. The relaxation to "covered by" is gone since the
    review of ivoa-std/AuthVO PR #23: a service whose paths vary generates a PRM per
    request, with `resource` set to the URL it was asked about.
    """
    resource = prm.get("resource")
    if not isinstance(resource, str) or not resource:
        raise Abort("the PRM has no `resource` member")
    servers = prm.get("authorization_servers")
    if not isinstance(servers, list) or not servers or not all(isinstance(s, str) for s in servers):
        raise Abort("the PRM names no authorization_servers")
    if not urls_match_exactly(resource_url, resource):
        raise Abort(f"the PRM's resource {resource} is not identical to the requested URL "
                    f"{resource_url} (RFC 9728 3.3 requires an exact match)")
    return servers


def check_a(as_doc, issuer):
    """Check (a): the metadata really is this issuer's (RFC 8414 3.3)."""
    if as_doc.get("issuer") != issuer:
        raise Abort(f"check (a): metadata issuer {as_doc.get('issuer')!r} != the issuer "
                    f"{issuer!r} named by the PRM")


def check_b(as_doc, resource_url):
    """Check (b): the issuer lists the resource (RFC 9728 4; mandatory in the AuthVO draft). Returns the matched id.
    An ABSENT list is a failure, not a pass."""
    listed = as_doc.get("protected_resources")
    if listed is None:
        raise Abort("check (b): the issuer publishes no protected_resources "
                    "(an absent list is a failure)")
    if not isinstance(listed, list) or not all(isinstance(x, str) for x in listed):
        raise Abort("check (b): protected_resources is not a list of strings")
    matched = most_specific_cover(resource_url, listed)
    if matched is None:
        raise Abort(f"check (b): {resource_url} is not covered by the issuer's "
                    f"protected_resources {listed}")
    if not is_valid_indicator(matched):
        raise Abort(f"check (b): the covering entry {matched!r} is not a valid RFC 8707 "
                    "resource indicator (absolute URI, no fragment)")
    return matched


def audience_entries(as_doc, matched, mode=AUDIENCE_COVERING):
    """The `protected_resources` entries the token is requested for (step 5).

    The audience comes from the ISSUER's list, never from the PRM `resource` (which is
    the requested URL, perhaps with a query that RFC 8707 says an indicator should not
    carry). "covering": just the entry that covered the URL. "domain": every usable entry,
    the covering one first, for a domain-wide token. Entries that are not valid indicators
    are skipped.
    """
    if mode not in (AUDIENCE_COVERING, AUDIENCE_DOMAIN):
        raise ValueError(f"audience must be {AUDIENCE_COVERING!r} or {AUDIENCE_DOMAIN!r}, not {mode!r}")
    if mode == AUDIENCE_COVERING:
        return [matched]
    out = [matched]
    for entry in as_doc.get("protected_resources") or []:
        if entry not in out and is_valid_indicator(entry):
            out.append(entry)
    return out


def resource_params(entries):
    """The RFC 8707 `resource` parameter, REPEATED once per entry, as form pairs
    (a dict cannot hold the same key twice)."""
    return [("resource", e) for e in entries]


def resource_check(session, resource_url, issuers):
    """Step 3 for the first issuer that passes both checks.

    Returns (issuer, as_doc, matched_resource_id, oidc_url); raises Abort listing
    every issuer's reason if none passes. as_doc is the RFC 8414 document; the OIDC
    URL is returned only so the caller can read endpoints the RFC 8414 document
    lacks -- it must never be used to skip a check.
    """
    failures = []
    for issuer in issuers:
        try:
            require_https(issuer, "Issuer")
            as_url, oidc_url = as_metadata_urls(issuer)
            doc = get_json(session, as_url, "RFC 8414 metadata")
            check_a(doc, issuer)
            return issuer, doc, check_b(doc, resource_url), oidc_url
        except Abort as e:
            failures.append(f"{issuer}: {e}")
    raise Abort("no authorization server vouches for " + resource_url + " (" + "; ".join(failures) + ")")


def endpoints(session, as_doc, issuer, oidc_url, *need):
    """Endpoint values from the RFC 8414 document, reading OIDC discovery ONLY for
    any it lacks (and only if its issuer matches)."""
    out = {k: as_doc.get(k) for k in need}
    if any(not v for v in out.values()):
        oidc = get_json(session, oidc_url, "OIDC discovery")
        check_a(oidc, issuer)
        out = {k: out[k] or oidc.get(k) for k in need}
    return out


def aud_of(token):
    """The `aud` claim of a JWT, for display only (NO signature check). None if opaque
    or absent -- never a trust decision; the resource server enforces `aud`."""
    import base64
    import json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))).get("aud")
    except Exception:
        return None
