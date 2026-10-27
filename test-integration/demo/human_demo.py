#!/usr/bin/env python3
"""
human_demo.py -- a guided, realistic walk through the AuthVO bearer-token flow.

Unlike auto_demo.py (which fakes the human approval), this driver follows the
flow the way a real client + real user would:

  * the client REGISTERS ITSELF dynamically (RFC 7591) -- nothing is
    pre-provisioned for it; it walks away with a brand-new client_id,
  * the HUMAN opens the IAM in a browser and types their own username/password
    into the IAM login page, then approves the request,
  * the client only ever uses the client_id it just obtained,
  * before any of that, the client REFUSES to proceed unless the issuer itself
    vouches for the resource (the resource check, step 3),
  * the device authorization request AND the token request carry the audience as RFC 8707
    `resource` indicators, taken from the ISSUER's list (never from the resource's own
    metadata), so an issuer that supports it can bind the token's audience.

It stops before every step and explains what is about to happen and why.

  python human_demo.py --resource https://src.local.io/vo/resource \
                       --cacert ../certs/local-ca.pem
"""
import argparse
import json
import base64
import sys
import time
import webbrowser

import requests

import authvo_checks as chk

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


# --------------------------------------------------------------------------- #
#  little presentation helpers                                                #
# --------------------------------------------------------------------------- #

BOLD = "\033[1m"; DIM = "\033[2m"; CYAN = "\033[36m"; GREEN = "\033[32m"
YELLOW = "\033[33m"; RED = "\033[31m"; RESET = "\033[0m"


def step(n, title, *explanation):
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}STEP {n}: {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    for line in explanation:
        print(f"{DIM}{line}{RESET}")
    input(f"\n{YELLOW}  [Enter] to run this step...{RESET}")


def shown(label, value):
    print(f"  {GREEN}{label}{RESET} {value}")


def ok(msg):
    print(f"{GREEN}  {msg}{RESET}")


def refuse(msg):
    print(f"{RED}  {msg}{RESET}")
    print(f"{RED}  -> ABORT. Nothing was sent anywhere and you were never asked to log in.{RESET}")


# --------------------------------------------------------------------------- #
#  the flow                                                                    #
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource", default="https://src.local.io/vo/resource")
    ap.add_argument("--cacert", default="../certs/local-ca.pem")
    ap.add_argument("--scope", default="vo.read")
    ap.add_argument("--audience", choices=(chk.AUDIENCE_COVERING, chk.AUDIENCE_DOMAIN),
                    default=chk.AUDIENCE_COVERING,
                    help="covering: ask for a token for the ONE service entry covering the URL "
                         "(default); domain: ask for every entry the IAM lists")
    ap.add_argument("--no-browser", action="store_true",
                    help="don't try to open the verification URL automatically")
    args = ap.parse_args()

    s = requests.Session()
    s.verify = args.cacert

    print(f"{BOLD}AuthVO guided demo{RESET}")
    print(f"Target protected resource: {BOLD}{args.resource}{RESET}")
    print("We are a brand-new client that knows nothing but that URL.")

    try:
        # ---- STEP 1 --------------------------------------------------------- #
        step("1", "Knock on the door anonymously",
             "A real client starts with just a resource URL and no token.",
             "We GET it with no Authorization header, and we do NOT follow redirects",
             "(a redirect could itself be a trick). We EXPECT a 401 whose",
             "WWW-Authenticate header hands back ONLY a pointer to a metadata",
             "document. The pointer is UNTRUSTED -- a malicious server could put",
             "anything there, including a link to a document it forged.")
        r = s.get(args.resource, allow_redirects=False)
        shown("HTTP status :", r.status_code)
        if r.status_code != 401:
            print(f"{RED}Expected 401, aborting.{RESET}")
            return 1
        challenge = r.headers.get("WWW-Authenticate", "")
        shown("WWW-Authenticate:", challenge)
        pointer = chk.parse_pointer(challenge)
        chk.require_https(pointer, "PRM pointer")
        shown("=> PRM pointer (untrusted):", pointer)

        # ---- STEP 2 --------------------------------------------------------- #
        step("2", "Fetch the resource server's own Protected-Resource-Metadata",
             "We follow the pointer and read the RFC 9728 document. It is published",
             "by the RESOURCE SERVER about itself: which resource it is, and which",
             "authorization server(s) it says issue tokens for it.",
             "",
             "Our only check here: the resource it describes must be EXACTLY the URL we",
             "asked for -- character for character, query string included.",
             "",
             "Why so strict? This document is the service speaking about ITSELF. If we",
             "accepted one that merely 'covers' our URL (say it describes /vo while we",
             "asked for /vo/datalink?ID=7), any server could answer for paths it was",
             "never asked about, and one document could be replayed for many URLs.",
             "Requiring the exact URL means the service has looked at THIS request and",
             "said: 'this is what I am, for this URL'. (A service with variable paths,",
             "like TAP jobs, simply generates this small document on demand for",
             "whatever URL it is asked about.) A document about some OTHER URL is",
             "useless to us, and a sign of spoofing.")
        prm = chk.get_json(s, pointer, "Protected Resource Metadata")
        shown("resource described  :", prm.get("resource"))
        shown("authorization_servers:", prm.get("authorization_servers"))
        shown("scopes_supported    :", prm.get("scopes_supported"))
        issuers = chk.check_prm(args.resource, prm)
        ok(f"OK: {prm['resource']} is identical to {args.resource}")

        # ---- STEP 3 --------------------------------------------------------- #
        step("3", "RESOURCE CHECK  (the security crux)",
             "Everything so far came from the resource server -- and a resource server",
             "can say anything about itself. Picture an EVIL service: it answers 401,",
             "and its own metadata politely names the REAL identity provider as the",
             "issuer. If we believed that, we would send the user to log in at the",
             "real IAM and then hand the resulting real token to the evil service.",
             "",
             "So we ask the other side. The issuer's OWN metadata (RFC 8414), fetched",
             "from the issuer, must say two things:",
             "  (a) 'issuer' is exactly the issuer the resource named -- it really is",
             "      that issuer's document;",
             "  (b) 'protected_resources' lists a resource covering our URL -- the",
             "      issuer itself vouches that it issues tokens for this service.",
             "      HERE 'covering' is the right test: the issuer lists whole SERVICES",
             "      (e.g. https://src.local.io/vo) and the service's URLs below that",
             "      path -- /vo covers /vo/tap/async/1 but not /vocab -- are in it. Any",
             "      query string on our URL is ignored for this.",
             "If the issuer publishes NO list, we ABORT too: an unanswered question is",
             "not a yes. And all of this happens BEFORE you are asked to log in.")
        # Run the two gates one at a time (chk.resource_check does the same in one
        # call) so each result is visible. The first issuer passing both is used.
        passed, failures = None, []
        for candidate in issuers:
            try:
                chk.require_https(candidate, "Issuer")
                as_url, oidc_url = chk.as_metadata_urls(candidate)
                shown("fetching the issuer's metadata:", as_url)
                as_doc = chk.get_json(s, as_url, "RFC 8414 metadata")
                print(f"  checking (a): metadata issuer {as_doc.get('issuer')!r} == named issuer {candidate!r}")
                chk.check_a(as_doc, candidate)
                ok("gate (a) OK")
                print(f"  checking (b): is {args.resource!r} covered by {as_doc.get('protected_resources')}?")
                resource_id = chk.check_b(as_doc, args.resource)
                ok(f"gate (b) OK -> the issuer vouches for {resource_id}")
                passed = (candidate, as_doc, resource_id, oidc_url)
                audience = chk.audience_entries(as_doc, resource_id, args.audience)
                break
            except chk.Abort as e:
                print(f"{RED}  issuer {candidate} REJECTED: {e}{RESET}")
                failures.append(f"{candidate}: {e}")
        if passed is None:
            raise chk.Abort("no authorization server vouches for " + args.resource)
        issuer, as_doc, resource_id, oidc_url = passed
        ep = chk.endpoints(s, as_doc, issuer, oidc_url, "registration_endpoint",
                           "device_authorization_endpoint", "token_endpoint")
        print(f"{DIM}  Now that we trust the issuer for this resource we read its endpoints:{RESET}")
        for k, v in ep.items():
            shown(f"{k:29}:", v)

        # ---- STEP 4 --------------------------------------------------------- #
        step("4", "Register OURSELVES dynamically (RFC 7591)",
             "Nothing was pre-provisioned for this client. We ask the IAM to mint a",
             "fresh client_id for us. We declare we are a public client doing the",
             "device-code grant. (This IAM forbids self-registered clients from",
             "requesting token-exchange, which is fine: token exchange is optional.)")
        reg = s.post(ep["registration_endpoint"], json={
            "client_name": "authvo-human-demo",
            "token_endpoint_auth_method": "none",
            "grant_types": [DEVICE_GRANT, "refresh_token"],
            "response_types": [],
            "scope": f"openid {args.scope}",
        }, allow_redirects=False)
        if reg.status_code >= 400:
            print(f"{RED}registration failed: {reg.status_code} {reg.text}{RESET}")
            return 3
        reg = reg.json()
        client_id = reg["client_id"]
        shown("=> our NEW client_id:", client_id)
        shown("   granted scopes   :", reg.get("scope"))
        print(f"{DIM}   From here on, every request carries THIS client_id.{RESET}")

        # ---- STEP 5 --------------------------------------------------------- #
        step("5", "Start the device-authorization grant (RFC 8628)",
             "We send our client_id and the scopes we want. The IAM returns a code",
             "the user will approve, plus the URL where they go to do it.",
             "",
             "We also say WHAT the token is for, with the RFC 8707 'resource'",
             "parameter -- and here we use the IAM's list, not the resource's own",
             "document. Why? The resource's document names the exact URL we asked",
             "for (it may even carry a query string, which an audience identifier",
             "should not), and it comes from the party we are trying to be careful",
             "with. The IAM's list names the SERVICES the IAM really issues tokens for,",
             "and the IAM itself will be the one to mint the token. So the token is",
             "asked for the service entry the IAM said covers our URL"
             + (", and for every other entry in its list (a token for the whole domain)."
                if args.audience == chk.AUDIENCE_DOMAIN else "."),
             "(Device grant: there is no authorization request, so this is where the",
             "resource is first stated; we repeat it when we ask for the token.)",
             "",
             *[f"   resource={e}" for e in audience])
        da = s.post(ep["device_authorization_endpoint"], data=[
            ("client_id", client_id),
            ("scope", f"openid {args.scope}"),
        ] + chk.resource_params(audience), allow_redirects=False).json()
        verify = da.get("verification_uri_complete") or da["verification_uri"]
        shown("user_code        :", da["user_code"])
        shown("verification_uri :", verify)

        # ---- STEP 5b -------------------------------------------------------- #
        step("5b", "HUMAN STEP: log in to the IAM and approve",
             "Now YOU act as the resource owner. Check what you are authorizing:",
             "",
             f"   Resource          : {args.resource}",
             *[f"   {'Token is for' if i == 0 else '':<17} : {e}" for i, e in enumerate(audience)],
             f"   Identity provider : {issuer}",
             "",
             "Open the URL below in a browser, log in with your IAM username/password",
             "ON THE IAM'S OWN PAGE (the client never sees your credentials), and",
             f"approve the request for scope '{args.scope}'. Meanwhile this client",
             "just polls and waits.",
             "",
             f"   Open : {verify}",
             f"   Code : {da['user_code']}")
        if not args.no_browser:
            try:
                webbrowser.open(verify)
                print(f"{DIM}  (tried to open your browser automatically){RESET}")
            except Exception:
                pass
        print(f"\n{YELLOW}  Polling the token endpoint until you approve...{RESET}")

        interval = da.get("interval", 5)
        deadline = time.time() + da.get("expires_in", 600)
        token = None
        while time.time() < deadline:
            tr = s.post(ep["token_endpoint"], data=[
                ("grant_type", DEVICE_GRANT),
                ("device_code", da["device_code"]),
                ("client_id", client_id),
                # RFC 8707 resource indicator(s): the entries of the IAM's list chosen
                # in step 3, repeated once each. An issuer that supports it binds the
                # token's audience to them; one that does not simply ignores them.
            ] + chk.resource_params(audience), allow_redirects=False)
            body = tr.json()
            if tr.status_code == 200:
                token = body["access_token"]
                break
            if body.get("error") not in ("authorization_pending", "slow_down"):
                print(f"{RED}  token error: {body}{RESET}")
                return 4
            print(f"{DIM}  ...still waiting (server says: {body.get('error')}){RESET}")
            time.sleep(interval)
        if not token:
            print(f"{RED}  timed out waiting for approval{RESET}")
            return 4
        print(f"\n{GREEN}  Approved! Got an access token.{RESET}")

        # ---- STEP 5c -------------------------------------------------------- #
        step("5c", "Inspect the token -- and why audience binding still matters",
             "A token is a bearer instrument: whoever holds it can use it. The",
             "'aud' (audience) claim says WHICH service it is meant for. If the",
             "issuer sets it, a token minted for one service is useless at another,",
             "so a leaked or captured token cannot be replayed elsewhere.",
             "",
             "We asked for it with the 'resource' indicator, but binding is up to",
             "the issuer: some do, some ignore the request. So this client does not",
             "rely on it -- the RESOURCE SERVER enforces it: it refuses any token",
             "whose aud names someone else, and accepts a token with no aud only",
             "because the signature, issuer, scope and expiry are also checked.")
        claims = _claims(token)
        for k in ("aud", "iss", "scope", "client_id", "sub", "exp"):
            shown(f"{k:9}:", claims.get(k, "<absent>"))
        if "aud" not in claims:
            print(f"{DIM}  (no aud: this issuer did not bind an audience for this request){RESET}")
    except chk.Abort as e:
        refuse(str(e))
        return 2

    # ---- STEP 6 ------------------------------------------------------------- #
    step("6", "Call the resource with the token",
         "Finally we retry the original request, now as Bearer <token>, still",
         "without following redirects (a redirect must never carry the token",
         "somewhere the resource did not name). The resource server verifies the",
         "signature against the IAM's JWKS, checks iss, scope contains",
         f"'{args.scope}', not expired, and aud == itself whenever the token has one.")
    fr = s.get(args.resource, headers={"Authorization": f"Bearer {token}"},
               allow_redirects=False)
    shown("HTTP status:", fr.status_code)
    if fr.status_code != 200:
        print(f"{RED}  access failed: {fr.text}{RESET}")
        return 5
    print(f"\n{BOLD}{GREEN}  SUCCESS -- the resource returned:{RESET}")
    print(f"{BOLD}{GREEN}      {fr.text}{RESET}")
    return 0


def _claims(token):
    """Decode (WITHOUT verifying) a JWT payload, only to display its claims."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return {}


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted.")
        sys.exit(130)
