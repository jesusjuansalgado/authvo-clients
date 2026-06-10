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
  * the access token is bound to the target resource via the `aud` request
    parameter on the device grant (RFC 8707 resource-indicator style), so the
    resource server can enforce `aud == itself`.

It stops before every step and explains what is about to happen and why.

  python human_demo.py --resource https://src.local.io/vo-resource \
                       --cacert ../certs/local-ca.pem
"""
import argparse
import sys
import time
import webbrowser
from urllib.parse import urlparse

import requests

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


def host(url):
    return urlparse(url).netloc


# --------------------------------------------------------------------------- #
#  the flow                                                                    #
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource", default="https://src.local.io/vo-resource")
    ap.add_argument("--cacert", default="../certs/local-ca.pem")
    ap.add_argument("--scope", default="vo.read")
    ap.add_argument("--no-browser", action="store_true",
                    help="don't try to open the verification URL automatically")
    args = ap.parse_args()

    s = requests.Session()
    s.verify = args.cacert

    print(f"{BOLD}AuthVO guided demo{RESET}")
    print(f"Target protected resource: {BOLD}{args.resource}{RESET}")
    print("We are a brand-new client that knows nothing but that URL.")

    # ---- STEP 1 --------------------------------------------------------- #
    step("1", "Knock on the door anonymously",
         "A real client starts with just a resource URL and no token.",
         "We GET it with no Authorization header. We EXPECT a 401 whose",
         "WWW-Authenticate header hands back ONLY a pointer to a metadata",
         "document (the PRM). The pointer is UNTRUSTED at this stage -- a",
         "malicious server could put anything here.")
    r = s.get(args.resource)
    shown("HTTP status :", r.status_code)
    if r.status_code != 401:
        print(f"{RED}Expected 401, aborting.{RESET}"); return 1
    challenge = r.headers.get("WWW-Authenticate", "")
    shown("WWW-Authenticate:", challenge)
    prm_url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
    shown("=> PRM pointer (untrusted):", prm_url)

    # ---- STEP 2 --------------------------------------------------------- #
    step("2", "Fetch the Protected-Resource-Metadata (the 'sidecar')",
         "We follow the pointer and read the RFC 9728 descriptor. It tells us",
         "which authorization server (issuer) governs this resource, and which",
         "resources that descriptor is actually authoritative for.")
    prm = s.get(prm_url).json()
    issuer = prm["authorization_servers"][0]
    shown("resource described :", prm["resource"])
    shown("issuer (AS)        :", issuer)
    shown("scopes_supported   :", prm.get("scopes_supported"))

    # ---- STEP 3 --------------------------------------------------------- #
    step("3", "DOMAIN-PROXY CHECK  (the security crux)",
         "This is what defeats the 'evil service'. Before trusting the issuer,",
         "we require TWO things:",
         "  (a) the PRM is served from the SAME origin as the issuer it names",
         "      -- so only the real IAM can vouch for its own resources;",
         "  (b) the resource we actually called is one the descriptor covers.",
         "If either fails we ABORT -- we never send a token somewhere a spoofed",
         "401 told us to.")
    print(f"  checking (a): sidecar host {host(prm_url)!r} == issuer host {host(issuer)!r}")
    if host(prm_url) != host(issuer):
        print(f"{RED}  GATE (a) FAILED -> ABORT{RESET}"); return 2
    print(f"{GREEN}  gate (a) OK{RESET}")
    print(f"  checking (b): {args.resource!r} starts with {prm['resource']!r}")
    if not args.resource.startswith(prm["resource"]):
        print(f"{RED}  GATE (b) FAILED -> ABORT{RESET}"); return 2
    print(f"{GREEN}  gate (b) OK -> the issuer is trusted for this resource{RESET}")

    # ---- STEP 4 --------------------------------------------------------- #
    step("4", "Read the Authorization Server metadata (RFC 8414)",
         "Now that we trust the issuer, we discover its endpoints from its",
         "well-known document: where to register, where to start the device",
         "flow, and where to get tokens.")
    meta = s.get(issuer.rstrip("/") + "/.well-known/openid-configuration").json()
    shown("registration_endpoint        :", meta["registration_endpoint"])
    shown("device_authorization_endpoint:", meta["device_authorization_endpoint"])
    shown("token_endpoint               :", meta["token_endpoint"])

    # ---- STEP 5 --------------------------------------------------------- #
    step("5", "Register OURSELVES dynamically (RFC 7591)",
         "Nothing was pre-provisioned for this client. We ask the IAM to mint a",
         "fresh client_id for us. We declare we are a public client doing the",
         "device-code grant. (This IAM forbids self-registered clients from",
         "requesting token-exchange, so we won't use it -- see step 8.)")
    reg = s.post(meta["registration_endpoint"], json={
        "client_name": "authvo-human-demo",
        "token_endpoint_auth_method": "none",
        "grant_types": [DEVICE_GRANT, "refresh_token"],
        "response_types": [],
        "scope": f"openid {args.scope}",
    })
    if reg.status_code >= 400:
        print(f"{RED}registration failed: {reg.status_code} {reg.text}{RESET}"); return 3
    reg = reg.json()
    client_id = reg["client_id"]
    shown("=> our NEW client_id:", client_id)
    shown("   granted scopes   :", reg.get("scope"))
    print(f"{DIM}   From here on, every request carries THIS client_id.{RESET}")

    # ---- STEP 6 --------------------------------------------------------- #
    step("6", "Start the device-authorization grant (RFC 8628)",
         "We send our client_id and the scopes we want. The IAM returns a code",
         "the user will approve, plus the URL where they go to do it.")
    da = s.post(meta["device_authorization_endpoint"], data={
        "client_id": client_id,
        "scope": f"openid {args.scope}",
    }).json()
    verify = da.get("verification_uri_complete") or da["verification_uri"]
    shown("user_code        :", da["user_code"])
    shown("verification_uri :", verify)

    # ---- STEP 7 --------------------------------------------------------- #
    step("7", "HUMAN STEP: log in to the IAM and approve",
         "Now YOU act as the resource owner. Open the URL below in a browser,",
         "log in with your IAM username/password ON THE IAM'S OWN PAGE (the",
         "client never sees your credentials), and approve the request for",
         f"scope '{args.scope}'. Meanwhile this client just polls and waits.",
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

    # ---- STEP 8 --------------------------------------------------------- #
    # (polling happens here; explained as part of step 7/8)
    interval = da.get("interval", 5)
    deadline = time.time() + da.get("expires_in", 600)
    token = None
    while time.time() < deadline:
        tr = s.post(meta["token_endpoint"], data={
            "grant_type": DEVICE_GRANT,
            "device_code": da["device_code"],
            "client_id": client_id,
            # RFC 8707-style resource indicator: bind the token's audience to the
            # target resource up-front, so we don't need a separate token
            # exchange. The RS will enforce aud == its own id.
            "aud": prm["resource"],
        })
        body = tr.json()
        if tr.status_code == 200:
            token = body["access_token"]
            break
        if body.get("error") not in ("authorization_pending", "slow_down"):
            print(f"{RED}  token error: {body}{RESET}"); return 4
        print(f"{DIM}  ...still waiting (server says: {body.get('error')}){RESET}")
        time.sleep(interval)
    if not token:
        print(f"{RED}  timed out waiting for approval{RESET}"); return 4
    print(f"\n{GREEN}  Approved! Got an access token.{RESET}")

    step("8", "Inspect the audience-bound token",
         "Because we passed `aud` on the device grant, the IAM issued a token",
         "scoped to exactly this resource -- no broad token, no token exchange.",
         "Let's look at the claims the resource server will check.")
    import json, base64
    p = token.split(".")[1]; p += "=" * (-len(p) % 4)
    claims = json.loads(base64.urlsafe_b64decode(p))
    for k in ("aud", "iss", "scope", "client_id", "sub", "exp"):
        shown(f"{k:9}:", claims.get(k))

    # ---- STEP 9 --------------------------------------------------------- #
    step("9", "Call the resource with the token",
         "Finally we retry the original request, now as Bearer <token>. The",
         "resource server verifies the signature against the IAM's JWKS, checks",
         f"iss, aud == itself, scope contains '{args.scope}', and not expired.")
    fr = s.get(args.resource, headers={"Authorization": f"Bearer {token}"})
    shown("HTTP status:", fr.status_code)
    if fr.status_code != 200:
        print(f"{RED}  access failed: {fr.text}{RESET}"); return 5
    print(f"\n{BOLD}{GREEN}  SUCCESS -- the resource returned:{RESET}")
    print(f"{BOLD}{GREEN}      {fr.text}{RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted."); sys.exit(130)
