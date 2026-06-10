#!/usr/bin/env python3
"""
Non-interactive AuthVO demo driver.

Identical flow to demo.py (device grant + token exchange), but it also performs
the human step automatically: it logs the configured IAM user in and approves
the device authorization request, so the demo runs end to end with no browser.

  python auto_demo.py --resource https://src.local.io/vo-resource \
      --cacert ../certs/local-ca.pem --client-id-file ../seed/client_id \
      --username vouser --password vouser
"""
import argparse
import re
import sys
import time
from urllib.parse import urlparse

import requests

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def host(url):
    return urlparse(url).netloc


def auto_approve(s, issuer, user, pw, user_code):
    """Log the user in and approve the pending device authorization."""
    base = issuer.rstrip("/")
    s.get(base + "/login")                       # prime session cookie
    r = s.post(base + "/login",
               data={"username": user, "password": pw},
               allow_redirects=False)
    if r.status_code not in (301, 302) or "error" in (r.headers.get("Location") or ""):
        raise SystemExit(f"[approve] login failed for {user}: {r.status_code} {r.headers.get('Location')}")
    # /device/verify renders the consent page for this user_code
    s.post(base + "/device/verify", data={"user_code": user_code})
    # /device/approve grants it
    a = s.post(base + "/device/approve",
               data={"user_code": user_code, "user_oauth_approval": "true",
                     "authorize": "Authorize"})
    if a.status_code >= 400 or "denied" in a.text.lower():
        raise SystemExit(f"[approve] approval failed: {a.status_code}")
    print(f"[*] auto-approved device code as {user}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource", default="https://src.local.io/vo-resource")
    ap.add_argument("--cacert", default="../certs/local-ca.pem")
    ap.add_argument("--client-id-file", default="../seed/client_id")
    ap.add_argument("--scope", default="vo.read")
    ap.add_argument("--username", default="vouser")
    ap.add_argument("--password", default="vouser")
    args = ap.parse_args()

    s = requests.Session()
    s.verify = args.cacert

    # 1. Anonymous request -> 401 carrying only the PRM pointer.
    r = s.get(args.resource)
    if r.status_code != 401:
        print(f"[1] expected 401, got {r.status_code}")
        return 1
    prm_url = r.headers.get("WWW-Authenticate", "").split('resource_metadata="', 1)[1].split('"', 1)[0]
    print(f"[1] 401 -> PRM pointer: {prm_url}")

    # 2. Fetch the authoritative descriptor from the IAM origin.
    prm = s.get(prm_url).json()
    issuer = prm["authorization_servers"][0]
    print(f"[2] PRM: resource={prm['resource']} issuer={issuer}")

    # 3. DOMAIN-PROXY CHECK.
    if host(prm_url) != host(issuer):
        print(f"[3] ABORT: sidecar host {host(prm_url)} != issuer host {host(issuer)}")
        return 2
    if not args.resource.startswith(prm["resource"]):
        print(f"[3] ABORT: {args.resource} not covered by {prm['resource']}")
        return 2
    print("[3] domain-proxy check PASSED")

    # 4. AS metadata.
    meta = s.get(issuer.rstrip("/") + "/.well-known/openid-configuration").json()

    # 5. Client id (provisioned earlier).
    client_id = open(args.client_id_file).read().strip()
    print(f"[5] client_id={client_id}")

    # 6. Device authorization grant.
    da = s.post(meta["device_authorization_endpoint"],
                data={"client_id": client_id, "scope": f"openid {args.scope}"}).json()
    print(f"[6] device authorization: user_code={da['user_code']}")

    # 6b. Automate the human: a separate "browser" session logs in and approves.
    approver = requests.Session()
    approver.verify = args.cacert
    auto_approve(approver, issuer, args.username, args.password, da["user_code"])

    # 7. Poll for the broad token.
    interval = da.get("interval", 5)
    token = None
    deadline = time.time() + da.get("expires_in", 600)
    while time.time() < deadline:
        tr = s.post(meta["token_endpoint"], data={
            "grant_type": DEVICE_GRANT, "device_code": da["device_code"],
            "client_id": client_id})
        body = tr.json()
        if tr.status_code == 200:
            token = body["access_token"]
            break
        if body.get("error") not in ("authorization_pending", "slow_down"):
            print("[7] token error:", body)
            return 3
        time.sleep(interval)
    if not token:
        print("[7] timed out waiting for authorization")
        return 3
    print("[7] got broad access token")

    # 8. Token exchange -> narrow the audience to exactly this resource.
    xr = s.post(meta["token_endpoint"], data={
        "grant_type": TOKEN_EXCHANGE, "client_id": client_id,
        "subject_token": token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": prm["resource"], "scope": args.scope})
    if xr.status_code != 200:
        print("[8] token exchange failed:", xr.status_code, xr.text)
        return 4
    narrow = xr.json()["access_token"]
    print(f"[8] exchanged for token bound to aud={prm['resource']}")

    # 9. Access the resource with the narrowed token.
    fr = s.get(args.resource, headers={"Authorization": f"Bearer {narrow}"})
    if fr.status_code != 200:
        print("[9] access failed:", fr.status_code, fr.text)
        return 5
    print("\n[9] SUCCESS - resource returned:")
    print("    " + fr.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
