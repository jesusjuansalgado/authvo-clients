#!/usr/bin/env python3
"""
Non-interactive AuthVO demo driver.

Identical flow to demo.py (probe -> PRM -> resource check -> device grant), but it
also performs the human step automatically: it logs the configured IAM user in and
approves the device authorization request, so the demo runs end to end with no
browser.

The security gate is the RESOURCE CHECK (step 3), not a comparison of host names:
the PRM comes from the resource server, which can name any issuer it likes, so we
ask the issuer's own RFC 8414 metadata whether it really serves this resource (its
`issuer` must match and `protected_resources` must list the resource). An absent
list aborts. See authvo_checks.py.

  python auto_demo.py --resource https://src.local.io/vo-resource \
      --cacert ../certs/local-ca.pem --client-id-file ../seed/client_id \
      --username vouser --password vouser
"""
import argparse
import sys
import time

import requests

import authvo_checks as chk

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


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
    ap.add_argument("--token-exchange", action="store_true",
                    help="also narrow the token with RFC 8693 token exchange (off by default)")
    args = ap.parse_args()

    s = requests.Session()
    s.verify = args.cacert

    try:
        # 1. Anonymous request -> 401 carrying only a pointer. No redirects.
        r = s.get(args.resource, allow_redirects=False)
        if r.status_code != 401:
            print(f"[1] expected 401, got {r.status_code}")
            return 1
        pointer = chk.parse_pointer(r.headers.get("WWW-Authenticate", ""))
        chk.require_https(pointer, "PRM pointer")
        print(f"[1] 401 -> PRM pointer (untrusted): {pointer}")

        # 2. The resource server's own PRM must cover the URL we asked for.
        prm = chk.get_json(s, pointer, "Protected Resource Metadata")
        issuers = chk.check_prm(args.resource, prm)
        print(f"[2] PRM: resource={prm['resource']} authorization_servers={issuers}; "
              "it covers the requested URL")

        # 3. RESOURCE CHECK, on the issuer's own RFC 8414 metadata.
        issuer, as_doc, resource_id, oidc_url = chk.resource_check(s, args.resource, issuers)
        print(f"[3] resource check PASSED: {issuer} vouches for {resource_id}")
        ep = chk.endpoints(s, as_doc, issuer, oidc_url,
                           "device_authorization_endpoint", "token_endpoint")

        # 4. Client id (provisioned earlier).
        client_id = open(args.client_id_file).read().strip()
        print(f"[4] client_id={client_id}")

        # 5. Device authorization grant.
        da = s.post(ep["device_authorization_endpoint"],
                    data={"client_id": client_id, "scope": f"openid {args.scope}"},
                    allow_redirects=False).json()
        print(f"[5] device authorization: user_code={da['user_code']}")

        # 5b. Automate the human: a separate "browser" session logs in and approves.
        approver = requests.Session()
        approver.verify = args.cacert
        auto_approve(approver, issuer, args.username, args.password, da["user_code"])

        # 5c. Poll for the token, bound to the matched resource (RFC 8707).
        interval = da.get("interval", 5)
        token = None
        deadline = time.time() + da.get("expires_in", 600)
        while time.time() < deadline:
            tr = s.post(ep["token_endpoint"], data={
                "grant_type": DEVICE_GRANT, "device_code": da["device_code"],
                "client_id": client_id, "resource": resource_id},
                allow_redirects=False)
            body = tr.json()
            if tr.status_code == 200:
                token = body["access_token"]
                break
            if body.get("error") not in ("authorization_pending", "slow_down"):
                print("[5] token error:", body)
                return 3
            time.sleep(interval)
        if not token:
            print("[5] timed out waiting for authorization")
            return 3
        print(f"[5] got access token (resource={resource_id}; "
              f"aud={chk.aud_of(token) or '<absent/opaque>'}, informational)")

        if args.token_exchange:
            xr = s.post(ep["token_endpoint"], data={
                "grant_type": TOKEN_EXCHANGE, "client_id": client_id,
                "subject_token": token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": resource_id, "resource": resource_id, "scope": args.scope},
                allow_redirects=False)
            if xr.status_code != 200:
                print("[5d] token exchange failed:", xr.status_code, xr.text)
                return 4
            token = xr.json()["access_token"]
            print(f"[5d] exchanged for token bound to aud={chk.aud_of(token)}")
    except chk.Abort as e:
        print(f"ABORT: {e}")
        return 2

    # 6. Access the resource with the token (no redirects).
    fr = s.get(args.resource, headers={"Authorization": f"Bearer {token}"},
               allow_redirects=False)
    if fr.status_code != 200:
        print("[6] access failed:", fr.status_code, fr.text)
        return 5
    print("\n[6] SUCCESS - resource returned:")
    print("    " + fr.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
