#!/usr/bin/env python3
"""
Reference AuthVO client -- closes the demo.

Walks the AuthVO flow (RFC 9728-conformant) against the local stack:

  1. GET the protected resource anonymously (no redirects) -> 401 + a pointer to
     the resource server's own Protected Resource Metadata (PRM). UNTRUSTED.
  2. Fetch the PRM from that pointer. ABORT unless its `resource` COVERS the URL
     we asked for.                                           (RFC 9728 s3; AuthVO draft 3.3.1)
  3. RESOURCE CHECK -- the security gate. A resource server can claim any issuer,
     so ask the ISSUER: its own RFC 8414 metadata must (a) carry the issuer the
     PRM named and (b) list this resource in `protected_resources`. An absent
     list aborts. This is what stops the "evil service" (a resource that names a
     real issuer to harvest a real token); it happens BEFORE any login.
                                                            (RFC 8414 s3.3; RFC 9728 s4, mandatory in the AuthVO draft)
  4. Client id (registered by provision.sh).
  5. Device Authorization Grant (RFC 8628) -- a human logs in -- then poll the
     token endpoint, sending resource=<the matched id> (RFC 8707) so a
     cooperating issuer can bind the token's audience to it.
     (--token-exchange additionally narrows it with RFC 8693; off by default.)
  6. GET the resource with the Bearer token -> "protected resource data".

Swap this out for the real authvo-clients implementation; it exists so the
harness is runnable on its own. (The checks live in authvo_checks.py.)

Usage:
  python demo.py --resource https://src.local.io/vo-resource \
                 --cacert ../certs/local-ca.pem
"""
import argparse
import sys
import time

import requests

import authvo_checks as chk

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource", default="https://src.local.io/vo-resource")
    ap.add_argument("--cacert", default="../certs/local-ca.pem")
    ap.add_argument("--client-id-file", default="../seed/client_id")
    ap.add_argument("--scope", default="vo.read")
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

        # 2. The PRM, published by the resource server itself. It must describe the
        #    resource we asked for.
        prm = chk.get_json(s, pointer, "Protected Resource Metadata")
        issuers = chk.check_prm(args.resource, prm)
        print(f"[2] PRM: resource={prm['resource']} authorization_servers={issuers}; "
              "it covers the requested URL")

        # 3. RESOURCE CHECK -- ask the issuer whether it really serves this resource.
        issuer, as_doc, resource_id, oidc_url = chk.resource_check(s, args.resource, issuers)
        print(f"[3] resource check PASSED: {issuer} vouches for {resource_id} "
              "(issuer matches; resource listed in protected_resources)")
        ep = chk.endpoints(s, as_doc, issuer, oidc_url,
                           "device_authorization_endpoint", "token_endpoint")

        # 4. Client id (registered by provision.sh).
        client_id = open(args.client_id_file).read().strip()

        # 5. Device authorization grant.
        da = s.post(ep["device_authorization_endpoint"],
                    data={"client_id": client_id, "scope": f"openid {args.scope}"},
                    allow_redirects=False).json()
        print("\n[5] To authorize, open this URL and enter the code:")
        print(f"    Resource : {args.resource}")
        print(f"    Issuer   : {issuer}")
        print("    URL :", da.get("verification_uri_complete", da["verification_uri"]))
        print("    CODE:", da["user_code"])
        print("    (waiting for you to log in and approve...)\n")

        # ... poll for the token, bound to the matched resource (RFC 8707).
        interval = da.get("interval", 5)
        token = None
        deadline = time.time() + da.get("expires_in", 600)
        while time.time() < deadline:
            tr = s.post(ep["token_endpoint"], data={
                "grant_type": DEVICE_GRANT,
                "device_code": da["device_code"],
                "client_id": client_id,
                "resource": resource_id,            # RFC 8707 resource indicator
            }, allow_redirects=False)
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

    # 6. Access the resource with the token (no redirects: never carry it elsewhere).
    fr = s.get(args.resource, headers={"Authorization": f"Bearer {token}"},
               allow_redirects=False)
    if fr.status_code != 200:
        print("[6] access failed:", fr.status_code, fr.text)
        return 5
    print("\n[6] SUCCESS -- resource returned:")
    print("    " + fr.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
