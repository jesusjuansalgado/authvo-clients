#!/usr/bin/env python3
"""
Reference AuthVO client — closes the demo.

Walks the exact sequence from the deck (slides 18-21) against the local stack:

  1. GET the protected resource anonymously            -> 401 + PRM pointer
  2. Fetch the PRM sidecar named by the pointer
  3. DOMAIN-PROXY CHECK: sidecar host == issuer host, and the resource we hit
     is covered by the descriptor (else ABORT)         <-- the security gate
  4. Read AS metadata (RFC 8414) from the named issuer
  5. (client already registered via DCR by seed.sh)
  6. Device Authorization Grant (RFC 8628) — human logs in
  7. Poll the token endpoint -> broad access token
  8. Token exchange (RFC 8693): audience=resource, scope=vo.read -> narrow token
  9. GET the resource with the narrowed Bearer token   -> "protected resource data"

Swap this out for the real authvo-clients implementation; it exists so the
harness is runnable on its own.

Usage:
  python demo.py --resource https://src.local.io/vo-resource \
                 --cacert ../certs/local-ca.pem
"""
import argparse
import sys
import time
from urllib.parse import urlparse

import requests

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def host(url: str) -> str:
    return urlparse(url).netloc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource", default="https://src.local.io/vo-resource")
    ap.add_argument("--cacert", default="../certs/local-ca.pem")
    ap.add_argument("--client-id-file", default="../seed/client_id")
    ap.add_argument("--scope", default="vo.read")
    args = ap.parse_args()

    s = requests.Session()
    s.verify = args.cacert

    # 1. Anonymous request -> 401 carrying only the PRM pointer.
    r = s.get(args.resource)
    if r.status_code != 401:
        print(f"expected 401, got {r.status_code}")
        return 1
    challenge = r.headers.get("WWW-Authenticate", "")
    prm_url = challenge.split('resource_metadata="', 1)[1].split('"', 1)[0]
    print(f"[1] 401 -> PRM pointer: {prm_url}")

    # 2. Fetch the authoritative descriptor from the IAM origin.
    prm = s.get(prm_url).json()
    issuer = prm["authorization_servers"][0]
    print(f"[2] PRM: resource={prm['resource']} issuer={issuer}")

    # 3. DOMAIN-PROXY CHECK — refuse to continue unless the descriptor is
    #    served from the same origin as the issuer, and our resource is the one
    #    it describes. This is what defeats the slide-5 spoof.
    if host(prm_url) != host(issuer):
        print(f"[3] ABORT: sidecar host {host(prm_url)} != issuer host {host(issuer)}")
        return 2
    if not args.resource.startswith(prm["resource"]):
        print(f"[3] ABORT: {args.resource} not covered by {prm['resource']}")
        return 2
    print("[3] domain-proxy check PASSED")

    # 4. AS metadata.
    meta = s.get(issuer.rstrip("/") + "/.well-known/openid-configuration").json()

    # 5. Client id (registered by seed.sh).
    client_id = open(args.client_id_file).read().strip()

    # 6. Device authorization grant.
    da = s.post(meta["device_authorization_endpoint"],
                data={"client_id": client_id, "scope": f"openid {args.scope}"}).json()
    print("\n[6] To authorize, open this URL and enter the code:")
    print("    URL :", da.get("verification_uri_complete", da["verification_uri"]))
    print("    CODE:", da["user_code"])
    print("    (waiting for you to log in and approve...)\n")

    # 7. Poll for the broad token.
    interval = da.get("interval", 5)
    token = None
    deadline = time.time() + da.get("expires_in", 600)
    while time.time() < deadline:
        tr = s.post(meta["token_endpoint"], data={
            "grant_type": DEVICE_GRANT,
            "device_code": da["device_code"],
            "client_id": client_id,
        })
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
        "grant_type": TOKEN_EXCHANGE,
        "client_id": client_id,
        "subject_token": token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": prm["resource"],
        "scope": args.scope,
    })
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
    print("\n[9] SUCCESS — resource returned:")
    print("    " + fr.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
