#!/usr/bin/env bash
# Register a test client with the IAM via RFC 7591 dynamic client registration.
# Writes the resulting client_id to ./client_id so the demo driver can read it.
#
# This uses ONLY standard OIDC/OAuth endpoints (well-known + DCR), which are
# stable across IAM versions. If your IAM restricts DCR or audiences, you can
# instead register the client + allowed audience `https://src.local.io` through
# the IAM web UI / admin API and just drop the client_id into ./client_id.
set -euo pipefail

ISSUER="${IAM_ISSUER:-https://iam.local.io/}"
CA="${RS_CA_BUNDLE:-./certs/local-ca.pem}"
CURL=(curl -fsS)
[ -f "$CA" ] && CURL+=(--cacert "$CA")

echo ">> waiting for IAM at ${ISSUER} ..."
for i in $(seq 1 60); do
  if "${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration" >/dev/null 2>&1; then
    break
  fi
  sleep 5
  [ "$i" = 60 ] && { echo "IAM did not come up"; exit 1; }
done

REG_EP=$("${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["registration_endpoint"])')
echo ">> registration endpoint: ${REG_EP}"

# A public client that can do device flow + token exchange, scoped to vo.read.
REQ=$(cat <<'JSON'
{
  "client_name": "authvo-test-client",
  "token_endpoint_auth_method": "none",
  "grant_types": [
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "refresh_token"
  ],
  "response_types": [],
  "scope": "openid profile offline_access vo.read"
}
JSON
)

RESP=$("${CURL[@]}" -X POST "$REG_EP" \
  -H "Content-Type: application/json" -d "$REQ")

echo "$RESP" | python3 -c 'import sys,json;d=json.load(sys.stdin);open("client_id","w").write(d["client_id"]);print(">> registered client_id =",d["client_id"])'

echo ">> done. Remember: a login user must exist in the IAM for the device grant"
echo "   (use the IAM admin or the dev image's default test user)."
