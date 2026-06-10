#!/usr/bin/env bash
# One-shot bring-up for the AuthVO local integration harness.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p certs traefik/dynamic

# --- 1. self-signed CA + a cert covering both local origins ----------------
if [ ! -f certs/local-ca.pem ]; then
  echo ">> generating a local CA and a *.local.io certificate"
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout certs/local-ca.key -out certs/local-ca.pem \
    -subj "/CN=AuthVO Local Test CA" >/dev/null 2>&1

  openssl req -nodes -newkey rsa:2048 \
    -keyout certs/local.key -out certs/local.csr \
    -subj "/CN=iam.local.io" >/dev/null 2>&1

  cat > certs/san.ext <<'EXT'
subjectAltName = DNS:iam.local.io, DNS:src.local.io
EXT

  openssl x509 -req -in certs/local.csr \
    -CA certs/local-ca.pem -CAkey certs/local-ca.key -CAcreateserial \
    -days 825 -extfile certs/san.ext -out certs/local.crt >/dev/null 2>&1
  echo ">> certs written to ./certs (trust certs/local-ca.pem in your client)"
fi

# --- 2. Traefik dynamic TLS config -----------------------------------------
cat > traefik/dynamic/tls.yml <<'YML'
tls:
  certificates:
    - certFile: /certs/local.crt
      keyFile: /certs/local.key
  stores:
    default:
      defaultCertificate:
        certFile: /certs/local.crt
        keyFile: /certs/local.key
YML

# --- 3. /etc/hosts reminder -------------------------------------------------
if ! grep -q "iam.local.io" /etc/hosts 2>/dev/null; then
  echo ""
  echo ">> ACTION REQUIRED: add this line to /etc/hosts, then re-run:"
  echo "   127.0.0.1  iam.local.io src.local.io"
  echo ""
fi

# --- 4. bring it up + seed --------------------------------------------------
echo ">> starting the stack"
docker compose up -d --build

echo ">> seeding the test client"
RS_CA_BUNDLE="$(pwd)/certs/local-ca.pem" \
IAM_ISSUER="https://iam.local.io/" \
  bash seed/seed.sh

cat <<'MSG'

Ready. Close the demo with:

  python demo/demo.py \
    --resource https://src.local.io/vo-resource \
    --cacert  certs/local-ca.pem \
    --client-id-file seed/client_id

You'll be shown a URL + code to log in (device grant); on approval the client
exchanges the token down to aud=https://src.local.io and prints:

  protected resource data
MSG
