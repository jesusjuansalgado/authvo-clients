#!/usr/bin/env bash
# One-shot bring-up for the AuthVO local integration harness.
#
# Generates TLS material + the IAM signing keystore, starts the stack, then
# provisions the (otherwise empty) INDIGO IAM with a vo.read scope, login users
# and the authvo-client. Re-running is safe.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p certs traefik/dynamic iam/keys

# --- 1. self-signed CA + a cert covering both local origins ----------------
# NOTE: the extensions matter. OpenSSL 3 (used by Python 3.11+) rejects a CA
# without basicConstraints/keyUsage ("CA cert does not include key usage
# extension"), so both the CA and the leaf are issued WITH explicit extensions.
if [ ! -f certs/local-ca.pem ]; then
  echo ">> generating a local CA and a *.local.io certificate"
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout certs/local-ca.key -out certs/local-ca.pem \
    -subj "/CN=AuthVO Local Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

  openssl req -nodes -newkey rsa:2048 \
    -keyout certs/local.key -out certs/local.csr \
    -subj "/CN=iam.local.io" >/dev/null 2>&1

  cat > certs/san.ext <<'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
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

# --- 3. IAM JWT signing key set --------------------------------------------
# v1.10.0 ships no keystore and won't start without one. Generate a JWK set
# (kid=rsa1) with the pure-JDK helper — no extra deps (JDK 11+ is already needed
# for the Java client).
if [ ! -f iam/keys/keystore.jwks ]; then
  echo ">> generating the IAM signing keystore (iam/keys/keystore.jwks)"
  java iam/GenKeystore.java iam/keys/keystore.jwks rsa1
fi

# --- 4. /etc/hosts reminder -------------------------------------------------
if ! grep -q "iam.local.io" /etc/hosts 2>/dev/null; then
  echo ""
  echo ">> ACTION REQUIRED: add this line to /etc/hosts, then re-run:"
  echo "   127.0.0.1  iam.local.io src.local.io"
  echo ""
fi

# --- 5. bring it up + provision --------------------------------------------
echo ">> starting the stack"
docker compose up -d --build

echo ">> provisioning the IAM (scope + users + client)"
bash seed/provision.sh

cat <<'MSG'

Ready. Run a demo from the demo/ directory, e.g. the guided one:

  cd demo && python human_demo.py          # client self-registers; you log in
  # or the non-interactive driver:
  python auto_demo.py --username vouser --password vouser
  # or the preconfigured-client driver:
  python demo.py --resource https://src.local.io/vo-resource \
    --cacert ../certs/local-ca.pem --client-id-file ../seed/client_id

Log in (device grant) as  vouser / vouser  (or admin / password); on approval
the resource returns the protected payload.
MSG
