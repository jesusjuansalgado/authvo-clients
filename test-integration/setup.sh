#!/usr/bin/env bash
# One-shot bring-up for the AuthVO local integration harness.
#
# Generates TLS material + the IAM signing keystore, starts the stack, then
# provisions the (otherwise empty) INDIGO IAM with a vo.read scope, login users
# and the authvo-client. Re-running is safe.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p certs traefik/dynamic iam/keys

# --- 1. self-signed CA + a cert covering every local origin ----------------
# NOTE: the extensions matter. OpenSSL 3 (used by Python 3.11+) rejects a CA
# without basicConstraints/keyUsage ("CA cert does not include key usage
# extension"), so both the CA and the leaf are issued WITH explicit extensions.
#
# Origins: iam.local.io (IAM), src.local.io (the protected resource) and
# evil.local.io (the negative-test resource server). The CA is created once and
# kept, so a CA you already trust stays valid; only the LEAF is re-issued when
# it does not cover all the names (e.g. it predates evil.local.io).
HOSTS="iam.local.io src.local.io evil.local.io"
REISSUED_LEAF=0

if [ ! -f certs/local-ca.pem ]; then
  echo ">> generating a local CA"
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout certs/local-ca.key -out certs/local-ca.pem \
    -subj "/CN=AuthVO Local Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  rm -f certs/local.crt    # a leaf from a previous CA would no longer verify
fi

leaf_covers_all() {
  [ -f certs/local.crt ] || return 1
  local text; text=$(openssl x509 -in certs/local.crt -noout -text 2>/dev/null)
  for h in $HOSTS; do
    case "$text" in *"DNS:$h"*) ;; *) return 1 ;; esac
  done
}

if ! leaf_covers_all; then
  echo ">> issuing a *.local.io certificate for: $HOSTS"
  openssl req -nodes -newkey rsa:2048 \
    -keyout certs/local.key -out certs/local.csr \
    -subj "/CN=iam.local.io" >/dev/null 2>&1

  san=""; for h in $HOSTS; do san="${san:+$san, }DNS:$h"; done
  cat > certs/san.ext <<EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
EXT

  openssl x509 -req -in certs/local.csr \
    -CA certs/local-ca.pem -CAkey certs/local-ca.key -CAcreateserial \
    -days 825 -extfile certs/san.ext -out certs/local.crt >/dev/null 2>&1
  REISSUED_LEAF=1
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
# All three names must resolve to 127.0.0.1. We only WARN (editing /etc/hosts needs
# root); evil.local.io is needed only for the negative test (tests/run_scenarios.py).
missing=""
for h in $HOSTS; do
  grep -qw "$h" /etc/hosts 2>/dev/null || missing="$missing $h"
done
if [ -n "$missing" ]; then
  echo ""
  echo ">> ACTION REQUIRED: these names are not in /etc/hosts:$missing"
  echo "   add this line, then re-run:"
  echo "   127.0.0.1  $HOSTS"
  echo ""
fi

# --- 5. bring it up + provision --------------------------------------------
echo ">> starting the stack"
docker compose up -d --build
if [ "$REISSUED_LEAF" = 1 ]; then
  # Traefik loads the certificate at start-up; make it pick up the re-issued one.
  docker compose up -d --force-recreate proxy
fi

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
