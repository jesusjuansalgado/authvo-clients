#!/usr/bin/env bash
# Provision a freshly-started INDIGO IAM so the AuthVO demos can run end to end.
# Under the production-style `mysql` profile the IAM starts EMPTY (schema only),
# so this script creates everything the flow needs. It is idempotent — safe to
# re-run.
#
#   - the `vo.read` system scope (the resource server requires it)
#   - two login users:  admin / password  (admin),  vouser / vouser  (user)
#   - the public `authvo-client` (device-code + token-exchange) used by
#     demo.py / auto_demo.py via seed/client_id. Token exchange is OPTIONAL in the
#     clients now (off by default); the grant is kept so it can be switched on.
#
# human_demo.py / HumanDemo.java don't need the client (they self-register), but
# they DO need a login user and the vo.read scope, both created here.
set -euo pipefail
cd "$(dirname "$0")/.."            # -> test-integration/

CA="certs/local-ca.pem"
ISSUER="https://iam.local.io/"
CURL=(curl -fsS --max-time 15 --cacert "$CA")
# Tunables (the defaults wait ~7.5 minutes and diagnose every ~30 s).
WAIT_TRIES=${IAM_WAIT_TRIES:-90}
WAIT_SECONDS=${IAM_WAIT_INTERVAL:-5}
DIAG_EVERY=${IAM_DIAG_EVERY:-6}
DB() { docker compose exec -T db mysql -uiam -ppwd iam "$@"; }

# Fixed bcrypt hashes so we don't need htpasswd/bcrypt at runtime. bcrypt verifies
# a password against ANY valid hash of it, regardless of the salt baked in here.
ADMIN_HASH='$2a$10$gbei9AcVjDTa1zkCCb/FVO5U/O74okJW67eg/fthes6Pu0mwgG08a'   # "password"
VOUSER_HASH='$2a$10$Q4STIYd2g4I5NaMVz6XFvOxIqRWpSkZNMNOP4IqZ.f0R6rlD94goi'  # "vouser"

# --- diagnosis: say WHY we are stuck, not just that we are --------------------
# Everything the demos and this script do goes to https://iam.local.io/ on :443
# through Traefik, so most failures are one of a handful of environment problems.
http_code() { curl -s --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true; }

diagnose() {
  # This runs because something is already wrong, so it must never die from `set -e`
  # (a refused connection is a non-zero curl exit, which is the very thing we report).
  local _errexit=0
  case $- in *e*) _errexit=1 ;; esac
  set +e
  local base="${ISSUER%/}" disc login rc published proxy_id iam_id state
  disc=$(http_code "$base/.well-known/openid-configuration")
  login=$(http_code "$base/login")
  curl -s --max-time 10 --cacert "$CA" -o /dev/null "$base/login"; rc=$?
  echo "   -- diagnosis --------------------------------------------------------"
  echo "   GET $base/.well-known/openid-configuration  -> HTTP $disc   (served by the augmenter)"
  echo "   GET $base/login                             -> HTTP $login   (served by the IAM itself)"

  proxy_id=$(docker compose ps -a -q proxy 2>/dev/null | head -1)
  iam_id=$(docker compose ps -a -q iam 2>/dev/null | head -1)
  published=$(docker compose port proxy 443 2>/dev/null | head -1 | sed 's/.*://')

  # The proxy itself.
  if [ -z "$proxy_id" ]; then
    echo "   * there is no proxy container: has the stack been brought up (docker compose up -d)?"
  else
    state=$(docker inspect -f '{{.State.Status}}' "$proxy_id" 2>/dev/null)
    if [ "$state" != "running" ]; then
      echo "   * the proxy (Traefik) is '$state', not running. See: docker compose logs proxy"
      if docker compose logs --tail 30 proxy 2>&1 | grep -qi "already allocated"; then
        echo "     -> host port 443 is already taken by something else (another stack's reverse proxy?)."
        echo "        Find it with: docker ps --format '{{.Names}}\t{{.Ports}}' | grep 443"
      fi
    elif [ -n "$published" ] && [ "$published" != "443" ]; then
      echo "   * Traefik is published on host port $published, but this script and the demos use"
      echo "     https://iam.local.io/ on :443, where nothing is listening."
      [ -f docker-compose.override.yml ] && \
        echo "     -> docker-compose.override.yml is present and docker compose MERGES it automatically."
      echo "     Re-run without it:   COMPOSE_FILE=docker-compose.yml ./setup.sh"
      echo "     (or rename docker-compose.override.yml while you don't need it)"
    fi
  fi

  # The IAM.
  if [ -n "$iam_id" ]; then
    state=$(docker inspect -f '{{.State.Status}} OOMKilled={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$iam_id" 2>/dev/null)
    case "$state" in
      running*) ;;
      *) echo "   * the IAM container is: $state   (docker compose logs iam)"
         case "$state" in *OOMKilled=true*)
           echo "     -> it was OOM-killed: Docker has too little memory. The IAM needs ~1.5 GB free;"
           echo "        stop other containers or raise Docker's memory limit.";; esac;;
    esac
  fi

  # What the HTTP answers say.
  if [ "$disc" = "000" ]; then
    case "$rc" in
      6)  echo "   * cannot resolve iam.local.io: add  127.0.0.1  iam.local.io src.local.io evil.local.io  to /etc/hosts" ;;
      7)  echo "   * connection refused on iam.local.io:443: nothing is listening there (see the proxy notes above)" ;;
      28) echo "   * timed out talking to iam.local.io:443" ;;
      35|51|58|60) echo "   * TLS problem (curl exit $rc): the certificate does not verify against $CA;"
                   echo "     re-run ./setup.sh (it re-issues the leaf certificate if it lacks a name)" ;;
    esac
  elif [ "$disc" = "200" ] && [ "$login" = "404" ]; then
    echo "   * the discovery document answers but the IAM's own paths give Traefik's '404 page not found':"
    echo "     Traefik has not registered the IAM's router (a start-up race when proxy and IAM were"
    echo "     recreated together). Fix:   docker compose restart proxy"
  elif [ "$disc" = "502" ] || [ "$disc" = "503" ]; then
    echo "   * the augmenter cannot reach the IAM yet: it is still starting. See: docker compose logs iam"
  elif [ "$disc" = "404" ]; then
    echo "   * Traefik has no route for iam.local.io at all: see 'docker compose logs proxy'"
    echo "     (e.g. its Docker provider failing against a Docker Engine >= 29, README section 11)"
  fi
  echo "   ---------------------------------------------------------------------"
  if [ "$_errexit" = 1 ]; then set -e; fi
}

# --- wait for the IAM -------------------------------------------------------------
# "Ready" means TWO things work through Traefik, because they travel different
# routes: the discovery document (the augmenter, which reaches the IAM directly) and
# a path only the IAM itself serves (/login, via the `iam` router). Checking only the
# first can say "up" before Traefik has registered the IAM, and the next request
# (client registration) then gets a 404.
iam_ready() {
  "${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration" >/dev/null 2>&1 &&
  "${CURL[@]}" "${ISSUER%/}/login" >/dev/null 2>&1
}

echo ">> waiting for IAM at ${ISSUER} ..."
for i in $(seq 1 "$WAIT_TRIES"); do
  if iam_ready; then break; fi
  if [ "$i" -ge "$WAIT_TRIES" ]; then diagnose; echo "IAM did not come up"; exit 1; fi
  if [ $((i % DIAG_EVERY)) -eq 0 ]; then echo ">> still waiting (try $i/$WAIT_TRIES)"; diagnose; fi
  sleep "$WAIT_SECONDS"
done
echo ">> IAM is up"

# --- 1. the vo.read system scope -------------------------------------------
DB <<'SQL'
INSERT IGNORE INTO system_scope(scope,description,restricted,default_scope,structured)
  VALUES ('vo.read','Read access to VO protected resources',0,0,0);
SQL
echo ">> vo.read scope ensured"

# --- 2. login users (idempotent) -------------------------------------------
DB <<'SQL'
INSERT IGNORE INTO iam_authority(auth) VALUES ('ROLE_USER'),('ROLE_ADMIN');
SQL

create_user() {  # username  bcrypt-hash  email  given  family  role(admin|user)
  local u="$1" h="$2" email="$3" given="$4" family="$5" role="$6"
  local exists
  exists=$(DB -N -e "SELECT COUNT(*) FROM iam_account WHERE USERNAME='$u';" | tr -d '[:space:]')
  if [ "$exists" != "0" ]; then echo ">> user '$u' already exists"; return; fi
  local uuid; uuid=$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')
  # iam_user_info uses single-table inheritance with DTYPE='IamUserInfo'.
  DB <<SQL
START TRANSACTION;
INSERT INTO iam_user_info(EMAIL,EMAILVERIFIED,FAMILYNAME,GIVENNAME,DTYPE)
  VALUES ('$email',1,'$family','$given','IamUserInfo');
SET @uinfo := LAST_INSERT_ID();
INSERT INTO iam_account(active,CREATIONTIME,LASTUPDATETIME,PASSWORD,USERNAME,UUID,user_info_id,provisioned)
  VALUES (1,NOW(),NOW(),'$h','$u','$uuid',@uinfo,0);
SET @acc := LAST_INSERT_ID();
INSERT INTO iam_account_authority(account_id,authority_id)
  SELECT @acc, ID FROM iam_authority WHERE auth='ROLE_USER';
COMMIT;
SQL
  if [ "$role" = "admin" ]; then
    DB <<SQL
INSERT INTO iam_account_authority(account_id,authority_id)
  SELECT a.ID, au.ID FROM iam_account a JOIN iam_authority au ON au.auth='ROLE_ADMIN'
  WHERE a.USERNAME='$u';
SQL
  fi
  echo ">> created user '$u' ($role)"
}
create_user admin  "$ADMIN_HASH"  admin@local.io  Admin User admin
create_user vouser "$VOUSER_HASH" vouser@local.io Vo    User  user

# --- 3. the authvo-client OAuth client -------------------------------------
exists=$(DB -N -e "SELECT COUNT(*) FROM client_details WHERE client_id='authvo-client';" | tr -d '[:space:]')
if [ "$exists" != "0" ]; then
  echo ">> client 'authvo-client' already exists"
else
  # Dynamic registration. Retried a few times: straight after a (re)start Traefik can
  # lag in registering the IAM's router, which shows up as a 404 on this endpoint.
  register() {
    local meta resp
    meta=$("${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration") || return 1
    REG_EP=$(printf '%s' "$meta" | python3 -c 'import sys,json;print(json.load(sys.stdin)["registration_endpoint"])' 2>/dev/null) || return 1
    resp=$("${CURL[@]}" -X POST "$REG_EP" -H "Content-Type: application/json" -d '{
        "client_name":"authvo-client",
        "token_endpoint_auth_method":"none",
        "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
        "response_types":[],
        "scope":"openid profile offline_access vo.read"}') || return 1
    # Dynamic registration forbids the token-exchange grant for self-service
    # clients, so we registered with device_code + refresh and add token-exchange
    # and the friendly id via SQL below.
    GEN=$(printf '%s' "$resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["client_id"])' 2>/dev/null) || return 1
  }
  registered=0
  for try in 1 2 3 4 5 6; do
    if register; then registered=1; break; fi
    echo ">> client registration failed (try $try/6); retrying in ${WAIT_SECONDS}s ..."
    sleep "$WAIT_SECONDS"
  done
  if [ "$registered" != 1 ]; then
    echo ">> could not register the client at ${REG_EP:-the registration endpoint}"
    diagnose
    echo "   If the IAM paths above give 404, restart the proxy and re-run:"
    echo "     docker compose restart proxy && ./setup.sh"
    exit 1
  fi
  DB <<SQL
UPDATE client_details SET client_id='authvo-client' WHERE client_id='$GEN';
INSERT INTO client_grant_type(owner_id, grant_type)
  SELECT id,'urn:ietf:params:oauth:grant-type:token-exchange'
  FROM client_details WHERE client_id='authvo-client';
SQL
  echo ">> created client 'authvo-client'"
fi
printf 'authvo-client' > seed/client_id
echo ">> wrote seed/client_id"

cat <<'MSG'

>> provisioning complete:
     users : admin/password (admin),  vouser/vouser (user)
     scope : vo.read
     client: authvo-client (device-code + token-exchange)  -> seed/client_id
MSG
