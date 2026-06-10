#!/usr/bin/env bash
# Provision a freshly-started INDIGO IAM so the AuthVO demos can run end to end.
# Under the production-style `mysql` profile the IAM starts EMPTY (schema only),
# so this script creates everything the flow needs. It is idempotent — safe to
# re-run.
#
#   - the `vo.read` system scope (the resource server requires it)
#   - two login users:  admin / password  (admin),  vouser / vouser  (user)
#   - the public `authvo-client` (device-code + token-exchange) used by
#     demo.py / auto_demo.py via seed/client_id
#
# human_demo.py / HumanDemo.java don't need the client (they self-register), but
# they DO need a login user and the vo.read scope, both created here.
set -euo pipefail
cd "$(dirname "$0")/.."            # -> test-integration/

CA="certs/local-ca.pem"
ISSUER="https://iam.local.io/"
CURL=(curl -fsS --cacert "$CA")
DB() { docker compose exec -T db mysql -uiam -ppwd iam "$@"; }

# Fixed bcrypt hashes so we don't need htpasswd/bcrypt at runtime. bcrypt verifies
# a password against ANY valid hash of it, regardless of the salt baked in here.
ADMIN_HASH='$2a$10$gbei9AcVjDTa1zkCCb/FVO5U/O74okJW67eg/fthes6Pu0mwgG08a'   # "password"
VOUSER_HASH='$2a$10$Q4STIYd2g4I5NaMVz6XFvOxIqRWpSkZNMNOP4IqZ.f0R6rlD94goi'  # "vouser"

# --- wait for the IAM to answer discovery ----------------------------------
echo ">> waiting for IAM at ${ISSUER} ..."
for i in $(seq 1 90); do
  if "${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration" >/dev/null 2>&1; then break; fi
  sleep 5
  [ "$i" = 90 ] && { echo "IAM did not come up"; exit 1; }
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
  REG_EP=$("${CURL[@]}" "${ISSUER%/}/.well-known/openid-configuration" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["registration_endpoint"])')
  # Dynamic registration forbids the token-exchange grant for self-service
  # clients, so register with device_code + refresh, then add token-exchange and
  # rename to the friendly id via SQL.
  GEN=$("${CURL[@]}" -X POST "$REG_EP" -H "Content-Type: application/json" -d '{
      "client_name":"authvo-client",
      "token_endpoint_auth_method":"none",
      "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
      "response_types":[],
      "scope":"openid profile offline_access vo.read"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["client_id"])')
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
