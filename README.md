# AuthVO clients & local integration harness

Reference clients and a self-contained, `docker compose`–based test
environment for the **IVOA AuthVO bearer-token flow** — securing Virtual
Observatory data services with OAuth2/OIDC bearer tokens, using **INDIGO IAM**
as the authorization server.

This repository contains:

* two **reference client implementations** (Python and Java) of the unified
  AuthVO flow, and
* a **local integration harness** (`test-integration/`) that stands up a real
  INDIGO IAM, a Protected-Resource-Metadata "sidecar", a single-origin Traefik
  proxy, and a protected resource server, plus three runnable demo drivers.

---

## 1. Background — the problem AuthVO solves

Plain OAuth2 does not tell a client *which* resource server a freshly-issued
token may be sent to. A malicious resource server (the "evil service") can point
token discovery at spoofed metadata and capture a real token issued for it.

The AuthVO direction (from the IVOA DSP *Bearer Tokens — Open Issues* deck) is
**PRM-based discovery + audience-bound tokens**:

* The resource server's `401` returns **only a pointer** (`resource_metadata`)
  to an [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) Protected-Resource-
  Metadata (PRM) document — never the authoritative descriptor itself.
* That PRM (the **sidecar**) is served from the **IAM's own origin**, so the
  client's **domain-proxy check** (sidecar host == issuer host, and the resource
  is one the descriptor covers) can distinguish a real binding from a forgery.
* The client uses the device grant and narrows the token's `aud` to exactly the
  target resource (via RFC 8693 token exchange **or** an RFC 8707-style `aud`
  request parameter). The resource server enforces `aud == its own id` plus the
  `vo.read` scope.

## 2. The flow

```
 1  GET the protected resource anonymously
 2  401 -> WWW-Authenticate: Bearer resource_metadata="<PRM url>"   (UNTRUSTED pointer)
 3  GET the PRM sidecar  -> issuer URL + protected-resources list
 4  DOMAIN-PROXY CHECK (abort on failure):
       (a) the sidecar and the issuer it names share the same origin
       (b) the resource we hit is covered by the descriptor (path-prefix match)
 5  GET the Authorization Server metadata (RFC 8414 / OIDC discovery)
 6  Obtain a client_id (dynamic registration RFC 7591, or preconfigured)
 7  Device authorization request (RFC 8628)
 8  User authenticates and approves on the IAM's own login page
 9  Poll the token endpoint -> access token (aud-bound to the resource)
10  Access the resource with the token (RS verifies aud/iss/scope/signature)
```

---

## 3. Repository layout

| Path | Role |
|------|------|
| `authvo_client.py` | Python reference client (full flow, incl. token exchange) |
| `AuthVoClient.java` | Java reference client (JDK 11+, Jackson) |
| `pom.xml` | Java build |
| `test-integration/` | The runnable Docker harness (everything below lives here) |
| `test-integration/docker-compose.yml` | The whole stack behind Traefik |
| `test-integration/setup.sh` | Generates certs + Traefik config, brings it up, seeds |
| `test-integration/iam/iam.env` | INDIGO IAM configuration |
| `test-integration/iam/keys/keystore.jwks` | JWT signing key set (see §7) |
| `test-integration/sidecar/prm.json` + `nginx.conf` | The PRM sidecar (see §6) |
| `test-integration/traefik/traefik.yml` | Single-origin proxy + TLS |
| `test-integration/fake-rs/` | The protected resource server (Flask) |
| `test-integration/seed/seed.sh` | Registers a test client via RFC 7591 |
| `test-integration/demo/demo.py` | Original reference driver (interactive device flow) |
| `test-integration/demo/auto_demo.py` | Non-interactive driver (auto-approves the login) |
| `test-integration/demo/human_demo.py` | Guided driver (Python): explains and pauses on every step |
| `test-integration/demo/HumanDemo.java` | Guided driver (Java, JDK-only): same as human_demo.py |

---

## 4. Architecture of the harness

```
                         ┌─────────────────────── iam.local.io (one TLS origin) ──────────────────────┐
   client ──TLS──▶ Traefik proxy ──▶ INDIGO IAM            (/, /token, /devicecode, /jwk, ...)
                         │           └▶ prm-sidecar (nginx) (/.well-known/oauth-protected-resource)
                         │
                         └──▶ resource server               on  src.local.io   (the protected data)
```

* **IAM and the sidecar share the `iam.local.io` origin** — that co-location is
  the entire point of the domain-proxy check. Split them across hosts and the
  check becomes vacuous.
* `iam.local.io` and `src.local.io` both resolve to `127.0.0.1` (via
  `/etc/hosts`) and are served by the same Traefik instance on `:443`.

---

## 5. Prerequisites

* Docker + Docker Compose.
* Add the hostnames to `/etc/hosts` (each on its own line):

  ```
  127.0.0.1  iam.local.io src.local.io
  ```

* Trust the generated CA (`test-integration/certs/local-ca.pem`) in your browser
  if you want to use the IAM web UI. On macOS:

  ```bash
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain test-integration/certs/local-ca.pem
  ```

* Python 3 with `requests` for the demo drivers.

> **Note on the IAM image.** The harness pins
> `indigoiam/iam-login-service:v1.10.0`. It is an `amd64` image, so it runs under
> emulation on Apple Silicon (slower first boot). Env var names and the bootstrap
> mechanism move between INDIGO releases — §7 documents exactly what v1.10.0
> needs.

---

## 6. The PRM sidecar — how to create it

The **sidecar** is the smallest possible thing: **one static JSON document**
([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) Protected Resource Metadata)
served from the IAM origin. It is *not* an application. It exists so the resource
server can hand back a bare pointer in its `401`, and the client can fetch the
authoritative descriptor from a host it can tie back to the issuer.

### 6.1 The PRM document (`sidecar/prm.json`)

```json
{
  "resource": "https://src.local.io",
  "authorization_servers": [
    "https://iam.local.io/"
  ],
  "scopes_supported": [
    "vo.read"
  ],
  "bearer_methods_supported": [
    "header"
  ],
  "resource_documentation": "https://www.ivoa.net/documents/authvo/"
}
```

**Field syntax** (RFC 9728 + the IVOA convention used by the clients):

| Field | Required | Meaning |
|-------|----------|---------|
| `resource` | yes | The canonical id of the protected resource. The token's `aud` must equal this, and every protected URL must be path-prefix-covered by it. |
| `authorization_servers` | yes | Issuer URL(s) allowed to mint tokens for this resource. The client trusts `authorization_servers[0]` **only after** the domain-proxy check. |
| `scopes_supported` | recommended | Scopes the resource understands (here `vo.read`). |
| `bearer_methods_supported` | recommended | How the token may be presented; `header` = `Authorization: Bearer`. |
| `resource_documentation` | optional | Human-facing docs URL. |
| `protected_resources` | optional (IVOA ext.) | A list of resource ids the descriptor is authoritative for, when one PRM covers several services. The clients fall back to the single `resource` value if absent. |

The two security gates the client runs against this document:

* **gate (a):** `host(prm_url) == host(authorization_servers[0])` — the sidecar
  and the issuer share an origin.
* **gate (b):** the resource URL the client started from is path-prefix-covered
  by `resource` (or one entry of `protected_resources`).

### 6.2 Serving it (`sidecar/nginx.conf`)

A bare nginx serves exactly that one path and 404s everything else:

```nginx
server {
    listen 80;
    default_type application/json;
    # The PRM document is mounted under this root; without it nginx uses its
    # compiled-in default (/etc/nginx/html) and try_files 404s.
    root /usr/share/nginx/html;

    location = /.well-known/oauth-protected-resource {
        add_header Content-Type application/json;
        try_files /.well-known/oauth-protected-resource =404;
    }

    location / { return 404; }
}
```

> ⚠️ The `root /usr/share/nginx/html;` line is **required**. Without it nginx
> resolves `try_files` against its compiled-in default directory and returns
> `404` even though the file is mounted.

The `prm.json` file is mounted into the container at the served path:

```yaml
# docker-compose.yml (prm-sidecar service)
volumes:
  - ./sidecar/prm.json:/usr/share/nginx/html/.well-known/oauth-protected-resource:ro
  - ./sidecar/nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

### 6.3 Putting it on the IAM origin (Traefik)

The sidecar must answer on `iam.local.io` at exactly the well-known path, with a
**higher router priority** than the IAM so that one path wins on the shared
origin:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.prm.rule=Host(`iam.local.io`) && Path(`/.well-known/oauth-protected-resource`)"
  - "traefik.http.routers.prm.entrypoints=websecure"
  - "traefik.http.routers.prm.tls=true"
  - "traefik.http.routers.prm.priority=100"     # IAM router is priority 1
  - "traefik.http.services.prm.loadbalancer.server.port=80"
```

---

## 7. INDIGO IAM — required configuration & provisioning

A stock `indigoiam/iam-login-service:v1.10.0` started with the production-style
`mysql` profile does **not** come up ready out of the box. The following changes
are what make the flow work end to end. They live in `iam/iam.env` and
`docker-compose.yml`.

### 7.1 `iam/iam.env` changes

```properties
# 1. Flyway bundles migrations for several DB vendors under db/migration/{h2,mysql,...}.
#    Pin to the mysql set, or it finds two "V1" migrations and aborts at boot.
SPRING_FLYWAY_LOCATIONS=classpath:db/migration/mysql

# 2. The IAM_DB_* names are NOT honored by v1.10.0 — it falls back to embedded H2
#    and runs the MySQL migrations against it (syntax error). Drive the datasource
#    with the standard Spring Boot properties so it connects to MariaDB.
SPRING_DATASOURCE_URL=jdbc:mysql://db:3306/iam
SPRING_DATASOURCE_USERNAME=iam
SPRING_DATASOURCE_PASSWORD=pwd
SPRING_DATASOURCE_DRIVER_CLASS_NAME=com.mysql.cj.jdbc.Driver

# 3. v1.10.0 ships NO signing keystore; the app won't start without one.
#    Generate a JWK set (see 7.2) and point the IAM at it.
IAM_KEY_STORE_LOCATION=file:/keystore.jwks

# 4. Put the granted scopes INTO the JWT access token (default is false) so the
#    resource server can enforce vo.read from the token itself.
IAM_ACCESS_TOKEN_INCLUDE_SCOPE=true
```

### 7.2 Generate the JWT signing keystore

INDIGO expects a JWK **set** (JSON) whose `kid` matches `IAM_JWK_DEFAULT_KEY_ID`
(default `rsa1`). Generate one and mount it at `/keystore.jwks`:

```python
import json, base64
from cryptography.hazmat.primitives.asymmetric import rsa

def b64u(i):
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub, pri = k.public_key().public_numbers(), k.private_numbers()
jwk = {"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256",
       "n": b64u(pub.n), "e": b64u(pub.e), "d": b64u(pri.d),
       "p": b64u(pri.p), "q": b64u(pri.q),
       "dp": b64u(pri.dmp1), "dq": b64u(pri.dmq1), "qi": b64u(pri.iqmp)}
json.dump({"keys": [jwk]}, open("iam/keys/keystore.jwks", "w"), indent=2)
```

```yaml
# docker-compose.yml (iam service)
volumes:
  - ./iam/keys/keystore.jwks:/keystore.jwks:ro
```

### 7.3 Provision the empty database

Under the `mysql` profile the schema is created but **no seed data** is loaded —
no users, no clients, the custom `vo.read` scope does not exist. Provision the
following (the harness does this directly against the `db` container).

**a) A login user** (the device grant needs a real account). INDIGO stores a
bcrypt password and uses a `DTYPE='IamUserInfo'` discriminator on `iam_user_info`:

```sql
INSERT INTO iam_authority(auth) VALUES ('ROLE_USER'),('ROLE_ADMIN');  -- if absent
INSERT INTO iam_user_info(EMAIL,EMAILVERIFIED,FAMILYNAME,GIVENNAME,DTYPE)
  VALUES ('vouser@local.io',1,'User','Vo','IamUserInfo');
INSERT INTO iam_account(active,CREATIONTIME,LASTUPDATETIME,PASSWORD,USERNAME,UUID,user_info_id,provisioned)
  VALUES (1,NOW(),NOW(),'<bcrypt-hash>','vouser','<uuid>',LAST_INSERT_ID(),0);
-- then link the account to ROLE_USER in iam_account_authority
```

Generate the bcrypt hash with `htpasswd -bnBC 10 "" <password>` (normalize the
`$2y$` prefix to `$2a$`). The harness creates `admin`/`password` (admin) and
`vouser`/`vouser` (user).

**b) The `vo.read` system scope:**

```sql
INSERT INTO system_scope(scope,description,restricted,default_scope,structured)
  VALUES ('vo.read','Read access to VO protected resources',0,0,0);
```

**c) An OAuth client** — only needed by `demo.py`/`auto_demo.py`, which read a
preconfigured `client_id` from `seed/client_id`. `human_demo.py` registers its
own client at runtime instead. To create a friendly `client_id` (DCR generates a
random one), register via DCR then rename it and add the token-exchange grant:

```sql
UPDATE client_details SET client_id='authvo-client' WHERE client_id='<generated>';
INSERT INTO client_grant_type(owner_id, grant_type)
  SELECT id,'urn:ietf:params:oauth:grant-type:token-exchange'
  FROM client_details WHERE client_id='authvo-client';
```

### 7.4 The token-exchange restriction (important)

`DefaultClientRegistrationService` hard-codes
`FORBIDDEN_GRANT_TYPES_FOR_ANONYMOUS` to include `token-exchange` and
`password`. A **self-registered** (RFC 7591) client therefore **cannot** request
the token-exchange grant — there is no env toggle for this.

Two ways to still get an audience-bound token:

* **Preconfigured client + token exchange** (`authvo_client.py`, `demo.py`):
  register the client with the token-exchange grant (admin/DB), get a broad
  token, then exchange it down to `aud=<resource>`.
* **Dynamic client + `aud` request parameter** (`human_demo.py`): pass
  `aud=<resource>` on the device-grant token request. INDIGO issues a token
  already bound to that audience, so **no token exchange is needed** — which is
  what lets a purely self-registered client complete the flow.

---

## 8. TLS / certificates

`setup.sh` generates a local CA and a `*.local.io` leaf. Modern OpenSSL 3
(used by Python 3.11+) **rejects a CA without the proper X.509 extensions**
(`CA cert does not include key usage extension`), so the CA and leaf are issued
with explicit extensions:

```bash
# CA
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout certs/local-ca.key -out certs/local-ca.pem -subj "/CN=AuthVO Local Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# leaf extensions (certs/san.ext)
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:iam.local.io, DNS:src.local.io
```

---

## 9. The resource server (`fake-rs/`)

A small Flask service standing in for a TAP/DataLink/SODA endpoint.

* Unauthenticated `GET /vo-resource` (or `GET /datalink/download/...`) →
  `401` with `WWW-Authenticate: Bearer resource_metadata="<PRM>"`.
* With a Bearer token it verifies, before returning anything: signature against
  the IAM JWKS, `iss == IAM`, **`aud == its own resource id`**, scope contains
  **`vo.read`**, not expired.
* Valid → `200` with the payload (`protected_resource.txt`).
* Missing scope → `403 insufficient_scope`; bad/expired/wrong-aud → `401`.

Two harness fixes worth noting:

* The pinned **PyJWT 2.7.0** `PyJWKClient` fetches the JWKS via `urllib`, which
  ignores the app's `requests` CA bundle. Point urllib's default TLS context at
  the CA with `SSL_CERT_FILE=/certs/local-ca.pem` on the service.
* The payload file is mounted (`./fake-rs/protected_resource.txt`) so editing it
  needs only a `docker compose up -d resource`, not an image rebuild.

---

## 10. Running it

```bash
cd test-integration
./setup.sh            # certs + Traefik config + docker compose up + seed
```

Then run any of the three drivers from `test-integration/demo/`:

```bash
# Original reference driver — you complete the device login in a browser.
python demo.py --resource https://src.local.io/vo-resource \
  --cacert ../certs/local-ca.pem --client-id-file ../seed/client_id

# Non-interactive — auto-approves the device login as the given user.
python auto_demo.py --username vouser --password vouser

# Guided — explains and pauses on every step; client self-registers (RFC 7591),
# you log in and approve on the IAM's own page.
python human_demo.py

# Same guided flow in Java, no build step (JDK 11+):
java HumanDemo.java
```

On success the resource returns the protected payload (an ASCII galaxy in this
harness).

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| IAM exits: *Found more than one migration with version 1* | Flyway scanning both vendor dirs — set `SPRING_FLYWAY_LOCATIONS=classpath:db/migration/mysql`. |
| IAM exits: H2 syntax error on `token_value(767)` | Datasource fell back to H2 — set the `SPRING_DATASOURCE_*` properties. |
| IAM exits: *Key Set resource could not be read: keystore.jwks* | No signing keystore — generate one (§7.2) and set `IAM_KEY_STORE_LOCATION`. |
| PRM URL returns nginx `404` | `root` missing in `sidecar/nginx.conf` (§6.2). |
| PRM URL returns the IAM 404 page | Traefik hasn't re-registered the sidecar after a restart — retry, or restart the proxy. |
| Client TLS: *CA cert does not include key usage extension* | Regenerate certs with the X.509 extensions (§8). |
| RS `401 invalid_token`, `PyJWKClientConnectionError` | JWKS fetch can't verify TLS — set `SSL_CERT_FILE` on the resource (§9). |
| RS `403 insufficient_scope` | Token has no `scope` claim — set `IAM_ACCESS_TOKEN_INCLUDE_SCOPE=true`. |
| DCR: *Grant type not allowed: ...token-exchange* | Self-registration can't request token-exchange — use the `aud` parameter instead (§7.4). |

---

## 12. Security notes

* This harness uses self-signed certs, throwaway passwords, and a public
  (`token_endpoint_auth_method: none`) client. It is for **local testing only**.
* The whole security argument rests on IAM and sidecar **sharing one origin**.
  Do not split them across hosts.
* The resource server validates the token server-side (signature, `iss`, `aud`,
  scope, expiry). The client's domain-proxy check is what stops it from sending a
  token to a spoofed resource in the first place.
