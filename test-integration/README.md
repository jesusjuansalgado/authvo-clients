# AuthVO local integration harness

A self-contained, `docker compose`–based environment for exercising the AuthVO
bearer-token flow end to end, with **INDIGO IAM** as the authorization server. It
implements the RFC 9728-conformant flow agreed after
[AuthVO issue #22](https://github.com/ivoa-std/AuthVO/issues/22): the **resource
server publishes its own Protected Resource Metadata (PRM)**, and the client
confirms the binding from the **issuer's own RFC 8414 metadata**, whose
`protected_resources` member must list the resource.

It closes with a real protected REST service that requires a token scoped
`vo.read` and hands back the ASCII file `protected resource data`, and an "evil"
resource server for a negative test. The top-level [README](../README.md) has the
full explanation; this page is the quick tour.

## What's in the box

| Component | Role | Lives at |
|-----------|------|----------|
| `iam` (INDIGO IAM + db, redis, trustanchors) | Authorization server: device grant, DCR, JWTs | `https://iam.local.io/` |
| `augmenter` (`augmenter/`) | Adds `protected_resources` to the IAM's two `/.well-known` metadata documents. **Interim emulation** — delete it once INDIGO publishes the member | `https://iam.local.io/.well-known/oauth-authorization-server` and `/openid-configuration` |
| `proxy` (Traefik) | TLS front door for all three origins; sends exactly the two metadata paths to the augmenter (priority 100), the rest of `iam.local.io` to the IAM | `:443` |
| `resource` (`fake-rs/`) | The protected REST interface; serves its **own** RFC 9728 PRM | `https://src.local.io/` |
| `evil` (`fake-rs/`, 2nd instance) | A resource server whose PRM names the real IAM but which the IAM does not list — every client must refuse it | `https://evil.local.io/` |
| `seed/provision.sh` | Provisions the IAM: `vo.read` scope, login users, the `authvo-client` | — |
| `demo/` | Reference, non-interactive and guided drivers (Python and Java) | — |
| `tests/` | Offline unit tests and the live scenario runner | — |

## Run it

```bash
# one-time: map the hostnames locally (evil.local.io is only for the negative test)
echo "127.0.0.1  iam.local.io src.local.io evil.local.io" | sudo tee -a /etc/hosts

./setup.sh           # certs (leaf re-issued if it lacks a name), keystore, up, provision

python demo/demo.py \
  --resource https://src.local.io/vo/resource \
  --cacert  certs/local-ca.pem \
  --client-id-file seed/client_id
```

The demo prints the device-flow URL + code; log in and approve, and it prints
`protected resource data`. Everything is covered in the top-level README, §10
(drivers, the reference clients, offline tests, the live scenarios):

```bash
python tests/run_scenarios.py --java-cp "$JACKSON"      # real clients vs. the live stack
```

### Running the Java client instead

`demo/Demo.java` and `demo/HumanDemo.java` need no build step on JDK 11+:

```bash
java demo/Demo.java \
  --resource https://src.local.io/vo/resource \
  --cacert   certs/local-ca.pem \
  --client-id-file seed/client_id
```

The demos are standalone reference drivers that reimplement the flow so the
harness runs on its own (the checks they share are in `demo/authvo_checks.py`).
The real clients are `authvo_client.py` and `AuthVoClient.java` at the repo root;
the scenario runner exercises those.

## Why the resource check, not a shared origin

The old design hosted the PRM on the IAM origin and had the client require the
sidecar and the issuer to share an origin. RFC 9728 puts the PRM at the resource
server — but then the resource server can claim *any* issuer, including the real
IAM, to lure the user into obtaining a real token for it. So the client asks the
other side: the issuer's own RFC 8414 metadata must (a) carry the issuer the PRM
named and (b) list the resource in `protected_resources` (absent list = abort),
all before the user logs in. Co-locating anything is no longer part of the
argument. See the top-level README §1–§2 and §13.

## The protected REST service (`fake-rs/app.py`)

- Unauthenticated `GET /vo/resource` (or any URL under `RS_SERVICE_PATH`, query included,
  e.g. `/vo/tap/async/<id>`) → `401` with
  `WWW-Authenticate: Bearer resource_metadata="<the PRM URL for that request>"`.
- `GET /.well-known/oauth-protected-resource/<path>[?<query>]` → the PRM **generated for that
  URL** (`resource` = the URL asked about, query included; RFC 9728 §3.1/§3.3), built from the
  environment (`RS_RESOURCE_ID`, `RS_SERVICE_PATH`, `RS_ISSUER`, `RS_REQUIRED_SCOPE`); `404`
  outside the service path.
- With a Bearer token it checks, before returning anything: signature against the
  IAM JWKS, `iss` == IAM, scope contains **`vo.read`**, not expired, and — **if
  the token carries an `aud`** — that it includes an identifier from `RS_AUDIENCE_IDS`
  that covers the request.
- Valid → `200` with the ASCII body. Missing scope → `403 insufficient_scope`.
  Bad/expired/wrong-aud → `401`.

The validation is covered by `tests/test_fake_rs.py` (valid, wrong aud, missing
scope, rogue issuer, expired, unauthenticated; plus the per-request PRM, the 404 outside the
service path, and `aud` present/absent/with several entries).

## INDIGO IAM caveats (worth reading before you commit)

- **Pin the image tag.** Env var names and the bootstrap mechanism shift between
  releases; `iam/iam.env` mirrors the upstream compose shape but check the
  configuration reference for the tag you pin in `docker-compose.yml`.
- **JWT signing key.** The resource server verifies a JWT against the IAM JWKS,
  so the IAM must issue JWT access tokens (mount a signing keystore).
- **A login user** must exist for the device grant (`provision.sh` creates one).
- **`protected_resources` is not published by INDIGO today**, hence the augmenter.
  Resource indicators (RFC 8707) are not honoured either: v1.10.0 accepts the
  `resource` parameter the clients send but ignores it, so the token has no `aud`
  (the resource server checks `aud` only when the token carries one). The optional
  token exchange is what yields an `aud`-bound token.
- Token exchange (RFC 8693) is optional and off by default; a self-registered
  client can't use it on INDIGO (see the top-level README §7.4).

## CI note

The device grant needs a human. The scenario runner and `demo/auto_demo.py`
auto-approve it by logging in as `vouser` on the IAM's own pages. For other
non-interactive set-ups, register a confidential client and use a direct grant.
