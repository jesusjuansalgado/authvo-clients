# AuthVO local integration harness

A self-contained, `docker compose`–based environment for exercising the AuthVO
bearer-token flow end to end, with **INDIGO IAM** as the authorization server
and a **protected-resources "sidecar" that is just the RFC 9728 JSON document**.
It implements the unified proposal from the *Bearer Tokens in AuthVO — Open
Issues* deck (the PRM-discovery + token-exchange flow, slides 13–22).

It closes with a real protected REST service that requires a token scoped
`vo.read` and hands back the ASCII file `protected resource data`.

## What's in the box

| Component | Role | Lives at |
|-----------|------|----------|
| `iam` (INDIGO IAM + db, redis, trustanchors) | Authorization server: device grant, DCR, token exchange, audience-bound JWTs | `https://iam.local.io/` |
| `prm-sidecar` (nginx + `sidecar/prm.json`) | The **sidecar** — one RFC 9728 Protected Resource Metadata document, nothing more | `https://iam.local.io/.well-known/oauth-protected-resource` |
| `proxy` (Traefik) | Puts IAM **and** sidecar on **one origin** so the client's domain-proxy check is meaningful | `:443` |
| `resource` (`fake-rs/`) | The protected REST interface — the demo closer | `https://src.local.io/` |
| `seed/seed.sh` | Registers a test client (device + token-exchange, `vo.read`) via RFC 7591 | — |
| `demo/demo.py` | Reference client (Python) that walks the whole flow; swap for the Python `authvo-client` | — |
| `demo/Demo.java` | Same flow in Java (JDK 11+, no build step) — for the Java client | — |

## Why the sidecar sits at the IAM origin

This is the security crux from slide 5 and slide 14. The resource server's
`401` returns **only a pointer** (`resource_metadata=...`) — it never serves the
authoritative descriptor. The client honours that pointer only after the
**domain-proxy check**: the sidecar and the issuer must share an origin, and the
resource being accessed must be the one the descriptor covers. Co-locating IAM
and sidecar behind one Traefik origin (`iam.local.io`) is exactly what makes a
spoofed `evil.com` descriptor fail that check. Run them on separate hosts and
the check becomes vacuous — so the harness deliberately shares the origin.

## The protected REST service (`fake-rs/app.py`)

- Unauthenticated `GET /vo-resource` (or a dynamic `GET /datalink/download/...`
  deep link) → `401` with `WWW-Authenticate: Bearer resource_metadata="<PRM>"`.
- With a Bearer token it checks, before returning anything:
  signature against the IAM JWKS, `iss` == IAM, **`aud` == its own resource id**,
  scope contains **`vo.read`**, not expired.
- Valid → `200` with the ASCII body `protected resource data`.
- Missing scope → `403 insufficient_scope`. Bad/expired/wrong-aud → `401`.

The validation logic ships verified against six cases (valid, wrong-aud,
missing-scope, rogue-issuer, expired, unauthenticated).

## Run it

```bash
# one-time: map the hostnames locally
echo "127.0.0.1  iam.local.io src.local.io" | sudo tee -a /etc/hosts

./setup.sh           # generates *.local.io certs, brings the stack up, seeds the client

python demo/demo.py \
  --resource https://src.local.io/vo-resource \
  --cacert  certs/local-ca.pem \
  --client-id-file seed/client_id
```

The demo prints the device-flow URL + code; log in and approve, and it exchanges
the token down to `aud=https://src.local.io`, calls the resource, and prints
`protected resource data`.

### Running the Java client instead

Everything in the harness is Python/shell except `demo/Demo.java`, which exists
because one of the two clients is in Java. It needs no build step on JDK 11+:

```bash
java demo/Demo.java \
  --resource https://src.local.io/vo-resource \
  --cacert   certs/local-ca.pem \
  --client-id-file seed/client_id
```

Both `demo.py` and `Demo.java` are reference drivers that reimplement the flow
so the harness runs standalone. Replace the `[6]`–`[9]` section of each with
calls into your real client: `demo.py` → the Python `authvo-client`, `Demo.java`
→ the Java one. The harness contract (the 401 pointer, the PRM, the
domain-proxy check, token exchange, `aud`/`vo.read` enforcement) is identical
for both, so the two clients are exercised against exactly the same stack.

## INDIGO IAM caveats (worth reading before you commit)

- **Pin the image tag.** Env var names and the bootstrap mechanism shift between
  releases; `iam/iam.env` mirrors the upstream compose shape but check the
  configuration reference for the tag you pin in `docker-compose.yml`.
- **JWT signing key.** The resource server verifies a JWT against the IAM JWKS,
  so the IAM must issue JWT access tokens (mount a signing keystore or use the
  dev image's generated key).
- **A login user** must exist for the device grant (IAM admin, or the dev
  image's default test user).
- **Resource indicators / RFC 9728 are partial in INDIGO today** (deck slide 11)
  — which is fine: the harness serves the PRM itself and relies on token
  exchange (8693, supported) to mint the `aud`-bound token. If your IAM
  restricts audiences, register `https://src.local.io` as an allowed audience.

## CI note

The device grant needs a human. For non-interactive CI, register a confidential
client and use a direct grant (e.g. password) to get the broad token, then run
steps 8–9 unchanged.
