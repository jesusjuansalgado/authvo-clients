# AuthVO local integration harness — context for Claude Code

This directory (`test/integration/`) is a self-contained local environment for
exercising the **AuthVO bearer-token flow** end to end. It was built in a prior
Claude.ai session and dropped in here; this file is the handoff so you have full
context.

## What AuthVO is (background)

IVOA (astronomy / Virtual Observatory) work on securing data services with
OAuth2/OIDC bearer tokens. The core problem ("the evil service"): plain OAuth
doesn't tell a client *which* server a freshly-issued token may be sent to, so a
malicious resource server can point discovery at spoofed metadata and capture a
real token. The agreed direction (from the "Bearer Tokens in AuthVO — Open
Issues" deck) is **PRM-based discovery + token exchange**:

- The resource server's `401` returns **only a pointer** (`resource_metadata`)
  to an RFC 9728 Protected-Resource-Metadata (PRM) document — never the
  authoritative descriptor itself.
- That PRM (the "sidecar") is served from the **IAM's own origin**, so the
  client's **domain-proxy check** (sidecar host == issuer host, and the resource
  is one the descriptor covers) can distinguish a real binding from a forged one.
- The client uses the device grant, then **RFC 8693 token exchange** to narrow
  the token's `aud` to exactly the target resource. The resource server enforces
  `aud == its own id` plus the `vo.read` scope.

## What's in here

| Path | Role |
|------|------|
| `docker-compose.yml` | Whole stack behind Traefik |
| `iam/iam.env` | INDIGO IAM config (the authorization server) |
| `sidecar/prm.json` + `sidecar/nginx.conf` | The "sidecar" = one RFC 9728 JSON doc, served at the IAM origin |
| `traefik/traefik.yml` | Single-origin proxy (`iam.local.io`) + TLS |
| `fake-rs/app.py` | The protected REST service (Python/Flask): 401+pointer, JWT `aud`/`vo.read` checks, returns the ASCII file `protected resource data` |
| `seed/seed.sh` | Registers a test client via RFC 7591 (device + token-exchange, `vo.read`) |
| `demo/demo.py` | Reference driver in **Python** (the default language) |
| `demo/Demo.java` | Same flow in **Java**, JDK-only, `java demo/Demo.java` |
| `setup.sh` | Generates certs + Traefik dynamic config, brings it up, seeds |

## Conventions

- **Python is the default for everything.** `demo/Demo.java` exists only because
  one of the two AuthVO clients is in Java; do not add further Java unless it's
  for that client.
- Hostnames `iam.local.io` and `src.local.io` must be in `/etc/hosts`.
- The IAM and the PRM sidecar **must** share an origin — that's the whole point
  of the domain-proxy check; don't split them across hosts.

## Verified so far

The resource server's token validation was tested against six cases (valid,
wrong-aud, missing-`vo.read`, rogue-issuer, expired, unauthenticated) and the
live 401 challenge + 200 payload. `Demo.java` compiles and runs (source-file
mode). The INDIGO IAM service itself was **not** run in the build sandbox.

## Open tasks (likely next steps)

1. **Wire the drivers to the real clients.** `demo.py` and `Demo.java` currently
   reimplement the flow. Replace their steps `[6]`–`[9]` with calls into the
   actual Python `authvo-client` / Java client, keeping steps 1–4 (discovery +
   domain-proxy check) if the clients don't own that yet.
2. **Pin a known-good INDIGO IAM image tag** in `docker-compose.yml` and
   reconcile `iam/iam.env` var names against that release's config reference.
3. **Ensure the IAM issues JWT access tokens** (mount a signing keystore) so the
   resource server can verify them, and that a **login user** exists for the
   device grant.
4. If the IAM restricts audiences, register `https://src.local.io` as allowed so
   the token exchange in step 8 mints an `aud`-bound token.
5. Add a non-interactive CI variant (confidential client + direct grant) so the
   flow can run without a human completing the device login.

## Run it

```bash
echo "127.0.0.1  iam.local.io src.local.io" | sudo tee -a /etc/hosts
./setup.sh
python demo/demo.py --resource https://src.local.io/vo-resource \
  --cacert certs/local-ca.pem --client-id-file seed/client_id
# or the Java client:
java demo/Demo.java --resource https://src.local.io/vo-resource \
  --cacert certs/local-ca.pem --client-id-file seed/client_id
```

Success prints: `protected resource data`.
