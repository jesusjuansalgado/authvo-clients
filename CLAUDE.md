# AuthVO clients & integration harness — context for Claude Code

This repository holds the two reference AuthVO clients (`authvo_client.py`,
`AuthVoClient.java`) and `test-integration/`, a self-contained local environment for
exercising the **AuthVO bearer-token flow** end to end against a real INDIGO IAM.
This file is the handoff so you have full context.

## What AuthVO is (background)

IVOA (astronomy / Virtual Observatory) work on securing data services with
OAuth2/OIDC bearer tokens. The core problem ("the evil service"): plain OAuth
doesn't tell a client *which* server a freshly-issued token may be sent to, so a
malicious resource server can name a **real** issuer and lure the user into
obtaining a real token for it. The agreed direction — as revised by
[AuthVO issue #22](https://github.com/ivoa-std/AuthVO/issues/22) — follows
**RFC 9728**:

- The resource server's `401` returns **only a pointer** (`resource_metadata`) to
  its **own** Protected Resource Metadata (PRM), published at its own well-known
  URL. The pointer is untrusted; the PRM's `resource` must **cover the requested
  URL** (equal to it, or same origin and a path extending it at a segment
  boundary).
- The binding between resource and issuer is checked from the **issuer's** side
  (the **resource check**): its RFC 8414 metadata must carry the same `issuer` the
  PRM named *and* list the resource in **`protected_resources`** (RFC 9728 §4 defines it as
  optional; the AuthVO draft §3.3.1 makes it mandatory).
  An **absent** list is a failure, not a pass. This happens before any login.
- The client uses the device grant and sends `resource=<matched id>` (RFC 8707).
  RFC 8693 token exchange is **optional, off by default**. The resource server
  enforces signature, `iss`, `vo.read`, expiry, and `aud` **only when present**.
- No discovery request, nor any request carrying a bearer token, follows a redirect.

## What's in here

| Path | Role |
|------|------|
| `authvo_client.py` / `AuthVoClient.java` | The two reference clients — **identical behaviour**; change both together |
| `test-integration/docker-compose.yml` | Whole stack behind Traefik |
| `test-integration/iam/iam.env` | INDIGO IAM config (the authorization server; **never modify INDIGO**) |
| `test-integration/augmenter/` | **Metadata augmenter** (Python, stdlib): adds `protected_resources` to the IAM's `/.well-known/oauth-authorization-server` and `/openid-configuration`. An **interim emulation** — delete it (and its Traefik router) once INDIGO publishes the member |
| `test-integration/augmenter/config/protected_resources.json` | Resource ids the augmenter publishes (read per request) |
| `test-integration/traefik/traefik.yml` | Proxy + TLS; the two metadata paths go to the augmenter at priority 100 |
| `test-integration/fake-rs/app.py` | Protected REST service (Flask): 401 + pointer, **serves its own PRM**, JWT checks; also the "evil" instance and the `RS_TEST_FAULTS` discovery fixtures |
| `test-integration/seed/provision.sh` | Provisions the IAM (scope, users, `authvo-client`) |
| `test-integration/demo/` | Reference (`demo.py`), non-interactive (`auto_demo.py`) and guided (`human_demo.py`, `HumanDemo.java`) drivers; shared checks in `authvo_checks.py` |
| `test-integration/tests/` | Offline unit tests + `run_scenarios.py` (real clients vs. the live stack) |
| `test-integration/setup.sh` | Generates certs + Traefik dynamic config, brings it up, provisions |

## Conventions

- **Python is the default for everything.** Java exists for the second reference
  client (`AuthVoClient.java`) and the Java demo twins; don't add further Java, and
  ask before adding dependencies beyond what's already used.
- Hostnames `iam.local.io`, `src.local.io` (and `evil.local.io` for the negative
  test) must be in `/etc/hosts` and are served by one Traefik on `:443`.
- **Don't reintroduce "IAM and the PRM must share an origin".** That was the old
  domain-proxy design. The security argument is the resource check (above), not
  where a document is hosted.
- **RFC conformance:** coverage instead of RFC 9728 §3.3's exact match, a mandatory
  `protected_resources` and `aud`-only-when-present are *deliberate AuthVO-profile departures*
  (README §15). Never cite RFC 9728 §3.3 as the basis of the coverage rule, and RFC 9207
  does not apply to the device grant.
- The two clients must stay behaviourally identical; the URL-coverage rules are
  pinned for both by `test-integration/tests/coverage_vectors.json`.

## Verifying

```bash
python -m unittest discover -s test-integration/tests -p "test_*.py"   # offline (needs requests, flask, pyjwt[crypto])
# Java offline tests + the live scenarios: see README.md §10
python test-integration/tests/run_scenarios.py --java-cp "$JACKSON"    # needs the stack up
```

The scenarios: happy path, evil RS, `protected_resources` removed, PRM not covering,
PRM redirect, resource-server token cases. Each abort scenario also asserts the
client stopped before registration / the device grant.

## Open tasks (likely next steps)

1. **Wire the drivers to the real clients.** The demos reimplement the flow
   (standalone reference drivers); they could call into `authvo_client.py` /
   `AuthVoClient.java` instead.
2. **Pin Traefik** (currently `traefik:v3.1`): its bundled Docker client requests
   API 1.24, which Docker Engine ≥ 29 refuses (the proxy then 404s every request).
3. Remove the **augmenter** once INDIGO IAM publishes `protected_resources`.
4. Refresh (step 7 of the flow) is not implemented in the reference clients; it
   should re-send the same `resource`.

## Run it

```bash
echo "127.0.0.1  iam.local.io src.local.io evil.local.io" | sudo tee -a /etc/hosts
cd test-integration && ./setup.sh
python demo/demo.py --resource https://src.local.io/vo-resource \
  --cacert certs/local-ca.pem --client-id-file seed/client_id
# or the Java demo:
java demo/Demo.java --resource https://src.local.io/vo-resource \
  --cacert certs/local-ca.pem --client-id-file seed/client_id
```

Success prints the protected payload. Full details: `README.md`.
