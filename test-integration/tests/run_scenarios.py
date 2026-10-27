#!/usr/bin/env python3
"""
Live scenario runner for the AuthVO flow (as revised after the ivoa-std/AuthVO PR #23 review).

Runs the REAL clients (authvo_client.py and AuthVoClient.java, unmodified)
against the running harness, auto-approving the device login as a test user, and
prints each client's full output followed by a PASS/FAIL verdict.

Prerequisites
  * the stack is up:   ./setup.sh            (iam/src/evil.local.io in /etc/hosts
                                              -- evil.local.io is optional here,
                                              see below)
  * Python with `requests` (and flask, pyjwt[crypto] for scenario 6)
  * for the Java client: a JDK and the Jackson jars (core, annotations, databind),
    given as a classpath via --java-cp or $AUTHVO_JACKSON_CP

    python tests/run_scenarios.py --java-cp "$JACKSON"          # everything
    python tests/run_scenarios.py --only 2,3 --skip-java        # a subset

Scenarios
  0  preflight: the stack serves what the flow relies on (a PRM generated per request)
  1  happy path (preconfigured client), 1b with dynamic registration, 1c with the
     optional RFC 8693 token exchange switched on
  2  evil resource server (evil.local.io): abort at the resource check
  3  `protected_resources` removed from the augmenter config: abort at the check
  4  PRM `resource` is a different resource: abort at step 2
  5  the PRM URL redirects: abort (redirects are never followed)
  6  resource server: token-validation, PRM and routing cases (unit tests)
  7  variable paths: /vo/tap/async/<random> and a URL with a query. A PRM is generated
     for each, step 2 (exact match) passes, the token is for https://src.local.io/vo
  8  PRM whose `resource` COVERS the requested URL but is not equal to it (the
     pre-review profile accepted it): abort at step 2
  9  AUTHVO_AUDIENCE=domain: a MEASUREMENT (not pass/fail) of what the IAM issues when
     several `resource` parameters are sent (RFC 8707 2)

Every abort scenario also asserts the client stopped BEFORE registration and the
device grant -- i.e. before the user would ever be asked to log in.

If evil.local.io is not in /etc/hosts the runner maps it to 127.0.0.1 for the
client processes only (Python: _client_launcher.py; Java: -Djdk.net.hosts.file).
"""
import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                      # test-integration/
REPO = ROOT.parent
CA = ROOT / "certs" / "local-ca.pem"
AUGMENTER_CFG = ROOT / "augmenter" / "config" / "protected_resources.json"
PAYLOAD = ROOT / "fake-rs" / "protected_resource.txt"

IAM = "https://iam.local.io"
SRC = "https://src.local.io"
EVIL = "https://evil.local.io"
SERVICE = SRC + "/vo"                  # the protected_resources entry for the fake resource server
DATALINK = SRC + "/datalink"           # a second entry: listed, not the one requested
RESOURCE_URL = SERVICE + "/resource"   # the default protected URL
PRM_PREFIX = SRC + "/.well-known/oauth-protected-resource"

BOLD, DIM, GREEN, RED, YELLOW, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"

results = []          # (scenario, client, ok, detail); ok is None for a measurement


# --------------------------------------------------------------------------- #
#  the device-login approver (what a human would do in a browser)             #
# --------------------------------------------------------------------------- #

def approve_device(user_code, username, password):
    """Log in at the IAM and approve the pending device authorization."""
    s = requests.Session()
    s.verify = str(CA)
    s.get(IAM + "/login")                                   # prime the session cookie
    r = s.post(IAM + "/login", data={"username": username, "password": password},
               allow_redirects=False)
    if r.status_code not in (301, 302) or "error" in (r.headers.get("Location") or ""):
        raise RuntimeError(f"approver: login failed for {username}: {r.status_code}")
    s.post(IAM + "/device/verify", data={"user_code": user_code})
    a = s.post(IAM + "/device/approve", data={"user_code": user_code,
                                              "user_oauth_approval": "true",
                                              "authorize": "Authorize"})
    if a.status_code >= 400 or "denied" in a.text.lower():
        raise RuntimeError(f"approver: approval failed: {a.status_code}")
    print(f"    {DIM}[runner] approved device code {user_code} as {username}{RESET}")


# --------------------------------------------------------------------------- #
#  the clients under test                                                     #
# --------------------------------------------------------------------------- #

class Client:
    """A way to launch one of the two reference clients on a URL."""

    def __init__(self, name, argv_for, env):
        self.name, self.argv_for, self.env = name, argv_for, env

    def run(self, url, *, approve, creds, client_id, timeout=240, env_extra=None):
        """Run the client; auto-approve the device login if it asks. -> (rc, output)."""
        env = dict(os.environ, **self.env, **(env_extra or {}))
        env.pop("AUTHVO_CLIENT_ID", None)
        if client_id:
            env["AUTHVO_CLIENT_ID"] = client_id
        p = subprocess.Popen(self.argv_for(url), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        lines, user_code, approved = [], None, False
        try:
            for line in p.stdout:
                lines.append(line)
                print("    | " + line, end="")
                text = line.strip()
                if text.startswith("Open"):
                    q = parse_qs(urlparse(text.split(":", 1)[1].strip()).query)
                    user_code = (q.get("user_code") or [None])[0] or user_code
                elif text.startswith("Enter code"):
                    user_code = text.split(":", 1)[1].strip()
                if approve and not approved and user_code and text.startswith(("Open", "Enter code")):
                    # `Open` may be followed by `Enter code`; approve as soon as we have a code
                    approve_device(user_code, *creds)
                    approved = True
            rc = p.wait()
        finally:
            timer.cancel()
        return rc, "".join(lines)


def resolves(host):
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def build_clients(args):
    """The Python client, and the Java client if we can build it."""
    need_override = not resolves("evil.local.io")
    py_env = {"REQUESTS_CA_BUNDLE": str(CA)}
    if need_override:
        py_env["AUTHVO_TEST_HOSTS"] = "evil.local.io=127.0.0.1"
    clients = [Client("python", lambda u: [sys.executable, str(HERE / "_client_launcher.py"), u], py_env)]

    cp = args.java_cp or os.environ.get("AUTHVO_JACKSON_CP")
    if args.skip_java:
        return clients, "Java client skipped (--skip-java)"
    if not cp:
        return clients, "Java client SKIPPED: no Jackson classpath (--java-cp / $AUTHVO_JACKSON_CP)"
    work = Path(tempfile.mkdtemp(prefix="authvo-java-"))
    out = work / "classes"
    subprocess.run(["javac", "-d", str(out), "-cp", cp, str(REPO / "AuthVoClient.java")], check=True)
    jks = work / "ca.jks"
    subprocess.run(["keytool", "-importcert", "-noprompt", "-alias", "authvo-local", "-file", str(CA),
                    "-keystore", str(jks), "-storepass", "changeit"],
                   check=True, stdout=subprocess.DEVNULL)
    jopts = [f"-Djavax.net.ssl.trustStore={jks}", "-Djavax.net.ssl.trustStorePassword=changeit"]
    if need_override:
        # jdk.net.hosts.file REPLACES the system resolver, so start from /etc/hosts.
        hosts = work / "hosts"
        hosts.write_text(Path("/etc/hosts").read_text() + "\n127.0.0.1 evil.local.io\n")
        jopts.append(f"-Djdk.net.hosts.file={hosts}")
    clients.append(Client("java", lambda u: ["java", *jopts, "-cp", f"{out}{os.pathsep}{cp}",
                                             "org.ivoa.authvo.AuthVoClient", u], {}))
    return clients, None


# --------------------------------------------------------------------------- #
#  assertions                                                                 #
# --------------------------------------------------------------------------- #

# Steps that must NEVER appear in an aborted run: registration, device grant,
# user prompt, token poll, resource access.
NEVER_AFTER_ABORT = ("STEP 4", "STEP 5", "STEP 6", "user action required", "device_authorization")


def record(scenario, client, ok, detail):
    """ok=True/False is a verdict; ok=None records a measurement (no pass/fail)."""
    results.append((scenario, client, ok, detail))
    mark = f"{YELLOW}INFO{RESET}" if ok is None else f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  [{scenario}] {client}: {detail}\n")


def expect_success(scenario, client, rc, out):
    marker = [l.strip() for l in PAYLOAD.read_text().splitlines() if l.strip()][-1]
    ok = rc == 0 and "STEP 6" in out and "SUCCESS" in out and marker in out
    record(scenario, client, ok, "protected payload returned" if ok
           else f"expected success (rc=0, payload); got rc={rc}")


def expect_exchange(scenario, client, rc, out):
    """Success, AND the optional RFC 8693 exchange ran and produced an aud-bound token."""
    marker = [l.strip() for l in PAYLOAD.read_text().splitlines() if l.strip()][-1]
    ok = (rc == 0 and "STEP 5d" in out and marker in out
          and f"exchanged token aud={SERVICE}" in out)
    record(scenario, client, ok, "token exchange ran; exchanged token aud=" + SERVICE if ok
           else f"expected an exchanged, aud-bound token and the payload; got rc={rc}")


def expect_token_for(scenario, client, rc, out, url, audience):
    """Success, AND step 2 passed on an EXACT match, AND the token was asked for `audience`
    (an entry of the IAM's protected_resources) -- never for the requested URL or its query."""
    marker = [l.strip() for l in PAYLOAD.read_text().splitlines() if l.strip()][-1]
    problems = []
    if not (rc == 0 and "SUCCESS" in out and marker in out):
        problems.append(f"expected success and the payload; got rc={rc}")
    if "OK: PRM resource is identical to the requested URL" not in out:
        problems.append("step 2 did not report an exact match")
    wk = PRM_PREFIX + urlparse(url).path
    if f"GET PRM {wk}" not in out:
        problems.append(f"did not fetch the PRM derived from the requested URL ({wk}...)")
    for_lines = re.findall(r"Token is for\s*:\s*(\S+)", out)
    if for_lines != [audience]:
        problems.append(f"'Token is for' lines {for_lines}, expected [{audience}]")
    if urlparse(url).query and urlparse(url).query in "".join(for_lines):
        problems.append("the query leaked into the audience")
    record(scenario, client, not problems,
           f"PRM generated for the request, exact match passed, token for {audience}"
           if not problems else "; ".join(problems))


def expect_abort(scenario, client, rc, out, must_contain):
    problems = []
    if rc != 1:
        problems.append(f"rc={rc}, expected 1")
    if "ABORT:" not in out:
        problems.append("no ABORT line")
    for needle in must_contain:
        if not re.search(needle, out, re.S):
            problems.append(f"missing /{needle}/")
    for step in NEVER_AFTER_ABORT:
        if step in out:
            problems.append(f"went on to '{step}' after the failed check")
    record(scenario, client, not problems,
           "aborted before any login: " + must_contain[0] if not problems else "; ".join(problems))


def header(title):
    print(f"\n{BOLD}{'=' * 74}\n{title}\n{'=' * 74}{RESET}")


# --------------------------------------------------------------------------- #
#  the scenarios                                                              #
# --------------------------------------------------------------------------- #

def s0_preflight(args):
    header("Scenario 0 - preflight: the stack serves what the flow relies on")
    s = requests.Session()
    s.verify = str(CA)
    checks = []

    r = s.get(RESOURCE_URL, allow_redirects=False)
    ptr = re.search(r'resource_metadata="([^"]+)"', r.headers.get("WWW-Authenticate", ""))
    checks.append(("resource: anonymous GET -> 401 + a pointer to the PRM derived from the REQUESTED URL (RFC 9728 3.1)",
                   r.status_code == 401 and ptr and ptr.group(1) == PRM_PREFIX + "/vo/resource"))

    q = "?ID=ivo%3A%2F%2Fsrc.local.io%2Fobs%3Fid%3D42&b=%22q%22"
    r = s.get(RESOURCE_URL + q, allow_redirects=False)
    ptr = re.search(r'resource_metadata="([^"]+)"', r.headers.get("WWW-Authenticate", ""))
    checks.append(("resource: the pointer for a URL with a query keeps the query, byte for byte",
                   r.status_code == 401 and ptr and ptr.group(1) == PRM_PREFIX + "/vo/resource" + q))

    r = s.get(RESOURCE_URL, headers={"Authorization": "Bearer not.a.token"}, allow_redirects=False)
    checks.append(("resource: garbage bearer token -> 401 invalid_token", r.status_code == 401
                   and "invalid_token" in r.headers.get("WWW-Authenticate", "")))

    prm = s.get(PRM_PREFIX + "/vo/resource", allow_redirects=False)
    doc = prm.json() if prm.ok else {}
    checks.append(("resource: PRM resource == the requested URL, issuer == the IAM",
                   doc.get("resource") == RESOURCE_URL and doc.get("authorization_servers") == [IAM + "/"]))

    prm = s.get(PRM_PREFIX + "/vo/resource" + q, allow_redirects=False)
    doc = prm.json() if prm.ok else {}
    checks.append(("resource: the PRM for a URL with a query names that URL, query included (generated per request)",
                   doc.get("resource") == RESOURCE_URL + q))

    r = s.get(PRM_PREFIX + "/elsewhere/x", allow_redirects=False)
    checks.append(("resource: no PRM for a path the service does not own (404)", r.status_code == 404))

    sidecar = s.get(IAM + "/.well-known/oauth-protected-resource", allow_redirects=False)
    checks.append(("IAM origin does not serve a PRM sidecar (404)", sidecar.status_code == 404))

    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        r = s.get(IAM + path, allow_redirects=False)
        d = r.json() if r.ok else {}
        listed = d.get("protected_resources") or []
        checks.append((f"IAM {path}: 200, issuer=https://iam.local.io/, protected_resources lists the service AND a second entry",
                       r.ok and d.get("issuer") == IAM + "/" and SERVICE in listed and DATALINK in listed))
        checks.append((f"IAM {path}: still carries the IAM's own endpoints",
                       bool(d.get("token_endpoint") and d.get("device_authorization_endpoint")
                            and d.get("jwks_uri"))))

    ok = True
    for text, passed in checks:
        ok &= bool(passed)
        print(f"  {GREEN + 'ok  ' if passed else RED + 'FAIL'}{RESET}  {text}")
    record("0", "stack", ok, "preflight " + ("ok" if ok else "FAILED -- is the stack up (./setup.sh)?"))
    return ok


def run_each(clients, scenario, url, *, approve, creds, client_id, check, env_extra=None):
    for c in clients:
        print(f"{BOLD}--- {c.name} client{RESET}")
        rc, out = c.run(url, approve=approve, creds=creds, client_id=client_id, env_extra=env_extra)
        check(scenario, c.name, rc, out)


def s1_happy(args, clients, creds, cid):
    header("Scenario 1 - happy path: both clients return the protected payload")
    run_each(clients, "1", RESOURCE_URL, approve=True, creds=creds, client_id=cid,
             check=expect_success)
    header("Scenario 1b - happy path with dynamic client registration (no preconfigured client_id)")
    run_each(clients, "1b", RESOURCE_URL, approve=True, creds=creds, client_id=None,
             check=expect_success)
    header("Scenario 1c - OPTIONAL token exchange switched on (AUTHVO_TOKEN_EXCHANGE=1): aud-bound token")
    print(f"{DIM}INDIGO 1.10 ignores the `resource` indicator (no aud in the token above); the exchange is how "
          f"an aud-bound token is obtained.{RESET}")
    run_each(clients, "1c", RESOURCE_URL, approve=True, creds=creds, client_id=cid,
             check=expect_exchange, env_extra={"AUTHVO_TOKEN_EXCHANGE": "1"})


def s2_evil(args, clients, creds, cid):
    header("Scenario 2 - evil resource server: aborts at the resource check, before any login")
    print(f"{DIM}evil.local.io's PRM names the REAL IAM; the IAM does not list evil.local.io.{RESET}")
    run_each(clients, "2", EVIL + "/vo/resource", approve=True, creds=creds, client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"STEP 3 FAILED", r"check \(b\)", r"evil\.local\.io"]))


def s3_list_removed(args, clients, creds, cid):
    header("Scenario 3 - protected_resources removed from the augmenter config: aborts at the check")
    original = AUGMENTER_CFG.read_text()
    try:
        AUGMENTER_CFG.write_text("{}\n")
        r = requests.get(IAM + "/.well-known/oauth-authorization-server", verify=str(CA))
        gone = "protected_resources" not in r.json()
        print(f"  {DIM}[runner] augmenter config emptied; IAM metadata now has no protected_resources: {gone}{RESET}")
        if not gone:
            record("3", "stack", False, "the augmenter did not pick up the config change")
            return
        run_each(clients, "3", RESOURCE_URL, approve=True, creds=creds, client_id=cid,
                 check=lambda sc, cl, rc, out: expect_abort(
                     sc, cl, rc, out, [r"STEP 3 FAILED", r"no protected_resources"]))
    finally:
        AUGMENTER_CFG.write_text(original)
        r = requests.get(IAM + "/.well-known/oauth-authorization-server", verify=str(CA))
        print(f"  {DIM}[runner] augmenter config restored; protected_resources back: "
              f"{'protected_resources' in r.json()}{RESET}")


def s4_not_covering(args, clients, creds, cid):
    header("Scenario 4 - PRM resource is a different resource: aborts at step 2")
    run_each(clients, "4", SERVICE + "/faults/prm-not-covering/resource", approve=True, creds=creds,
             client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"STEP 2 FAILED", r"some-other-service"]))


def s5_redirect(args, clients, creds, cid):
    header("Scenario 5 - the PRM URL redirects: the client refuses to follow")
    print(f"{DIM}The redirect target is a perfectly good PRM, so a client that followed it would proceed.{RESET}")
    run_each(clients, "5", SERVICE + "/faults/prm-redirect/resource", approve=True, creds=creds,
             client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"redirect", r"refusing to follow"]))


def s6_resource_server(args, clients, creds, cid):
    header("Scenario 6 - resource server: token validation, per-request PRM, ownership, fixtures")
    p = subprocess.run([sys.executable, "-m", "unittest", "-v", str(HERE / "test_fake_rs.py")],
                       capture_output=True, text=True)
    print("\n".join("    | " + l for l in (p.stdout + p.stderr).splitlines()))
    record("6", "fake-rs", p.returncode == 0,
           "unit tests passed" if p.returncode == 0 else "unit tests FAILED")


def s7_variable_paths(args, clients, creds, cid):
    header("Scenario 7 - variable paths: a PRM is generated per request, the token is for the service")
    print(f"{DIM}One handler answers every /.well-known/oauth-protected-resource/vo/... URL; the IAM still lists one "
          f"identifier ({SERVICE}). The PRM resource is the requested URL; the token is NOT.{RESET}")
    job = SERVICE + "/tap/async/" + uuid.uuid4().hex[:12]
    with_query = SERVICE + "/datalink/links?ID=ivo%3A%2F%2Fsrc.local.io%2Fobs%3Fid%3D42&b=2"
    for url in (job, with_query):
        print(f"\n{BOLD}requested URL: {url}{RESET}")
        run_each(clients, "7", url, approve=True, creds=creds, client_id=cid,
                 check=lambda sc, cl, rc, out, u=url: expect_token_for(sc, cl, rc, out, u, SERVICE))


def s8_covering_prm(args, clients, creds, cid):
    header("Scenario 8 - PRM resource COVERS the requested URL but is not equal to it: aborts at step 2")
    print(f"{DIM}The pre-review profile accepted this PRM (resource {SERVICE}); RFC 9728 3.3 does not.{RESET}")
    run_each(clients, "8", SERVICE + "/faults/prm-covering/resource", approve=True, creds=creds,
             client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"STEP 2 FAILED", r"not identical", re.escape(SERVICE)]))


def jwt_claims(token):
    """The (unverified) payload of a JWT, or None if the token is not one. Measurement only."""
    try:
        body = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:
        return None


def probe_token(resources, creds, cid):
    """Run the device grant by hand, sending `resource` once per entry on BOTH requests, and
    return the token response. A measurement probe: it states what the IAM does with the values."""
    s = requests.Session()
    s.verify = str(CA)
    meta = s.get(IAM + "/.well-known/openid-configuration").json()
    rp = [("resource", r) for r in resources]
    dev = s.post(meta["device_authorization_endpoint"],
                 data=[("client_id", cid), ("scope", "openid vo.read")] + rp).json()
    if "user_code" not in dev:
        return {"error": "device authorization refused", "detail": dev}
    try:
        approve_device(dev["user_code"], *creds)
    except RuntimeError as e:
        # e.g. INDIGO >= 1.12 refuses a resource with a query only when the user opens the consent
        # page (`invalid_target`): the device authorization request itself is accepted.
        v = requests.Session()
        v.verify = str(CA)
        v.get(IAM + "/login")
        v.post(IAM + "/login", data={"username": creds[0], "password": creds[1]}, allow_redirects=False)
        why = v.post(IAM + "/device/verify", data={"user_code": dev["user_code"]})
        return {"error": "approval refused", "detail": why.text[:240], "approver": str(e)}
    deadline = time.time() + 120
    while time.time() < deadline:
        time.sleep(int(dev.get("interval", 5)))
        r = s.post(meta["token_endpoint"], data=[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", dev["device_code"]), ("client_id", cid)] + rp)
        doc = r.json()
        if r.status_code == 200:
            return doc
        if doc.get("error") not in ("authorization_pending", "slow_down"):
            return doc
    return {"error": "timeout"}


def iam_version():
    """The IAM image tag the stack runs (what the measurement applies to)."""
    try:
        # whichever compose project is up: find its `iam` service container by label
        out = subprocess.run(["docker", "ps", "--filter", "label=com.docker.compose.service=iam",
                              "--format", "{{.Image}}"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip().replace("\n", ", ") or "unknown"
    except Exception:
        return "unknown"


def s9_domain_audience(args, clients, creds, cid):
    header("Scenario 9 - AUTHVO_AUDIENCE=domain: MEASURE what the IAM issues for several `resource` parameters")
    version = iam_version()
    print(f"{DIM}Not a pass/fail test. IAM image: {version}. The clients send resource={SERVICE} and "
          f"resource={DATALINK} (two parameters, RFC 8707 2) on the device authorization AND the token request.{RESET}")

    def measured(sc, cl, rc, out):
        prompts = re.findall(r"Token is for\s*:\s*(\S+)|^\s+:\s*(\S+)$", out, re.M)
        entries = [a or b for a, b in prompts]
        sent = re.search(r"polling token endpoint \(resource=\[?([^\n]*?)\]?\)", out)
        aud = re.search(r"access token aud=(\S.*)", out)
        opaque = "opaque" in out
        sent_both = bool(sent) and SERVICE in sent.group(1) and DATALINK in sent.group(1)
        ok_flow = rc == 0 and "SUCCESS" in out
        detail = (f"client sent both entries on the token request: {sent_both}; prompt listed {entries}; "
                  f"flow {'completed' if ok_flow else 'did NOT complete (rc=%s)' % rc}; "
                  f"{'aud=' + aud.group(1).split(' (informational')[0].strip() if aud else 'no aud in the access token' + (' (opaque)' if opaque else '')}")
        record(sc, cl, None if (sent_both and entries == [SERVICE, DATALINK]) else False, detail)

    run_each(clients, "9", RESOURCE_URL, approve=True, creds=creds, client_id=cid,
             check=measured, env_extra={"AUTHVO_AUDIENCE": "domain"})

    print(f"\n{BOLD}direct probe (the IAM's own answer, decoded; same user, same client){RESET}")
    volatile = {"jti", "iat", "exp", "nbf", "auth_time"}
    rows = []
    for label, res in (("no resource", []), ("one resource", [SERVICE]), ("two resources", [SERVICE, DATALINK])):
        doc = probe_token(res, creds, cid)
        claims = jwt_claims(doc.get("access_token", "")) or {}
        rows.append((label, doc, claims))
        print(f"    {label:<14} token_type={doc.get('token_type')}  scope={doc.get('scope')!r}  "
              f"aud={claims.get('aud', '<absent>')}  claims={sorted(claims)}"
              if "access_token" in doc else f"    {label:<14} {doc}")
    stable = [{k: v for k, v in c.items() if k not in volatile} for _, d, c in rows if c]
    same = len(stable) == 3 and all(x == stable[0] for x in stable)
    any_aud = [c.get("aud") for _, d, c in rows if c]
    # Extra, informational probes: ordering, an unlisted value, a query, and (only to MEASURE the
    # IAM -- the clients never send it) one space-separated value, which is not RFC 8707.
    print(f"\n{BOLD}more probes (what the IAM does with each shape of `resource`){RESET}")
    extra = (("[service, datalink]  (the clients' order)", [SERVICE, DATALINK]),
             ("[datalink, service]  (reversed)", [DATALINK, SERVICE]),
             ("[service, datalink, unlisted]", [SERVICE, DATALINK, "https://other.example/x"]),
             ("one UNLISTED value", ["https://other.example/x"]),
             ("one value WITH a query", [RESOURCE_URL + "?ID=ivo%3A%2F%2Fx"]),
             ("ONE space-separated value (not RFC 8707)", [SERVICE + " " + DATALINK]))
    for label, res in extra:
        doc = probe_token(res, creds, cid)
        if "access_token" in doc:
            aud = (jwt_claims(doc["access_token"]) or {}).get("aud", "<absent>")
            line = f"aud={aud}"
        else:
            line = f"no token: {doc.get('error')} {doc.get('detail', '')}"
        print(f"    {label:<44} -> {line}")
        record("9", "iam-probe", None, f"{label} -> {line}")
    summary = (f"IAM {version}: claims identical (apart from jti/iat/exp) for none/one/two `resource` values: {same}; "
               f"aud per probe: {any_aud}")
    print(f"  {summary}")
    record("9", "iam-probe", None, summary)


SCENARIOS = {"0": None, "1": s1_happy, "2": s2_evil, "3": s3_list_removed,
             "4": s4_not_covering, "5": s5_redirect, "6": s6_resource_server,
             "7": s7_variable_paths, "8": s8_covering_prm, "9": s9_domain_audience}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated scenario numbers (default: all)")
    ap.add_argument("--java-cp", help="Jackson classpath for the Java client")
    ap.add_argument("--skip-java", action="store_true")
    ap.add_argument("--username", default="vouser")
    ap.add_argument("--password", default="vouser")
    args = ap.parse_args()
    wanted = set((args.only or "0,1,2,3,4,5,6,7,8,9").split(","))

    cid = (ROOT / "seed" / "client_id").read_text().strip()
    creds = (args.username, args.password)
    clients, note = build_clients(args)
    if note:
        print(f"{YELLOW}{note}{RESET}")

    if "0" in wanted and not s0_preflight(args):
        print(f"{RED}preflight failed; stopping.{RESET}")
        return 1
    for n in sorted(wanted - {"0"}):
        SCENARIOS[n](args, clients, creds, cid)

    header("Summary")
    for sc, cl, ok, detail in results:
        tag = f"{YELLOW}INFO" if ok is None else f"{GREEN}PASS" if ok else f"{RED}FAIL"
        print(f"  {tag}{RESET}  scenario {sc:<3} {cl:<8} {detail}")
    verdicts = [r for r in results if r[2] is not None]
    failed = [r for r in verdicts if not r[2]]
    print(f"\n  {len(verdicts) - len(failed)}/{len(verdicts)} passed"
          f"   ({len(results) - len(verdicts)} measurement(s) recorded, not counted)"
          + (f"   ({note})" if note else ""))
    if failed:
        return 1
    return 3 if note and "SKIPPED" in note else 0


if __name__ == "__main__":
    sys.exit(main())
