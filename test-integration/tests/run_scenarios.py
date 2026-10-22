#!/usr/bin/env python3
"""
Live scenario runner for the AuthVO issue-#22 flow.

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
  0  preflight: the stack serves what the flow relies on
  1  happy path (preconfigured client), then 1b with dynamic registration
  2  evil resource server (evil.local.io): abort at the resource check
  3  `protected_resources` removed from the augmenter config: abort at the check
  4  PRM `resource` does not cover the requested URL: abort at step 2
  5  the PRM URL redirects: abort (redirects are never followed)
  6  resource server: the six token-validation cases (unit tests)

Every abort scenario also asserts the client stopped BEFORE registration and the
device grant -- i.e. before the user would ever be asked to log in.

If evil.local.io is not in /etc/hosts the runner maps it to 127.0.0.1 for the
client processes only (Python: _client_launcher.py; Java: -Djdk.net.hosts.file).
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
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

BOLD, DIM, GREEN, RED, YELLOW, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"

results = []          # (scenario, client, ok, detail)


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

    def run(self, url, *, approve, creds, client_id, timeout=240):
        """Run the client; auto-approve the device login if it asks. -> (rc, output)."""
        env = dict(os.environ, **self.env)
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
    results.append((scenario, client, ok, detail))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  [{scenario}] {client}: {detail}\n")


def expect_success(scenario, client, rc, out):
    marker = [l.strip() for l in PAYLOAD.read_text().splitlines() if l.strip()][-1]
    ok = rc == 0 and "STEP 6" in out and "SUCCESS" in out and marker in out
    record(scenario, client, ok, "protected payload returned" if ok
           else f"expected success (rc=0, payload); got rc={rc}")


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

    r = s.get(SRC + "/vo-resource", allow_redirects=False)
    ptr = re.search(r'resource_metadata="([^"]+)"', r.headers.get("WWW-Authenticate", ""))
    checks.append(("resource: anonymous GET -> 401 + resource_metadata pointer to its OWN PRM",
                   r.status_code == 401 and ptr and ptr.group(1) == SRC + "/.well-known/oauth-protected-resource"))

    r = s.get(SRC + "/vo-resource", headers={"Authorization": "Bearer not.a.token"}, allow_redirects=False)
    checks.append(("resource: garbage bearer token -> 401 invalid_token", r.status_code == 401
                   and "invalid_token" in r.headers.get("WWW-Authenticate", "")))

    prm = s.get(SRC + "/.well-known/oauth-protected-resource", allow_redirects=False)
    doc = prm.json() if prm.ok else {}
    checks.append(("resource: PRM served by the resource server, resource=https://src.local.io, issuer=IAM",
                   doc.get("resource") == SRC and doc.get("authorization_servers") == [IAM + "/"]))

    sidecar = s.get(IAM + "/.well-known/oauth-protected-resource", allow_redirects=False)
    checks.append(("IAM origin no longer serves a PRM sidecar (404)", sidecar.status_code == 404))

    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        r = s.get(IAM + path, allow_redirects=False)
        d = r.json() if r.ok else {}
        checks.append((f"IAM {path}: 200, issuer=https://iam.local.io/, protected_resources lists src",
                       r.ok and d.get("issuer") == IAM + "/" and SRC in (d.get("protected_resources") or [])))
        checks.append((f"IAM {path}: still carries the IAM's own endpoints",
                       bool(d.get("token_endpoint") and d.get("device_authorization_endpoint")
                            and d.get("jwks_uri"))))

    ok = True
    for text, passed in checks:
        ok &= bool(passed)
        print(f"  {GREEN + 'ok  ' if passed else RED + 'FAIL'}{RESET}  {text}")
    record("0", "stack", ok, "preflight " + ("ok" if ok else "FAILED -- is the stack up (./setup.sh)?"))
    return ok


def run_each(clients, scenario, url, *, approve, creds, client_id, check):
    for c in clients:
        print(f"{BOLD}--- {c.name} client{RESET}")
        rc, out = c.run(url, approve=approve, creds=creds, client_id=client_id)
        check(scenario, c.name, rc, out)


def s1_happy(args, clients, creds, cid):
    header("Scenario 1 - happy path: both clients return the protected payload")
    run_each(clients, "1", SRC + "/vo-resource", approve=True, creds=creds, client_id=cid,
             check=expect_success)
    header("Scenario 1b - happy path with dynamic client registration (no preconfigured client_id)")
    run_each(clients, "1b", SRC + "/vo-resource", approve=True, creds=creds, client_id=None,
             check=expect_success)


def s2_evil(args, clients, creds, cid):
    header("Scenario 2 - evil resource server: aborts at the resource check, before any login")
    print(f"{DIM}evil.local.io's PRM names the REAL IAM; the IAM does not list evil.local.io.{RESET}")
    run_each(clients, "2", EVIL + "/vo-resource", approve=True, creds=creds, client_id=cid,
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
        run_each(clients, "3", SRC + "/vo-resource", approve=True, creds=creds, client_id=cid,
                 check=lambda sc, cl, rc, out: expect_abort(
                     sc, cl, rc, out, [r"STEP 3 FAILED", r"no protected_resources"]))
    finally:
        AUGMENTER_CFG.write_text(original)
        r = requests.get(IAM + "/.well-known/oauth-authorization-server", verify=str(CA))
        print(f"  {DIM}[runner] augmenter config restored; protected_resources back: "
              f"{'protected_resources' in r.json()}{RESET}")


def s4_not_covering(args, clients, creds, cid):
    header("Scenario 4 - PRM resource does not cover the requested URL: aborts at step 2")
    run_each(clients, "4", SRC + "/faults/prm-not-covering/vo-resource", approve=True, creds=creds,
             client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"STEP 2 FAILED", r"some-other-service"]))


def s5_redirect(args, clients, creds, cid):
    header("Scenario 5 - the PRM URL redirects: the client refuses to follow")
    print(f"{DIM}The redirect target is a perfectly good PRM, so a client that followed it would proceed.{RESET}")
    run_each(clients, "5", SRC + "/faults/prm-redirect/vo-resource", approve=True, creds=creds,
             client_id=cid,
             check=lambda sc, cl, rc, out: expect_abort(
                 sc, cl, rc, out, [r"redirect", r"refusing to follow"]))


def s6_resource_server(args, clients, creds, cid):
    header("Scenario 6 - resource server: the six token-validation cases (+ PRM, fixtures)")
    p = subprocess.run([sys.executable, "-m", "unittest", "-v", str(HERE / "test_fake_rs.py")],
                       capture_output=True, text=True)
    print("\n".join("    | " + l for l in (p.stdout + p.stderr).splitlines()))
    record("6", "fake-rs", p.returncode == 0,
           "unit tests passed" if p.returncode == 0 else "unit tests FAILED")


SCENARIOS = {"0": None, "1": s1_happy, "2": s2_evil, "3": s3_list_removed,
             "4": s4_not_covering, "5": s5_redirect, "6": s6_resource_server}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated scenario numbers (default: all)")
    ap.add_argument("--java-cp", help="Jackson classpath for the Java client")
    ap.add_argument("--skip-java", action="store_true")
    ap.add_argument("--username", default="vouser")
    ap.add_argument("--password", default="vouser")
    args = ap.parse_args()
    wanted = set((args.only or "0,1,2,3,4,5,6").split(","))

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
        print(f"  {GREEN + 'PASS' if ok else RED + 'FAIL'}{RESET}  scenario {sc:<3} {cl:<8} {detail}")
    failed = [r for r in results if not r[2]]
    print(f"\n  {len(results) - len(failed)}/{len(results)} passed"
          + (f"   ({note})" if note else ""))
    if failed:
        return 1
    return 3 if note and "SKIPPED" in note else 0


if __name__ == "__main__":
    sys.exit(main())
