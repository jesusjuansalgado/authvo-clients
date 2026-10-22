#!/usr/bin/env python3
"""
Run authvo_client.py unchanged, optionally with extra host-name mappings.

  AUTHVO_TEST_HOSTS="evil.local.io=127.0.0.1" python _client_launcher.py <url>

run_scenarios.py uses this so the negative test can reach evil.local.io on a
machine whose /etc/hosts does not (yet) list it. Only name RESOLUTION is
redirected: TLS still verifies the certificate against the original host name,
so this changes nothing about what the client checks.
"""
import os
import runpy
import socket
import sys
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[2] / "authvo_client.py"

overrides = dict(kv.split("=", 1)
                 for kv in os.environ.get("AUTHVO_TEST_HOSTS", "").split(",") if kv)
if overrides:
    _real_getaddrinfo = socket.getaddrinfo

    def _getaddrinfo(host, *args, **kwargs):
        return _real_getaddrinfo(overrides.get(host, host), *args, **kwargs)

    socket.getaddrinfo = _getaddrinfo

sys.argv = [str(CLIENT)] + sys.argv[1:]
runpy.run_path(str(CLIENT), run_name="__main__")
