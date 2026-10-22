#!/usr/bin/env python3
"""
Moved. The AuthVO demo driver lives in test-integration/demo/demo.py (it shares
the discovery checks in test-integration/demo/authvo_checks.py with the other
drivers); this stub just runs it, so `python demo.py ...` from the repo root keeps
working. Arguments are passed through unchanged:

  python demo.py --resource https://src.local.io/vo-resource \
      --cacert test-integration/certs/local-ca.pem \
      --client-id-file test-integration/seed/client_id
"""
import runpy
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent / "test-integration" / "demo"
sys.path.insert(0, str(DEMO_DIR))
sys.argv[0] = str(DEMO_DIR / "demo.py")
runpy.run_path(sys.argv[0], run_name="__main__")
