#!/usr/bin/env python3
"""Offline, deterministic tests for passive_web_probe.py.

Stands up a REAL loopback HTTP server and a REAL loopback HTTPS server (embedded
self-signed cert — no openssl/network at runtime), points a surface/v2 fixture at
them, runs the probe, then runs enumerate_cells + coverage_gate and asserts the
gate's own verdict. No traffic ever leaves 127.0.0.1.

Variants covered:
  * happy path  -> the 8 mechanical cells are covered_negative and the gate PASSES
                   them (not in missing_cells), with ZERO artifacts/validated/.
  * --no-nmap   -> WEB-A06-COMPONENTS becomes a limitation, cell left OPEN.
  * missing CSP -> XC-SECURITY-HEADERS emits a finding, cell left OPEN.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PROBE = os.path.join(HERE, "passive_web_probe.py")
ENUM = os.path.join(HERE, "enumerate_cells.py")
GATE = os.path.join(HERE, "coverage_gate.py")
HAVE_NMAP = bool(shutil.which("nmap"))

# Long-lived self-signed cert (CN=127.0.0.1, SAN IP:127.0.0.1) embedded so the
# test needs no openssl at runtime and never touches the network.
_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUd379Ia/EwHxZNkiCyrtWdwUgKEkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDcxMzEwNTkxNloXDTQ2MDcw
ODEwNTkxNlowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAw35YXCd9jFN9vUyPffqcEG3MyHzxoHWjBI2cbDXFArzJ
xO4EQHOqY6I2xTfNOmMncBs+Qpm/iKtFeAjUS1U+fgfZua2H1JdLbbiiNYJ2D4Ov
XOv7woeosuZ3ydUNzF2MS+mtMXXCl0N+0pCXaStUlu82TF6GxNGB/2zDAymkKFV7
iyy6aLCP7g0uW0v1SYFBsfX2sIw0IVDiXJ0W4ewKYfQkf2tvz3HfLFhgyIY3xaZD
MgT3pL+UtquoU8iBI9pLYzdYcxnXE/eu47ahjC2iHI69ZCT+S84EUFXzgwZkk917
1Vcp9JpQiNoyUWExbg5fX3gNvuSen/cMT/matXZZbQIDAQABo2QwYjAdBgNVHQ4E
FgQUGeXc4kWht+MaixCBglPjXMaobeowHwYDVR0jBBgwFoAUGeXc4kWht+MaixCB
glPjXMaobeowDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQAfRki4KSq0QzaqhliL/wMdMuGTGiHJexT+Sxz1sszjXSn3
kvrynbdk+G+ajPI7HmJtP+y/8SmPZmAwHtK6GyIxmc2llo5PDtFs4jJcoW0XOTAv
PDvmLWJH8BXgIITsDfRKJK7p3VHIFvE3Ub2L+e0blgP3LcWEaIpokhjuIuF223F6
Xv9/yOHo8mqMBDofnnURi76doOL5VWXJa/ChzQUvWSswV7afb5gF8JzyqY93YX8g
nZmLl8AvMwzBTN39RvW6qaa9RBCOfIFdBs/VyCQb11NhGWe4fFHu8BRHLKhXxTuZ
kUHe8NtDM/YST1I+YQsaIxqYWoDeBbmo/jjD3K2s
-----END CERTIFICATE-----
"""
_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDflhcJ32MU329
TI99+pwQbczIfPGgdaMEjZxsNcUCvMnE7gRAc6pjojbFN806YydwGz5Cmb+Iq0V4
CNRLVT5+B9m5rYfUl0ttuKI1gnYPg69c6/vCh6iy5nfJ1Q3MXYxL6a0xdcKXQ37S
kJdpK1SW7zZMXobE0YH/bMMDKaQoVXuLLLposI/uDS5bS/VJgUGx9fawjDQhUOJc
nRbh7Aph9CR/a2/Pcd8sWGDIhjfFpkMyBPekv5S2q6hTyIEj2ktjN1hzGdcT967j
tqGMLaIcjr1kJP5LzgRQVfODBmST3XvVVyn0mlCI2jJRYTFuDl9feA2+5J6f9wxP
+Zq1dlltAgMBAAECggEADepH4Tz6xErLGyoNPeZHrPZ/Cmq0vkgXuikkUCJRq1y2
lfrSBagJO4qEqh9LNe09FbWl7F99d5dAj7pwXHGTmN/3lC5kcHImfDrItqHAxC29
uHg5ruj+GpUQdybgEqk6ZWSB0sPzMNYs+4SV3amoBA7AVC/kTIBgzizqAqce2E00
h0BLfWODUrt44FP2QbLVYJD3EwBrH5rxly7W4VCBq+U+ROechQD2UZCr4H1fnMLj
k9xAho30JtaukxvwaGDCdiEvBLqz7zRLIEqzGxroypa4ow96dKGuyvVLmSqatdsD
zCs92m9lOwPvs7APCzuTmJFGIROQrpRXEH/JeNKWVwKBgQD61w7wxgFX6lYBrlrP
gLZR6CiF2KmhsTGfeFRCXZF7v24nQBUsrxFKnvTmJUSY8MbZ4R+JuhKczljaQewj
MsxhlA8hnlVx7QzL3OMyTh4Om7xMO1kA/zQvZvSs7gGWWAFvWLVdzchPVdAa5BVv
YrCOF+BPdhw2eRPKZodYvl+bmwKBgQDHg9P4Fy3cJBJhkoby3YPhz5b9G4tgCAPY
MlXxR/NJ5nCDEIhb4vV6tAuOjLART3my0n/wXHSGrw52+p/vOXexnsvTFvy35Bz0
rRwuS01TM+6Qx/EkE05mkP0gOuMbOWke2vnadafAJYC7K5v12Bkw6yFuoyDwLOPh
c2l9YYhDlwKBgEf+lcExc41CKvFMk6/e53VWxtqztuw7qVx18ukhZfI4nWsSj4FF
thbOzMeJhsjGwqwiWyTyjQkIiKQMK7RmjharojQp96g9O2D/ww3bMfFLbZ4Lop4Q
oW/BgxRnM3ltROwqb9O+jnGG1bYCJMzVbIs7+xuTcMGJus5q4wnrihFlAoGBAJ3O
C05jJwbEETXTq6FUzAdDJm2z551hOYk65vccrbV56uv/m5rx/K+80JdDd895SQzD
qiX3OsN8mrhIq0+P6Lg4nYas296nMq/kbDHBpbt1i/A/9N9P1ecSLuPbL95MnnSl
RpIgFTrJbvScHZNqBSLIF31m0ZqmJugfXQSqrBipAoGAb4MgHQZwM0U+zn1ye/zu
Kwx/fsJPgkN7j+PNLe0Fqflg1EF615ORTQbY2xgOeAPjM3vJ8Km76OKUu8QGP3oJ
PyikmZ4sQK+fqdK2jxAhREk9cG/paVLC0REx6KeeRvMgju/13gqVlBZ1t/iEty/Q
5xTRLUFHZTLMqVNWa9VgZyE=
-----END PRIVATE KEY-----
"""


# --- controllable loopback servers -------------------------------------------
def make_handler(omit_csp: bool):
    class Handler(BaseHTTPRequestHandler):
        def _headers(self, code, length, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Server", "TestServer/1.0")
            self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            if not omit_csp:
                self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()

        def _route(self):
            path = urlparse(self.path).path
            if path == "/app.js":
                return 200, b"console.log('hello world, nothing secret here');", "application/javascript"
            if path == "/" or path == "/api":
                return 200, b"<html><body>ok</body></html>", "text/html"
            return 404, b"Not Found", "text/plain"  # plain 404, no stack trace

        def do_GET(self):
            code, body, ctype = self._route()
            self._headers(code, len(body), ctype)
            self.wfile.write(body)

        def do_HEAD(self):
            code, body, ctype = self._route()
            self._headers(code, len(body), ctype)

        def log_message(self, *a):
            pass

    return Handler


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # nmap's version probes reset connections on purpose — don't log


def start_server(omit_csp=False, tls=False, certfile=None):
    httpd = _QuietServer(("127.0.0.1", 0), make_handler(omit_csp))
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


# --- fixture + tool runners --------------------------------------------------
def write_surface(asset_dir, tag, http_port, https_port):
    units = [
        {"unit_id": "u1", "type": "endpoint", "address": f"http://127.0.0.1:{http_port}/api", "server": "TestServer/1.0"},
        {"unit_id": "u2", "type": "endpoint", "address": f"https://127.0.0.1:{https_port}/api", "server": "TestServer/1.0", "tls": True},
        {"unit_id": "u3", "type": "page", "address": f"http://127.0.0.1:{http_port}/app.js"},
    ]
    p = os.path.join(asset_dir, "recon", "inventory", "surface.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump({"schema": "surface/v2", "asset_tag": tag, "units": units}, f)


def run_probe(asset_dir, no_nmap=False):
    cmd = [sys.executable, PROBE, "--asset-dir", asset_dir, "--allow", "127.0.0.1", "--timeout", "8"]
    if no_nmap:
        cmd.append("--no-nmap")
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    assert p.returncode == 0, f"probe exited {p.returncode}: {p.stderr}\n{p.stdout}"
    line = [l for l in p.stdout.splitlines() if l.strip()][-1]
    return json.loads(line)


def run_gate(asset_dir):
    subprocess.run([sys.executable, ENUM, "--asset-dir", asset_dir], cwd=REPO, capture_output=True, text=True, check=True)
    subprocess.run([sys.executable, GATE, "--asset-dir", asset_dir], cwd=REPO, capture_output=True, text=True)
    with open(os.path.join(asset_dir, "reports", "coverage-matrix.json")) as f:
        return json.load(f)


def mechanical_cells(asset_dir):
    with open(os.path.join(asset_dir, "applicability", "cells.json")) as f:
        cells = json.load(f)["cells"]
    mech = {"XC-CORS", "XC-TRANSPORT-DOWNGRADE", "XC-VERBOSE-ERRORS", "XC-SECURITY-HEADERS",
            "XC-TLS-POSTURE", "WEB-A06-COMPONENTS", "API9-INVENTORY", "XC-SECRET-EXPOSURE"}
    return {(c["class_id"], c["scope_key"]) for c in cells if c["class_id"] in mech}


def open_cells(matrix):
    return {(r["class_id"], r["scope_key"]) for r in matrix["missing_cells"]}


# --- tests -------------------------------------------------------------------
def _fixture(tmp, omit_csp=False):
    certfile = os.path.join(tmp, "cert.pem")
    with open(certfile, "w") as f:
        f.write(_CERT_PEM + _KEY_PEM)
    http_httpd, http_port = start_server(omit_csp=omit_csp)
    tls_httpd, tls_port = start_server(omit_csp=omit_csp, tls=True, certfile=certfile)
    asset_dir = os.path.join(tmp, "webA")
    write_surface(asset_dir, "webA", http_port, tls_port)
    return asset_dir, (http_httpd, tls_httpd)


def test_happy_path_closes_mechanical_cells():
    with tempfile.TemporaryDirectory() as tmp:
        asset_dir, servers = _fixture(tmp)
        try:
            summary = run_probe(asset_dir)
            matrix = run_gate(asset_dir)
        finally:
            for s in servers:
                s.shutdown()

        mech = mechanical_cells(asset_dir)
        assert mech, "fixture must enumerate mechanical cells"
        opened = open_cells(matrix)

        # WEB-A06-COMPONENTS needs nmap; if nmap is absent it is (honestly) a limitation.
        expect_closed = {c for c in mech if HAVE_NMAP or c[0] != "WEB-A06-COMPONENTS"}
        still_open = expect_closed & opened
        assert not still_open, f"these mechanical cells should be PASSED, got open: {sorted(still_open)}"

        # Every closed mechanical cell shows up in the probe's covered_negative summary.
        cn = {(c["class_id"], c["scope_key"]) for c in summary["covered_negative"]}
        assert expect_closed <= cn, f"summary missing covered_negative for: {sorted(expect_closed - cn)}"

        # gate scored them as covered_negative via a real corroborator, with NO validated finding.
        assert not glob.glob(os.path.join(asset_dir, "artifacts", "validated", "*.json")), \
            "no validated findings must exist — these are code-corroborated negatives"
        for cid in {"XC-CORS", "XC-SECURITY-HEADERS", "XC-TLS-POSTURE", "API9-INVENTORY", "XC-SECRET-EXPOSURE"}:
            pc = matrix["per_class"].get(cid)
            if pc:
                assert pc["status"] == "covered_negative" and pc["passed"] == pc["applicable"], \
                    f"{cid} should be fully covered_negative: {pc}"

        if not HAVE_NMAP:
            assert any(x["class_id"] == "WEB-A06-COMPONENTS" for x in summary["limitations"]), \
                "no nmap -> COMPONENTS must be a limitation"


def test_no_nmap_leaves_components_open():
    with tempfile.TemporaryDirectory() as tmp:
        asset_dir, servers = _fixture(tmp)
        try:
            summary = run_probe(asset_dir, no_nmap=True)
            matrix = run_gate(asset_dir)
        finally:
            for s in servers:
                s.shutdown()

        opened = open_cells(matrix)
        comp = {c for c in mechanical_cells(asset_dir) if c[0] == "WEB-A06-COMPONENTS"}
        assert comp, "fixture must have COMPONENTS cells"
        assert comp <= opened, f"--no-nmap must leave COMPONENTS OPEN, got closed: {sorted(comp - opened)}"
        assert any(x["class_id"] == "WEB-A06-COMPONENTS" for x in summary["limitations"]), \
            f"COMPONENTS must be a limitation: {summary['limitations']}"
        assert not any(c["class_id"] == "WEB-A06-COMPONENTS" for c in summary["covered_negative"]), \
            "COMPONENTS must not be reported covered when nmap is unavailable"

        # The other (non-nmap) mechanical cells still close.
        others = {c for c in mechanical_cells(asset_dir) if c[0] != "WEB-A06-COMPONENTS"}
        assert not (others & opened), f"non-nmap mechanical cells should still pass: {sorted(others & opened)}"


def test_missing_header_emits_finding_and_leaves_cell_open():
    with tempfile.TemporaryDirectory() as tmp:
        asset_dir, servers = _fixture(tmp, omit_csp=True)
        try:
            # --no-nmap keeps the run fast; the CSP omission is what we're testing.
            summary = run_probe(asset_dir, no_nmap=True)
            matrix = run_gate(asset_dir)
        finally:
            for s in servers:
                s.shutdown()

        opened = open_cells(matrix)
        hdr = {c for c in mechanical_cells(asset_dir) if c[0] == "XC-SECURITY-HEADERS"}
        assert hdr, "fixture must have SECURITY-HEADERS cells"
        assert hdr <= opened, f"missing CSP must leave SECURITY-HEADERS OPEN: {sorted(hdr - opened)}"

        findings = {(f["class_id"], f["scope_key"]) for f in summary["findings"]}
        assert hdr <= findings, f"a finding must be emitted per SECURITY-HEADERS cell: {summary['findings']}"
        assert not any(c["class_id"] == "XC-SECURITY-HEADERS" for c in summary["covered_negative"]), \
            "a positive must NOT be written as covered_negative"

        # The raw finding is on disk (routed to the validation lane), NOT pre-validated.
        fdirs = glob.glob(os.path.join(asset_dir, "findings", "finding-XC-SECURITY-HEADERS-*"))
        assert fdirs, "a raw finding directory must exist"
        assert os.path.isfile(os.path.join(fdirs[0], "description.md"))
        assert os.path.isfile(os.path.join(fdirs[0], "evidence", "raw-source.txt"))
        assert not glob.glob(os.path.join(asset_dir, "artifacts", "validated", "*.json")), \
            "positive findings are raw, never pre-validated by the probe"


def test_out_of_scope_host_is_skipped_not_probed():
    with tempfile.TemporaryDirectory() as tmp:
        asset_dir, servers = _fixture(tmp)
        try:
            # No --allow -> 127.0.0.1 is not in {asset_tag}; every cell must be SKIPPED, never probed.
            cmd = [sys.executable, PROBE, "--asset-dir", asset_dir, "--timeout", "5", "--no-nmap"]
            p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
            assert p.returncode == 0, p.stderr
            summary = json.loads([l for l in p.stdout.splitlines() if l.strip()][-1])
        finally:
            for s in servers:
                s.shutdown()
        assert summary["covered_negative"] == [], "out-of-scope hosts must not be closed"
        assert summary["findings"] == [], "out-of-scope hosts must not be probed for findings"
        skipped_hosts = {s["host"] for s in summary["skipped_out_of_scope"]}
        assert "127.0.0.1" in skipped_hosts, f"127.0.0.1 must be skipped as out-of-scope: {summary['skipped_out_of_scope']}"


def test_no_mechanical_cells_is_graceful():
    with tempfile.TemporaryDirectory() as tmp:
        # A surface with no listeners/units -> no mechanical cells -> clean no-op exit 0.
        asset_dir = os.path.join(tmp, "empty")
        p = os.path.join(asset_dir, "recon", "inventory", "surface.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump({"schema": "surface/v2", "asset_tag": "empty", "units": []}, f)
        summary = run_probe(asset_dir)
        assert summary["covered_negative"] == [] and summary["findings"] == [], \
            f"empty surface must be a graceful no-op: {summary}"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed  (nmap {'present' if HAVE_NMAP else 'absent'})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
