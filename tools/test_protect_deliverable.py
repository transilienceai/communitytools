#!/usr/bin/env python3
"""Offline, deterministic tests for tools/protect_deliverable.py.

Proves: a real AES-256 protected zip + encrypted PDF are produced alongside the
plaintext ones; the correct password opens them and a wrong one is rejected; the
archived PDF is itself encrypted; the password never rides inside the zip; the
password is reused across runs; and when the AES tool is absent the artifact is
SKIPPED (recorded as a limitation) rather than silently downgraded to weak crypto.

Capability-aware (repo convention): branches on 7z / pypdf availability so it stays
green in a runner that lacks them; skips clean if no AES-256 tool is present at all.
Run: python3 tools/test_protect_deliverable.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "protect_deliverable.py")


def sevenzip():
    return next((t for t in ("7z", "7za", "7zz") if shutil.which(t)), None)


HAVE_7Z = sevenzip() is not None
HAVE_QPDF = shutil.which("qpdf") is not None
try:
    from pypdf import PdfReader  # noqa: F401
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False
HAVE_PDF_ENC = HAVE_QPDF or HAVE_PYPDF

if not (HAVE_7Z or HAVE_PDF_ENC):
    print("SKIP: no AES-256 tool (7z / qpdf / pypdf) available")
    sys.exit(0)

_pass = 0
_fail = 0


def ok(cond, msg):
    global _pass, _fail
    if cond:
        _pass += 1
    else:
        _fail += 1
        print("  FAIL " + msg)


def run_tool(eng, report_id="ACME-260713-v1.0", env=None, extra=None):
    cmd = [sys.executable, TOOL, "--engagement-dir", eng, "--report-id", report_id]
    if extra:
        cmd += extra
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1]), p
    except (json.JSONDecodeError, IndexError):
        print("  tool stdout:", p.stdout, "stderr:", p.stderr)
        return None, p


# A valid 1-page PDF built with whatever is available (no hard reportlab dep).
_MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>endobj\n"
    b"trailer<</Size 4/Root 1 0 R>>\n%%EOF\n"
)


def write_fixture_pdf(path):
    try:
        from reportlab.pdfgen import canvas  # noqa: PLC0415
        c = canvas.Canvas(path)
        c.drawString(72, 720, "CONFIDENTIAL — penetration test findings")
        c.save()
        return
    except ImportError:
        pass
    try:
        from pypdf import PdfWriter  # noqa: PLC0415
        w = PdfWriter()
        w.add_blank_page(width=612, height=792)
        with open(path, "wb") as fh:
            w.write(fh)
        return
    except Exception:  # noqa: BLE001
        pass
    with open(path, "wb") as fh:
        fh.write(_MINIMAL_PDF)


def make_fixture(root, with_pdf=True):
    os.makedirs(os.path.join(root, "reports"))
    os.makedirs(os.path.join(root, "input"))
    os.makedirs(os.path.join(root, "logs", "activity"))
    os.makedirs(os.path.join(root, "artifacts"))
    if with_pdf:
        write_fixture_pdf(os.path.join(root, "reports", "Penetration-Test-Report.pdf"))
    open(os.path.join(root, "reports", "summary.md"), "w").write("# Summary\nfindings: 3\n")
    open(os.path.join(root, "input", "scope.txt"), "w").write("example.com\n")
    open(os.path.join(root, "artifacts", "org-surface.json"), "w").write("{}\n")


# --------------------------------------------------------------------------- #
def test_happy_path():
    root = tempfile.mkdtemp()
    try:
        make_fixture(root)
        res, _ = run_tool(root)
        ok(res and res["ok"], "tool reports ok (something was protected)")
        if not res:
            return
        ok(res["password"] and len(res["password"]) >= 20, "strong password generated")
        ok(os.path.isfile(os.path.join(root, "reports", "Penetration-Test-Report.pdf")),
           "plaintext PDF kept alongside the protected one")

        if HAVE_PDF_ENC:
            ok(res["protected_pdf"] and os.path.isfile(res["protected_pdf"]), "protected PDF exists")
            ok(res["protected_pdf_algo"] and "AES-256" in res["protected_pdf_algo"], "PDF algo is AES-256")
            if HAVE_PYPDF and res["protected_pdf"]:
                r = PdfReader(res["protected_pdf"])
                ok(r.is_encrypted, "protected PDF is_encrypted")
                ok(r.decrypt(res["password"]) != 0, "correct password decrypts the PDF")
                ok(PdfReader(res["protected_pdf"]).decrypt("wrong-password-xyz") == 0,
                   "wrong password does NOT decrypt the PDF")
        else:
            ok(res["protected_pdf"] is None and any("PDF" in x for x in res["limitations"]),
               "no PDF tool -> protected_pdf skipped + limitation (no weak fallback)")

        if HAVE_7Z:
            ok(res["protected_zip"] and os.path.isfile(res["protected_zip"]), "protected zip exists")
            ok(res["protected_zip_algo"] and "AES-256" in res["protected_zip_algo"], "zip algo is AES-256")
            sz = sevenzip()
            good = subprocess.run([sz, "t", "-p" + res["password"], res["protected_zip"]], capture_output=True)
            ok(good.returncode == 0, "correct password opens the zip")
            bad = subprocess.run([sz, "t", "-pWRONGpw123", res["protected_zip"]], capture_output=True)
            ok(bad.returncode != 0, "wrong password is rejected by the zip")
            listing = subprocess.run([sz, "l", "-p" + res["password"], res["protected_zip"]],
                                     capture_output=True, text=True)
            ok("DELIVERABLE-PASSWORD.txt" not in listing.stdout,
               "password file is NOT inside the protected zip")
            if HAVE_PYPDF:
                ext = tempfile.mkdtemp()
                subprocess.run([sz, "x", "-y", "-p" + res["password"], "-o" + ext, res["protected_zip"],
                                "reports/Penetration-Test-Report.pdf"], capture_output=True)
                inner = os.path.join(ext, "reports", "Penetration-Test-Report.pdf")
                ok(os.path.isfile(inner) and PdfReader(inner).is_encrypted,
                   "PDF inside the protected zip is itself encrypted")
                shutil.rmtree(ext, ignore_errors=True)
        else:
            ok(res["protected_zip"] is None and any("zip" in x for x in res["limitations"]),
               "no 7z -> protected_zip skipped + limitation (no weak ZipCrypto)")

        pf = os.path.join(root, "DELIVERABLE-PASSWORD.txt")
        ok(os.path.isfile(pf), "password file written at engagement root")
        ok(res["password"] in open(pf).read(), "password file contains the password")
        ok((os.stat(pf).st_mode & 0o777) == 0o600, "password file is chmod 600")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_password_reuse():
    root = tempfile.mkdtemp()
    try:
        make_fixture(root)
        r1, _ = run_tool(root)
        r2, _ = run_tool(root)
        ok(r1 and r2 and r1["password"] == r2["password"], "password is reused across runs (stable)")
        ok(r2 and r2["password_reused"] is True, "second run reports password_reused=True")
        r3, _ = run_tool(root, extra=["--no-reuse"])
        ok(r3 and r3["password"] != r1["password"], "--no-reuse mints a fresh password")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_no_7z_skips_zip_no_weak_fallback():
    """With every 7z binary stripped from PATH, the zip is SKIPPED + a limitation is
    recorded — never a weak-crypto zip. Only meaningful where pypdf can still protect
    the PDF without PATH tools; otherwise it just asserts the no-weak-fallback contract."""
    if not HAVE_7Z:
        return  # can't demonstrate the strip if 7z was never there
    root = tempfile.mkdtemp()
    safe = tempfile.mkdtemp()
    try:
        make_fixture(root)
        env = dict(os.environ)
        env["PATH"] = safe  # no 7z AND no qpdf on PATH -> pypdf (in-process) still protects the PDF
        res, _ = run_tool(root, env=env)
        ok(res is not None, "tool still runs with an empty PATH")
        if res:
            ok(res["protected_zip"] is None, "no protected zip when 7z is absent")
            ok(any("zip skipped" in x for x in res["limitations"]),
               "a limitation is recorded for the skipped zip (no silent weak fallback)")
            if HAVE_PYPDF:
                ok(res["protected_pdf"] is not None and "pypdf" in (res["protected_pdf_algo"] or ""),
                   "PDF still protected via pypdf (AES-256) without external binaries")
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(safe, ignore_errors=True)


def test_missing_pdf_graceful():
    root = tempfile.mkdtemp()
    try:
        make_fixture(root, with_pdf=False)
        res, _ = run_tool(root)
        ok(res is not None and res["protected_pdf"] is None, "missing PDF -> protected_pdf None")
        ok(res and any("no plaintext PDF" in x for x in res["limitations"]),
           "missing PDF recorded as a limitation")
        if HAVE_7Z:
            ok(res and res["protected_zip"], "protected zip still produced without a PDF")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    for t in (test_happy_path, test_password_reuse, test_no_7z_skips_zip_no_weak_fallback,
              test_missing_pdf_graceful):
        t()
        print("  ran " + t.__name__)
    print("\n%d/%d passed  (7z=%s qpdf=%s pypdf=%s)" % (_pass, _pass + _fail, HAVE_7Z, HAVE_QPDF, HAVE_PYPDF))
    sys.exit(1 if _fail else 0)
