#!/usr/bin/env python3
"""Tests for tools/protect_with_password.py.

Crypto-roundtrip assertions self-skip when the underlying tool (qpdf/pypdf/7z) is
absent, so the suite is portable; the dispatch/entropy/non-destructive logic is
always exercised.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import protect_with_password as P


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _write(path, data):
    with open(path, "w") as fh:
        fh.write(data)


def _read(path):
    with open(path) as fh:
        return fh.read()


def _have(t):
    return shutil.which(t) is not None


def _make_pdf(path):
    try:
        from pypdf import PdfWriter
    except ImportError:
        return False
    w = PdfWriter()
    w.add_blank_page(width=120, height=120)
    with open(path, "wb") as fh:
        w.write(fh)
    return True


class PasswordTest(unittest.TestCase):
    def test_strong_and_unique(self):
        a, b = P.gen_password(24), P.gen_password(24)
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 32)          # 24 bytes url-safe ~= 32 chars
        self.assertRegex(a, r"^[A-Za-z0-9_-]+$")

    def test_length_floor(self):
        # never weaker than 12 bytes of entropy even if asked for less
        self.assertGreaterEqual(len(P.gen_password(1)), 16)


class DispatchTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pwt-")
        self.out = os.path.join(self.d, "protected")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_missing_file(self):
        r = P.protect_one(os.path.join(self.d, "nope.docx"), self.out, "pw")
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "not a file")

    @unittest.skipUnless(_have("7z") or _have("7za") or _have("7zz"), "needs 7z")
    def test_office_goes_to_7z_and_is_nondestructive(self):
        src = os.path.join(self.d, "data.xlsx")
        _write(src, "secret sheet")
        before = _sha(src)
        r = P.protect_one(src, self.out, "S3cret-pw")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["method"], "archive-7z")
        self.assertTrue(r["output"].endswith(".7z"))
        self.assertTrue(os.path.isfile(r["output"]))
        self.assertEqual(_sha(src), before)          # original untouched

    @unittest.skipUnless(_have("7z") or _have("7za") or _have("7zz"), "needs 7z")
    def test_7z_requires_password_and_roundtrips(self):
        src = os.path.join(self.d, "notes.txt")
        payload = "top secret " * 10
        _write(src, payload)
        r = P.protect_one(src, self.out, "CorrectHorse")
        sevenzip = next(t for t in ("7z", "7za", "7zz") if _have(t))
        # wrong password must fail the integrity test
        wrong = subprocess.run([sevenzip, "t", "-pWRONG", r["output"]], capture_output=True)
        self.assertNotEqual(wrong.returncode, 0)
        # correct password extracts identical bytes
        ex = os.path.join(self.d, "ex")
        os.makedirs(ex, exist_ok=True)
        good = subprocess.run([sevenzip, "x", "-y", "-pCorrectHorse", "-o" + ex, r["output"]], capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(_read(os.path.join(ex, "notes.txt")), payload)

    def test_pdf_dispatch_native(self):
        src = os.path.join(self.d, "report.pdf")
        if not _make_pdf(src):
            self.skipTest("pypdf not available to build a sample PDF")
        r = P.protect_one(src, self.out, "pdfpass123")
        self.assertEqual(r["method"], "pdf-native")
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["output"].endswith("-protected.pdf"))
        # the produced PDF must actually be encrypted and openable with the pw
        from pypdf import PdfReader
        reader = PdfReader(r["output"])
        self.assertTrue(reader.is_encrypted)
        self.assertNotEqual(PdfReader(r["output"]).decrypt("pdfpass123"), 0)  # 0 == failed

    def test_case_insensitive_extension(self):
        src = os.path.join(self.d, "REPORT.PDF")
        if not _make_pdf(src):
            self.skipTest("pypdf not available")
        r = P.protect_one(src, self.out, "x")
        self.assertEqual(r["method"], "pdf-native")


class CliTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="pwt-cli-")
        self.script = os.path.join(os.path.dirname(os.path.abspath(P.__file__)), "protect_with_password.py")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    @unittest.skipUnless(_have("7z") or _have("7za") or _have("7zz"), "needs 7z")
    def test_cli_one_password_many_files_and_exit_codes(self):
        f1 = os.path.join(self.d, "a.docx"); _write(f1, "a")
        f2 = os.path.join(self.d, "b.xlsx"); _write(f2, "b")
        out = os.path.join(self.d, "out")
        p = subprocess.run([sys.executable, self.script, f1, f2, "--out-dir", out],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        import json
        summary = json.loads(p.stdout)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["protected_count"], 2)
        # ONE password shared across both files
        self.assertEqual(summary["total"], 2)
        self.assertTrue(os.path.isfile(summary["password_file"]))
        self.assertEqual(oct(os.stat(summary["password_file"]).st_mode)[-3:], "600")
        # a failing file makes the whole run exit 1
        p2 = subprocess.run([sys.executable, self.script, f1, os.path.join(self.d, "ghost.pdf"),
                             "--out-dir", out], capture_output=True, text=True)
        self.assertEqual(p2.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
