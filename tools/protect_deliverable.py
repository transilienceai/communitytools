#!/usr/bin/env python3
"""Produce a PASSWORD-PROTECTED (AES-256) copy of an engagement's deliverable —
alongside the plaintext PDF + zip, never replacing them.

Auto-generates ONE strong random passphrase per engagement (reused across resume
rounds if an existing password file is present), then:
  1. encrypts reports/<pdf> -> reports/<stem>-protected.pdf (qpdf AES-256, pypdf fallback),
  2. builds <report_id>_deliverable_protected.zip (7z AES-256) whose <pdf> is the
     ENCRYPTED one — so even if the archive is opened the report stays protected,
  3. writes the password to <engagement>/DELIVERABLE-PASSWORD.txt (chmod 600),
     which lives at the engagement ROOT and is therefore EXCLUDED from the zip.

SECURITY POSTURE: AES-256 or nothing. If no AES-256 tool is available (qpdf/pypdf
for the PDF, 7z for the zip), that artifact is skipped and recorded as a limitation
— we NEVER fall back to weak ZipCrypto / RC4, which would give false assurance.
The password is printed to stdout (for the caller to relay OUT-OF-BAND) and written
to the root file; it is never placed inside any staged/zipped file.

Usage:
  python3 tools/protect_deliverable.py --engagement-dir DIR --report-id ID \
      [--pdf reports/Penetration-Test-Report.pdf] [--dirs reports input logs artifacts] \
      [--no-reuse]

Prints a JSON summary. Exit 0 if at least one protected artifact was produced (or
there was nothing to protect); 1 only on a bad invocation. Never raises on a missing
optional tool — it degrades to a recorded limitation.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

PASSWORD_FILE = "DELIVERABLE-PASSWORD.txt"


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def gen_or_reuse_password(engagement_dir: str, reuse: bool) -> tuple[str, bool]:
    """Reuse an existing engagement password (stable across resume rounds) else mint one."""
    path = os.path.join(engagement_dir, PASSWORD_FILE)
    if reuse and os.path.isfile(path):
        try:
            existing = open(path, encoding="utf-8").read().strip().splitlines()
            if existing and existing[0].strip():
                return existing[0].strip(), True
        except OSError:
            pass
    # ~32 url-safe chars => ~192 bits of entropy; unambiguous, copy-paste friendly.
    return secrets.token_urlsafe(24), False


def encrypt_pdf(plain_pdf: str, out_pdf: str, password: str) -> tuple[bool, str]:
    """AES-256 encrypt the PDF. qpdf first, then pypdf. Returns (ok, algo|reason)."""
    if _have("qpdf"):
        try:
            subprocess.run(
                ["qpdf", "--encrypt", "--user-password=" + password,
                 "--owner-password=" + password, "--bits=256", "--", plain_pdf, out_pdf],
                check=True, capture_output=True,
            )
            return True, "qpdf/AES-256"
        except (subprocess.CalledProcessError, OSError):
            pass
    try:
        from pypdf import PdfReader, PdfWriter  # noqa: PLC0415
        reader = PdfReader(plain_pdf)
        writer = PdfWriter()
        writer.append(reader)
        writer.encrypt(password, algorithm="AES-256")
        with open(out_pdf, "wb") as fh:
            writer.write(fh)
        return True, "pypdf/AES-256"
    except Exception:  # noqa: BLE001 — any pypdf/import failure degrades to a limitation
        return False, "no AES-256 PDF tool (qpdf/pypdf) available"


def build_protected_zip(engagement_dir: str, out_zip: str, dirs, encrypted_pdf: str | None,
                        pdf_rel: str, password: str) -> tuple[bool, str]:
    """AES-256 zip via 7z, swapping the plaintext PDF for the encrypted one. 7z ONLY
    (AES-256) — no weak ZipCrypto fallback. Returns (ok, algo|reason)."""
    sevenzip = next((t for t in ("7z", "7za", "7zz") if _have(t)), None)
    if not sevenzip:
        return False, "no AES-256 zip tool (7z) available"
    present = [d for d in dirs if os.path.isdir(os.path.join(engagement_dir, d))]
    if not present:
        return False, "no deliverable dirs to archive"
    if os.path.exists(out_zip):
        os.remove(out_zip)
    stage = tempfile.mkdtemp(prefix="protect-")
    try:
        for d in present:
            shutil.copytree(os.path.join(engagement_dir, d), os.path.join(stage, d))
        # Swap the plaintext report for the encrypted one so the archived PDF is protected too.
        if encrypted_pdf and os.path.isfile(encrypted_pdf):
            staged_pdf = os.path.join(stage, pdf_rel)
            if os.path.isdir(os.path.dirname(staged_pdf)):
                shutil.copyfile(encrypted_pdf, staged_pdf)
        # Never let a stray password file ride along inside the archive.
        for junk in (PASSWORD_FILE,):
            jp = os.path.join(stage, junk)
            if os.path.isfile(jp):
                os.remove(jp)
        try:
            subprocess.run(
                [sevenzip, "a", "-tzip", "-p" + password, "-mem=AES256", "-bso0", "-bsp0",
                 out_zip] + present,
                cwd=stage, check=True, capture_output=True,
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            return False, "7z failed: %s" % (getattr(exc, "stderr", b"") or exc)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return (os.path.isfile(out_zip) and os.path.getsize(out_zip) > 0), sevenzip + "/AES-256"


def write_password_file(engagement_dir: str, password: str) -> str:
    path = os.path.join(engagement_dir, PASSWORD_FILE)
    body = (password + "\n\n"
            "# Password for this engagement's PASSWORD-PROTECTED deliverable\n"
            "# (the *_deliverable_protected.zip and *-protected.pdf).\n"
            "# Share it with the client OUT-OF-BAND (not in the same channel as the zip).\n"
            "# This file lives at the engagement root and is EXCLUDED from the deliverable.\n"
            "# Delete it once the password has been handed over.\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement-dir", required=True)
    ap.add_argument("--report-id", default="engagement")
    ap.add_argument("--pdf", default="reports/Penetration-Test-Report.pdf",
                    help="plaintext PDF path RELATIVE to --engagement-dir")
    ap.add_argument("--dirs", nargs="+", default=["reports", "input", "logs", "artifacts"])
    ap.add_argument("--no-reuse", action="store_true",
                    help="always mint a fresh password (default reuses an existing one)")
    args = ap.parse_args()

    eng = os.path.abspath(args.engagement_dir)
    if not os.path.isdir(eng):
        print(json.dumps({"ok": False, "error": "engagement-dir not found: %s" % eng}))
        return 1

    limitations: list[str] = []
    password, reused = gen_or_reuse_password(eng, reuse=not args.no_reuse)

    # 1) protected PDF (kept alongside the plaintext one)
    protected_pdf = None
    pdf_algo = None
    plain_pdf = os.path.join(eng, args.pdf)
    encrypted_tmp = None
    if os.path.isfile(plain_pdf):
        stem, ext = os.path.splitext(args.pdf)
        out_rel = stem + "-protected" + ext
        out_pdf = os.path.join(eng, out_rel)
        ok, algo = encrypt_pdf(plain_pdf, out_pdf, password)
        if ok:
            protected_pdf, pdf_algo, encrypted_tmp = out_rel, algo, out_pdf
        else:
            limitations.append("protected PDF skipped: " + algo)
    else:
        limitations.append("no plaintext PDF at %s — protected PDF skipped" % args.pdf)

    # 2) protected zip (AES-256; archived PDF swapped for the encrypted one)
    out_zip = os.path.join(eng, "%s_deliverable_protected.zip" % args.report_id)
    zok, zalgo = build_protected_zip(eng, out_zip, args.dirs, encrypted_tmp, args.pdf, password)
    protected_zip = out_zip if zok else None
    if not zok:
        limitations.append("protected zip skipped: " + zalgo)

    # 3) password file at the engagement ROOT (excluded from the zip) — only if we produced something
    password_file = None
    if protected_zip or protected_pdf:
        password_file = write_password_file(eng, password)

    result = {
        "ok": bool(protected_zip or protected_pdf),
        "password": password,
        "password_reused": reused,
        "password_file": password_file,
        "protected_pdf": (os.path.join(eng, protected_pdf) if protected_pdf else None),
        "protected_pdf_algo": pdf_algo,
        "protected_zip": protected_zip,
        "protected_zip_algo": zalgo if zok else None,
        "limitations": limitations,
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
