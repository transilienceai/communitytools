#!/usr/bin/env python3
"""Generate ONE strong password and password-protect each referenced file with it.

Given a list of files (PDF, Word, Excel, PowerPoint, or anything else), this mints
a single strong random password and applies it to every file "accordingly":

  * PDF (.pdf)                       -> native AES-256 encryption (qpdf, pypdf
                                        fallback) -> <name>-protected.pdf. The
                                        recipient opens the PDF and is prompted
                                        for the password — no extra tooling.
  * Everything else (.docx/.xlsx/    -> wrapped in an AES-256 7-Zip archive
    .pptx/.doc/.xls/.ppt/images/…)      (-mhe=on, filenames encrypted too) ->
                                        <name>.7z. Native in-file Office password
                                        encryption (MS-OFFCRYPTO "agile") needs
                                        LibreOffice/a dedicated encryptor that is
                                        not available here, so we protect the file
                                        with a strong AES-256 archive instead — the
                                        recipient extracts it with the password
                                        (7-Zip / Keka / WinRAR).

SECURITY POSTURE (matches tools/protect_deliverable.py): AES-256 or nothing. We
NEVER fall back to weak ZipCrypto/RC4, which would give false assurance — if no
AES-256 tool is available for a file it is recorded as a failure, not "protected".

NON-DESTRUCTIVE: originals are never modified or deleted; a new protected artifact
is written alongside each (or into --out-dir). The password is printed and, by
default, written to a chmod-600 password file to share OUT-OF-BAND — never place it
in the same channel as the protected files.

Usage:
  python3 tools/protect_with_password.py FILE [FILE ...] \
      [--password PW] [--length 24] [--out-dir DIR] \
      [--password-file PATH | --no-password-file]

Prints a JSON summary (the password + per-file result) on stdout, and a human
banner with the password on stderr. Exit 0 iff every input file was protected;
1 if any file failed; 2 on a bad invocation (no files).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys

# Reuse the audited AES-256 PDF encryptor (qpdf -> pypdf) from the sibling tool.
try:
    from protect_deliverable import encrypt_pdf
except ImportError:  # allow running from another cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from protect_deliverable import encrypt_pdf

PASSWORD_FILENAME = "PROTECT-PASSWORD.txt"
# Extensions that get NATIVE in-file encryption. Everything else -> AES-256 7z.
PDF_EXTS = {".pdf"}


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def gen_password(nbytes: int) -> str:
    """One strong URL-safe password. 24 bytes ~= 32 chars ~= 192 bits of entropy;
    the [A-Za-z0-9_-] charset is unambiguous and safe to paste into any prompt."""
    return secrets.token_urlsafe(max(12, int(nbytes)))


def archive_encrypt(src: str, out_7z: str, password: str) -> tuple[bool, str]:
    """AES-256 7-Zip archive containing just the file. Header/filename encryption
    on. 7z ONLY (its encryption is always AES-256) — no weak ZipCrypto fallback."""
    sevenzip = next((t for t in ("7z", "7za", "7zz") if _have(t)), None)
    if not sevenzip:
        return False, "no AES-256 archive tool (7z) available"
    if os.path.exists(out_7z):
        os.remove(out_7z)
    srcdir = os.path.dirname(os.path.abspath(src)) or "."
    base = os.path.basename(src)
    try:
        subprocess.run(
            [sevenzip, "a", "-t7z", "-p" + password, "-mhe=on", "-bso0", "-bsp0",
             os.path.abspath(out_7z), base],
            cwd=srcdir, check=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        return False, "7z failed: %s" % (detail.decode("utf-8", "replace").strip() if isinstance(detail, bytes) else exc)
    ok = os.path.isfile(out_7z) and os.path.getsize(out_7z) > 0
    return ok, sevenzip + "/AES-256 (7z)"


def protect_one(src: str, out_dir: str | None, password: str) -> dict:
    """Protect a single file accordingly. Returns a result dict (never raises)."""
    res = {"input": src, "output": None, "method": None, "algo": None, "ok": False, "reason": None}
    if not os.path.isfile(src):
        res["reason"] = "not a file"
        return res
    ext = os.path.splitext(src)[1].lower()
    dest_dir = out_dir if out_dir else (os.path.dirname(os.path.abspath(src)) or ".")
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(src)
    if ext in PDF_EXTS:
        out = os.path.join(dest_dir, os.path.splitext(base)[0] + "-protected.pdf")
        ok, algo = encrypt_pdf(src, out, password)
        res.update(method="pdf-native", output=out if ok else None, algo=algo if ok else None, ok=ok)
        if not ok:
            res["reason"] = algo
            if os.path.exists(out):  # clean a partial/empty output
                os.remove(out)
    else:
        out = os.path.join(dest_dir, base + ".7z")
        ok, algo = archive_encrypt(src, out, password)
        res.update(method="archive-7z", output=out if ok else None, algo=algo if ok else None, ok=ok)
        if not ok:
            res["reason"] = algo
    return res


def write_password_file(path: str, password: str, protected: list[str]) -> str | None:
    body = (
        password + "\n\n"
        "# Password for the PASSWORD-PROTECTED files listed below.\n"
        "# Share it with the recipient OUT-OF-BAND — NOT in the same channel/email\n"
        "# as the protected files. Delete this file once the password is handed over.\n"
        "#\n"
        + "".join("#   %s\n" % p for p in protected)
    )
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(path, 0o600)
    except OSError as exc:
        print("WARN: could not write password file %s: %s" % (path, exc), file=sys.stderr)
        return None
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate one strong password and protect each referenced file with it.")
    ap.add_argument("files", nargs="+", help="the files to password-protect (pdf, docx, xlsx, pptx, …)")
    ap.add_argument("--password", help="use this password instead of generating one")
    ap.add_argument("--length", type=int, default=24, help="generated password entropy in bytes (default 24 ~= 32 chars)")
    ap.add_argument("--out-dir", help="write protected files here (default: alongside each input)")
    ap.add_argument("--password-file", help="write the password to this path (chmod 600)")
    ap.add_argument("--no-password-file", action="store_true", help="do not write any password file (print only)")
    args = ap.parse_args()

    # Dedupe inputs, preserve order.
    seen, files = set(), []
    for f in args.files:
        ap_f = os.path.abspath(f)
        if ap_f not in seen:
            seen.add(ap_f)
            files.append(f)

    password = args.password or gen_password(args.length)
    generated = not args.password

    results = [protect_one(f, args.out_dir, password) for f in files]
    protected = [r["output"] for r in results if r["ok"]]
    all_ok = all(r["ok"] for r in results)

    password_file = None
    if protected and not args.no_password_file:
        pf = args.password_file or os.path.join(args.out_dir or os.getcwd(), PASSWORD_FILENAME)
        password_file = write_password_file(pf, password, protected)

    # Human banner on stderr (visible even when stdout JSON is parsed).
    print("\n" + "=" * 64, file=sys.stderr)
    print("  PASSWORD (%s): %s" % ("generated" if generated else "supplied", password), file=sys.stderr)
    print("  Protected %d/%d file(s). Share the password OUT-OF-BAND." % (len(protected), len(results)), file=sys.stderr)
    if password_file:
        print("  Password also written to: %s (delete after handover)" % password_file, file=sys.stderr)
    print("=" * 64 + "\n", file=sys.stderr)

    print(json.dumps({
        "ok": all_ok,
        "password": password,
        "password_generated": generated,
        "password_file": password_file,
        "protected_count": len(protected),
        "total": len(results),
        "results": results,
    }, indent=2))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
