#!/usr/bin/env python3
"""Statically distinguish a REAL applied security control from an ORPHANED one on a
decompiled Android app.

This encodes a recurring mobile re-test crux: a control can be
*present in the APK* yet *inert* — a native anti-tamper lib shipped but never loaded, a
RootBeer/SafetyNet reference that gates no branch, a CertificatePinner built and then
discarded, a hardcoded AES key sitting in a decoy method. A naive re-test greps for the
library, finds it, and wrongly reports the control "fixed". This tool answers the harder
question: is the control actually WIRED into the app's control flow?

Pure static analysis over an apktool/jadx-style decompiled tree (no execution, no network):
smali disassembly (**/*.smali), bundled native libs (lib/<abi>/*.so). Stdlib only.

Four analyses (each an importable function, all folded into `analyze()`):

  1. NATIVE LIBRARY WIRING — `bundled` (basenames of lib/*/*.so, deduped across ABIs),
     `loaded` (every System.loadLibrary("x")/loadLibrary("x")/System.load(path) resolved
     to a libX.so via in-method const-string register tracking), `orphaned` (bundled libs
     with ZERO load reference — the libtoolChecker.so-shipped-but-never-loaded pattern).

  2. ROOT / INTEGRITY DETECTION — references to RootBeer (com/scottyab/rootbeer),
     SafetyNet (com/google/android/gms/safetynet), Play Integrity
     (com/google/android/play/core/integrity). For each present library, `wired` iff at
     least one call-site BRANCHES on its result (an invoke of a library method whose
     move-result feeds an if-*z in the same method); else `shipped_but_unwired`.

  3. SSL PINNING — `pinner_built` (a `new-instance ... CertificatePinner` /
     `CertificatePinner$Builder`), `attached` (a `->certificatePinner(` invoke on an
     OkHttpClient$Builder). Built-but-not-attached -> `pinning_present_but_inert` (the
     discarded-not-applied pattern).

  4. HARDCODED KEYS — AES/DES-key-shaped const-string literals (hex length 32/48/64, or
     base64 decoding to 16/24/32 bytes) that live in a SecretKeySpec/Cipher/AES|DES path;
     each reported as {literal_prefix, length, invoke_sites} (invoke_sites = # of distinct
     methods referencing the literal — the decoy-key-called-N-times pattern).

Overall: a `controls` summary whose `wiring_gaps` names every orphaned/inert/unwired
control — the things a re-test must NOT call "fixed".

Exit codes:
  0   analysis produced (even if wiring gaps were found)
  2   usage error / argument is not a directory
  3   the directory has no .smali (not a decompiled Android app)
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import re
import sys

VERSION = 1

# Root/integrity libraries keyed by their smali package prefix.
ROOT_LIBS = {
    "rootbeer": "com/scottyab/rootbeer",
    "safetynet": "com/google/android/gms/safetynet",
    "play_integrity": "com/google/android/play/core/integrity",
}

# Classes whose loadLibrary/load calls map a native lib into the process.
_LOADER_CLASSES = ("Ljava/lang/System;", "Ljava/lang/Runtime;")

_INVOKE_RE = re.compile(
    r"^\s*invoke-[a-z/]+\s*\{([^}]*)\}\s*,\s*(L[^;]+;)->([^(]+)\(([^)]*)\)(\S+)")
_CONST_STR_RE = re.compile(
    r'^\s*const-string(?:/jumbo)?\s+([vp]\d+)\s*,\s*"((?:[^"\\]|\\.)*)"')
_MOVE_RESULT_RE = re.compile(r"^\s*move-result(?:-object|-wide)?\s+([vp]\d+)")
_IFZ_RE = re.compile(r"^\s*(if-eqz|if-nez)\s+([vp]\d+)")
# Any other register (re)assignment that clears a prior taint on that register.
_ASSIGN_RE = re.compile(r"^\s*(?:const|move)[\w/-]*\s+([vp]\d+)")

_PINNER_BUILT_RE = re.compile(r"new-instance\s+[vp]\d+\s*,\s*L[^;\n]*CertificatePinner")
_ATTACH_RE = re.compile(r"->certificatePinner\(")
_CRYPTO_ALGO_RE = re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+\s*,\s*"(?:AES|DES)(?:/[^"]*)?"')
_CRYPTO_MARKERS = (
    "Ljavax/crypto/spec/SecretKeySpec",
    "Ljavax/crypto/spec/DESKeySpec",
    "Ljavax/crypto/Cipher",
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _find_smali(root):
    return sorted(glob.glob(os.path.join(root, "**", "*.smali"), recursive=True))


def bundled_libs(root):
    """Basenames of lib/<abi>/*.so, deduped across ABIs (sorted)."""
    paths = glob.glob(os.path.join(root, "lib", "*", "*.so"))
    return sorted({os.path.basename(p) for p in paths})


def _parse_reglist(text):
    if ".." in text:  # range form: {v0 .. v3}
        return re.findall(r"[vp]\d+", text)
    return [r.strip() for r in text.split(",") if r.strip()]


def _lib_name(literal, is_load):
    """Map a load-call string argument to a lib<name>.so basename, or None.

    loadLibrary("crypto") -> libcrypto.so ; System.load("/data/.../libfoo.so") -> libfoo.so.
    """
    if not literal:
        return None
    base = literal.replace("\\", "/").rsplit("/", 1)[-1]
    if base.endswith(".so"):
        return base
    if is_load:  # System.load expects a filesystem path to a .so; anything else is unresolvable
        return None
    return "lib" + base + ".so"


def _lib_for_class(cls):
    for key, pkg in ROOT_LIBS.items():
        if pkg in cls:
            return key
    return None


def _key_shaped(literal):
    """True iff the literal looks like a raw AES/DES key (hex 32/48/64, or base64 -> 16/24/32B)."""
    if re.fullmatch(r"[0-9a-fA-F]+", literal) and len(literal) in (32, 48, 64):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", literal) and len(literal) >= 16 and len(literal) % 4 == 0:
        try:
            raw = base64.b64decode(literal, validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        return len(raw) in (16, 24, 32)
    return False


def _is_crypto_method(body):
    txt = "\n".join(body)
    if any(m in txt for m in _CRYPTO_MARKERS):
        return True
    return bool(_CRYPTO_ALGO_RE.search(txt))


def iter_methods(text):
    """Yield (signature, body_lines) for each `.method ... .end method` block."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        if lines[i].lstrip().startswith(".method "):
            sig = lines[i].strip()
            body = []
            i += 1
            while i < n and not lines[i].lstrip().startswith(".end method"):
                body.append(lines[i])
                i += 1
            yield sig, body
        i += 1


def _scan_method(mid, body, acc):
    """Single linear pass: native-lib load resolution, root-integrity wiring taint, key literals."""
    reg_str = {}       # register -> last const-string value (for load-call resolution)
    tainted = {}       # register -> library key (holds a root-lib call result)
    pending_lib = None  # a root-lib invoke whose move-result is expected on the very next line
    literals_here = set()
    is_crypto = _is_crypto_method(body)

    for line in body:
        cs = _CONST_STR_RE.match(line)
        if cs:
            reg, val = cs.group(1), cs.group(2)
            reg_str[reg] = val
            tainted.pop(reg, None)
            pending_lib = None
            if _key_shaped(val):
                literals_here.add(val)
            continue

        inv = _INVOKE_RE.match(line)
        if inv:
            regs = _parse_reglist(inv.group(1))
            cls, meth, ret = inv.group(2), inv.group(3), inv.group(5)
            if regs and cls in _LOADER_CLASSES and meth in ("loadLibrary", "load"):
                lib = _lib_name(reg_str.get(regs[-1]), is_load=(meth == "load"))
                if lib:
                    acc["loaded"].add(lib)
            libkey = _lib_for_class(cls)
            pending_lib = libkey if (libkey and ret != "V") else None
            continue

        mr = _MOVE_RESULT_RE.match(line)
        if mr:
            if pending_lib:
                tainted[mr.group(1)] = pending_lib
            pending_lib = None
            continue

        pending_lib = None  # move-result must immediately follow the invoke; else the result is dropped

        ifz = _IFZ_RE.match(line)
        if ifz:
            reg = ifz.group(2)
            if reg in tainted:
                acc["root_wired"].add(tainted[reg])
            continue

        asg = _ASSIGN_RE.match(line)
        if asg:
            tainted.pop(asg.group(1), None)

    for lit in literals_here:
        acc["key_methods"].setdefault(lit, set()).add(mid)
        if is_crypto:
            acc["key_crypto"].add(lit)


# --------------------------------------------------------------------------- #
# top-level analysis
# --------------------------------------------------------------------------- #
def analyze(root):
    """Analyze a decompiled app tree. Returns the verdict dict, or None if no .smali found."""
    smali_files = _find_smali(root)
    if not smali_files:
        return None

    acc = {"loaded": set(), "root_wired": set(), "key_methods": {}, "key_crypto": set()}
    root_refs = {k: 0 for k in ROOT_LIBS}
    pinner_built = attached = False
    mid = 0

    for path in smali_files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for key, pkg in ROOT_LIBS.items():
            root_refs[key] += text.count("L" + pkg)
        if not pinner_built and (_PINNER_BUILT_RE.search(text) or "CertificatePinner$Builder" in text):
            pinner_built = True
        if not attached and _ATTACH_RE.search(text):
            attached = True
        for _sig, body in iter_methods(text):
            mid += 1
            _scan_method(mid, body, acc)

    bundled = bundled_libs(root)
    loaded = sorted(acc["loaded"])
    orphaned = sorted(set(bundled) - set(loaded))

    root_integrity = {}
    for key in ROOT_LIBS:
        present = root_refs[key] > 0
        wired = key in acc["root_wired"]
        root_integrity[key] = {
            "present": present,
            "references": root_refs[key],
            "wired": wired,
            "shipped_but_unwired": present and not wired,
        }

    inert = pinner_built and not attached
    ssl_pinning = {
        "pinner_built": pinner_built,
        "attached": attached,
        "pinning_present_but_inert": inert,
    }

    keys = []
    for lit, methods in acc["key_methods"].items():
        if lit in acc["key_crypto"]:
            keys.append({
                "literal_prefix": lit[:8] + "…",
                "length": len(lit),
                "invoke_sites": len(methods),
            })
    keys.sort(key=lambda k: (-k["invoke_sites"], k["literal_prefix"]))

    gaps = []
    for so in orphaned:
        gaps.append({"control": "native_lib", "name": so, "gap": "orphaned",
                     "detail": "bundled in lib/<abi> but never loaded via System.loadLibrary/load"})
    for key in ROOT_LIBS:
        if root_integrity[key]["shipped_but_unwired"]:
            gaps.append({"control": "root_integrity", "name": key, "gap": "shipped_but_unwired",
                         "detail": "library referenced but its result gates no branch"})
    if inert:
        gaps.append({"control": "ssl_pinning", "name": "CertificatePinner", "gap": "inert",
                     "detail": "CertificatePinner built but never attached to an OkHttpClient$Builder"})

    summary = ("%d wiring gap(s); %d hardcoded key(s) — a re-test must NOT report these "
               "controls 'fixed'." % (len(gaps), len(keys)))

    return {
        "tool": "apk_control_wiring",
        "version": VERSION,
        "decompiled_dir": root,
        "smali_files": len(smali_files),
        "native_library_wiring": {"bundled": bundled, "loaded": loaded, "orphaned": orphaned},
        "root_integrity": root_integrity,
        "ssl_pinning": ssl_pinning,
        "hardcoded_keys": keys,
        "controls": {
            "wiring_gaps": gaps,
            "wiring_gap_count": len(gaps),
            "hardcoded_key_count": len(keys),
            "summary": summary,
        },
    }


def _print_summary(result):
    nw = result["native_library_wiring"]
    print("apk_control_wiring: %d smali file(s), %d bundled lib(s), %d loaded, %d orphaned"
          % (result["smali_files"], len(nw["bundled"]), len(nw["loaded"]), len(nw["orphaned"])))
    print("  " + result["controls"]["summary"])
    for g in result["controls"]["wiring_gaps"]:
        print("  GAP  [%s] %s -> %s (%s)" % (g["control"], g["name"], g["gap"], g["detail"]))
    for k in result["hardcoded_keys"]:
        print("  KEY  %s len=%d invoke_sites=%d" % (k["literal_prefix"], k["length"], k["invoke_sites"]))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("decompiled_dir", help="apktool/jadx-style decompiled app tree")
    ap.add_argument("--json", action="store_true", help="emit the full JSON verdict (default: summary)")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.decompiled_dir)
    if not os.path.isdir(root):
        print("apk_control_wiring: not a directory: %s" % root, file=sys.stderr)
        return 2

    result = analyze(root)
    if result is None:
        print("apk_control_wiring: no .smali files under %s — not a decompiled Android app" % root,
              file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_summary(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
