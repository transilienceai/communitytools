#!/usr/bin/env python3
"""Tests for tools/apk_control_wiring.py (static control-wiring analyzer).

Synthetic decompiled-tree fixtures only (client-neutral package names like
com/example/app; no real app/vendor identifiers). Run: python3 tools/test_apk_control_wiring.py
"""
import contextlib
import io
import os
import tempfile
import unittest

from apk_control_wiring import analyze, main


def _write_smali(root, rel, content):
    path = os.path.join(root, "smali", rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _touch_so(root, abi_rel):
    path = os.path.join(root, "lib", abi_rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").close()


# --- smali fixtures (client-neutral) ---------------------------------------- #
LOAD_A = """\
.class public Lcom/example/app/Native;
.super Ljava/lang/Object;

.method public static init()V
    .registers 1
    const-string v0, "a"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
"""

ROOT_WIRED = """\
.class public Lcom/example/app/Guard;
.super Ljava/lang/Object;

.method public check()Z
    .registers 3
    new-instance v0, Lcom/scottyab/rootbeer/RootBeer;
    invoke-direct {v0, p0}, Lcom/scottyab/rootbeer/RootBeer;-><init>(Landroid/content/Context;)V
    invoke-virtual {v0}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z
    move-result v1
    if-eqz v1, :cond_0
    const/4 v2, 0x0
    return v2
    :cond_0
    const/4 v2, 0x1
    return v2
.end method
"""

ROOT_UNWIRED = """\
.class public Lcom/example/app/Guard;
.super Ljava/lang/Object;

.method public check()V
    .registers 2
    new-instance v0, Lcom/scottyab/rootbeer/RootBeer;
    invoke-direct {v0, p0}, Lcom/scottyab/rootbeer/RootBeer;-><init>(Landroid/content/Context;)V
    return-void
.end method
"""

PIN_INERT = """\
.class public Lcom/example/app/Net;
.super Ljava/lang/Object;

.method public build()V
    .registers 2
    new-instance v0, Lokhttp3/CertificatePinner$Builder;
    invoke-direct {v0}, Lokhttp3/CertificatePinner$Builder;-><init>()V
    invoke-virtual {v0}, Lokhttp3/CertificatePinner$Builder;->build()Lokhttp3/CertificatePinner;
    return-void
.end method
"""

PIN_ATTACHED = PIN_INERT + """
.method public wire()V
    .registers 3
    new-instance v0, Lokhttp3/CertificatePinner$Builder;
    invoke-direct {v0}, Lokhttp3/CertificatePinner$Builder;-><init>()V
    invoke-virtual {v0}, Lokhttp3/CertificatePinner$Builder;->build()Lokhttp3/CertificatePinner;
    move-result-object v1
    invoke-virtual {v2, v1}, Lokhttp3/OkHttpClient$Builder;->certificatePinner(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;
    return-void
.end method
"""

_HEX_KEY = "0123456789abcdef0123456789abcdef"  # 32 hex chars -> 16-byte AES key


def _key_method(name):
    return """\
.method public %s()V
    .registers 4
    const-string v0, "%s"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v1
    const-string v2, "AES"
    new-instance v3, Ljavax/crypto/spec/SecretKeySpec;
    invoke-direct {v3, v1, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-void
.end method
""" % (name, _HEX_KEY)


KEY_3METHODS = (
    ".class public Lcom/example/app/Crypto;\n.super Ljava/lang/Object;\n\n"
    + _key_method("m1") + "\n" + _key_method("m2") + "\n" + _key_method("m3")
)

NO_KEY = """\
.class public Lcom/example/app/Plain;
.super Ljava/lang/Object;

.method public hello()V
    .registers 2
    const-string v0, "hello world"
    return-void
.end method
"""


class NativeLibraryWiringTest(unittest.TestCase):
    def test_orphaned_and_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Native.smali", LOAD_A)
            _touch_so(d, "arm64-v8a/liba.so")
            _touch_so(d, "arm64-v8a/libtoolChecker.so")
            _touch_so(d, "armeabi-v7a/liba.so")  # same basename in a second ABI -> deduped
            nw = analyze(d)["native_library_wiring"]
            self.assertEqual(nw["bundled"], ["liba.so", "libtoolChecker.so"])
            self.assertIn("liba.so", nw["loaded"])
            self.assertEqual(nw["orphaned"], ["libtoolChecker.so"])
            self.assertNotIn("liba.so", nw["orphaned"])


class RootIntegrityTest(unittest.TestCase):
    def test_shipped_but_unwired(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Guard.smali", ROOT_UNWIRED)
            rb = analyze(d)["root_integrity"]["rootbeer"]
            self.assertTrue(rb["present"])
            self.assertGreater(rb["references"], 0)
            self.assertFalse(rb["wired"])
            self.assertTrue(rb["shipped_but_unwired"])

    def test_wired(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Guard.smali", ROOT_WIRED)
            rb = analyze(d)["root_integrity"]["rootbeer"]
            self.assertTrue(rb["present"])
            self.assertTrue(rb["wired"])
            self.assertFalse(rb["shipped_but_unwired"])

    def test_absent_library_is_not_a_gap(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Guard.smali", ROOT_WIRED)
            sn = analyze(d)["root_integrity"]["safetynet"]
            self.assertFalse(sn["present"])
            self.assertFalse(sn["shipped_but_unwired"])


class SslPinningTest(unittest.TestCase):
    def test_built_but_inert(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Net.smali", PIN_INERT)
            ssl = analyze(d)["ssl_pinning"]
            self.assertTrue(ssl["pinner_built"])
            self.assertFalse(ssl["attached"])
            self.assertTrue(ssl["pinning_present_but_inert"])

    def test_built_and_attached(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Net.smali", PIN_ATTACHED)
            ssl = analyze(d)["ssl_pinning"]
            self.assertTrue(ssl["pinner_built"])
            self.assertTrue(ssl["attached"])
            self.assertFalse(ssl["pinning_present_but_inert"])


class HardcodedKeyTest(unittest.TestCase):
    def test_key_referenced_from_three_methods(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Crypto.smali", KEY_3METHODS)
            keys = analyze(d)["hardcoded_keys"]
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0]["invoke_sites"], 3)
            self.assertEqual(keys[0]["length"], 32)
            self.assertEqual(keys[0]["literal_prefix"], _HEX_KEY[:8] + "…")

    def test_no_key(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Plain.smali", NO_KEY)
            self.assertEqual(analyze(d)["hardcoded_keys"], [])


class ControlsSummaryTest(unittest.TestCase):
    def test_wiring_gaps_names_each_inert_control(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Native.smali", LOAD_A)
            _write_smali(d, "com/example/app/Guard.smali", ROOT_UNWIRED)
            _write_smali(d, "com/example/app/Net.smali", PIN_INERT)
            _write_smali(d, "com/example/app/Crypto.smali", KEY_3METHODS)
            _touch_so(d, "arm64-v8a/libtoolChecker.so")  # orphaned
            _touch_so(d, "arm64-v8a/liba.so")            # loaded
            ctrl = analyze(d)["controls"]
            gaps = {(g["control"], g["name"]) for g in ctrl["wiring_gaps"]}
            self.assertIn(("native_lib", "libtoolChecker.so"), gaps)
            self.assertIn(("root_integrity", "rootbeer"), gaps)
            self.assertIn(("ssl_pinning", "CertificatePinner"), gaps)
            self.assertNotIn(("native_lib", "liba.so"), gaps)
            self.assertEqual(ctrl["wiring_gap_count"], 3)
            self.assertEqual(ctrl["hardcoded_key_count"], 1)

    def test_clean_app_has_no_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Native.smali", LOAD_A)
            _write_smali(d, "com/example/app/Guard.smali", ROOT_WIRED)
            _write_smali(d, "com/example/app/Net.smali", PIN_ATTACHED)
            _write_smali(d, "com/example/app/Plain.smali", NO_KEY)
            _touch_so(d, "arm64-v8a/liba.so")  # loaded, not orphaned
            ctrl = analyze(d)["controls"]
            self.assertEqual(ctrl["wiring_gaps"], [])
            self.assertEqual(ctrl["hardcoded_key_count"], 0)


class CliTest(unittest.TestCase):
    def test_non_decompiled_dir_exits_3(self):
        with tempfile.TemporaryDirectory() as d:
            # a directory with no .smali is not a decompiled app
            with open(os.path.join(d, "AndroidManifest.xml"), "w") as f:
                f.write("<manifest/>")
            self.assertIsNone(analyze(d))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([d]), 3)

    def test_valid_dir_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            _write_smali(d, "com/example/app/Native.smali", LOAD_A)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([d]), 0)
                self.assertEqual(main([d, "--json"]), 0)

    def test_missing_path_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([os.path.join(os.sep, "no", "such", "dir", "xyz")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
