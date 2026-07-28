#!/usr/bin/env python3
"""Tests for tools/mobile_manifest_facts.py — stdlib + subprocess, no device."""
from __future__ import annotations

import json
import os
import plistlib
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = os.path.join(HERE, "mobile_manifest_facts.py")

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fieldapp" android:versionName="2.4.1" android:versionCode="240">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <application android:allowBackup="true" android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".MainActivity" android:exported="true"/>
    <activity android:name=".SecretActivity" android:exported="false"/>
    <activity android:name=".DeepLinkActivity">
      <intent-filter>
        <data android:scheme="fieldapp" android:host="ticket" android:pathPrefix="/open"/>
      </intent-filter>
    </activity>
    <activity android:name=".ExplicitlyClosed" android:exported="false">
      <intent-filter><data android:scheme="closed"/></intent-filter>
    </activity>
    <provider android:name="com.example.fieldapp.Files" android:exported="true"/>
    <service android:name=".Sync"/>
  </application>
</manifest>
"""
NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
</network-security-config>
"""


def run(platform, decoded, app_dir):
    p = subprocess.run([sys.executable, TOOL, "--platform", platform,
                        "--decoded", decoded, "--app-dir", app_dir],
                       cwd=REPO, capture_output=True, text=True)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    return p.returncode, (json.loads(lines[-1]) if lines else None), p.stdout + p.stderr


def android_tree(tmp):
    d = os.path.join(tmp, "apktool")
    os.makedirs(os.path.join(d, "res", "xml"))
    with open(os.path.join(d, "AndroidManifest.xml"), "w") as f:
        f.write(MANIFEST)
    with open(os.path.join(d, "res", "xml", "network_security_config.xml"), "w") as f:
        f.write(NSC)
    return d


def test_android_exported_defaulting():
    """Android's rule: absent `exported` + an intent-filter => exported=true.

    Getting this backwards would silently shrink the MAS-PLATFORM-IPC work-list,
    which is exactly why it is code rather than agent judgement.
    """
    with tempfile.TemporaryDirectory() as tmp:
        d, app = android_tree(tmp), os.path.join(tmp, "app")
        os.makedirs(app)
        rc, s, out = run("android", d, app)
        assert rc == 0, out
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        by_name = {c["name"]: c for c in facts["components"]}
        assert by_name["com.example.fieldapp.MainActivity"]["exported"] is True
        assert by_name["com.example.fieldapp.SecretActivity"]["exported"] is False
        # implicit-true via intent-filter
        assert by_name["com.example.fieldapp.DeepLinkActivity"]["exported"] is True
        assert by_name["com.example.fieldapp.DeepLinkActivity"]["explicit_exported"] is False
        # an explicit false wins over the intent-filter
        assert by_name["com.example.fieldapp.ExplicitlyClosed"]["exported"] is False
        # no intent-filter, no attribute => not exported
        assert by_name["com.example.fieldapp.Sync"]["exported"] is False
        assert by_name["com.example.fieldapp.Files"]["exported"] is True
        assert facts["exported_component_count"] == 3, facts["exported_component_count"]


def test_version_comes_from_apktool_yml():
    """apktool MOVES versionCode/versionName into apktool.yml — the manifest has neither.

    Regression: the original fixture carried android:versionName inline, which real
    apktool output never does, so the tool reported version_name=None on every real
    APK the workflow feeds it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        d, app = android_tree(tmp), os.path.join(tmp, "app")
        os.makedirs(app)
        # strip the inline attributes, exactly as apktool leaves the manifest
        mpath = os.path.join(d, "AndroidManifest.xml")
        txt = open(mpath).read().replace(' android:versionName="2.4.1"', "").replace(' android:versionCode="240"', "")
        assert "versionName" not in txt
        open(mpath, "w").write(txt)
        with open(os.path.join(d, "apktool.yml"), "w") as f:
            f.write("!!brut.androlib.apk.ApkInfo\napkFileName: app.apk\nversionInfo:\n"
                    "  versionCode: 46\n  versionName: 7.3.1\nresourcesInfo:\n  minSdkVersion: 24\n")
        rc, s, out = run("android", d, app)
        assert rc == 0, out
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        assert facts["version_name"] == "7.3.1", facts["version_name"]
        assert facts["version_code"] == "46", facts["version_code"]


def test_missing_apktool_yml_is_not_a_crash():
    with tempfile.TemporaryDirectory() as tmp:
        d, app = android_tree(tmp), os.path.join(tmp, "app")
        os.makedirs(app)
        rc, s, out = run("android", d, app)  # no apktool.yml written
        assert rc == 0, out
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        assert facts["version_name"] == "2.4.1", "the inline manifest attribute still wins"


def test_android_relative_names_are_qualified():
    with tempfile.TemporaryDirectory() as tmp:
        d, app = android_tree(tmp), os.path.join(tmp, "app")
        os.makedirs(app)
        run("android", d, app)
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        assert all(not c["name"].startswith(".") for c in facts["components"])


def test_android_transport_and_deeplinks():
    with tempfile.TemporaryDirectory() as tmp:
        d, app = android_tree(tmp), os.path.join(tmp, "app")
        os.makedirs(app)
        run("android", d, app)
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        assert facts["uses_cleartext_traffic"] is True
        assert facts["nsc_cleartext_permitted"] is True
        assert facts["nsc_user_ca_trusted"] is True
        assert facts["allow_backup"] is True
        assert facts["package"] == "com.example.fieldapp" and facts["version_name"] == "2.4.1"
        pats = [d_["pattern"] for d_ in facts["deeplinks"]]
        assert "fieldapp://ticket/open" in pats, pats
        assert "android.permission.INTERNET" in facts["permissions"]


def test_ios_info_plist():
    with tempfile.TemporaryDirectory() as tmp:
        appdir = os.path.join(tmp, "extracted", "Payload", "Field.app")
        os.makedirs(appdir)
        with open(os.path.join(appdir, "Info.plist"), "wb") as f:
            plistlib.dump({
                "CFBundleIdentifier": "com.example.fieldapp",
                "CFBundleShortVersionString": "2.4.1", "CFBundleVersion": "240",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                                           "NSExceptionDomains": {"legacy.example.test": {}}},
                "CFBundleURLTypes": [{"CFBundleURLName": "main", "CFBundleURLSchemes": ["fieldapp"]}],
                "NSCameraUsageDescription": "scan tickets",
                "com.apple.developer.associated-domains": ["applinks:example.test"],
            }, f)
        out_app = os.path.join(tmp, "app")
        os.makedirs(out_app)
        rc, s, out = run("ios", os.path.join(tmp, "extracted"), out_app)
        assert rc == 0, out
        facts = json.load(open(os.path.join(out_app, "recon", "manifest-facts.json")))
        assert facts["platform"] == "ios" and facts["package"] == "com.example.fieldapp"
        assert facts["uses_cleartext_traffic"] is True
        assert facts["ats_exception_domains"] == ["legacy.example.test"]
        pats = [d["pattern"] for d in facts["deeplinks"]]
        assert "fieldapp://" in pats and "applinks:example.test" in pats, pats
        assert "NSCameraUsageDescription" in facts["permissions"]


def test_missing_input_is_usage_error():
    with tempfile.TemporaryDirectory() as tmp:
        app = os.path.join(tmp, "app")
        os.makedirs(app)
        rc, s, out = run("android", os.path.join(tmp, "nope"), app)
        assert rc == 2, out


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
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
