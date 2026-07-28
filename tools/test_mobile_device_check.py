#!/usr/bin/env python3
"""Tests for tools/mobile_device_check.py — fixture-driven, never needs a device.

Every external binary (adb, frida-ps, xcrun) is replaced by a shim on PATH, so the
exit contract is tested deterministically on any machine.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = os.path.join(HERE, "mobile_device_check.py")

READY, DEGRADED, NO_DEVICE, USAGE = 0, 20, 3, 2


def shim(bindir, name, body):
    p = os.path.join(bindir, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run(app_dir, bindir, platform="android"):
    env = dict(os.environ, PATH=bindir)  # ONLY the shims — no real adb can leak in
    p = subprocess.run([sys.executable, TOOL, "--platform", platform,
                        "--engagement-dir", app_dir, "--json"],
                       cwd=REPO, capture_output=True, text=True, env=env)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    v = json.loads(lines[-1]) if lines else None
    return p.returncode, v, p.stdout + p.stderr


def android_shims(bindir, *, devices=True, root=True, frida=True, ca=True):
    dev = "emulator-5554\tdevice" if devices else ""
    shim(bindir, "adb", f"""
case "$*" in
  *devices*) printf 'List of devices attached\\n{dev}\\n' ;;
  *"getprop ro.build.version.sdk"*) echo 32 ;;
  *"getprop ro.build.version.release"*) echo 12 ;;
  *"shell id"*) {'echo "uid=0(root) gid=0(root)"' if root else 'echo "uid=2000(shell)"'} ;;
  *"su -c id"*) {'echo "uid=0(root)"' if root else 'exit 1'} ;;
  *mount*) echo "/dev/block/dm-0 /system ext4 rw,seclabel 0 0" ;;
  *cacerts-added*) {'echo c8750f0d.0' if ca else 'exit 1'} ;;
  *security/cacerts*) echo "" ;;
  *) echo "" ;;
esac
""")
    shim(bindir, "frida-ps", "echo '1234 com.example.fieldapp'" if frida else "exit 1")


def test_ready_when_every_capability_present():
    with tempfile.TemporaryDirectory() as tmp:
        bindir, app = os.path.join(tmp, "bin"), os.path.join(tmp, "app")
        os.makedirs(bindir); os.makedirs(app)
        android_shims(bindir)
        rc, v, out = run(app, bindir)
        assert rc == READY, f"expected READY, got {rc}: {out}"
        assert v["ready"] is True and v["blockers"] == [], v
        assert v["backend"] == "emulator" and v["api_level"] == 32
        assert v["blocked_classes"] == [], v["blocked_classes"]
        assert os.path.isfile(os.path.join(app, "recon", "dast", "device-check.json"))


def test_no_device_is_exit_3():
    with tempfile.TemporaryDirectory() as tmp:
        bindir, app = os.path.join(tmp, "bin"), os.path.join(tmp, "app")
        os.makedirs(bindir); os.makedirs(app)
        android_shims(bindir, devices=False)
        rc, v, out = run(app, bindir)
        assert rc == NO_DEVICE, f"expected NO_DEVICE, got {rc}: {out}"
        assert v["ready"] is False and v["backend"] is None
        # with nothing to test on, every runtime class is blocked
        assert "MAS-NETWORK-PINNING" in v["blocked_classes"]
        assert "MAS-PLATFORM-IPC" in v["blocked_classes"]


def test_degraded_is_not_ready():
    """The load-bearing decision: DEGRADED routes to the obstruction path, not DAST."""
    with tempfile.TemporaryDirectory() as tmp:
        for missing in ("root", "frida", "ca"):
            bindir = os.path.join(tmp, f"bin-{missing}")
            app = os.path.join(tmp, f"app-{missing}")
            os.makedirs(bindir); os.makedirs(app)
            android_shims(bindir, **{missing: False})
            rc, v, out = run(app, bindir)
            assert rc == DEGRADED, f"missing {missing} must be DEGRADED, got {rc}: {out}"
            assert v["ready"] is False, f"DEGRADED must never be ready ({missing})"
            assert v["blockers"], v
            assert v["blocked_classes"], "a shortfall must name the cells it costs"


def test_missing_adb_is_not_a_crash():
    with tempfile.TemporaryDirectory() as tmp:
        bindir, app = os.path.join(tmp, "bin"), os.path.join(tmp, "app")
        os.makedirs(bindir); os.makedirs(app)  # empty PATH: no adb at all
        rc, v, out = run(app, bindir)
        assert rc == NO_DEVICE, out
        assert any("adb" in b for b in v["blockers"]), v["blockers"]


def test_ios_simulator_is_degraded_with_named_limitations():
    with tempfile.TemporaryDirectory() as tmp:
        bindir, app = os.path.join(tmp, "bin"), os.path.join(tmp, "app")
        os.makedirs(bindir); os.makedirs(app)
        shim(bindir, "frida-ps", "exit 1")  # no USB device
        # a realistic hex simctl UDID — an all-digit placeholder both misrepresents
        # the format and reads as a card PAN to the content guard
        shim(bindir, "xcrun", """
printf '== Devices ==\\n-- iOS 17.4 --\\n    iPhone 15 (A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D) (Booted)\\n'
""")
        rc, v, out = run(app, bindir, platform="ios")
        assert rc == DEGRADED, f"a Simulator must be DEGRADED, got {rc}: {out}"
        assert v["backend"] == "simulator" and v["ready"] is False
        assert len(v["limitations"]) == 3, v["limitations"]
        assert any("FairPlay" in l for l in v["limitations"])
        assert any("pinning" in l for l in v["limitations"])


def test_ios_usb_device_is_ready():
    with tempfile.TemporaryDirectory() as tmp:
        bindir, app = os.path.join(tmp, "bin"), os.path.join(tmp, "app")
        os.makedirs(bindir); os.makedirs(app)
        shim(bindir, "frida-ps", "echo '501 SpringBoard'")
        rc, v, out = run(app, bindir, platform="ios")
        assert rc == READY, out
        assert v["backend"] == "physical" and v["ready"] is True
        assert v["limitations"] == [], "a real device carries no Simulator caveat"


def test_bad_engagement_dir_is_usage_error():
    with tempfile.TemporaryDirectory() as tmp:
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        android_shims(bindir)
        rc, v, out = run(os.path.join(tmp, "nope"), bindir)
        assert rc == USAGE, f"expected usage error, got {rc}: {out}"


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
