#!/usr/bin/env python3
"""Mobile DAST preflight — emit a machine verdict about the test device.

A VERDICT tool, never a provisioner. It reports what is true about the attached
device/emulator so the workflow's DAST gate rests on a machine fact instead of an
agent's say-so. It never installs, roots, patches, or launches anything.

EXIT CONTRACT (the workflow keys off this)
  0   READY     — every capability present; DAST may run
  20  DEGRADED  — a device is present but a capability is missing
  3   NO_DEVICE — nothing to test on
  2   usage error

Only exit 0 counts as deviceReady. DEGRADED is deliberately NOT ready: an iOS
Simulator is DEGRADED by definition (no FairPlay decryption, no Keychain ACL
classes, no on-device pinning enforcement), and treating it as ready would let
Simulator results be reported as real-device DAST coverage. A DEGRADED or
NO_DEVICE verdict routes the engagement to the obstruction + client-input-request
path, where the shortfall is recorded rather than silently absorbed.

Writes <engagement_dir>/recon/dast/device-check.json and prints the same JSON on
its last stdout line.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

READY, DEGRADED, NO_DEVICE, USAGE = 0, 20, 3, 2

# Capability -> the MAS classes it blocks. Recorded in the verdict so an obstruction
# record can name exactly which cells a shortfall costs, rather than deferring the lot.
BLOCKS = {
    "root": ["MAS-STORAGE-LOCAL", "MAS-STORAGE-LOGS"],
    "frida": ["MAS-NETWORK-PINNING", "MAS-RESILIENCE-ROOT", "MAS-AUTH-LOCAL"],
    "mitm_ca": ["MAS-NETWORK-PINNING", "MAS-PRIVACY-DATA"],
    "device": ["MAS-PLATFORM-IPC", "MAS-PLATFORM-SCREEN"],
}
IOS_SIMULATOR_LIMITS = [
    "iOS Simulator covers a SUBSET of real-device DAST: no FairPlay decryption "
    "(the Simulator binary is not the shipped encrypted ARM64 binary)",
    "no real Keychain accessibility-class semantics (kSecAttrAccessible* is not enforced)",
    "no on-device TLS pinning enforcement path — a Simulator pass does not prove the "
    "shipped app pins",
]


def sh(cmd: list, timeout: int = 15) -> tuple[int, str]:
    """Run a command. A missing binary is a fact to report, never a crash."""
    if not shutil.which(cmd[0]):
        return 127, ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return 1, ""


# --- android -----------------------------------------------------------------
def check_android(serial: str | None) -> dict:
    v: dict = {"platform": "android", "backend": None, "handle": serial, "blockers": [],
               "limitations": [], "root": False, "writable_system": False,
               "frida_ok": False, "mitm_ca": False, "api_level": None, "os_version": None}

    rc, out = sh(["adb", "devices"])
    if rc == 127:
        v["blockers"].append("adb not on PATH")
        return v
    devices = [l.split("\t")[0] for l in out.splitlines()[1:]
               if "\tdevice" in l and l.split("\t")[0]]
    if not devices:
        v["blockers"].append("no adb device in state 'device'")
        return v
    handle = serial if serial in devices else devices[0]
    v["handle"] = handle
    v["backend"] = "emulator" if handle.startswith("emulator-") else "physical"
    adb = ["adb", "-s", handle]

    rc, out = sh(adb + ["shell", "getprop", "ro.build.version.sdk"])
    if rc == 0 and out.strip().isdigit():
        v["api_level"] = int(out.strip())
    rc, out = sh(adb + ["shell", "getprop", "ro.build.version.release"])
    if rc == 0:
        v["os_version"] = out.strip() or None

    # root: `id` as root, or a usable su
    rc, out = sh(adb + ["shell", "id"])
    v["root"] = "uid=0" in out
    if not v["root"]:
        rc, out = sh(adb + ["shell", "su", "-c", "id"])
        v["root"] = "uid=0" in out
    if not v["root"]:
        v["blockers"].append("device is not rooted (no uid=0 shell)")

    # writable system — needed to install a MITM CA as a system CA on API >= 24
    rc, out = sh(adb + ["shell", "mount"])
    v["writable_system"] = bool(re.search(r"\s/system\s.*\brw\b", out))

    # frida-server responding on the device
    rc, out = sh(["frida-ps", "-U"], timeout=25)
    v["frida_ok"] = rc == 0 and bool(out.strip())
    if not v["frida_ok"]:
        v["blockers"].append("frida-server not responding (frida-ps -U)")

    # a MITM CA present in the system trust store
    rc, out = sh(adb + ["shell", "ls", "/system/etc/security/cacerts"])
    sys_cas = out.split() if rc == 0 else []
    rc2, out2 = sh(adb + ["shell", "ls", "/data/misc/user/0/cacerts-added"])
    added = out2.split() if rc2 == 0 else []
    v["mitm_ca"] = bool(added) or len(sys_cas) > 100
    if not v["mitm_ca"]:
        v["blockers"].append("no interception CA found in the device trust store")
    return v


# --- ios ---------------------------------------------------------------------
def check_ios(udid: str | None) -> dict:
    v: dict = {"platform": "ios", "backend": None, "handle": udid, "blockers": [],
               "limitations": [], "root": False, "writable_system": False,
               "frida_ok": False, "mitm_ca": False, "api_level": None, "os_version": None}

    # a physical/jailbroken device shows up to frida over USB; a Simulator does not
    rc, out = sh(["frida-ps", "-U"], timeout=25)
    if rc == 0 and out.strip():
        v.update(backend="physical", frida_ok=True, root=True)
        return v

    rc, out = sh(["xcrun", "simctl", "list", "devices", "booted"])
    if rc == 127:
        v["blockers"].append("neither frida (USB device) nor xcrun simctl is available")
        return v
    m = re.search(r"^\s+(.+?)\s+\(([0-9A-Fa-f-]{36})\)\s+\(Booted\)", out, re.M)
    if not m:
        v["blockers"].append("no booted iOS Simulator and no USB device")
        return v

    v["backend"] = "simulator"
    v["handle"] = udid or m.group(2)
    v["os_version"] = m.group(1)
    # A Simulator is structurally DEGRADED — say so rather than letting a Simulator
    # pass be read as real-device coverage.
    v["limitations"] = list(IOS_SIMULATOR_LIMITS)
    v["blockers"].append("iOS Simulator is not a real-device DAST environment "
                         "(see limitations); a jailbroken device or Corellium is required "
                         "for the runtime MAS classes")
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, choices=["android", "ios"])
    ap.add_argument("--serial", default=None)
    ap.add_argument("--udid", default=None)
    ap.add_argument("--avd", default=None, help="recorded for provenance; never launched")
    ap.add_argument("--engagement-dir", required=True, help="the app-bundle asset dir")
    ap.add_argument("--json", action="store_true", help="accepted for symmetry; output is always JSON")
    args = ap.parse_args()

    if not os.path.isdir(args.engagement_dir):
        print(f"mobile_device_check: --engagement-dir not found: {args.engagement_dir}",
              file=sys.stderr)
        return USAGE

    v = check_android(args.serial) if args.platform == "android" else check_ios(args.udid)
    v["avd"] = args.avd

    if v.get("backend") is None:
        v["exit_code"], v["ready"] = NO_DEVICE, False
    elif v["blockers"]:
        v["exit_code"], v["ready"] = DEGRADED, False
    else:
        v["exit_code"], v["ready"] = READY, True

    # Name the cells each shortfall costs, so an obstruction record defers exactly
    # those and not the whole runtime set.
    blocked: set = set()
    if v["exit_code"] == NO_DEVICE:
        for cls in BLOCKS.values():
            blocked |= set(cls)
    else:
        if not v.get("root"):
            blocked |= set(BLOCKS["root"])
        if not v.get("frida_ok"):
            blocked |= set(BLOCKS["frida"])
        if not v.get("mitm_ca"):
            blocked |= set(BLOCKS["mitm_ca"])
    v["blocked_classes"] = sorted(blocked)

    out = os.path.join(args.engagement_dir, "recon", "dast", "device-check.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(v, fh, indent=1)
    v["verdict_path"] = out
    print(json.dumps(v))
    return v["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
