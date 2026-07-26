#!/usr/bin/env python3
"""Fail if client/engagement data or a credential reaches the public repo.

Broader than `check_neutrality.py`, which covers only IPv4 across four trees. The
classes this guard covers are wider than IP addresses: client names in prose and
docstrings, credential material, and non-documentation hostnames in examples —
across every tree, in every text extension.

Checks, over every tracked + staged text file outside the ignored engagement trees:
  1. term list         — digests from $CLIENT_DENYLIST (never committed)
  2. credentials       — AWS keys, sk-/ghp_/xox*/AIza tokens, PEM private keys, API-key UUIDs
  3. public IPv4       — anything outside RFC 1918/5737 + well-known resolvers
  4. operator paths    — /Users/<name>/ absolute paths (leak the analyst's identity)

Usage:
  python3 scripts/check_client_data.py            # scan the whole tracked tree
  python3 scripts/check_client_data.py --staged   # pre-commit: scan staged content only

Exit 0 = clean, 1 = leak(s) found.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Supplied at run time, never committed: with the salt in the tree, a committed
# digest file would let anyone test whether a given name is on the list.
DENYLIST = os.environ.get("CLIENT_DENYLIST") or os.path.expanduser(
    "~/.config/transilience/client-denylist.sha256")
SALT = b"transilience-communitytools-denylist-v1:"

# Binary/large types we cannot meaningfully regex; excluded from the text scan.
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".7z", ".apk", ".ipa",
              ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".ico", ".xlsx",
              ".docx", ".pptx", ".so", ".dylib", ".dll", ".jar", ".db", ".sqlite",
              ".pack", ".idx", ".ccache", ".kirbi", ".keytab", ".DS_Store"}

# Trees exempt from the *denylist* check only (they legitimately discuss public
# incidents and public benchmark suites). Credentials/IPs are still checked.
NAME_EXEMPT_PREFIXES = ("benchmarks/", "papers/", "threat_intel_case_studies/")

# This file and the denylist necessarily contain the patterns themselves.
# This file holds the SECRET regexes, so it is exempt from the credential check
# only — never from the denylist check. The denylist is hashed, so this file has
# no legitimate reason to contain a plaintext identifier.
SECRET_SELF_EXEMPT = {"scripts/check_client_data.py"}

# Narrow, reviewed exceptions: (path, finding-label). Each needs a justification.
# Keep this list SHORT — every entry is a place the guard is deliberately blind.
PATH_EXEMPT = {
    # Self-signed throwaway fixture: CN=127.0.0.1, SAN 127.0.0.1, used only to stand
    # up a loopback HTTPS server inside the unit test. Authenticates nothing, grants
    # nothing, and is regenerable.
    # TODO: generate at test time so no PEM lives in the tree at all.
    ("tools/test_passive_web_probe.py", "private-key"),
}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("anthropic-style-token", re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9]{8,}-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    # Require real key MATERIAL, not just the header: a header string alone is
    # documentation (a grep dork, a prompt-completion prefix, a truncated debug
    # excerpt). Two+ full base64 lines after the header means an actual key.
    ("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----\s*\n"
        r"(?:[A-Za-z0-9+/=]{60,}\s*\n){2,}")),
    ("api-key-uuid", re.compile(
        r"(?i)api[ _-]?key\s*[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("operator-home-path", re.compile(r"/Users/[A-Za-z][A-Za-z0-9._-]{2,}/")),
]

# Published-by-vendor example values that are documentation, not secrets.
SECRET_ALLOW = re.compile(
    r"AKIAIOSFODNN7EXAMPLE|AKIAABCDEFGHIJKLMNOP|ASIAYEXAMPLEKEY|xoxb-actual-token-here"
    r"|sk-(?:ant-)?(?:api\d\d-)?(?:your|xxx|placeholder|REDACTED)"
    r"|/Users/(?:username|user|you|<user>|\$USER)/")

IP_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
                   r"\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))(?![\d.])")
IP_ALLOW = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "255.255.255.255",
            "1.2.3.4", "4.3.2.1", "5.6.7.8", "93.184.216.34"}
# Vendor CDN/WAF ranges that skills legitimately document as fingerprints.
IP_ALLOW_PREFIX = ("103.21.244.", "103.22.200.", "104.16.", "172.64.", "151.101.",
                   "100.100.100.")


def load_denylist() -> set[str]:
    """Salted SHA-256 digests of client identifiers. Plaintext deliberately absent —
    the roster itself is sensitive; see scripts/gen_denylist.py."""
    if not os.path.exists(DENYLIST):
        print("check_client_data: term list not configured — running credential, "
              "address and path checks only. Set CLIENT_DENYLIST to enable term "
              "matching (see scripts/gen_denylist.py).", file=sys.stderr)
        return set()
    out = set()
    with open(DENYLIST, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                out.add(line)
    return out


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _digest(s: str) -> str:
    return hashlib.sha256(SALT + " ".join(s.lower().split()).encode()).hexdigest()


def denylisted_tokens(line: str, digests: set[str]) -> list[str]:
    """Hash each unigram and adjacent bigram (spaced and joined) and test membership.
    Catches 'Acme', 'Acme Bank', 'acmebank' and 'acme.io' alike without ever
    holding the plaintext names."""
    words = _TOKEN_RE.findall(line)
    hits = []
    for i, w in enumerate(words):
        if _digest(w) in digests:
            hits.append(w)
        # A dotted token hides its apex: 'sdk-h1.acme.io' must still match 'acme.io'.
        # Test every trailing dotted suffix of 2+ labels.
        parts = w.split(".")
        for j in range(1, len(parts) - 1):
            suffix = ".".join(parts[j:])
            if _digest(suffix) in digests:
                hits.append(suffix)
        if i + 1 < len(words):
            bigram = f"{w} {words[i + 1]}"
            if _digest(bigram) in digests or _digest(bigram.replace(" ", "")) in digests:
                hits.append(bigram)
    return hits


def is_doc_ip(ip: ipaddress.IPv4Address) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved
            or ip in ipaddress.ip_network("192.0.2.0/24")
            or ip in ipaddress.ip_network("198.51.100.0/24")
            or ip in ipaddress.ip_network("203.0.113.0/24"))


def looks_like_oid_or_version(line: str, ip: str) -> bool:
    """1.3.6.1.x / 2.5.29.x are OIDs; 'version 3.0.0.0' is a version, not an IP."""
    if ip.startswith(("1.3.6.", "2.5.", "1.2.840.", "2.16.840.", "0.9.")):
        return True
    ctx = line.lower()
    return any(k in ctx for k in ("oid", "version", "snmp", "iso.org", "sysdescr", "v=",
                                  "assembly", "publickeytoken", "netstandard",
                                  # browser User-Agent strings carry 4-part versions
                                  # (Chrome/121.0.0.0) that look exactly like IPs
                                  "mozilla/", "chrome/", "safari/", "applewebkit",
                                  "gecko", "edg/", "user-agent"))


def files_to_scan(staged: bool) -> list[str]:
    if staged:
        cmds = [["git", "-C", REPO, "diff", "--cached", "--name-only", "--diff-filter=ACMR"]]
    else:
        # Tracked files AND untracked-but-not-ignored files. Untracked files are the
        # highest-risk set: they are what the NEXT commit publishes, so scanning
        # `ls-files` alone is not sufficient.
        cmds = [["git", "-C", REPO, "ls-files"],
                ["git", "-C", REPO, "ls-files", "--others", "--exclude-standard"]]
    out = "".join(subprocess.run(c, capture_output=True, text=True).stdout for c in cmds)
    return [f for f in out.splitlines()
            if f and os.path.splitext(f)[1].lower() not in BINARY_EXT
            and not f.endswith(".DS_Store")]


def read_content(rel: str, staged: bool) -> str | None:
    if staged:
        r = subprocess.run(["git", "-C", REPO, "show", f":{rel}"],
                           capture_output=True)
        if r.returncode != 0:
            return None
        data = r.stdout
    else:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path) or os.path.getsize(path) > 4_000_000:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true",
                    help="scan staged content only (pre-commit mode)")
    args = ap.parse_args()

    denylist = load_denylist()
    leaks: list[str] = []

    for rel in files_to_scan(args.staged):
        content = read_content(rel, args.staged)
        if content is None:
            continue
        name_exempt = rel.startswith(NAME_EXEMPT_PREFIXES)

        # Whole-file checks (patterns that legitimately span lines).
        for label, rx in SECRET_PATTERNS:
            if not rx.flags & re.MULTILINE and "\\n" not in rx.pattern:
                continue
            if rel in SECRET_SELF_EXEMPT:
                continue
            if (rel, label) in PATH_EXEMPT:
                continue
            for m in rx.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                leaks.append(f"{rel}:{lineno}: SECRET [{label}] -> private key material")

        for n, line in enumerate(content.splitlines(), 1):
            if not name_exempt:
                # Report the location only. Echoing the matched term would write it
                # into a public CI log every time the check fails.
                for _ in denylisted_tokens(line, denylist):
                    leaks.append(f"{rel}:{n}: denylisted term match")
                    break

            for label, rx in SECRET_PATTERNS:
                if "\\n" in rx.pattern:      # handled by the whole-file pass above
                    continue
                if rel in SECRET_SELF_EXEMPT:
                    continue
                for m in rx.finditer(line):
                    if SECRET_ALLOW.search(m.group(0)) or SECRET_ALLOW.search(line):
                        continue
                    leaks.append(f"{rel}:{n}: SECRET [{label}] -> {m.group(0)[:48]!r}")

            for m in IP_RE.finditer(line):
                s = m.group(1)
                if s in IP_ALLOW or s.startswith(IP_ALLOW_PREFIX) or len(set(s.split("."))) == 1:
                    continue
                if looks_like_oid_or_version(line, s):
                    continue
                try:
                    ip = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if not is_doc_ip(ip):
                    leaks.append(f"{rel}:{n}: PUBLIC IP -> {s}")

    if not leaks:
        scope = "staged content" if args.staged else "the tracked tree"
        print(f"check_client_data: OK — no client data, credentials, or public IPs in {scope}")
        return 0

    print("check_client_data: FAIL — client data / credentials must not enter this public repo:",
          file=sys.stderr)
    for leak in sorted(set(leaks)):
        print(f"  {leak}", file=sys.stderr)
    print("\nFix: describe the CLASS of issue, not the customer — write 'a recurring mobile "
          "re-test crux', never '<ClientA>/<ClientB>'. Use RFC 5737 IPs (203.0.113.x) in examples, "
          "read secrets from os.environ, and keep engagement data under an ignored projects/ tree.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
