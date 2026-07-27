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
  5. symlink targets   — read from the git blob, never followed (see symlink_targets)
  6. engagement ids    — engagement directory names, and finding ids minted inside one

Coverage is a checked property, not a claim: --manifest records one entry per
publishable path, each either scanned or carrying an explicit reason it was not,
so "every file, every folder" can be verified rather than asserted.

Usage:
  python3 scripts/check_client_data.py            # scan the whole tracked tree
  python3 scripts/check_client_data.py --staged   # pre-commit: scan staged content only
  python3 scripts/check_client_data.py --manifest # + write the coverage manifest

Exit 0 = clean, 1 = leak(s) found.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
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

# Credential/key material identified by EXTENSION rather than content. These are
# caught by filename because the content checks cannot see them: a binary .p12 or
# .key is skipped by files_to_scan's BINARY_EXT filter, and a DER blob has no PEM
# banner for SECRET_PATTERNS to match. .gitignore already excludes these, so a hit
# here means the pattern was bypassed (git add -f, a pre-existing tracked file, or
# a new extension) — exactly the case a guard is for.
CREDENTIAL_EXT = {".ovpn", ".crt", ".cer", ".der", ".key", ".jks", ".p12", ".pfx",
                  ".pem", ".keytab", ".kirbi", ".ccache"}

# Trees exempt from the *denylist* check only (they legitimately discuss public
# incidents and public benchmark suites). Credentials/IPs are still checked.
NAME_EXEMPT_PREFIXES = ("benchmarks/", "papers/", "threat_intel_case_studies/")

# These files necessarily contain the patterns and fixtures themselves: the guard
# holds the SECRET/ENGAGEMENT regexes, and the two test suites hold a synthetic
# leak per rule (wf-helpers' scrubCheck enforces the same classes workflow-side).
# All are exempt from the pattern checks ONLY — never from the denylist check.
# The denylist is hashed, so none has any legitimate reason to contain a plaintext
# customer identifier, and a fixture must be invented, never borrowed from a real
# engagement.
SECRET_SELF_EXEMPT = {"scripts/check_client_data.py",
                      "scripts/test_check_client_data.py",
                      ".claude/workflows/lib/helpers.test.mjs"}

# Reviewed exceptions live in a tracked, reviewable file — not in this source.
# Keyed on the sha256 of the MATCHED LINE so an entry cannot outlive the content
# it was granted for; see load_allowlist().
ALLOWLIST_PATH = os.path.join(REPO, "scripts", "content-guard-allowlist.json")

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
    # macOS, Linux and Windows home directories all name the account holder.
    ("operator-home-path", re.compile(
        r"/(?:Users|home)/[A-Za-z][A-Za-z0-9._-]{2,}/"
        r"|[A-Za-z]:\\Users\\[A-Za-z][A-Za-z0-9._-]{2,}")),
]

# Shared, service, or lab accounts that name nobody. Measured against the tree:
# these cover every /home/ and C:\Users\ occurrence in it, which is why the two
# new platforms can block from the start rather than warn.
GENERIC_USER = (r"username|users?|you|carlos|kali|claude|root|admin|administrator"
                r"|public|restricted_user|asterisk|current_user|target|victim|attacker"
                r"|ubuntu|ec2-user|vagrant|student|htb|svc_[A-Za-z0-9_]*")

# Published-by-vendor example values that are documentation, not secrets.
SECRET_ALLOW = re.compile(
    r"AKIAIOSFODNN7EXAMPLE|AKIAABCDEFGHIJKLMNOP|ASIAYEXAMPLEKEY|xoxb-actual-token-here"
    r"|sk-(?:ant-)?(?:api\d\d-)?(?:your|xxx|placeholder|REDACTED)"
    # A home path naming a generic account, on any platform.
    rf"|(?i:/(?:Users|home)/(?:{GENERIC_USER})(?:/|\b))"
    rf"|(?i:[A-Za-z]:\\Users\\(?:{GENERIC_USER})\b)"
    # ...or a metavariable rather than a name: <user>, [user], *, %USERNAME%, $USER.
    r"|/(?:Users|home)/[^/\s]*[<>\[\]*%$]"
    r"|[A-Za-z]:\\Users\\[^\\\s]*[<>\[\]*%$]")

# Engagement identifiers. These name a specific customer engagement even when the
# customer's own name never appears, so the digest lane cannot catch them: an
# engagement directory is `<tree>/<YYYYMMDD|YYMMDD>_<slug>`, and finding ids are
# minted inside one. projects/ctf/ is deliberately absent — those are public
# challenge platforms, cited on purpose, not customers.
ENGAGEMENT_PATTERNS = [
    ("engagement-path", re.compile(
        r"\b(?:projects/(?:pentest|compliance|offsec|webinars|attacks-validation"
        r"|attack-path-prioritisation)/|outputs?/)(\d{6,8}[_-][A-Za-z0-9_.-]+)")),
    # An engagement-local script name, fNN_<name>.py — the NN is the finding number
    # and the rest is the engagement's own naming.
    ("finding-id", re.compile(r"\bf\d{2}_[a-z][a-z0-9_]*\.py\b")),
    ("finding-id", re.compile(r"\bF-SWEEP-[A-Za-z0-9_-]+\b")),
    # A BARE sequence id (F-12, F-01) is deliberately NOT matched. It carries no
    # customer information — it identifies an engagement only in combination with
    # context this guard already covers by other means — and the tree uses those
    # ids as synthetic fixtures throughout (80+ occurrences across tools/test_*.py,
    # test_generate_report.py, merge-reports.js). Matching them would produce pure
    # noise, and a guard people learn to ignore protects nothing.
]

# Slugs that are teaching placeholders rather than customers: a path like
# `projects/pentest/260101_acme` documents the FORMAT, not an engagement.
# Letter-boundary lookarounds, NOT \b: the slug follows an underscore, and `_` is
# a word character, so \bacme\b never fires inside `260101_acme`.
PLACEHOLDER_SLUG = re.compile(
    r"(?i)(?<![A-Za-z])(acme|example|sample|demo|dummy|placeholder|foo|bar|test|yourco"
    r"|client|customer)(?![A-Za-z])")

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


def _git_file_list(staged: bool) -> list[str]:
    """Every path the next commit would publish, unfiltered."""
    if staged:
        cmds = [["git", "-C", REPO, "diff", "--cached", "--name-only", "--diff-filter=ACMR"]]
    else:
        # Tracked files AND untracked-but-not-ignored files. Untracked files are the
        # highest-risk set: they are what the NEXT commit publishes, so scanning
        # `ls-files` alone is not sufficient.
        cmds = [["git", "-C", REPO, "ls-files"],
                ["git", "-C", REPO, "ls-files", "--others", "--exclude-standard"]]
    out = "".join(subprocess.run(c, capture_output=True, text=True).stdout for c in cmds)
    return [f for f in out.splitlines() if f]


def _index_modes() -> dict[str, str]:
    """path -> git mode from the index. Mode 120000 is a symlink."""
    r = subprocess.run(["git", "-C", REPO, "ls-files", "-s", "-z"],
                       capture_output=True, text=True)
    modes: dict[str, str] = {}
    for rec in r.stdout.split("\0"):
        if not rec:
            continue
        meta, _, path = rec.partition("\t")
        if path:
            modes[path] = meta.split()[0]
    return modes


def symlink_targets(staged: bool) -> dict[str, str]:
    """Every symlink the next commit would publish, mapped to its TARGET STRING.

    Read from the git blob (or os.readlink), never by following the link. A
    symlink's target IS published content — git stores it as an ordinary blob —
    so an absolute target publishes the operator's home directory, and once
    published the name of a private sibling repository. Following the link
    instead reads the destination file and never examines the target string,
    which is exactly how that class stayed invisible to every text grep.
    """
    modes = _index_modes()
    wanted = set(_git_file_list(staged))
    out: dict[str, str] = {}
    for rel, mode in modes.items():
        if mode != "120000" or rel not in wanted:
            continue
        r = subprocess.run(["git", "-C", REPO, "cat-file", "-p", f":{rel}"],
                           capture_output=True)
        if r.returncode == 0:
            out[rel] = r.stdout.decode("utf-8", "replace").strip()
    if not staged:
        # Untracked-but-stageable symlinks have no index entry yet.
        for rel in wanted:
            if rel not in out:
                p = os.path.join(REPO, rel)
                if os.path.islink(p):
                    out[rel] = os.readlink(p)
    return out


def symlink_leaks(targets: dict[str, str]) -> list[str]:
    """Structural verdicts on symlink targets. An absolute target is NOT echoed —
    that string is itself the leak."""
    leaks = []
    for rel, tgt in sorted(targets.items()):
        if tgt.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", tgt):
            leaks.append(f"{rel}:0: SYMLINK [absolute-target] -> absolute link target "
                         f"publishes a local filesystem path; make it relative")
        elif os.path.normpath(os.path.join(os.path.dirname(rel), tgt)).startswith(".."):
            leaks.append(f"{rel}:0: SYMLINK [escapes-repo] -> {tgt}")
    return leaks


def files_to_scan(staged: bool, symlinks: frozenset = frozenset()) -> list[str]:
    """Text files for the line scanners. Symlinks are excluded and handled by
    symlink_targets(): open()ing one follows it, re-reading the destination file
    while never examining the link target itself."""
    return [f for f in _git_file_list(staged)
            if os.path.splitext(f)[1].lower() not in BINARY_EXT
            and not f.endswith(".DS_Store")
            and f not in symlinks]


def credential_material_files(staged: bool) -> list[str]:
    """Paths whose EXTENSION is credential/key material. Content-blind on purpose:
    these never reach the line scanners (binary, or no PEM banner to match)."""
    return [f for f in _git_file_list(staged)
            if os.path.splitext(f)[1].lower() in CREDENTIAL_EXT]


MAX_TEXT_BYTES = 4_000_000
MANIFEST_DEFAULT = ".claude/state/confidentiality/manifest.json"


def file_bytes(rel: str, staged: bool) -> bytes | None:
    """The raw bytes this path would publish. For a symlink that is the TARGET
    STRING — git's own blob — never the destination file's content."""
    if staged:
        r = subprocess.run(["git", "-C", REPO, "show", f":{rel}"], capture_output=True)
        return r.stdout if r.returncode == 0 else None
    p = os.path.join(REPO, rel)
    if os.path.islink(p):
        return os.readlink(p).encode("utf-8", "replace")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def classify(rel: str, raw: bytes | None, is_symlink: bool) -> tuple[str, str | None]:
    """(kind, skip_reason). A skip_reason is mandatory whenever the line scanners
    do not run: silence about a file is indistinguishable from a clean verdict,
    and that ambiguity is the whole reason this manifest exists."""
    if is_symlink:
        return "symlink", None
    if os.path.splitext(rel)[1].lower() in BINARY_EXT or rel.endswith(".DS_Store"):
        return "binary", "binary extension — content not read"
    if raw is None:
        return "unreadable", "could not be read"
    if b"\x00" in raw[:4096]:
        return "binary", "NUL byte within the first 4096 bytes"
    if len(raw) > MAX_TEXT_BYTES:
        return "text", f"larger than {MAX_TEXT_BYTES} bytes"
    return "text", None


class AllowlistError(Exception):
    """Config-integrity failure. Distinct from a leak: the guard cannot be trusted
    until it is resolved, so it exits 2 rather than 1."""


def load_allowlist(today: str) -> tuple[dict, dict]:
    """(entries_by_key, consumed_tracker). Enforces the rules that stop a baseline
    from quietly absorbing new leaks:

      * every entry expires — the list is a queue, not a landfill;
      * an expired entry FAILS rather than silently continuing to suppress;
      * high-severity classes cannot be allowlisted at all;
      * the list is capped, which makes "just allowlist it" zero-sum against
        everyone else's future exceptions — the most effective thing available
        against a gate becoming a rubber stamp.
    """
    try:
        with open(ALLOWLIST_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return {}, {}
    except (OSError, ValueError) as e:
        raise AllowlistError(f"{os.path.relpath(ALLOWLIST_PATH, REPO)}: unreadable ({e})") from e

    entries = doc.get("entries", [])
    cap = int(doc.get("max_entries", 25))
    if len(entries) > cap:
        raise AllowlistError(
            f"{len(entries)} allowlist entries exceeds the cap of {cap}. "
            f"Fix the findings instead of adding exceptions.")
    banned = {str(r).lower() for r in doc.get("unallowlistable", [])}

    out = {}
    for e in entries:
        for field in ("path", "rule", "line_sha256", "reason", "added_by", "expires"):
            if not str(e.get(field, "")).strip():
                raise AllowlistError(f"allowlist entry for {e.get('path', '?')} is missing `{field}`")
        if str(e["rule"]).lower() in banned:
            raise AllowlistError(
                f"rule `{e['rule']}` may never be allowlisted (path {e['path']})")
        if str(e["expires"]) < today:
            raise AllowlistError(
                f"allowlist entry for {e['path']} [{e['rule']}] expired on {e['expires']} — "
                f"re-review it or fix the finding")
        out[(e["path"], str(e["rule"]), e["line_sha256"])] = e
    return out, {k: False for k in out}


def line_sha256(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()


BINARY_ALLOWLIST = os.path.join(REPO, "scripts", "content-guard-binaries.json")


def binary_leaks(entries: dict[str, dict]) -> list[str]:
    """Binaries are hash-pinned, never read.

    No text lane can inspect a .pdf/.apk/.ttf, so the honest guarantee is
    "unchanged since a human reviewed it", not "inspected". A new binary blocks
    until someone approves it, and a changed one blocks until someone re-reviews
    it — a client report is far likelier to arrive as a PDF or a spreadsheet than
    as prose. Deliberately not strings-extracted: that measurably false-positives
    inside font tables.
    """
    try:
        with open(BINARY_ALLOWLIST, encoding="utf-8") as fh:
            allow = {b["path"]: b["sha256"] for b in json.load(fh)["binaries"]}
    except (OSError, ValueError, KeyError) as e:
        return [f"{os.path.relpath(BINARY_ALLOWLIST, REPO)}:0: BINARY [allowlist-unreadable]"
                f" -> {type(e).__name__}; cannot certify any binary"]
    leaks = []
    for rel, e in sorted(entries.items()):
        if e["kind"] != "binary":
            continue
        if rel not in allow:
            leaks.append(f"{rel}:0: BINARY [unlisted] -> a binary no text lane can read; "
                         f"review it, then add its sha256 to "
                         f"{os.path.relpath(BINARY_ALLOWLIST, REPO)}")
        elif allow[rel] != e["sha256"]:
            leaks.append(f"{rel}:0: BINARY [changed] -> content differs from the reviewed "
                         f"sha256; re-review and update the allowlist")
    return leaks


def _would_be_published(abspath: str) -> bool:
    """True when this path is inside the worktree AND git does not ignore it.

    A path outside the worktree is not publishable BY THIS REPO, so it is safe —
    `git check-ignore` reports "not ignored" for it, which is the opposite of the
    question being asked.
    """
    real, root = os.path.realpath(abspath), os.path.realpath(REPO)
    if not (real == root or real.startswith(root + os.sep)):
        return False
    r = subprocess.run(["git", "-C", REPO, "check-ignore", "-q", "--no-index", real],
                       capture_output=True)
    return r.returncode != 0


def write_manifest(path: str, staged: bool, entries: dict[str, dict]) -> None:
    """Prove the scan was exhaustive: one entry per publishable path, each either
    scanned or carrying an explicit reason it was not.

    Refuses to write anywhere git would publish — the manifest lists every path in
    the repo and would be a map of the tree.
    """
    abspath = path if os.path.isabs(path) else os.path.join(REPO, path)
    if _would_be_published(abspath):
        raise SystemExit(f"check_client_data: refusing to write the manifest to a "
                         f"path this repo would publish: {path}")

    dirs: dict[str, dict] = {}
    for rel, e in entries.items():
        top = rel.split("/")[0] if "/" in rel else "(root)"
        d = dirs.setdefault(top, {"files": 0, "scanned": 0, "hits": 0})
        d["files"] += 1
        d["scanned"] += 1 if e["scanned"] else 0
        d["hits"] += e["hits"]

    kinds = {"text": 0, "binary": 0, "symlink": 0, "unreadable": 0}
    for e in entries.values():
        kinds[e["kind"]] += 1

    head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    payload = {
        "schema": "content-guard-manifest/v1",
        "head": head,
        "mode": "staged" if staged else "full",
        "universe_source": (["git diff --cached --name-only --diff-filter=ACMR"] if staged
                            else ["git ls-files", "git ls-files --others --exclude-standard"]),
        "counts": {"total": len(entries), **kinds,
                   "skipped": sum(1 for e in entries.values() if not e["scanned"]),
                   "hits": sum(e["hits"] for e in entries.values())},
        "dirs": dict(sorted(dirs.items())),
        "files": [entries[k] for k in sorted(entries)],
    }
    # Invariants — the manifest is worthless if it cannot be trusted to be total.
    assert len(payload["files"]) == payload["counts"]["total"]
    assert len({f["path"] for f in payload["files"]}) == len(payload["files"]), "duplicate path"
    for f in payload["files"]:
        assert f["scanned"] or f["skip_reason"], f"{f['path']}: skipped with no reason"

    os.makedirs(os.path.dirname(abspath), exist_ok=True)
    with open(abspath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"check_client_data: manifest — {payload['counts']['total']} paths "
          f"({kinds['text']} text, {kinds['binary']} binary, {kinds['symlink']} symlink) "
          f"-> {path}")


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
    ap.add_argument("--manifest", nargs="?", const=MANIFEST_DEFAULT, default=None,
                    metavar="PATH",
                    help="write a per-file coverage manifest proving every publishable "
                         f"path was examined (default {MANIFEST_DEFAULT}; must be gitignored)")
    args = ap.parse_args()

    denylist = load_denylist()
    today = subprocess.run(["date", "-u", "+%Y-%m-%d"], capture_output=True,
                           text=True).stdout.strip()
    try:
        allowlist, consumed = load_allowlist(today)
    except AllowlistError as e:
        print(f"check_client_data: CONFIG ERROR — {e}", file=sys.stderr)
        return 2
    leaks: list[str] = []
    # One entry per publishable path. Built even when --manifest is absent so the
    # unreadable-file check below is always enforced.
    entries: dict[str, dict] = {}

    # Filename-level check first: credential material the content scanners cannot see.
    for rel in credential_material_files(args.staged):
        leaks.append(f"{rel}:0: SECRET [credential-file] -> "
                     f"{os.path.splitext(rel)[1]} key/cert material must never be committed")

    # Symlink targets: structural verdicts, plus the target string run through the
    # ordinary line scanners (an absolute target is an operator path by definition).
    symlinks = symlink_targets(args.staged)
    leaks.extend(symlink_leaks(symlinks))

    # Enumerate the whole publishable universe first, so that every path has a
    # recorded disposition — scanned, or skipped for a stated reason.
    for rel in sorted(set(_git_file_list(args.staged))):
        raw = file_bytes(rel, args.staged)
        kind, skip = classify(rel, raw, rel in symlinks)
        entries[rel] = {"path": rel, "kind": kind,
                        "bytes": len(raw) if raw is not None else None,
                        "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                        "scanned": skip is None, "skip_reason": skip, "hits": 0}
    for rel, tgt in symlinks.items():
        # A symlink IS scanned: symlink_leaks ran, and its target string goes
        # through the line scanners below.
        entries[rel]["hits"] = sum(1 for lk in leaks if lk.startswith(f"{rel}:"))

    def record(rel: str) -> None:
        if rel in entries:
            entries[rel]["hits"] = sum(1 for lk in leaks if lk.startswith(f"{rel}:"))

    for rel in files_to_scan(args.staged, frozenset(symlinks)):
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
            for m in rx.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                first = content.splitlines()[lineno - 1]
                key = (rel, label, line_sha256(first))
                if key in allowlist:
                    consumed[key] = True
                    continue
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
                    key = (rel, label, line_sha256(line))
                    if key in allowlist:
                        consumed[key] = True
                        continue
                    leaks.append(f"{rel}:{n}: SECRET [{label}] -> {m.group(0)[:48]!r}")

            for label, rx in ENGAGEMENT_PATTERNS:
                if rel in SECRET_SELF_EXEMPT:
                    continue
                for m in rx.finditer(line):
                    hit = m.group(0)
                    # A placeholder slug documents the format rather than naming
                    # an engagement, and the CTF tree holds public challenges.
                    if PLACEHOLDER_SLUG.search(hit) or "projects/ctf/" in line:
                        continue
                    leaks.append(f"{rel}:{n}: ENGAGEMENT [{label}] -> {hit[:60]!r}")

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

        record(rel)

    # A file that could not be read was never checked. Reporting OK for it would
    # be a silent pass on exactly the case a guard exists for.
    # An entry that suppressed nothing is stale: the line it was granted for is
    # gone or changed. Failing here is what stops the list from accreting dead
    # exceptions that could later be repurposed.
    #
    # FULL SCANS ONLY. --staged sees just the changed files, so an entry for a file
    # not in this commit is legitimately unconsumed — enforcing staleness there
    # would fail every commit that does not happen to touch every allowlisted file.
    stale = [] if args.staged else [k for k, used in consumed.items() if not used]
    if stale:
        print("check_client_data: CONFIG ERROR — stale allowlist entr(ies); the line each "
              "was granted for no longer matches:", file=sys.stderr)
        for path, rule, sha in stale:
            print(f"  {path} [{rule}] line_sha256={sha[:16]}…", file=sys.stderr)
        return 2

    leaks.extend(binary_leaks(entries))

    unreadable = sorted(r for r, e in entries.items() if e["kind"] == "unreadable")
    for rel in unreadable:
        leaks.append(f"{rel}:0: UNREADABLE -> publishable but could not be read; "
                     f"cannot certify it is clean")

    if args.manifest:
        write_manifest(args.manifest, args.staged, entries)

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
