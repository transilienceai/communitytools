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
  7. personal data     — national ids (checksum-validated, BLOCKING); address,
                         named contact and phone (heuristic, WARN only)

Coverage is a checked property, not a claim: --manifest records one entry per
publishable path, each either scanned or carrying an explicit reason it was not,
so "every file, every folder" can be verified rather than asserted.

Usage:
  python3 scripts/check_client_data.py            # scan the whole tracked tree
  python3 scripts/check_client_data.py --staged   # pre-commit: scan staged content only
  python3 scripts/check_client_data.py --manifest # + write the coverage manifest

Exit 0 = clean (warnings do not fail), 1 = leak(s) found, 2 = config error.
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

# --------------------------------------------------------------------------
# Personal data. A customer is identified by a name, but also by an address, a
# phone number, a national id or a named contact — classes the digest lane cannot
# reach because they are shapes, not words.
#
# Severity is split deliberately. Checksum-validated ids are BLOCKING: a
# Verhoeff-valid Aadhaar or a Luhn+IIN-valid card number is not an accident.
# Addresses and person names only WARN, because both are heuristics over ordinary
# prose and a false positive that blocks a commit is how a guard gets bypassed.
# --------------------------------------------------------------------------

# Checksum-validated identifiers -> blocking.
PAN_RE = re.compile(r"\b([A-Z]{5})(\d{4})([A-Z])\b")          # Indian PAN
AADHAAR_RE = re.compile(r"\b([2-9]\d{3})\s?(\d{4})\s?(\d{4})\b")
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
CARD_IIN = ("4", "34", "37", "51", "52", "53", "54", "55", "6011", "65", "35")
# Digit runs that are plainly not identifiers.
ID_CONTEXT_DENY = re.compile(
    r"(?i)\b(imei|iccid|order|invoice|timestamp|epoch|nanos|bytes|size|offset|sha|md5"
    r"|hash|sequence|port|version|cve|cvss|build|serial)\b")

# Phone: two high-precision shapes only. A general phone regex is a noise cannon
# over 800+ markdown files of ports, offsets and version strings.
PHONE_RE = re.compile(
    r"(?<![\w+])\+(\d{1,3})[\s.\-]?(\d[\s.\-]?){7,13}\d(?![\w])"
    r"|\b(?:\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\+91[\s-]?\d{5}[\s-]?\d{5})\b")
# 555 is the reserved fictional NANP exchange; sequential/repeated runs are examples.
PHONE_ALLOW = re.compile(r"555|1234567890|0123456789|(\d)\1{6,}")

# Postal address: context-SCORED, never a single regex. No individual signal is
# sufficient, so each contributes and the total decides.
# Unambiguous address tokens ONLY. Measured against the tree, a broader list fired
# on `phase` (attack phases), `main` (main(), pg main), `floor` (math.floor),
# `block` (cipher block), `unit` (unit test) and `sector` (disk sector). In a
# security repo those words are overwhelmingly technical, so including them buys
# no recall and costs the rule its credibility.
STREET_SUFFIX = re.compile(
    r"(?i)\b(street|st\.|road|rd\.|avenue|ave\.|boulevard|blvd\.|suite|ste\."
    r"|marg|nagar|colony|plaza)\b")
HOUSE_NUMBER = re.compile(r"(?<![\w])\d{1,5}[A-Za-z]?[,\s]")
POSTCODE_STRONG = re.compile(r"\b\d{5}(-\d{4})?\b|\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b")
POSTCODE_WEAK = re.compile(r"\b\d{6}\b|\b\d{4}\b")
GEO_TOKEN = re.compile(
    r"(?i)\b(mumbai|delhi|bengaluru|bangalore|chennai|hyderabad|pune|kolkata|singapore"
    r"|dubai|abu dhabi|manila|makati|taipei|london|new york|san francisco|tokyo|sydney"
    r"|toronto|berlin|paris|madrid|milan|zurich|dublin|amsterdam)\b")
PLACEHOLDER_MARKER = re.compile(
    r"(?i)\b(example|sample|placeholder|dummy|synthetic|fictional|redacted|acme|your|test)\b"
    r"|<[A-Z_]{3,}>|\$\{")

# Person names: three NARROW sub-rules only. A person's name is two capitalised
# non-dictionary words — structurally identical to `Burp Suite` or `Active
# Directory` — so the general case is not a regular language and is not attempted.
PERSON_LABELLED = re.compile(
    r"(?i)\b(attn|prepared\s+by|reviewed\s+by|approved\s+by|point\s+of\s+contact"
    r"|account\s+manager|requested\s+by|primary\s+contact)\b\s*[:\-–]\s*"
    r"([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z']{1,20}){1,2})")
PERSON_EMAIL = re.compile(r"\b([a-z]{2,})[._]([a-z]{2,})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Attacker/victim/target domains are the standing convention in this tree's
# examples, alongside the RFC-reserved ones.
EMAIL_DOMAIN_ALLOW = re.compile(
    r"(?i)^(.*\.)?(example\.(com|org|net)|acme\.com|test\.com|localhost|transilience\.ai"
    r"|attacker\.com|evil\.com|victim\.com|trusted\.com|target\.com|corp\.com"
    r"|company\.com|yourdomain\.com|domain\.com)$"
    r"|\.(local|invalid|test|internal|example|ccache|keytab)$")


def verhoeff_valid(number: str) -> bool:
    """Aadhaar checksum. Digits alone are ~10x noisier than digits + checksum, and
    a Verhoeff-valid 12-digit run is not something prose produces by accident."""
    d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
         [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
         [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
         [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
         [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
    p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
         [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
         [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
         [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
    c = 0
    for i, ch in enumerate(reversed(number)):
        if not ch.isdigit():
            return False
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        if not ch.isdigit():
            return False
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def address_score(line: str) -> int:
    """No single signal identifies an address; the combination does — but a street
    token is MANDATORY. Measured against the tree, scoring without it fired on
    Postgres tablespace paths, a CVSS table and a crypto transcript: a number plus
    a city name is not an address."""
    if not STREET_SUFFIX.search(line):
        return 0
    score = 2
    if HOUSE_NUMBER.match(line.strip()):
        score += 2
    if POSTCODE_STRONG.search(line):
        score += 3
    elif POSTCODE_WEAK.search(line):
        score += 1
    if GEO_TOKEN.search(line):
        score += 2
    if PLACEHOLDER_MARKER.search(line):
        score -= 3
    return score


def personal_data_findings(rel: str, n: int, line: str) -> tuple[list[str], list[str]]:
    """(blocking, warnings) for one line."""
    leaks, warns = [], []
    if ID_CONTEXT_DENY.search(line):
        return leaks, warns

    for m in PAN_RE.finditer(line):
        if m.group(1)[3] in "ABCFGHLJPTK":
            leaks.append(f"{rel}:{n}: PERSONAL [indian-pan] -> redacted ({len(m.group(0))} chars)")
    for m in AADHAAR_RE.finditer(line):
        if verhoeff_valid("".join(m.groups())):
            leaks.append(f"{rel}:{n}: PERSONAL [aadhaar] -> Verhoeff-valid, redacted")
    for _ in SSN_RE.finditer(line):
        leaks.append(f"{rel}:{n}: PERSONAL [us-ssn] -> redacted")
    for m in CARD_RE.finditer(line):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits.startswith(CARD_IIN) and luhn_valid(digits):
            leaks.append(f"{rel}:{n}: PERSONAL [card-pan] -> Luhn+IIN valid, redacted")

    for m in PHONE_RE.finditer(line):
        raw = m.group(0)
        if PHONE_ALLOW.search(re.sub(r"[^\d]", "", raw)):
            continue
        warns.append(f"{rel}:{n}: PERSONAL [phone] -> redacted ({len(raw)} chars)")
    for m in PERSON_LABELLED.finditer(line):
        warns.append(f"{rel}:{n}: PERSONAL [named-contact after '{m.group(1)}'] -> redacted")
    for m in PERSON_EMAIL.finditer(line):
        if not EMAIL_DOMAIN_ALLOW.search(m.group(3)):
            warns.append(f"{rel}:{n}: PERSONAL [first.last email] -> redacted @{m.group(3)}")
    score = address_score(line)
    if score >= 5:
        warns.append(f"{rel}:{n}: PERSONAL [postal address, score {score}] -> redacted")
    return leaks, warns


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


# --------------------------------------------------------------------------
# The scan universe.
#
# Three modes, and the distinction that matters is not WHICH paths but WHERE
# each one's bytes are read from. That is why an item carries a `source` rather
# than the scan carrying a boolean:
#
#   full     — every tracked + untracked-not-ignored path, read from the WORKTREE
#   staged   — what `git commit` would write, read from the INDEX
#   changed  — what pushing this branch would publish, read from all three:
#              the worktree (tip state), the index (staged-but-not-worktree),
#              and every blob any commit on the branch INTRODUCED.
#
# That last lane is the whole reason `changed` is not a path filter over `full`.
# A push publishes history, not the tip: a secret added in one commit and deleted
# in the next is absent from `BASE...HEAD` yet is fetched by anyone who clones the
# PR ref, and stays reachable from the PR ref after the branch is deleted.
# Measured on this repository's own feature branch: 35 net-diff paths, 57 distinct
# destination blobs. A net-diff scan would have read 60% of what it published.
# --------------------------------------------------------------------------

MODES = ("full", "staged", "changed")

# Recorded verbatim into the manifest's `universe_source`, so the coverage proof
# names the commands that actually ran rather than a hand-maintained description.
UNIVERSE_CMDS = {
    "full": ["git ls-files", "git ls-files --others --exclude-standard"],
    "staged": ["git diff --cached --name-only --diff-filter=ACMRT"],
    "changed": ["git rev-list BASE..HEAD | git diff-tree -r -m --raw --no-abbrev -z -M --stdin",
                "git diff HEAD --name-only --diff-filter=ACMRT -z",
                "git diff --cached --name-only --diff-filter=ACMRT -z",
                "git ls-files --others --exclude-standard -z"],
}

# A, C, M, R, T — deletions (D) publish nothing, and U/X/B are not states a scan
# of publishable content can act on. T is load-bearing and easy to omit: replacing
# a tracked FILE with a symlink is a type change, so `ACMR` silently drops it —
# and "file replaced by a link to /Users/<name>/..." is precisely the operator-path
# class the symlink lane exists for.
DIFF_FILTER = "--diff-filter=ACMRT"


class GitError(Exception):
    """A git command the scan depends on failed. Never downgraded to "no results":
    an unresolvable base ref must not be able to mean "scanned nothing, therefore
    clean" — that is the one failure a content guard may never have."""


def _git(*args: str, check: bool = False, text: bool = True):
    r = subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=text)
    if check and r.returncode != 0:
        err = (r.stderr if text else r.stderr.decode("utf-8", "replace")) or ""
        raise GitError(f"git {' '.join(args)} failed ({r.returncode}): {err.strip()[:200]}")
    return r


def _zsplit(s: str) -> list[str]:
    return [f for f in s.split("\0") if f]


def resolve_base(base: str | None) -> tuple[str, str]:
    """(ref, merge-base sha) for the changed scan.

    Deliberately does NOT fetch. A network call inside a gate is a source of
    non-determinism and a new way to fail, so a stale or missing remote ref is
    reported for the caller to fix rather than silently repaired.
    """
    candidates = [base] if base else ["origin/main", "main", "origin/master", "master"]
    for ref in candidates:
        if not ref:
            continue
        if _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode != 0:
            continue
        mb = _git("merge-base", ref, "HEAD", check=True).stdout.strip()
        if mb:
            return ref, mb
    raise GitError(
        f"cannot resolve a base ref (tried {', '.join(c for c in candidates if c)}). "
        f"Pass --changed <ref>, or run: git fetch origin")


def _history_items(base_sha: str) -> list[dict]:
    """Every blob introduced by a commit in BASE..HEAD.

    `-m` so a merge commit's own contributions are diffed against each parent
    rather than skipped; `-M` so a rename reports its destination. Deletions
    (all-zero destination sha) are excluded: they publish nothing.
    """
    revs = _git("rev-list", f"{base_sha}..HEAD", check=True).stdout
    if not revs.strip():
        return []
    r = subprocess.run(
        ["git", "-C", REPO, "diff-tree", "-r", "-m", "--raw", "--no-abbrev", "-z", "-M", "--stdin"],
        input=revs, capture_output=True, text=True)
    if r.returncode != 0:
        raise GitError(f"git diff-tree failed ({r.returncode}): {r.stderr.strip()[:200]}")

    fields, out, i = r.stdout.split("\0"), [], 0
    while i < len(fields):
        meta = fields[i]
        i += 1
        # Commit-id lines and the trailing empty field are not raw records.
        if not meta.startswith(":"):
            continue
        parts = meta[1:].split()
        if len(parts) < 5 or i >= len(fields):
            continue
        dst_mode, dst_sha, status = parts[1], parts[3], parts[4]
        path = fields[i]
        i += 1
        if status[0] in "RC":          # rename/copy: a second path field follows
            if i >= len(fields):
                break
            path = fields[i]
            i += 1
        if status[0] not in "AMRCT" or set(dst_sha) == {"0"}:
            continue
        out.append({"path": path, "source": "history", "sha": dst_sha, "mode": dst_mode})
    return out


def build_universe(mode: str, base_sha: str | None = None) -> list[dict]:
    """The scan's work list: one item per (path, source, blob) that would be published.

    An item is {key, path, source, sha, mode}. `key` is what every leak line and
    manifest entry is reported under — `path` for a live file, `path@<short-sha>`
    for a blob that exists only in branch history, so the two can never be
    confused for one another in a report.
    """
    if mode not in MODES:
        raise GitError(f"unknown mode {mode!r}")

    items: list[dict] = []
    if mode == "full":
        for cmd in (["ls-files", "-z"], ["ls-files", "--others", "--exclude-standard", "-z"]):
            for p in _zsplit(_git(*cmd, check=True).stdout):
                items.append({"path": p, "source": "worktree", "sha": None, "mode": None})
    elif mode == "staged":
        for p in _zsplit(_git("diff", "--cached", "--name-only", DIFF_FILTER, "-z",
                              check=True).stdout):
            items.append({"path": p, "source": "index", "sha": None, "mode": None})
    else:
        if not base_sha:
            raise GitError("changed mode requires a base commit")
        items.extend(_history_items(base_sha))
        # Tip state: `git diff HEAD` covers staged AND unstaged worktree changes.
        for p in _zsplit(_git("diff", "HEAD", "--name-only", DIFF_FILTER, "-z",
                              check=True).stdout):
            items.append({"path": p, "source": "worktree", "sha": None, "mode": None})
        # Staged content that differs from the worktree is a third distinct blob.
        for p in _zsplit(_git("diff", "--cached", "--name-only", DIFF_FILTER, "-z",
                              check=True).stdout):
            items.append({"path": p, "source": "index", "sha": None, "mode": None})
        for p in _zsplit(_git("ls-files", "--others", "--exclude-standard", "-z",
                              check=True).stdout):
            items.append({"path": p, "source": "worktree", "sha": None, "mode": None})

    seen, out = set(), []
    for it in items:
        if it["source"] == "history":
            it["key"] = f"{it['path']}@{it['sha'][:12]}"
        else:
            it["key"] = it["path"]
        dedupe = (it["key"], it["source"])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        out.append(it)
    # A history blob identical to the file now on disk is the same bytes twice.
    # Identical CONTENT is not identical OBJECT, though: git stores a symlink as
    # an ordinary blob holding its target string, so a history symlink and a
    # regular worktree file whose text happens to equal that target have the same
    # blob sha. Deduping across that boundary would drop the symlink item and with
    # it the whole symlink lane for that path — the absolute-target check included.
    # So only a regular-file history blob may be deduped against a regular file.
    live = {it["path"] for it in out if it["source"] == "worktree"}
    deduped = []
    for it in out:
        if (it["source"] == "history" and it["path"] in live
                and it.get("mode") in ("100644", "100755")):
            wt = os.path.join(REPO, it["path"])
            try:
                if os.path.isfile(wt) and not os.path.islink(wt):
                    with open(wt, "rb") as fh:
                        blob = b"blob " + str(os.path.getsize(wt)).encode() + b"\0" + fh.read()
                    if hashlib.sha1(blob).hexdigest() == it["sha"]:
                        continue
            except OSError:
                pass
        deduped.append(it)
    return sorted(deduped, key=lambda i: (i["key"], i["source"]))


def _index_modes() -> dict[str, str]:
    """path -> git mode from the index. Mode 120000 is a symlink."""
    r = _git("ls-files", "-s", "-z")
    modes: dict[str, str] = {}
    for rec in r.stdout.split("\0"):
        if not rec:
            continue
        meta, _, path = rec.partition("\t")
        if path:
            modes[path] = meta.split()[0]
    return modes


def item_is_symlink(item: dict, index_modes: dict[str, str] | None = None) -> bool:
    if item["source"] == "history":
        return item.get("mode") == "120000"
    if item["source"] == "worktree":
        return os.path.islink(os.path.join(REPO, item["path"]))
    modes = index_modes if index_modes is not None else _index_modes()
    return modes.get(item["path"]) == "120000"


def item_link_target(item: dict) -> str | None:
    """The link's TARGET STRING, read from the item's OWN source.

    Reading the index blob regardless of source — which this did before there was
    a worktree lane — reports the OLD target for a link that has been re-pointed
    but not yet staged. That is precisely the case the symlink lane exists for.
    """
    try:
        if item["source"] == "worktree":
            return os.readlink(os.path.join(REPO, item["path"]))
        if item["source"] == "history":
            r = _git("cat-file", "blob", item["sha"], text=False)
        else:
            r = _git("cat-file", "-p", f":{item['path']}", text=False)
    except OSError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", "replace").strip()


def universe_symlink_targets(items: list[dict]) -> dict[str, str]:
    """key -> target string, for every symlink in the work list."""
    modes = _index_modes()
    out: dict[str, str] = {}
    for it in items:
        if not item_is_symlink(it, modes):
            continue
        tgt = item_link_target(it)
        if tgt is not None:
            out[it["key"]] = tgt
    return out


def item_bytes(item: dict) -> bytes | None:
    """The raw bytes this item would publish. For a symlink that is the TARGET
    STRING — git's own blob — never the destination file's content."""
    if item["source"] == "history":
        r = _git("cat-file", "blob", item["sha"], text=False)
        return r.stdout if r.returncode == 0 else None
    if item["source"] == "index":
        r = _git("show", f":{item['path']}", text=False)
        return r.stdout if r.returncode == 0 else None
    p = os.path.join(REPO, item["path"])
    if os.path.islink(p):
        try:
            return os.readlink(p).encode("utf-8", "replace")
        except OSError:
            return None
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _mode_for(staged: bool) -> str:
    return "staged" if staged else "full"


def symlink_targets(staged: bool) -> dict[str, str]:
    """Every symlink the next commit would publish, mapped to its TARGET STRING.

    Read from the git blob (or os.readlink), never by following the link. A
    symlink's target IS published content — git stores it as an ordinary blob —
    so an absolute target publishes the operator's home directory, and once
    published the name of a private sibling repository. Following the link
    instead reads the destination file and never examines the target string,
    which is exactly how that class stayed invisible to every text grep.
    """
    return universe_symlink_targets(build_universe(_mode_for(staged)))


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


def is_scannable_text(path: str) -> bool:
    return (os.path.splitext(path)[1].lower() not in BINARY_EXT
            and not path.endswith(".DS_Store"))


def items_to_scan(items: list[dict], symlinks: frozenset = frozenset()) -> list[dict]:
    """Text items for the line scanners. Symlinks are excluded and handled by
    universe_symlink_targets(): open()ing one follows it, re-reading the
    destination file while never examining the link target itself."""
    return [it for it in items
            if is_scannable_text(it["path"]) and it["key"] not in symlinks]


def credential_material_items(items: list[dict]) -> list[dict]:
    """Items whose EXTENSION is credential/key material. Content-blind on purpose:
    these never reach the line scanners (binary, or no PEM banner to match)."""
    return [it for it in items
            if os.path.splitext(it["path"])[1].lower() in CREDENTIAL_EXT]


def files_to_scan(staged: bool, symlinks: frozenset = frozenset()) -> list[str]:
    """Path-level view of items_to_scan, kept for callers that work in paths."""
    return [it["key"] for it in
            items_to_scan(build_universe(_mode_for(staged)), symlinks)]


def credential_material_files(staged: bool) -> list[str]:
    return [it["key"] for it in credential_material_items(build_universe(_mode_for(staged)))]


MAX_TEXT_BYTES = 4_000_000
MANIFEST_DEFAULT = ".claude/state/confidentiality/manifest.json"
JSON_DEFAULT = ".claude/state/confidentiality/report.json"


def manifest_default(mode: str) -> str:
    """A partial scan must never overwrite the full scan's coverage proof: both
    declare the same schema, and a `changed` manifest sitting at the full-scan
    path would read as "the whole tree was examined"."""
    return MANIFEST_DEFAULT if mode == "full" else MANIFEST_DEFAULT.replace(
        "manifest.json", f"manifest-{mode}.json")


def json_default(mode: str) -> str:
    return JSON_DEFAULT if mode == "full" else JSON_DEFAULT.replace(
        "report.json", f"report-{mode}.json")


def file_bytes(rel: str, staged: bool) -> bytes | None:
    """The raw bytes this path would publish. For a symlink that is the TARGET
    STRING — git's own blob — never the destination file's content."""
    return item_bytes({"path": rel, "source": "index" if staged else "worktree", "sha": None})


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
        # Pin by PATH, report under the item KEY. A history item is keyed
        # `path@<sha>`, which is in no pin list by construction, so keying the
        # lookup would report every reviewed binary on a branch as unlisted.
        path = e.get("path", rel)
        if path not in allow:
            leaks.append(f"{rel}:0: BINARY [unlisted] -> a binary no text lane can read; "
                         f"review it, then add its sha256 to "
                         f"{os.path.relpath(BINARY_ALLOWLIST, REPO)}")
        elif allow[path] != e["sha256"]:
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


def leak_summary(leak: str) -> str:
    """A leak line with everything after the first ' -> ' removed.

    That tail is the only part of the grammar that can carry a matched VALUE —
    `PUBLIC IP -> <addr>`, `SECRET [...] -> <repr>`, `SYMLINK [escapes-repo] ->
    <target>`, `PERSONAL [first.last email] -> @<domain>`. Location and rule are
    enough to act on, and are all that may reach a public CI log, a PR body, or a
    JSON artefact. Deliberately truncates rather than parses: a parser that fails
    open on an unrecognised shape would emit the value it was meant to strip.

    The split is anchored PAST the `<key>:<line>: ` prefix, because a path may
    itself contain " -> " — splitting on the first occurrence in the whole line
    would then cut inside the filename and drop the rule, reporting a location
    with no reason attached.
    """
    m = re.match(r"^(.*?:\d+: )(.*)$", leak, re.DOTALL)
    if not m:
        return leak.split(" -> ", 1)[0].rstrip()
    return (m.group(1) + m.group(2).split(" -> ", 1)[0]).rstrip()


def tree_digest(entries: dict[str, dict]) -> str:
    """A stable fingerprint of exactly the bytes this scan certified.

    Content-addressed over (path, sha256-of-content) pairs, NOT over the item
    keys. The distinction is load-bearing: `git commit` moves an item from the
    worktree lane to the history lane, and a history item is keyed `path@<sha>`
    while a live one is keyed `path`. Digesting keys would therefore change on
    every commit, so /safe-pr's "is what I am pushing still what the guard read?"
    check could never pass. Digesting (path, content) makes the answer depend on
    the published bytes alone — which is the question actually being asked.
    """
    h = hashlib.sha256()
    pairs = sorted({(e["path"], e.get("sha256") or "") for e in entries.values()})
    for path, sha in pairs:
        h.update(f"{path}\0{sha}\n".encode())
    return h.hexdigest()


def write_manifest(path: str, mode: str, entries: dict[str, dict],
                   base: str | None = None) -> None:
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
    for key, e in entries.items():
        rel = e["path"]
        top = rel.split("/")[0] if "/" in rel else "(root)"
        d = dirs.setdefault(top, {"files": 0, "scanned": 0, "hits": 0})
        d["files"] += 1
        d["scanned"] += 1 if e["scanned"] else 0
        d["hits"] += e["hits"]

    kinds = {"text": 0, "binary": 0, "symlink": 0, "unreadable": 0}
    for e in entries.values():
        kinds[e["kind"]] += 1

    head = _git("rev-parse", "HEAD").stdout.strip()
    payload = {
        "schema": "content-guard-manifest/v1",
        "head": head,
        "mode": mode,
        "base": base,
        "universe_source": UNIVERSE_CMDS[mode],
        "counts": {"total": len(entries), **kinds,
                   "skipped": sum(1 for e in entries.values() if not e["scanned"]),
                   "hits": sum(e["hits"] for e in entries.values())},
        "dirs": dict(sorted(dirs.items())),
        "files": [entries[k] for k in sorted(entries)],
    }
    # Invariants — the manifest is worthless if it cannot be trusted to be total.
    assert len(payload["files"]) == payload["counts"]["total"]
    assert len({f["key"] for f in payload["files"]}) == len(payload["files"]), "duplicate key"
    for f in payload["files"]:
        assert f["scanned"] or f["skip_reason"], f"{f['path']}: skipped with no reason"

    os.makedirs(os.path.dirname(abspath), exist_ok=True)
    with open(abspath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"check_client_data: manifest — {payload['counts']['total']} paths "
          f"({kinds['text']} text, {kinds['binary']} binary, {kinds['symlink']} symlink) "
          f"-> {path}")


def write_json_report(path: str, payload: dict) -> None:
    """The machine-readable verdict, for a caller that must gate on it.

    Carries summaries only — `leak_summary` has already removed every matched
    value — because this file is what a workflow reads, quotes and forwards.
    """
    abspath = path if os.path.isabs(path) else os.path.join(REPO, path)
    if _would_be_published(abspath):
        raise SystemExit(f"check_client_data: refusing to write the JSON report to a "
                         f"path this repo would publish: {path}")
    for rec in payload["findings"] + payload["warnings"]:
        assert " -> " not in rec, "a finding record must never carry a matched value"
    os.makedirs(os.path.dirname(abspath), exist_ok=True)
    with open(abspath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")


def decode_scannable(data: bytes | None) -> str | None:
    """Text for the line scanners, or None when there is nothing to scan. The
    size and NUL guards apply to EVERY source — they were previously on the
    worktree arm only, so an oversized or binary index blob was decoded anyway."""
    if data is None or len(data) > MAX_TEXT_BYTES or b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


def read_item_content(item: dict) -> str | None:
    return decode_scannable(item_bytes(item))


def read_content(rel: str, staged: bool) -> str | None:
    return read_item_content({"path": rel, "source": "index" if staged else "worktree",
                              "sha": None})


def scan_lines(rel: str, content: str, denylist: set[str], allowlist: dict,
               consumed: dict, leaks: list[str], warnings: list[str],
               name_exempt: bool = False, self_exempt: bool = False,
               allow_path: str | None = None) -> None:
    """Run every line-level lane over one item's text, appending to leaks/warnings.

    Extracted verbatim from main() so that --scan-file gets the identical rule set:
    a PR body scanned by a second, thinner implementation would be exactly the
    fork this guard exists to prevent.

    `rel` is the item KEY and is what every finding is reported under.
    `allow_path` is the plain repository path and is what allowlist suppression is
    looked up by — an allowlist entry names a file, and a history item's key
    (`path@<sha>`) matches no entry, so keying suppression would make every
    reviewed exception reappear the moment the same file is scanned on a branch.
    """
    allow_path = allow_path or rel
    for label, rx in SECRET_PATTERNS:
        if not rx.flags & re.MULTILINE and "\\n" not in rx.pattern:
            continue
        if self_exempt:
            continue
        for m in rx.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            first = content.splitlines()[lineno - 1]
            key = (allow_path, label, line_sha256(first))
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
            if self_exempt:
                continue
            for m in rx.finditer(line):
                if SECRET_ALLOW.search(m.group(0)) or SECRET_ALLOW.search(line):
                    continue
                key = (allow_path, label, line_sha256(line))
                if key in allowlist:
                    consumed[key] = True
                    continue
                leaks.append(f"{rel}:{n}: SECRET [{label}] -> {m.group(0)[:48]!r}")

        for label, rx in ENGAGEMENT_PATTERNS:
            if self_exempt:
                continue
            for m in rx.finditer(line):
                hit = m.group(0)
                # A placeholder slug documents the format rather than naming
                # an engagement, and the CTF tree holds public challenges.
                if PLACEHOLDER_SLUG.search(hit) or "projects/ctf/" in line:
                    continue
                leaks.append(f"{rel}:{n}: ENGAGEMENT [{label}] -> {hit[:60]!r}")

        if not self_exempt:
            pl, pw = personal_data_findings(rel, n, line)
            leaks.extend(pl)
            warnings.extend(pw)

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


def _today() -> str:
    """UTC date for allowlist expiry. Fails closed: without a usable date every
    `expires < today` comparison is False, which would silently disable expiry
    enforcement in the gate this whole feature rests on."""
    out = subprocess.run(["date", "-u", "+%Y-%m-%d"], capture_output=True,
                         text=True).stdout.strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", out):
        raise AllowlistError("cannot determine today's UTC date; allowlist expiry "
                             "cannot be enforced")
    return out


def scan_external_file(path: str, denylist: set[str]) -> tuple[list[str], list[str]]:
    """Run the line lanes over a file that is NOT in the repo — a PR or issue body
    on its way to becoming public. Authored text is published text; nothing in this
    repo scanned it before."""
    try:
        with open(path, "rb") as fh:
            content = decode_scannable(fh.read())
    except OSError as e:
        raise GitError(f"cannot read {path}: {e}") from e
    if content is None:
        raise GitError(f"{path} is binary or too large to scan")
    leaks: list[str] = []
    warnings: list[str] = []
    scan_lines(os.path.basename(path), content, denylist, {}, {}, leaks, warnings)
    return leaks, warnings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", action="store_true",
                    help="scan staged content only (pre-commit mode)")
    ap.add_argument("--changed", nargs="?", const="", default=None, metavar="BASE",
                    help="scan only what this branch would publish relative to BASE "
                         "(default origin/main, then main): every blob any commit on "
                         "the branch introduced, plus the worktree, index and "
                         "untracked files. A push publishes history, not just the tip.")
    ap.add_argument("--manifest", nargs="?", const="", default=None,
                    metavar="PATH",
                    help="write a per-file coverage manifest proving every publishable "
                         f"path was examined (default {MANIFEST_DEFAULT}; must be gitignored)")
    ap.add_argument("--json", nargs="?", const="", default=None, metavar="PATH",
                    help="write the machine-readable verdict, summaries only — never a "
                         f"matched value (default {JSON_DEFAULT}; must be gitignored)")
    ap.add_argument("--redact", action="store_true",
                    help="print rule and location only, never the matched value. Use "
                         "wherever the output is published — a CI log, a transcript.")
    ap.add_argument("--scan-file", metavar="PATH", default=None,
                    help="scan one file outside the repo (a PR or issue body) with the "
                         "same line rules, then exit")
    ap.add_argument("--require-denylist", action="store_true",
                    help="fail when the client-name term list is not configured, rather "
                         "than reporting clean on a scan that never ran that lane")
    args = ap.parse_args()

    if args.staged and args.changed is not None:
        print("check_client_data: CONFIG ERROR — --staged and --changed are exclusive",
              file=sys.stderr)
        return 2
    mode = "staged" if args.staged else ("changed" if args.changed is not None else "full")

    denylist = load_denylist()
    if args.require_denylist and not denylist:
        print("check_client_data: CONFIG ERROR — the client-name term list is not "
              "configured, so that lane did not run; a clean result would be "
              "misleading. Set CLIENT_DENYLIST (see scripts/gen_denylist.py).",
              file=sys.stderr)
        return 2

    base_ref = base_sha = None
    try:
        if mode == "changed":
            base_ref, base_sha = resolve_base(args.changed or None)
        if args.scan_file:
            leaks, warnings = scan_external_file(args.scan_file, denylist)
            items = []
        else:
            items = build_universe(mode, base_sha)
    except GitError as e:
        print(f"check_client_data: CONFIG ERROR — {e}", file=sys.stderr)
        return 2

    try:
        today = _today()
        allowlist, consumed = load_allowlist(today)
    except AllowlistError as e:
        print(f"check_client_data: CONFIG ERROR — {e}", file=sys.stderr)
        return 2

    if args.scan_file:
        return report(mode, leaks, warnings, args, base_ref, {}, scanned_label=args.scan_file)

    leaks: list[str] = []
    warnings: list[str] = []
    # One entry per publishable item. Built even when --manifest is absent so the
    # unreadable-file check below is always enforced.
    entries: dict[str, dict] = {}

    # Filename-level check first: credential material the content scanners cannot see.
    for it in credential_material_items(items):
        rel = it["key"]
        leaks.append(f"{rel}:0: SECRET [credential-file] -> "
                     f"{os.path.splitext(it['path'])[1]} key/cert material must never be committed")

    # Symlink targets: structural verdicts, plus the target string run through the
    # ordinary line scanners (an absolute target is an operator path by definition).
    symlinks = universe_symlink_targets(items)
    leaks.extend(symlink_leaks(symlinks))

    # Enumerate the whole publishable universe first, so that every item has a
    # recorded disposition — scanned, or skipped for a stated reason.
    for it in items:
        key = it["key"]
        raw = item_bytes(it)
        kind, skip = classify(it["path"], raw, key in symlinks)
        entries[key] = {"key": key, "path": it["path"], "source": it["source"],
                        "kind": kind,
                        "bytes": len(raw) if raw is not None else None,
                        "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                        "scanned": skip is None, "skip_reason": skip, "hits": 0}
    for key in symlinks:
        # A symlink IS scanned: symlink_leaks ran, and its target string goes
        # through the line scanners below.
        if key in entries:
            entries[key]["hits"] = sum(1 for lk in leaks if lk.startswith(f"{key}:"))

    def record(rel: str) -> None:
        if rel in entries:
            entries[rel]["hits"] = sum(1 for lk in leaks if lk.startswith(f"{rel}:"))

    for it in items_to_scan(items, frozenset(symlinks)):
        rel = it["key"]
        content = read_item_content(it)
        if content is None:
            continue
        scan_lines(rel, content, denylist, allowlist, consumed, leaks, warnings,
                   name_exempt=it["path"].startswith(NAME_EXEMPT_PREFIXES),
                   self_exempt=it["path"] in SECRET_SELF_EXEMPT,
                   allow_path=it["path"])
        record(rel)

    # A file that could not be read was never checked. Reporting OK for it would
    # be a silent pass on exactly the case a guard exists for.
    # An entry that suppressed nothing is stale: the line it was granted for is
    # gone or changed. Failing here is what stops the list from accreting dead
    # exceptions that could later be repurposed.
    #
    # FULL SCANS ONLY. --staged and --changed see only the touched files, so an
    # entry for a file not in this scan is legitimately unconsumed — enforcing
    # staleness there would fail every commit and every PR that does not happen
    # to touch every allowlisted file.
    stale = [k for k, used in consumed.items() if not used] if mode == "full" else []
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

    # Text that no line lane read. Reachable only via the MAX_TEXT_BYTES cap, and
    # it must FAIL CLOSED for the same reason UNREADABLE does: the file is
    # publishable, nothing examined it, and reporting OK would certify content
    # this guard never saw. The size cap exists for memory safety, not as a
    # licence to publish — and a client report, a HAR capture, an nmap XML or a
    # Postman export is routinely larger than the cap, which makes this exactly
    # the class the guard exists for. The --scan-file lane already fails closed on
    # the identical condition; these lanes must not disagree.
    oversize = sorted(r for r, e in entries.items()
                      if e["kind"] == "text" and not e["scanned"])
    for rel in oversize:
        leaks.append(f"{rel}:0: UNSCANNED -> publishable text no line lane read "
                     f"({entries[rel]['skip_reason']}); cannot certify it is clean")

    if args.manifest is not None:
        write_manifest(args.manifest or manifest_default(mode), mode, entries, base_ref)

    return report(mode, leaks, warnings, args, base_ref, entries,
                  denylist_active=bool(denylist))


def report(mode: str, leaks: list[str], warnings: list[str], args, base_ref: str | None,
           entries: dict[str, dict], denylist_active: bool = True,
           scanned_label: str | None = None) -> int:
    """Print the human verdict, optionally write the machine one, and return the
    exit code. Exit codes stay 0/1/2 exactly — .githooks/pre-commit, .githooks/
    pre-push and three CI workflows all branch on them."""
    show = leak_summary if args.redact else (lambda s: s)

    if args.json is not None:
        scope = scanned_label or ("the tracked tree" if mode == "full" else f"{mode} content")
        write_json_report(args.json or json_default(mode), {
            "schema": "content-guard-report/v1",
            "mode": mode,
            "base": base_ref,
            "head": _git("rev-parse", "HEAD").stdout.strip(),
            "scope": scope,
            "lanes": {"denylist": "active" if denylist_active else "absent"},
            "counts": {
                "universe": len(entries),
                "scanned": sum(1 for e in entries.values() if e["scanned"]),
                "skipped": sum(1 for e in entries.values() if not e["scanned"]),
                "findings": len(set(leaks)),
                "warnings": len(set(warnings)),
            },
            "tree_digest": tree_digest(entries),
            # Live paths only — worktree and index. A history-only blob has no
            # file to stage, and a caller that staged one would be inventing work.
            "paths": sorted({e["path"] for e in entries.values()
                             if e["source"] in ("worktree", "index")}),
            # Summaries only. leak_summary has already removed the matched value,
            # and write_json_report asserts that it did.
            "findings": sorted({leak_summary(lk) for lk in leaks}),
            "warnings": sorted({leak_summary(w) for w in warnings}),
            "exit": 1 if leaks else 0,
        })

    if warnings:
        print(f"check_client_data: {len(warnings)} warning(s) — heuristic classes "
              f"(address / named contact / phone). Review, do not ignore; these do "
              f"not fail the build:", file=sys.stderr)
        for w in sorted({show(w) for w in warnings})[:25]:
            print(f"  {w}", file=sys.stderr)
        if len({show(w) for w in warnings}) > 25:
            print(f"  ... and {len({show(w) for w in warnings}) - 25} more", file=sys.stderr)

    if not leaks:
        scope = scanned_label or {
            "staged": "staged content",
            "changed": f"the changes on this branch vs {base_ref}",
        }.get(mode, "the tracked tree")
        print(f"check_client_data: OK — no client data, credentials, or public IPs in {scope}")
        return 0

    print("check_client_data: FAIL — client data / credentials must not enter this public repo:",
          file=sys.stderr)
    for leak in sorted({show(lk) for lk in leaks}):
        print(f"  {leak}", file=sys.stderr)
    print("\nFix: describe the CLASS of issue, not the customer — write 'a recurring mobile "
          "re-test crux', never '<ClientA>/<ClientB>'. Use RFC 5737 IPs (203.0.113.x) in examples, "
          "read secrets from os.environ, and keep engagement data under an ignored projects/ tree.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
