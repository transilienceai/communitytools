#!/usr/bin/env python3
"""Tests for scripts/check_client_data.py — the public-repo content guard.

Two halves, and the second matters as much as the first:

  * TRUE POSITIVES  — every rule fires on a synthetic leak. All fixtures are
    invented (Zorbix, Quellhaven, Nemora Bank) and use RFC 5737 addresses, so
    this file never becomes the leak it tests for.
  * FALSE POSITIVES — a corpus of things that must NEVER fire, measured against
    the real tree. A guard that cries wolf gets bypassed, and a bypassed guard
    protects nothing, so the noise floor is a hard assertion rather than a hope.

Run: python3 scripts/test_check_client_data.py
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(REPO, "scripts", "check_client_data.py")

_spec = importlib.util.spec_from_file_location("ccd", GUARD)
ccd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ccd)


def engagement_hits(line: str) -> list[tuple[str, str]]:
    """Mirror of the engagement lane in main(), including its suppressors."""
    out = []
    for label, rx in ccd.ENGAGEMENT_PATTERNS:
        for m in rx.finditer(line):
            hit = m.group(0)
            if ccd.PLACEHOLDER_SLUG.search(hit) or "projects/ctf/" in line:
                continue
            out.append((label, hit))
    return out


# --------------------------------------------------------------------------
# Engagement identifiers — true positives
# --------------------------------------------------------------------------

def test_engagement_path_8digit():
    hits = engagement_hits("see projects/pentest/20260709_zorbix_ext_vapt/report.pdf")
    assert hits and hits[0][0] == "engagement-path", hits


def test_engagement_path_legacy_6digit():
    assert engagement_hits("outputs/260602_quellhaven/findings"), "legacy YYMMDD_ must match"


def test_engagement_path_every_tree():
    for tree in ("pentest", "compliance", "offsec", "webinars",
                 "attacks-validation", "attack-path-prioritisation"):
        line = f"projects/{tree}/20260101_nemora_bank/scope.md"
        assert engagement_hits(line), f"{tree} not covered"


def test_finding_id_engagement_local_script():
    hits = engagement_hits("ported from f09_zmtp_probe.py into the skill")
    assert hits and hits[0][0] == "finding-id", hits


def test_finding_id_sweep():
    assert engagement_hits("finding F-SWEEP-0042 was confirmed"), "F-SWEEP-* must match"


# --------------------------------------------------------------------------
# Engagement identifiers — false positives that must stay silent
# --------------------------------------------------------------------------

def test_placeholder_slug_after_underscore_is_suppressed():
    """Regression: \\bacme\\b never fires inside `260101_acme` because `_` is a word
    character. The suppressor uses letter-boundary lookarounds for exactly this."""
    assert not engagement_hits("projects/pentest/260101_acme is the documented format")


def test_placeholder_slugs_generally():
    for slug in ("acme", "example", "demo", "test", "yourco", "customer"):
        line = f"projects/pentest/260101_{slug}/scope.md"
        assert not engagement_hits(line), f"placeholder {slug} must be suppressed"


def test_ctf_tree_is_not_an_engagement():
    """projects/ctf/ holds public challenge platforms, cited on purpose."""
    line = ("see `projects/ctf/260516_art_of_capture/emulation/qiling_emul.py`")
    assert not engagement_hits(line)


def test_bare_sequence_finding_ids_never_match():
    """A bare F-12 is a sequence number carrying no customer information, and the
    tree uses those ids as synthetic fixtures 80+ times. Matching them would be
    pure noise. This asserts the decision, so it cannot be silently reversed."""
    for fid in ("F-1", "F-01", "F-03", "F-12", "F-200", "F-404", "F-100"):
        assert not engagement_hits(f"the fixture uses {fid} as its id"), fid


# --------------------------------------------------------------------------
# Symlink lane
# --------------------------------------------------------------------------

def test_symlink_absolute_target_blocks():
    leaks = ccd.symlink_leaks({"a/b": "/Users/someone/dev/other-repo/x"})
    assert len(leaks) == 1 and "absolute-target" in leaks[0]


def test_symlink_absolute_target_is_not_echoed():
    """The target string IS the leak; printing it would republish it into CI logs."""
    leaks = ccd.symlink_leaks({"a/b": "/Users/someone/dev/private-repo/x"})
    assert "someone" not in leaks[0] and "private-repo" not in leaks[0], leaks


def test_symlink_windows_absolute_target_blocks():
    assert ccd.symlink_leaks({"a/b": r"C:\Users\someone\x"}), "drive-letter path must block"


def test_symlink_escaping_repo_blocks():
    leaks = ccd.symlink_leaks({"a/b": "../../../outside"})
    assert len(leaks) == 1 and "escapes-repo" in leaks[0]


def test_symlink_relative_in_repo_is_clean():
    assert ccd.symlink_leaks({".claude/skills": "../skills"}) == []


def test_symlink_lane_reads_the_real_tree():
    """Targets come from the git blob, so a link to a DIRECTORY is still seen --
    os.path.isfile() gating is what made this class invisible."""
    targets = ccd.symlink_targets(False)
    assert len(targets) > 50, f"expected the tree's symlinks, saw {len(targets)}"
    assert targets.get(".claude/skills") == "../skills", targets.get(".claude/skills")


def test_symlinks_excluded_from_the_text_scan():
    """open()ing a symlink follows it: it re-reads the destination and never
    examines the target string."""
    targets = ccd.symlink_targets(False)
    scanned = set(ccd.files_to_scan(False, frozenset(targets)))
    assert not (set(targets) & scanned), sorted(set(targets) & scanned)[:5]


def test_tree_has_no_absolute_symlinks():
    """The live invariant. 66 absolute targets were once published this way."""
    assert ccd.symlink_leaks(ccd.symlink_targets(False)) == []


# --------------------------------------------------------------------------
# Noise floor — the anti-rot assertion
# --------------------------------------------------------------------------

def test_current_tree_noise_floor():
    """The guard must be CLEAN on the real tree. If a new rule lands with false
    positives, this fails and the rule gets fixed or dropped -- rather than the
    whole guard getting bypassed."""
    r = subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, f"guard is not clean on the tracked tree:\n{r.stderr[:3000]}"


def test_guard_still_catches_a_planted_leak():
    """A clean tree must not mean a dead guard: prove it still fails on input."""
    line = "artifacts live in projects/pentest/20260709_zorbix_ext_vapt/"
    assert engagement_hits(line), "guard no longer detects a planted engagement path"


# --------------------------------------------------------------------------
# Operator home paths — macOS, Linux and Windows
# --------------------------------------------------------------------------

def _operator_path_hit(line: str) -> str | None:
    rx = dict(ccd.SECRET_PATTERNS)["operator-home-path"]
    for m in rx.finditer(line):
        if ccd.SECRET_ALLOW.search(m.group(0)) or ccd.SECRET_ALLOW.search(line):
            continue
        return m.group(0)
    return None


def test_operator_path_every_platform():
    for line in ("cd /Users/areallyrealperson/dev/x",
                 "cd /home/jsmith/tools",
                 r"dir C:\Users\jdoe\Desktop",
                 "/home/mariarossi/loot"):
        assert _operator_path_hit(line), line


def test_generic_accounts_are_not_operator_paths():
    """Shared/lab/service accounts name nobody. This corpus is every /home/ and
    C:\\Users\\ occurrence measured in the real tree."""
    for line in ("/home/carlos/secret", "/home/claude/x", "/home/restricted_user/a",
                 "/home/user/b", "/home/asterisk/c", "/Users/username/a",
                 r"C:\Users\Public\x", r"C:\Users\Administrator\y",
                 r"C:\Users\current_user\z", r"C:\Users\svc_backup\z"):
        assert _operator_path_hit(line) is None, line


def test_metavariables_are_not_operator_paths():
    """A placeholder is syntax, not a name: <user>, [user], *, %VAR%, $VAR."""
    for line in (r"C:\Users\<user>\z", r"C:\Users\[user]\z", r"C:\Users\*\z",
                 r"C:\Users\<sam>.<DOMAIN>", "/home/<username>/x", "/Users/$USER/x"):
        assert _operator_path_hit(line) is None, line


# --------------------------------------------------------------------------
# Binaries — hash-pinned, never read
# --------------------------------------------------------------------------

def test_binary_allowlist_covers_the_tree():
    """Every binary in the publishable tree must be pinned, or the guard fails."""
    import json
    with open(os.path.join(REPO, "scripts", "content-guard-binaries.json"),
              encoding="utf-8") as fh:
        allow = {b["path"] for b in json.load(fh)["binaries"]}
    binaries = {f["path"] for f in _manifest()["files"] if f["kind"] == "binary"}
    assert not (binaries - allow), f"unpinned binaries: {sorted(binaries - allow)}"


def test_unlisted_binary_blocks():
    e = {"x/new.pdf": {"kind": "binary", "sha256": "a" * 64}}
    leaks = ccd.binary_leaks(e)
    assert len(leaks) == 1 and "unlisted" in leaks[0], leaks


def test_changed_binary_blocks():
    """A reviewed binary whose content moved is unreviewed again."""
    import json
    with open(os.path.join(REPO, "scripts", "content-guard-binaries.json"),
              encoding="utf-8") as fh:
        first = json.load(fh)["binaries"][0]
    leaks = ccd.binary_leaks({first["path"]: {"kind": "binary", "sha256": "b" * 64}})
    assert len(leaks) == 1 and "changed" in leaks[0], leaks


def test_pinned_binary_is_clean():
    import json
    with open(os.path.join(REPO, "scripts", "content-guard-binaries.json"),
              encoding="utf-8") as fh:
        first = json.load(fh)["binaries"][0]
    assert ccd.binary_leaks({first["path"]:
                             {"kind": "binary", "sha256": first["sha256"]}}) == []


# --------------------------------------------------------------------------
# Coverage manifest — "file by file, folder by folder" as a checked property
# --------------------------------------------------------------------------

def _manifest() -> dict:
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "m.json")   # outside the repo -> git ignores it
        r = subprocess.run([sys.executable, GUARD, "--manifest", out],
                           capture_output=True, text=True, cwd=REPO)
        assert os.path.exists(out), f"no manifest written: {r.stdout}{r.stderr}"
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)


def test_manifest_covers_the_git_universe_exactly():
    """Set equality in BOTH directions against git itself. This is the property
    that turns 'we scanned everything' from an assertion into a proof."""
    def g(*a):
        out = subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True).stdout
        return {x for x in out.splitlines() if x}
    universe = g("ls-files") | g("ls-files", "--others", "--exclude-standard")
    man = {f["path"] for f in _manifest()["files"]}
    assert not (universe - man), f"unscanned: {sorted(universe - man)[:5]}"
    assert not (man - universe), f"phantom: {sorted(man - universe)[:5]}"


def test_manifest_counts_are_self_consistent():
    d = _manifest()
    assert d["counts"]["total"] == len(d["files"])
    assert len({f["path"] for f in d["files"]}) == len(d["files"]), "duplicate path"
    assert sum(v["files"] for v in d["dirs"].values()) == d["counts"]["total"]


def test_every_entry_is_scanned_or_states_why_not():
    """Silence about a file is indistinguishable from a clean verdict. Binaries,
    oversized files and unreadable ones must each carry an explicit reason."""
    for f in _manifest()["files"]:
        assert f["scanned"] or f["skip_reason"], f"{f['path']} skipped with no reason"


def test_manifest_includes_binaries_and_symlinks():
    """The universe is every publishable path, not just the ones with line
    scanners — a binary that no lane reads must still be accounted for."""
    d = _manifest()
    assert d["counts"]["symlink"] > 50, d["counts"]
    assert d["counts"]["binary"] > 0, d["counts"]
    assert d["counts"]["unreadable"] == 0, "an unreadable file cannot be certified clean"


def test_manifest_refuses_a_non_gitignored_path():
    """The manifest lists every path in the repo; publishing it would be a map of
    the tree. It must refuse to write anywhere git would publish, and create
    nothing when it refuses."""
    target = os.path.join(REPO, "docs", "_probe_manifest.md")
    assert not os.path.exists(target), "stale probe file"
    r = subprocess.run([sys.executable, GUARD, "--manifest", "docs/_probe_manifest.md"],
                       capture_output=True, text=True, cwd=REPO)
    try:
        assert "refusing" in (r.stdout + r.stderr), r.stdout + r.stderr
        assert not os.path.exists(target), "refused but wrote the file anyway"
    finally:
        if os.path.exists(target):
            os.unlink(target)


# --------------------------------------------------------------------------
# Allowlist — the mechanism that stops a baseline absorbing new leaks
# --------------------------------------------------------------------------

ALLOWLIST = os.path.join(REPO, "scripts", "content-guard-allowlist.json")


def _with_allowlist(mutate):
    """Run the guard with a mutated allowlist, always restoring the original."""
    import json
    with open(ALLOWLIST, encoding="utf-8") as fh:
        original = fh.read()
    doc = json.loads(original)
    mutate(doc)
    try:
        with open(ALLOWLIST, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        return subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
    finally:
        with open(ALLOWLIST, "w", encoding="utf-8") as fh:
            fh.write(original)


def test_allowlist_entry_suppresses_its_finding():
    """The shipped entry must actually be consumed — otherwise it is stale."""
    r = subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stderr[:500]


def test_stale_allowlist_entry_fails_closed():
    """A location cannot be allowlisted and later refilled with other content."""
    r = _with_allowlist(lambda d: d["entries"][0].__setitem__("line_sha256", "0" * 64))
    assert r.returncode == 2, r.returncode
    assert "stale" in (r.stdout + r.stderr).lower()


def test_expired_allowlist_entry_fails_closed():
    """The list is a queue, not a landfill."""
    r = _with_allowlist(lambda d: d["entries"][0].__setitem__("expires", "2020-01-01"))
    assert r.returncode == 2 and "expired" in (r.stdout + r.stderr).lower()


def test_unallowlistable_rule_is_rejected():
    r = _with_allowlist(lambda d: d["entries"][0].__setitem__("rule", "credential-file"))
    assert r.returncode == 2 and "never be allowlisted" in (r.stdout + r.stderr)


def test_allowlist_entry_requires_a_justification():
    r = _with_allowlist(lambda d: d["entries"][0].__setitem__("reason", ""))
    assert r.returncode == 2 and "missing" in (r.stdout + r.stderr)


def test_allowlist_is_capped():
    """A cap makes 'just allowlist it' zero-sum against everyone else's future
    exceptions — the most effective device against a gate becoming a rubber stamp."""
    def blow_the_cap(d):
        e = d["entries"][0]
        d["entries"] = [dict(e, path=f"x{i}.py") for i in range(int(d["max_entries"]) + 5)]
    r = _with_allowlist(blow_the_cap)
    assert r.returncode == 2 and "exceeds the cap" in (r.stdout + r.stderr)


# --------------------------------------------------------------------------
# PreToolUse write-gate — the only guard that fires before content hits disk
# --------------------------------------------------------------------------

WRITE_GATE = os.path.join(REPO, "tools", "content-guard-write.py")


def _write_gate(payload: str) -> int:
    return subprocess.run([sys.executable, WRITE_GATE], input=payload,
                          capture_output=True, text=True, cwd=REPO).returncode


def test_write_gate_blocks_the_structural_classes():
    for content in ("cd /Users/somebody/dev/x",
                    "see projects/pentest/20260709_zorbix_vapt/report",
                    "ported from f09_zmtp_probe.py",
                    "key=AKIA1234567890ABCDEF",
                    "-----BEGIN RSA PRIVATE KEY-----"):
        p = '{"tool_input":{"file_path":"skills/x/SKILL.md","content":%s}}' % json_dumps(content)
        assert _write_gate(p) == 2, content


def test_write_gate_is_silent_inside_an_engagement():
    """Client data belongs under projects/. The gate must never fire there, or it
    would block the work it exists to protect."""
    p = ('{"tool_input":{"file_path":"projects/pentest/20260709_x/notes.md",'
         '"content":"cd /Users/somebody/dev/x"}}')
    assert _write_gate(p) == 0


def test_write_gate_allows_generic_accounts_and_metavariables():
    for content in ("cd /home/carlos/loot", r"C:\\Users\\<user>\\x", "/Users/username/a"):
        p = '{"tool_input":{"file_path":"skills/x/SKILL.md","content":%s}}' % json_dumps(content)
        assert _write_gate(p) == 0, content


def test_write_gate_fails_open():
    """A misfiring write-blocker makes the repo unusable; the committed-content
    guards are the ones that must be exhaustive."""
    for payload in ("not json", "{}", '{"tool_input":{"file_path":"skills/x.md"}}'):
        assert _write_gate(payload) == 0, payload



def test_staleness_is_not_enforced_on_a_staged_scan():
    """--staged sees only the changed files, so an entry for a file outside this
    commit is legitimately unconsumed. Enforcing staleness there would fail every
    commit that does not happen to touch every allowlisted file — which is how the
    pre-commit hook blocked its own guard's commit."""
    import json
    with open(ALLOWLIST, encoding="utf-8") as fh:
        original = fh.read()
    doc = json.loads(original)
    doc["entries"][0]["line_sha256"] = "0" * 64
    try:
        with open(ALLOWLIST, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        full = subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
        staged = subprocess.run([sys.executable, GUARD, "--staged"],
                                capture_output=True, text=True, cwd=REPO)
        assert full.returncode == 2, "a full scan must still catch a stale entry"
        assert staged.returncode != 2, "a staged scan cannot know an entry is stale"
    finally:
        with open(ALLOWLIST, "w", encoding="utf-8") as fh:
            fh.write(original)


# --------------------------------------------------------------------------
# Personal data — name, address, phone, national id
# --------------------------------------------------------------------------

def _personal(line: str):
    return ccd.personal_data_findings("fixture.md", 1, line)


def test_checksum_validated_ids_block():
    """A Verhoeff-valid Aadhaar or a Luhn+IIN-valid card is not an accident, so
    these BLOCK rather than warn. All fixtures are synthetic."""
    for line, label in (("card 4111111111111111 on file", "card"),
                        ("PAN ABCPD1234E issued", "indian pan"),
                        ("SSN 123-45-6789", "us ssn"),
                        ("uid 2345 6789 0124", "aadhaar")):
        leaks, _ = _personal(line)
        assert leaks, f"{label} must block: {line}"


def test_identifier_findings_never_carry_the_value():
    """Reporting a leak must not reproduce it in a CI log."""
    leaks, _ = _personal("card 4111111111111111 on file")
    assert leaks and "4111" not in leaks[0], leaks


def test_verhoeff_rejects_a_bad_checksum():
    assert ccd.verhoeff_valid("234567890124")
    assert not ccd.verhoeff_valid("234567890123")


def test_luhn_and_iin_both_required():
    assert ccd.luhn_valid("4111111111111111")
    assert not ccd.luhn_valid("4111111111111112")
    # Luhn-valid but no known IIN -> not a card.
    leaks, _ = _personal("value 7992739871000005 here")
    assert not leaks


def test_heuristic_classes_warn_but_do_not_block():
    """Address and person-name are heuristics over ordinary prose. A false positive
    that blocks a commit is how a guard gets bypassed, so these only warn."""
    for line in ("Attn: Maria Rossi",
                 "mail john.smith@nemora-bank.co.in",
                 "call +442071838750 now",
                 "12 Maple Street, Springfield 90210"):
        leaks, warns = _personal(line)
        assert warns and not leaks, line


def test_technical_words_are_not_addresses():
    """Regression: `phase`, `main`, `floor`, `block`, `unit`, `sector` are street
    suffixes in the abstract and technical terms in this repo. A street token is
    mandatory, and the list excludes every ambiguous one."""
    for line in ("cipher block phase main floor unit sector 12345",
                 "return math.floor(i / 10000) + 1",
                 "ln -sf /tmp/x /var/lib/postgresql/14/main/pg_tblspc/99999"):
        _, warns = _personal(line)
        assert not warns, line


def test_pentest_example_domains_are_not_people():
    for dom in ("attacker.com", "victim.com", "evil.com", "example.org", "acme.com"):
        _, warns = _personal(f"mail john.smith@{dom}")
        assert not warns, dom


def test_fictional_and_placeholder_phones_are_ignored():
    for line in ("call +15551234567", "dial +1234567890"):
        _, warns = _personal(line)
        assert not warns, line


def test_digit_context_suppresses_identifier_shapes():
    """A port, an offset or a hash is a digit run, not an identity."""
    for line in ("port 4111111111111111 offset", "sha 4111111111111111"):
        leaks, _ = _personal(line)
        assert not leaks, line


def test_tree_has_no_personal_data_warnings():
    """The warn tier only stays useful while it is empty on a clean tree."""
    r = subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
    assert "PERSONAL [" not in r.stderr, r.stderr[:1500]


def json_dumps(s: str) -> str:
    import json
    return json.dumps(s)


# --------------------------------------------------------------------------
# Changed-scope scanning — what PUSHING this branch would publish.
#
# The class these cover: a push publishes HISTORY, not the tip. A secret added in
# one commit and deleted in the next is absent from `BASE...HEAD` and absent from
# the worktree, yet it is fetched by anyone who clones the PR ref and stays
# reachable from that ref after the branch is deleted. A net-diff scan reports
# clean on it, and so does a whole-tree scan.
#
# Every fixture is synthetic AND assembled at run time from fragments, so this
# file contains no literal that matches a credential pattern. That keeps the
# PreToolUse write-gate — which has no self-exemption list — able to protect this
# file like any other, instead of the test suite being a hole in it.
# --------------------------------------------------------------------------

import tempfile  # noqa: E402

FAKE_AWS_KEY = "AKIA" + "QQQQWWWWEEEERRRR"
FAKE_GH_TOKEN = "ghp_" + "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII"
FAKE_HOME_LINK = "/" + "Users/someone/private-repo/x"
# Routable and outside every documentation range, so the IP lane must fire.
FAKE_PUBLIC_IP = "93.184." + "9.11"


def _probe_repo(tmp: str) -> str:
    """A throwaway git repo carrying a copy of the guard, so the changed lane can
    be exercised against real commits without touching this repository.

    Created in a SUBdirectory of tmp on purpose: the guard refuses to write a
    manifest or a JSON report anywhere the repo under test would publish, and a
    probe repo has no .gitignore, so artefacts must land beside it, not in it.
    """
    import shutil
    tmp = os.path.join(tmp, "repo")
    os.makedirs(tmp, exist_ok=True)
    run = lambda *a: subprocess.run(["git", "-C", tmp, *a], capture_output=True, text=True)
    subprocess.run(["git", "init", "-q", tmp], capture_output=True)
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    os.makedirs(os.path.join(tmp, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "skills"), exist_ok=True)
    shutil.copy(GUARD, os.path.join(tmp, "scripts", "check_client_data.py"))
    with open(os.path.join(tmp, "scripts", "content-guard-binaries.json"), "w") as fh:
        fh.write('{"binaries": []}\n')
    with open(os.path.join(tmp, "skills", "base.md"), "w") as fh:
        fh.write("a clean baseline\n")
    run("add", "-A")
    run("commit", "-qm", "base")
    run("branch", "-M", "main")
    return tmp


def _probe_git(tmp: str, *a):
    return subprocess.run(["git", "-C", tmp, *a], capture_output=True, text=True)


def _probe_guard(tmp: str, *flags):
    return subprocess.run([sys.executable, os.path.join(tmp, "scripts", "check_client_data.py"),
                           *flags], capture_output=True, text=True, cwd=tmp)


def _write(tmp: str, rel: str, text: str, mode: str = "w") -> None:
    with open(os.path.join(tmp, rel), mode, encoding="utf-8") as fh:
        fh.write(text)


def test_changed_scan_catches_a_secret_added_then_deleted():
    """THE case that motivates the history lane. The whole-tree scan reports clean
    because the file no longer exists; the push still publishes the blob."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "feature/probe")
        _write(repo, "skills/oops.md", f"key {FAKE_AWS_KEY}\n")
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "add")
        _probe_git(repo, "rm", "-q", "skills/oops.md")
        _probe_git(repo, "commit", "-qm", "remove")

        full = _probe_guard(repo)
        changed = _probe_guard(repo, "--changed", "main")
        assert full.returncode == 0, "precondition: the tip is clean, so a full scan passes"
        assert changed.returncode == 1, "the changed scan must read the orphaned history blob"
        assert "aws-access-key" in changed.stderr, changed.stderr


def test_changed_scan_reads_the_worktree_not_only_commits():
    """An uncommitted edit is what the next commit publishes; it must be scanned."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        _write(repo, "skills/base.md",
               f"host 198.51.100.7 is fine\nreal {FAKE_PUBLIC_IP} endpoint\n", mode="a")
        assert _probe_guard(repo, "--changed", "main").returncode == 1


def test_changed_scan_covers_untracked_files():
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _write(repo, "skills/new.md", f"token {FAKE_GH_TOKEN}\n")
        assert _probe_guard(repo, "--changed", "main").returncode == 1


def test_changed_scan_is_clean_on_a_clean_branch():
    """Precision matters as much as recall: a guard that cries wolf gets bypassed."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        _write(repo, "skills/ok.md", "Use 203.0.113.5 and /home/kali/tools in examples.\n")
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "docs: add an example")
        r = _probe_guard(repo, "--changed", "main")
        assert r.returncode == 0, r.stderr


def test_unresolvable_base_fails_closed():
    """"Scanned nothing" must never be reported as "clean" — the one failure a
    content guard may not have."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        r = _probe_guard(repo, "--changed", "no-such-ref")
        assert r.returncode == 2, r.stdout + r.stderr
        assert "cannot resolve a base ref" in r.stderr, r.stderr


def test_staged_and_changed_are_exclusive():
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        assert _probe_guard(repo, "--staged", "--changed", "main").returncode == 2


def test_changed_scan_exempts_allowlist_staleness():
    """A changed scan is partial exactly as a staged one is, so an entry for an
    untouched file is legitimately unconsumed. Without this exemption every
    /pr-save run would exit 2 as a config error.

    Runs entirely inside a probe repo. Mutating this repository's own tracked
    allowlist to assert a property of the guard means a crashed run leaves the
    tree dirty and every later scan failing on a stale entry that no change
    introduced — which is exactly what happened while this suite was written.
    """
    import json
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        allow = {
            "schema": "content-guard-allowlist/v1",
            "max_entries": 25,
            "unallowlistable": ["denylisted term match"],
            "entries": [{
                "path": "skills/nothing.md",
                "rule": "aws-access-key",
                # Matches no line anywhere, so it is unconsumed by construction.
                "line_sha256": "0" * 64,
                "reason": "synthetic fixture for the staleness exemption test",
                "added_by": "test",
                "added": "2026-01-01",
                "expires": "2099-01-01",
            }],
        }
        with open(os.path.join(repo, "scripts", "content-guard-allowlist.json"), "w") as fh:
            json.dump(allow, fh, indent=2)
        assert _probe_guard(repo).returncode == 2, "a FULL scan must catch a stale entry"
        assert _probe_guard(repo, "--changed", "main").returncode != 2, \
            "a changed scan cannot know an entry is stale"
        assert _probe_guard(repo, "--staged").returncode != 2, \
            "a staged scan cannot know an entry is stale either"


def test_changed_universe_is_blobs_not_the_net_diff():
    """Structural proof of the lane's reason for existing: every intermediate
    revision of a file is its own published blob."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        for i in range(3):
            _write(repo, "skills/base.md", f"revision {i}\n")
            _probe_git(repo, "add", "-A")
            _probe_git(repo, "commit", "-qm", f"chore: rev {i}")
        out = os.path.join(tmp, "m.json")
        _probe_guard(repo, "--changed", "main", "--manifest", out)
        doc = json.load(open(out, encoding="utf-8"))
        assert doc["mode"] == "changed" and doc["base"] == "main", doc["mode"]
        versions = [f for f in doc["files"] if f["path"] == "skills/base.md"]
        assert len(versions) >= 3, f"each intermediate blob must be scanned, got {len(versions)}"


def test_changed_scan_covers_a_type_change():
    """Replacing a tracked FILE with a symlink is git status `T`, which
    `--diff-filter=ACMR` silently drops — and "file replaced by a link to
    /Users/<name>/…" is exactly the operator-path class the symlink lane exists
    for. Regression guard on DIFF_FILTER including T."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        os.remove(os.path.join(repo, "skills", "base.md"))
        os.symlink(FAKE_HOME_LINK, os.path.join(repo, "skills", "base.md"))
        r = _probe_guard(repo, "--changed", "main")
        assert r.returncode == 1, "a file->symlink type change must be scanned"
        assert "absolute-target" in r.stderr, r.stderr


def test_symlink_target_is_read_from_its_own_source():
    """A tracked symlink re-pointed in the worktree but not yet staged must report
    its NEW target. Reading the index blob regardless of source reported the OLD,
    clean one — the exact case the symlink lane exists for."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        link = os.path.join(repo, "skills", "link")
        os.symlink("base.md", link)
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "add a relative link")
        assert _probe_guard(repo, "--changed", "main").returncode == 0, "a relative link is fine"
        os.remove(link)
        os.symlink(FAKE_HOME_LINK, link)          # re-pointed, deliberately NOT staged
        r = _probe_guard(repo, "--changed", "main")
        assert r.returncode == 1, "the worktree target must be read, not the index blob"
        assert "absolute-target" in r.stderr, r.stderr
        assert "someone" not in r.stderr, "the target itself must never be echoed"


# --------------------------------------------------------------------------
# The value-free reporting invariant. A finding travels — into a public CI log, a
# PR body, an agent transcript — so the matched value may never travel with it.
# --------------------------------------------------------------------------

def test_leak_summary_drops_every_matched_value():
    for leak, expected in (
        ("a.md:3: PUBLIC IP -> 203.0.113.9", "a.md:3: PUBLIC IP"),
        ("a.md:4: SECRET [aws-access-key] -> 'KEY'", "a.md:4: SECRET [aws-access-key]"),
        ("a.md:5: SYMLINK [escapes-repo] -> ../../elsewhere", "a.md:5: SYMLINK [escapes-repo]"),
        ("a.md:6: PERSONAL [first.last email] -> redacted @corp.example",
         "a.md:6: PERSONAL [first.last email]"),
        # A line with no ' -> ' is already value-free and must survive intact.
        ("a.md:7: denylisted term match", "a.md:7: denylisted term match"),
    ):
        assert ccd.leak_summary(leak) == expected, ccd.leak_summary(leak)


def test_json_report_never_echoes_a_matched_value():
    """The JSON artefact is what a workflow reads, quotes and forwards into a PR."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _write(repo, "skills/leak.md", f"key {FAKE_AWS_KEY}\nhost {FAKE_PUBLIC_IP}\n")
        out = os.path.join(tmp, "report.json")
        r = _probe_guard(repo, "--changed", "main", "--json", out)
        assert r.returncode == 1, r.stdout + r.stderr
        raw = open(out, encoding="utf-8").read()
        assert FAKE_AWS_KEY not in raw, "the key reached the JSON report"
        assert FAKE_PUBLIC_IP not in raw, "the address reached the JSON report"
        doc = json.loads(raw)
        assert doc["schema"] == "content-guard-report/v1"
        assert doc["counts"]["findings"] >= 2 and doc["exit"] == 1
        assert all(" -> " not in f for f in doc["findings"]), doc["findings"]


def test_redact_strips_values_from_stderr():
    """CI logs on a public repository are public."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _write(repo, "skills/leak.md", f"key {FAKE_AWS_KEY}\n")
        plain = _probe_guard(repo, "--changed", "main")
        red = _probe_guard(repo, "--changed", "main", "--redact")
        assert FAKE_AWS_KEY in plain.stderr, "precondition: the default output shows it"
        assert FAKE_AWS_KEY not in red.stderr, red.stderr
        assert "aws-access-key" in red.stderr, "the rule and location must survive"


def test_scan_file_covers_an_authored_body():
    """A PR or issue body is public text that no other seam in this repo scans."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        body = os.path.join(repo, "body.md")
        _write(repo, "body.md", f"Fixes the parser.\nkey {FAKE_AWS_KEY}\n")
        r = _probe_guard(repo, "--scan-file", body, "--redact")
        assert r.returncode == 1, r.stdout + r.stderr
        assert FAKE_AWS_KEY not in r.stderr, r.stderr
        _write(repo, "ok.md", "Fixes the parser so 203.0.113.5 examples keep working.\n")
        assert _probe_guard(repo, "--scan-file", os.path.join(repo, "ok.md")).returncode == 0


def test_require_denylist_refuses_a_scan_that_skipped_the_name_lane():
    """load_denylist() returns an empty set when the list is absent, so a green
    scan can mean the client-name lane never ran. That is not clean."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        env = dict(os.environ, CLIENT_DENYLIST=os.path.join(tmp, "absent.sha256"))
        r = subprocess.run([sys.executable, os.path.join(repo, "scripts", "check_client_data.py"),
                            "--changed", "main", "--require-denylist"],
                           capture_output=True, text=True, cwd=tmp, env=env)
        assert r.returncode == 2, r.stdout + r.stderr
        assert "term list is not configured" in r.stderr, r.stderr


def test_json_report_refuses_a_published_path():
    """The report names paths and findings; writing it into the tree would publish
    a map of them. The probe path deliberately is NOT a .json — the repo ignores
    `*.json` wholesale, so a .json path is never "would be published" and would
    make this assertion vacuous."""
    probe = "docs/_probe_report.md"
    r = subprocess.run([sys.executable, GUARD, "--changed", "--json", probe],
                       capture_output=True, text=True, cwd=REPO)
    assert "refusing to write the JSON report" in (r.stdout + r.stderr), r.stdout + r.stderr
    assert not os.path.exists(os.path.join(REPO, probe))


def test_oversized_text_fails_closed_in_every_mode():
    """A text file above MAX_TEXT_BYTES is read by no line lane. Reporting OK for
    it certifies content nothing examined — and a client report, a HAR capture or
    an nmap XML is routinely larger than the cap, so this is the class the guard
    exists for, not an edge case. The --scan-file lane already fails closed on the
    same condition; the repo lanes must not disagree with it."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        head = f"key {FAKE_AWS_KEY} host {FAKE_PUBLIC_IP}\n"
        _write(repo, "skills/big.md", head + "x" * (ccd.MAX_TEXT_BYTES + 1 - len(head)))
        assert _probe_guard(repo, "--changed", "main").returncode == 1, "changed mode"
        assert _probe_guard(repo).returncode == 1, "full mode"
        _probe_git(repo, "add", "-A")
        assert _probe_guard(repo, "--staged").returncode == 1, "staged mode"
        r = _probe_guard(repo, "--changed", "main", "--redact")
        assert "UNSCANNED" in r.stderr, r.stderr
        # One byte smaller is scanned normally — the boundary must be exact.
        _write(repo, "skills/big.md", head + "x" * (ccd.MAX_TEXT_BYTES - len(head)))
        r2 = _probe_guard(repo, "--changed", "main", "--redact")
        assert "UNSCANNED" not in r2.stderr and "aws-access-key" in r2.stderr, r2.stderr


def test_tree_digest_is_invariant_across_a_commit():
    """/pr-save re-scans after committing and refuses to push unless the digest
    still matches what the guard certified. Committing moves an item from the
    worktree lane to the history lane and changes its KEY, so a key-addressed
    digest would change on every commit and that check could never pass."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        _write(repo, "skills/new.md", "some ordinary content\n")
        before_p, after_p = os.path.join(tmp, "b.json"), os.path.join(tmp, "a.json")
        _probe_guard(repo, "--changed", "main", "--json", before_p)
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "feat: add a note")
        _probe_guard(repo, "--changed", "main", "--json", after_p)
        before = json.load(open(before_p, encoding="utf-8"))["tree_digest"]
        after = json.load(open(after_p, encoding="utf-8"))["tree_digest"]
        assert before == after, f"digest changed across commit: {before[:16]} -> {after[:16]}"
        # ...but it MUST change when the content does, or it certifies nothing.
        _write(repo, "skills/new.md", "different content\n")
        changed_p = os.path.join(tmp, "c.json")
        _probe_guard(repo, "--changed", "main", "--json", changed_p)
        assert json.load(open(changed_p, encoding="utf-8"))["tree_digest"] != after


def test_allowlist_suppression_keys_on_path_not_item_key():
    """An allowlist entry names a FILE. A history item is keyed `path@<sha>`, which
    matches no entry, so keying suppression by it would make every reviewed
    exception reappear the moment that file is scanned on a branch."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        line = f"key {FAKE_AWS_KEY}\n"
        _write(repo, "skills/fixture.md", line)
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "add a fixture")
        assert _probe_guard(repo, "--changed", "main").returncode == 1, "precondition"
        with open(os.path.join(repo, "scripts", "content-guard-allowlist.json"), "w") as fh:
            json.dump({"schema": "content-guard-allowlist/v1", "max_entries": 25,
                       "unallowlistable": [], "entries": [{
                           "path": "skills/fixture.md", "rule": "aws-access-key",
                           "line_sha256": ccd.line_sha256(line.rstrip("\n")),
                           "reason": "synthetic fixture", "added_by": "test",
                           "added": "2026-01-01", "expires": "2099-01-01"}]}, fh)
        assert _probe_guard(repo, "--changed", "main").returncode == 0, \
            "the allowlist entry must suppress the finding on a history blob too"


def test_history_symlink_is_not_deduped_against_a_regular_file():
    """git stores a symlink as a blob holding its target string, so a history
    symlink and a regular file whose text equals that target share a blob sha.
    Deduping across that boundary drops the symlink item and with it the whole
    symlink lane for that path — the absolute-target check included."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _probe_repo(tmp)
        _probe_git(repo, "checkout", "-qb", "f")
        os.symlink(FAKE_HOME_LINK, os.path.join(repo, "skills", "link"))
        _probe_git(repo, "add", "-A")
        _probe_git(repo, "commit", "-qm", "add a link")
        # A regular file whose CONTENT is byte-identical to the link's target.
        os.remove(os.path.join(repo, "skills", "link"))
        _write(repo, "skills/link", FAKE_HOME_LINK)
        r = _probe_guard(repo, "--changed", "main", "--redact")
        assert r.returncode == 1, "the history symlink blob must still be scanned"
        assert "absolute-target" in r.stderr or "operator-home-path" in r.stderr, r.stderr


def test_manifest_default_differs_per_mode():
    """A partial scan must not overwrite the full scan's coverage proof: both
    declare the same schema, so a changed manifest at the full path would read as
    "the whole tree was examined"."""
    paths = {m: ccd.manifest_default(m) for m in ("full", "staged", "changed")}
    assert len(set(paths.values())) == 3, paths
    assert paths["full"] == ccd.MANIFEST_DEFAULT


def main() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
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
