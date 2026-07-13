#!/usr/bin/env python3
"""PostToolUse hook on the Bash tool — deterministic activity logging.

Fires (harness-run) after EVERY Bash tool call, including calls made inside
subagents (the payload then carries ``agent_id``/``agent_type``). Appends one line
per command to ``<engagement-root>/logs/activity/tool-invocations.jsonl`` so the
final report can enumerate exactly what tooling ran — without depending on any
agent choosing to hand-log it. Mirrors ``tools/stats-updater.py``: read the JSON
payload on stdin, do best-effort work, and **exit 0 always** (a hook must never
block a tool call). Network-free; all writes wrapped in try/except.

Assurance (see skills/coordination/reference/output-discipline.md):
  - the full command STRING of every Bash call is harness-guaranteed here;
  - tool-binary extraction from that string is best-effort;
  - ``agent_id``/``agent_type``/``asset`` attribution is best-effort (nullable).

Secrets: command strings are REDACTED by default (basic-auth, bearer/tokens,
Authorization/Cookie headers, --password, api keys, PEM keys). Set
``ACTIVITY_LOG_NO_REDACT=1`` for a verbatim internal-audit run.

Line schema (tool-invocations.jsonl):
  {ts, agent_id, agent_type, asset, bins:[...], full_command, cwd, exit_code, source}

Also best-effort auto-detects source IPs from OUR OWN provisioning / IP-echo
commands (never from arbitrary target output) and appends unverified
``role:"detected"`` rows to source-ips.jsonl; these never clear a reconciliation
gap (only register_source_ip.py writes verified rows).
"""
import datetime as _dt
import json
import os
import re
import shlex
import sys
from pathlib import Path

MAX_LINE = 4000  # < PIPE_BUF (4096): keep a single O_APPEND write atomic

INTERPRETERS = {"python", "python3", "python2", "perl", "ruby", "bash", "sh", "node"}
SCRIPT_EXT = (".py", ".pl", ".rb", ".sh", ".js")
TRIVIAL = {"cd", "ls", "cat", "echo", "pwd", "mkdir"}
WRAPPERS = {"env", "sudo", "time", "nice", "nohup", "stdbuf", "doas"}
WRAPPER_VALUE_FLAGS = {"-u", "-g", "-C", "--user", "--group", "--preserve-env"}

ECHO_HOSTS = ("ifconfig.me", "api.ipify.org", "ipinfo.io", "icanhazip.com")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# (compiled pattern, replacement) — replacement keeps the flag/label, drops the value.
SECRET_SUBS = [
    (re.compile(r"(--password[=\s]+)\S+", re.I), r"\1***"),
    (re.compile(r"(--pass[=\s]+)\S+", re.I), r"\1***"),
    (re.compile(r"(\s-u\s+)[^\s/]+:[^\s/@]+", re.I), r"\1***"),  # curl basic-auth (not a URL)
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),         # scheme://user:pass@
    (re.compile(r"(Authorization:\s*)[^\"'\r\n]+", re.I), r"\1***"),
    (re.compile(r"(Cookie:\s*)[^\"'\r\n]+", re.I), r"\1***"),
    (re.compile(r"(Bearer\s+)\S+", re.I), r"\1***"),
    (re.compile(r"(api[-_]?key[\"']?\s*[=:]\s*[\"']?)[^\s\"'&]+", re.I), r"\1***"),
    (re.compile(r"(x-api-key:\s*)\S+", re.I), r"\1***"),
    (re.compile(r"(token[\"']?\s*[=:]\s*[\"']?)[^\s\"'&]+", re.I), r"\1***"),
    (re.compile(r"(secret[\"']?\s*[=:]\s*[\"']?)[^\s\"'&]+", re.I), r"\1***"),
    (re.compile(r"(aws_secret\w*\s*=\s*)\S+", re.I), r"\1***"),
    (re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
     "***PRIVATE KEY***"),
]


def now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- secret redaction --------------------------------------------------------

def redact(cmd):
    """Mask high-confidence secrets. Never touches bare ``-p``/``-pNNN`` (nmap ports)."""
    s = cmd
    for pat, repl in SECRET_SUBS:
        s = pat.sub(repl, s)
    return s


# --- command → tool binaries -------------------------------------------------

def split_segments(cmd):
    """Quote/escape-aware split on top-level ``&&`` ``||`` ``|`` ``;``."""
    segs, buf = [], []
    i, n, quote = 0, len(cmd), None
    while i < n:
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(cmd[i + 1])
            i += 2
            continue
        if c == "&" and i + 1 < n and cmd[i + 1] == "&":
            segs.append("".join(buf)); buf = []; i += 2; continue
        if c == "|" and i + 1 < n and cmd[i + 1] == "|":
            segs.append("".join(buf)); buf = []; i += 2; continue
        if c in ("|", ";"):
            segs.append("".join(buf)); buf = []; i += 1; continue
        buf.append(c)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def _strip_prefixes(toks):
    """Drop leading VAR=val assignments and env/sudo/time wrappers (and their flags)."""
    i = 0
    while i < len(toks) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]):
        i += 1
    while i < len(toks) and os.path.basename(toks[i]) in WRAPPERS:
        i += 1
        while i < len(toks) and (toks[i].startswith("-")
                                 or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i])):
            if toks[i] in WRAPPER_VALUE_FLAGS:
                i += 2
            else:
                i += 1
    return toks[i:]


def parse_bins(cmd):
    """Best-effort list of distinct tool binaries invoked by a command line."""
    bins = []
    for seg in split_segments(cmd):
        try:
            toks = shlex.split(seg)
        except Exception:
            toks = seg.split()
        toks = _strip_prefixes(toks)
        if not toks:
            continue
        bin0 = os.path.basename(toks[0])
        if bin0 in INTERPRETERS:
            script = None
            for t in toks[1:]:
                if t.startswith("-"):
                    if t in ("-c", "-m"):  # inline code / module → keep interpreter
                        break
                    continue
                script = os.path.basename(t) if t.endswith(SCRIPT_EXT) else None
                break
            name = script or bin0
        else:
            name = bin0
        if not name or name in TRIVIAL:
            continue
        if name not in bins:
            bins.append(name)
    return bins


# --- engagement-root resolution (filesystem anchor) --------------------------

def path_candidates(cmd):
    """Path-like tokens in a command, incl. the value side of ``--flag=path``."""
    try:
        toks = shlex.split(cmd)
    except Exception:
        toks = cmd.split()
    cands = []
    for t in toks:
        pieces = [t]
        if "=" in t:
            pieces.append(t.split("=", 1)[1])
        for p in pieces:
            p = p.strip().strip("'\"").lstrip("<>")
            if p and ("/" in p or p in (".", "..")):
                cands.append(p)
    return cands


def _markers_for(path_str):
    """Nearest ancestor with engagement-meta.json and with stats.json (each or None)."""
    p = Path(path_str)
    meta = stats = None
    for anc in [p, *p.parents]:
        if meta is None and (anc / "engagement-meta.json").is_file():
            meta = str(anc)
        if stats is None and (anc / "stats.json").is_file():
            stats = str(anc)
        if meta and stats:
            break
    return meta, stats


def _shallowest(hits):
    # hits: list of (root, token_abspath) — pick fewest path parts, tie-break lexically.
    return min(hits, key=lambda h: (len(Path(h[0]).parts), h[0]))


def derive_asset(token_abspath, root):
    try:
        rel = os.path.relpath(token_abspath, root)
    except Exception:
        return None
    parts = [seg for seg in rel.split(os.sep) if seg and seg != "."]
    if not parts or parts[0] == "..":
        return None
    if parts[0] == "hosts" and len(parts) >= 2:
        return parts[1]
    return parts[0]


def resolve_root(cmd, cwd, repo_cwd):
    """Resolve the engagement root to log under, and the best-effort asset label.

    engagement-meta.json (only the engagement ROOT has it) always beats a nearer
    stats.json (per-asset dirs have their own), so a hosts/<ip>/ executor still
    attributes to the root. Returns (root|None, asset|None, how)."""
    cwd = cwd or repo_cwd
    meta_hits, stats_hits = [], []
    for cand in path_candidates(cmd):
        ap = cand if os.path.isabs(cand) else os.path.normpath(os.path.join(cwd, cand))
        m, s = _markers_for(ap)
        if m:
            meta_hits.append((m, ap))
        if s:
            stats_hits.append((s, ap))
    if meta_hits:
        root, ap = _shallowest(meta_hits)
        return root, derive_asset(ap, root), "meta-token"
    if stats_hits:
        root, ap = _shallowest(stats_hits)
        return root, derive_asset(ap, root), "stats-token"
    # path-less commands: walk up from the tool cwd itself
    m, s = _markers_for(cwd)
    if m:
        return m, None, "meta-cwd"
    if s:
        return s, None, "stats-cwd"
    # best-effort pointer (written by Setup/Bootstrap), relative to the hook's cwd
    ptr = os.path.join(repo_cwd, ".claude", "state", "active-engagement")
    try:
        if os.path.isfile(ptr):
            target = open(ptr).read().strip()
            if target and os.path.isdir(target):
                return target, None, "pointer"
    except Exception:
        pass
    return None, None, "orphan"


# --- source-IP auto-detect (best-effort, our-own-output only) ----------------

def _is_public(ip):
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(o) != 4 or any(x > 255 for x in o):
        return False
    a, b = o[0], o[1]
    if a in (0, 10, 127):
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    return True


def detect_ips(cmd, output, bins):
    """Return [(kind, ip)] scraped ONLY from our own provisioning / IP-echo commands."""
    found, low = [], cmd.lower()
    is_provision = (any(b in ("gcloud", "aws", "az") for b in bins)
                    and any(v in low for v in ("compute instances create",
                                               "ec2 run-instances", "vm create")))
    if is_provision and output:
        for m in re.finditer(
            r'"?(?:EXTERNAL_IP|PublicIpAddress|publicIpAddress)"?\s*[:=]?\s*"?'
            r'(\d{1,3}(?:\.\d{1,3}){3})', output):
            found.append(("attack-vm-detect", m.group(1)))
        if not found:
            found += [("attack-vm-detect", ip) for ip in IP_RE.findall(output) if _is_public(ip)]
    is_echo = (any(b in ("curl", "wget", "http", "dig") for b in bins)
               and any(h in low for h in ECHO_HOSTS))
    if is_echo and output:
        for ip in IP_RE.findall(output):
            if _is_public(ip):
                found.append(("egress-detect", ip))
                break
    seen, res = set(), []
    for kind, ip in found:
        if (kind, ip) not in seen:
            seen.add((kind, ip))
            res.append((kind, ip))
    return res


# --- append (atomic, capped) -------------------------------------------------

def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    buf = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    if len(buf) >= MAX_LINE:
        fc = obj.get("full_command", "")
        obj = dict(obj)
        if isinstance(fc, str) and len(fc) > 64:
            keep = max(0, len(fc) - (len(buf) - MAX_LINE) - 64)
            obj["full_command"] = fc[:keep] + "…[truncated]"
        else:
            obj["full_command"] = "…[truncated]"
        buf = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        if len(buf) >= MAX_LINE:  # last-resort guard
            obj["full_command"] = "…[truncated]"
            buf = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, buf)
    finally:
        os.close(fd)


def extract_output(payload):
    """Read (exit_code, combined_output) from either PostToolUse payload shape."""
    exit_code, parts = None, []
    tr = payload.get("tool_response")
    if isinstance(tr, dict):
        exit_code = tr.get("exit_code", tr.get("exitCode", tr.get("returncode")))
        for k in ("stdout", "output", "stderr", "content"):
            v = tr.get(k)
            if isinstance(v, str):
                parts.append(v)
    elif isinstance(tr, str):
        parts.append(tr)
    to = payload.get("tool_output")
    if isinstance(to, list):
        for blk in to:
            if not isinstance(blk, dict):
                continue
            t, c = blk.get("type"), blk.get("content")
            if t == "exit_code" and exit_code is None:
                try:
                    exit_code = int(str(c).strip())
                except Exception:
                    exit_code = c
            elif isinstance(c, str):
                parts.append(c)
    elif isinstance(to, str):
        parts.append(to)
    return exit_code, "\n".join(parts)


def run(payload):
    if not isinstance(payload, dict):
        return
    ti = payload.get("tool_input") or {}
    command = ti.get("command") if isinstance(ti, dict) else None
    if not isinstance(command, str) or not command.strip():
        return
    cwd = payload.get("cwd") or ""
    repo_cwd = os.getcwd()
    exit_code, output = extract_output(payload)
    root, asset, _how = resolve_root(command, cwd, repo_cwd)
    bins = parse_bins(command)
    redact_on = os.environ.get("ACTIVITY_LOG_NO_REDACT") != "1"
    rec = {
        "ts": now_iso(),
        "agent_id": payload.get("agent_id"),
        "agent_type": payload.get("agent_type"),
        "asset": asset,
        "bins": bins,
        "full_command": redact(command) if redact_on else command,
        "cwd": cwd,
        "exit_code": exit_code,
        "source": "activity-logger",
    }
    if root:
        inv_path = os.path.join(root, "logs", "activity", "tool-invocations.jsonl")
    else:
        inv_path = os.path.join(repo_cwd, ".claude", "state", "activity-orphan.jsonl")
    append_jsonl(inv_path, rec)

    if not root:
        return
    for kind, ip in detect_ips(command, output, bins):
        provider = ""
        if kind == "attack-vm-detect":
            provider = next((b for b in bins if b in ("gcloud", "aws", "az")), "")
        append_jsonl(os.path.join(root, "logs", "activity", "source-ips.jsonl"), {
            "ts": now_iso(), "ip": ip, "role": "detected", "provider": provider,
            "region": "", "note": kind, "source": "activity-logger", "verified": False,
        })


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        run(payload)
    except Exception:
        pass  # a hook must never block the tool call
    return 0


if __name__ == "__main__":
    sys.exit(main())
