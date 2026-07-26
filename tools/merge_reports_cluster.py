#!/usr/bin/env python3
"""Deterministic duplicate-candidate clusterer for merge-reports.

Given ONE JSON array of normalized findings gathered from several source reports,
group findings that are *candidate duplicates* of one another so an adjudicating
agent only has to judge small clusters instead of the full N x N cross-product.
This tool NEVER decides that two findings ARE the same — it is high-recall: it
proposes clusters on strong structural signals; the merge-reports workflow then
has an LLM confirm/split each multi-member cluster (precision) and a final
cross-cluster sweep catches semantic duplicates no structural signal linked.

No LLM in this file — pure, deterministic, stdlib-only, so a given input array
always yields the same clusters (idempotent, clockless).

Input finding object (extra keys ignored). `uid` is the only required field and
must be unique across every source (the workflow uses "<source-slug>::<orig_id>"):

    {
      "uid": "acme-vapt::F-3",
      "source": "acme-vapt",            # optional, provenance only
      "title": "Reflected XSS in search",
      "affected": ["https://app.acme.com/search"],   # or "asset": "app.acme.com"
      "url": "https://app.acme.com/search",          # optional
      "param": "q",                                    # optional
      "cwe": "CWE-79",                                 # optional
      "cves": ["CVE-2024-1234"]                        # optional (strings or {"id":...})
    }

Candidate-duplicate EDGES (union-find; two findings in the same set iff a chain
of edges links them):
  * cve            — share >=1 normalized CVE id.
  * asset+cwe      — same normalized asset AND same normalized CWE.
  * asset+urlparam — same normalized asset AND same url path AND same param.
  * asset+title    — same normalized asset AND title token Jaccard >= --threshold.

A finding linked by no edge is its own singleton cluster (so EVERY input finding
appears in exactly one output cluster).

HOST-OVERLAP CANDIDATE PAIRS (see `candidate_pairs`) are a SEPARATE, high-recall
signal that does NOT union: two findings citing the SAME bare host are proposed
as a candidate duplicate pair EVEN WHEN their CWEs (and every other structural
signal) differ — the recall backstop for free-text asset strings + divergent
CWEs where no union edge fires. It never collapses genuinely-different issues on
one host into a single cluster on its own; the workflow's LLM adjudication makes
the final call. A pair is suppressed when the two findings cite that host with
two DIFFERENT explicit ports (host:64680 vs host:64780) — different port ⇒
different service ⇒ not a candidate.

HOST[:PORT] parsing keeps the cited port when present: `norm_hosts(f)` yields bare
hosts (the union key) and `norm_host_ports(f)` yields `host:port` tokens. When the
members of a formed cluster disagree on the cited port for the SAME host, that
cluster carries a `warnings: ["divergent cited port for <host>: {...}"]` entry so a
100-off port divergence is never silently collapsed.

Usage:
    python3 tools/merge_reports_cluster.py --findings <in.json> [-o <out.json>]
        [--threshold 0.6]

Exit codes: 0 ok; 1 missing/bad input; 2 runtime error.
Prints a JSON summary (counts) on the last stdout line.
"""
import argparse
import json
import re
import sys
from urllib.parse import urlsplit

_STOPWORDS = {
    "a", "an", "the", "in", "on", "of", "to", "for", "and", "or", "at", "by",
    "with", "via", "is", "are", "was", "were", "be", "no", "not", "this", "that",
    "it", "its", "as", "from", "into", "over",
}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]+")


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def norm_cves(f):
    """Uppercase CVE ids drawn from `cves` (strings or {id:...}) and any title/desc text."""
    out = set()
    for c in _as_list(f.get("cves")):
        cid = c.get("id") if isinstance(c, dict) else c
        if isinstance(cid, str):
            for m in _CVE_RE.findall(cid):
                out.add(m.upper())
    for key in ("title", "description"):
        val = f.get(key)
        if isinstance(val, str):
            for m in _CVE_RE.findall(val):
                out.add(m.upper())
    return out


def norm_cwe(f):
    """Canonical 'CWE-<n>' (no leading zeros) or '' when absent."""
    for key in ("cwe", "cwe_id"):
        val = f.get(key)
        if isinstance(val, int):
            return "CWE-" + str(val)
        if isinstance(val, str):
            s = val.strip()
            if s.isdigit():
                return "CWE-" + str(int(s))
            m = _CWE_RE.search(s)
            if m:
                return "CWE-" + str(int(m.group(1)))
    return ""


def _split_host_port(s):
    """(host, port) from a URL / asset / free-text string.

    host: lowercased, trailing-dot & path stripped, "" when none is parseable.
    port: int when an explicit, valid :PORT was cited, else None.
    Handles "https://h:8443/x", "1.2.3.4:64780/tcp", "h:443", and messy free
    text like "1.2.3.4: 145 open ports" (host only — "145" is prose, not a port).
    """
    if not isinstance(s, str) or not s.strip():
        return ("", None)
    t = s.strip()
    parts = urlsplit(t if "//" in t else "//" + t)
    host = parts.hostname or ""
    try:
        port = parts.port  # ValueError on a non-integer "port" (e.g. "145 open ports")
    except ValueError:
        port = None
    if not host:
        # Not URL-ish — first whitespace/comma token, optional trailing :PORT.
        tok = re.split(r"[\s,]+", t)[0]
        m = re.match(r"^([^\s:/]+)(?::(\d+))?$", tok)
        if m:
            host = m.group(1)
            if m.group(2) is not None:
                port = int(m.group(2))
        else:
            host = tok.split(":")[0]
    return (host.lower().rstrip("."), port)


def _host_of(s):
    """Lowercase host (or bare token) from a URL / asset string; port & path stripped."""
    return _split_host_port(s)[0]


def _asset_strings(f):
    """Every raw asset/host string a finding cites (affected[] + the scalar keys)."""
    vals = list(_as_list(f.get("affected")))
    for key in ("asset", "url", "host", "endpoint", "target"):
        vals.append(f.get(key))
    return vals


def norm_hosts(f):
    """Set of normalized asset hosts (bare, port stripped) from affected[] / asset / url."""
    out = set()
    for a in _asset_strings(f):
        h = _split_host_port(a)[0]
        if h:
            out.add(h)
    return out


# Historical public name — has always returned the bare-host set.
norm_assets = norm_hosts


def _host_port_pairs(f):
    """Set of (host, port) tuples for assets citing an explicit, valid port."""
    out = set()
    for a in _asset_strings(f):
        host, port = _split_host_port(a)
        if host and port is not None:
            out.add((host, port))
    return out


def norm_host_ports(f):
    """Set of 'host:port' tokens — only assets that cite an explicit port."""
    return {"%s:%d" % (h, p) for (h, p) in _host_port_pairs(f)}


def norm_urlpath(f):
    """(host, path) tuple for a finding's url, or None."""
    u = f.get("url") or f.get("endpoint")
    if not isinstance(u, str) or not u.strip():
        return None
    parts = urlsplit(u if "//" in u else "//" + u)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if not host:
        return None
    return (host, path.rstrip("/") or "/")


def norm_param(f):
    p = f.get("param") or f.get("parameter")
    return p.strip().lower() if isinstance(p, str) and p.strip() else ""


def title_tokens(f):
    val = f.get("title") or ""
    toks = {w for w in _WORD_RE.findall(str(val).lower()) if w not in _STOPWORDS and len(w) > 1}
    return toks


def jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if not inter:
        return 0.0
    return inter / len(a | b)


class _DSU:
    def __init__(self, keys):
        self.parent = {k: k for k in keys}

    def find(self, x):
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic: smaller key becomes the root.
            hi, lo = (ra, rb) if ra > rb else (rb, ra)
            self.parent[hi] = lo


def candidate_pairs(findings):
    """High-recall host-overlap candidate duplicate pairs for LLM adjudication.

    Two findings that cite the SAME bare host are proposed as a candidate pair
    EVEN WHEN their CWEs (and every other structural signal) differ. This is the
    recall backstop the union edges miss when free-text asset strings + divergent
    CWEs mean asset+cwe never fires. It is deliberately NOT a union edge: it never
    collapses distinct issues on one host into a single cluster — the workflow's
    LLM adjudication decides. A pair is suppressed only when the two findings cite
    that shared host with two DIFFERENT explicit ports (different service).

    Returns a deterministically-ordered list of
      {"pair": [uidA, uidB], "hosts": [...], "signal": "host-overlap"}.
    """
    uids = [f.get("uid") for f in findings]
    if any(u is None for u in uids):
        raise ValueError("every finding must have a unique 'uid'")
    # host -> list of (uid, set-of-explicit-ports-cited-on-that-host)
    host_members = {}
    for f in findings:
        u = f["uid"]
        ports_by_host = {}
        for (h, p) in _host_port_pairs(f):
            ports_by_host.setdefault(h, set()).add(p)
        for h in norm_hosts(f):
            host_members.setdefault(h, []).append((u, ports_by_host.get(h, set())))

    pairs = {}  # frozenset(uidA, uidB) -> set(shared hosts)
    for host, members in host_members.items():
        if len(members) < 2:
            continue
        for i in range(len(members)):
            ua, pa = members[i]
            for j in range(i + 1, len(members)):
                ub, pb = members[j]
                if ua == ub:
                    continue
                # Suppress ONLY when both cite explicit ports and they disagree.
                if pa and pb and pa.isdisjoint(pb):
                    continue
                pairs.setdefault(frozenset((ua, ub)), set()).add(host)

    out = []
    for key, hosts in pairs.items():
        a, b = sorted(key)
        out.append({"pair": [a, b], "hosts": sorted(hosts), "signal": "host-overlap"})
    out.sort(key=lambda d: (d["pair"][0], d["pair"][1]))
    return out


def cluster(findings, threshold=0.6):
    """Return (clusters, edges_by_pair). clusters: list of dicts sorted deterministically."""
    uids = [f.get("uid") for f in findings]
    if any(u is None for u in uids):
        raise ValueError("every finding must have a unique 'uid'")
    if len(set(uids)) != len(uids):
        raise ValueError("finding 'uid' values must be unique across all sources")

    by_uid = {f["uid"]: f for f in findings}
    dsu = _DSU(uids)
    signals = {}  # frozenset(pair) -> set(reasons), for cluster explainability

    def link(u, v, reason):
        if u == v:
            return
        dsu.union(u, v)
        key = frozenset((u, v))
        signals.setdefault(key, set()).add(reason)

    # Bucket-based edges — O(sum bucket^2) only within a shared key, never global N^2.
    cve_buckets = {}
    assetcwe_buckets = {}
    urlparam_buckets = {}
    asset_buckets = {}
    for f in findings:
        u = f["uid"]
        for cve in norm_cves(f):
            cve_buckets.setdefault(cve, []).append(u)
        assets = norm_assets(f)
        cwe = norm_cwe(f)
        if cwe:
            for a in assets:
                assetcwe_buckets.setdefault((a, cwe), []).append(u)
        up = norm_urlpath(f)
        param = norm_param(f)
        if up and param:
            urlparam_buckets.setdefault((up[0], up[1], param), []).append(u)
        for a in assets:
            asset_buckets.setdefault(a, []).append(u)

    def _link_bucket(bucket, reason):
        for members in bucket.values():
            if len(members) < 2:
                continue
            anchor = members[0]
            for other in members[1:]:
                link(anchor, other, reason)

    _link_bucket(cve_buckets, "cve")
    _link_bucket(assetcwe_buckets, "asset+cwe")
    _link_bucket(urlparam_buckets, "asset+urlparam")

    # Title-Jaccard edges — pairwise, but ONLY within a shared-asset bucket.
    tok_cache = {f["uid"]: title_tokens(f) for f in findings}
    for members in asset_buckets.values():
        if len(members) < 2:
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = members[i], members[j]
                if dsu.find(a) == dsu.find(b):
                    continue  # already linked by a stronger signal
                jac = jaccard(tok_cache[a], tok_cache[b])
                if jac >= threshold:
                    link(a, b, "asset+title:%.2f" % jac)

    # Collect components deterministically.
    comps = {}
    for u in uids:
        comps.setdefault(dsu.find(u), []).append(u)
    ordered = sorted(comps.values(), key=lambda m: min(m))

    clusters = []
    for idx, members in enumerate(ordered, 1):
        members = sorted(members)
        reasons = set()
        for key, rs in signals.items():
            if key <= set(members):
                reasons |= rs
        entry = {
            "cluster_id": "C%03d" % idx,
            "members": members,
            "size": len(members),
            "signals": sorted(reasons),
            "titles": [by_uid[m].get("title", "") for m in members],
        }
        # Divergent-cited-port warning: members that got clustered but disagree on
        # the port cited for the SAME host (e.g. 64680 vs 64780) must never be
        # collapsed silently — surface it for the adjudicator.
        ports_by_host = {}
        for m in members:
            for (h, p) in _host_port_pairs(by_uid[m]):
                ports_by_host.setdefault(h, set()).add(p)
        warnings = [
            "divergent cited port for %s: {%s}" % (h, ", ".join(str(p) for p in sorted(ports)))
            for h, ports in sorted(ports_by_host.items())
            if len(ports) > 1
        ]
        if warnings:
            entry["warnings"] = warnings
        clusters.append(entry)
    return clusters


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True, help="JSON array of normalized findings")
    ap.add_argument("-o", "--out", help="clusters JSON output path (default: stdout only)")
    ap.add_argument("--threshold", type=float, default=0.6, help="title Jaccard threshold (default 0.6)")
    args = ap.parse_args()

    try:
        with open(args.findings) as fh:
            findings = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print("ERROR: cannot read --findings: %s" % e, file=sys.stderr)
        return 1
    if not isinstance(findings, list):
        print("ERROR: --findings must be a JSON array", file=sys.stderr)
        return 1

    try:
        clusters = cluster(findings, threshold=args.threshold)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - report any runtime error as exit 2
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    try:
        cand_pairs = candidate_pairs(findings)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1

    multi = [c for c in clusters if c["size"] > 1]
    payload = {
        "clusters": clusters,
        "candidate_pairs": cand_pairs,
        "stats": {
            "findings": len(findings),
            "clusters": len(clusters),
            "multi_member_clusters": len(multi),
            "duplicates_collapsed": len(findings) - len(clusters),
            "host_overlap_candidate_pairs": len(cand_pairs),
        },
    }
    if args.out:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)

    print(json.dumps({"out": args.out, **payload["stats"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
