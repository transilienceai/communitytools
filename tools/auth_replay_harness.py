#!/usr/bin/env python3
"""Per-role authorization-testing harness — the BOLA/BFLA-at-scale replay engine.

Generalizes the per-engagement request / login / authz-matrix
one-off scripts into ONE reusable primitive: a per-role (and per-tenant) bearer
TOKEN STORE plus a REQUEST-TEMPLATE BATTERY replayed under EVERY role's token, with
each cross-role response classified and a BOLA/BFLA flag raised whenever a role that
should NOT reach an object/action nevertheless got an authorized, data-bearing
response. This is the object-/function-level access-control (IDOR/BOLA/BFLA) engine
the API-at-scale engagement mode drives.

WHAT IT DOES (deterministic, stdlib-only, NO LLM):
  * TokenStore — holds a bearer token per role (optionally tagged with a tenant).
    `extract_token` pulls a token out of a login response either by a dotted JSON
    path (Cognito-style "AuthenticationResult.AccessToken") or by a localStorage key
    name inside a Playwright storageState blob.
  * replay_matrix — for each request template, replay it under EVERY role in the
    store (not just its owner) and classify each response:
        authorized   — 2xx with a real, non-error, non-empty body
        denied       — 401 / 403
        soft-denied  — 2xx but an empty / {error:...} / {data:null} body
        error        — anything else (5xx, 404, ...) — never a positive finding
    A cross-role `authorized` (a role other than the object/action owner getting in)
    is a FINDING: BOLA when the template names an object (`object_ref`), BFLA when it
    is a privileged function/action with no object.
  * cross_tenant_probe — replay an object-scoped template substituting each OTHER
    tenant's object_ref under each OTHER tenant's token, to catch cross-tenant BOLA.

EVIDENCE: every (request x role) emits a record whose `evidence_id` is a STABLE,
deterministic hash of (request_id, as_role) — no uuid / random, so the same matrix
replays to byte-identical evidence ids (idempotent, auditable, re-runnable).

EGRESS ROUTING: the single live-I/O seam `_http(...)` honors an optional SOCKS/HTTP
proxy handle so every request egresses from the provisioned attack vantage. Provision
and register that vantage with tools/provision_vantage.sh + tools/register_source_ip.py
(this tool never opens infrastructure itself) and tunnel to it (e.g. `ssh -D 1080`,
then --proxy socks5h://127.0.0.1:1080).

CREDENTIALS: tokens are referenced in the --tokens spec by env-var NAME (`token_env`),
never inlined; values are resolved via the sibling tools/env-reader.py (os.environ ->
.env). Inline `token` is accepted only for synthetic / test roles.

Usage:
    python3 tools/auth_replay_harness.py --requests <json> --tokens <json> \
        [--proxy <handle>] [--out <path>] [--json]

--requests JSON is either a bare array of request templates (replayed as the matrix)
or an object {"requests": [...], "cross_tenant": [...]}.
--tokens JSON is {"roles": [{"role","token"|"token_env"|("login_response"+"token_path"),
"tenant"?}, ...]}.

Exit codes: 0 = clean (no cross-role authorization anywhere); 1 = at least one
cross-role authorization / BOLA / BFLA / cross-tenant finding detected (scriptable);
2 = usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

# HTTP methods that MUTATE state — used only to annotate a record (mutate vs read),
# never to gate the replay: an authz harness must exercise reads AND writes.
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


# --------------------------------------------------------------------------- #
# The single live-I/O seam. Tests reassign this module attribute so no network
# is ever touched in unit tests. Everything else calls it via the module global
# so the reassignment is picked up at call time.
# --------------------------------------------------------------------------- #
def _http(method, url, headers=None, body=None, proxy=None, timeout=30):
    """Perform ONE HTTP request, optionally through a SOCKS/HTTP proxy handle.

    Returns {"status": int, "headers": {..}, "body": str}. HTTP error statuses
    (4xx/5xx) are returned like any other response, not raised — the caller
    classifies them. `proxy` is a proxy URL (http://, https://, socks5h://, ...);
    when set, the request egresses through it (the provisioned attack vantage).
    """
    import urllib.error
    import urllib.request

    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=str(method).upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        opener = urllib.request.build_opener()
    try:
        resp = opener.open(req, timeout=timeout)
        raw = resp.read()
        return {"status": getattr(resp, "status", resp.getcode()),
                "headers": dict(resp.headers), "body": raw.decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return {"status": e.code, "headers": dict(e.headers or {}),
                "body": raw.decode("utf-8", "replace")}


# --------------------------------------------------------------------------- #
# Token extraction & store
# --------------------------------------------------------------------------- #
def extract_token(login_response, path):
    """Pull a token out of a login response.

    Two shapes are supported by the same `path`:
      * Nested login JSON — `path` is a dotted key path walked through dicts (and
        list indices), e.g. "AuthenticationResult.AccessToken".
      * Playwright storageState — when `login_response` has an "origins" array, the
        localStorage entries are searched for a `name` equal to `path` (or its final
        dotted segment), returning that entry's `value`.

    `login_response` may be a JSON string or an already-parsed object.
    """
    if isinstance(login_response, (str, bytes, bytearray)):
        login_response = json.loads(login_response)

    # Playwright storageState: [{origin, localStorage:[{name,value}, ...]}, ...]
    if isinstance(login_response, dict) and "origins" in login_response:
        key = path.split(".")[-1]
        for origin in login_response.get("origins") or []:
            for item in origin.get("localStorage") or []:
                if item.get("name") in (path, key):
                    return item.get("value")
        raise KeyError("localStorage key not found in storageState: %r" % path)

    # Dotted-path walk through nested JSON.
    cur = login_response
    for seg in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(seg)]
        elif isinstance(cur, dict):
            if seg not in cur:
                raise KeyError("path segment %r not found in login response" % seg)
            cur = cur[seg]
        else:
            raise KeyError("cannot descend into %r at segment %r" % (type(cur).__name__, seg))
    return cur


class TokenStore:
    """Per-role (and per-tenant) bearer token store."""

    def __init__(self):
        self._roles = {}  # role -> {"token": str, "tenant": str|None}

    # extraction is also reachable as TokenStore.extract_token(...)
    extract_token = staticmethod(extract_token)

    def add_role(self, role, token, tenant=None):
        if not role:
            raise ValueError("role name is required")
        if token is None:
            raise ValueError("role %s: token is required" % role)
        self._roles[role] = {"token": token, "tenant": tenant}
        return self

    def get(self, role):
        """Bearer token for a role (raises KeyError if unknown)."""
        return self._roles[role]["token"]

    def tenant(self, role):
        return self._roles[role]["tenant"]

    def roles(self):
        """Role names, sorted for deterministic replay order."""
        return sorted(self._roles)

    def tenants(self):
        """Distinct tenants present, sorted."""
        return sorted({r["tenant"] for r in self._roles.values() if r["tenant"] is not None})

    def token_for_tenant(self, tenant):
        """A representative token for a tenant (the min-named role in it)."""
        cand = sorted(role for role, r in self._roles.items() if r["tenant"] == tenant)
        if not cand:
            raise KeyError("no role registered for tenant %r" % tenant)
        return self._roles[cand[0]]["token"]


# --------------------------------------------------------------------------- #
# Classification & evidence
# --------------------------------------------------------------------------- #
def evidence_id(request_id, as_role):
    """Stable, deterministic evidence id for a (request, role) replay.

    A SHA-256 over "request_id|as_role" — NO random/uuid, so re-running the exact
    same matrix produces byte-identical evidence ids (idempotent & auditable).
    """
    h = hashlib.sha256(("%s|%s" % (request_id, as_role)).encode("utf-8")).hexdigest()
    return "ev-" + h[:16]


def _has_data(body):
    """True when a 2xx body carries real data (not empty / an error / data:null)."""
    if body is None:
        return False
    s = body.strip() if isinstance(body, str) else body
    if not s:
        return False
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        return True  # non-JSON but non-empty body = data
    if obj in (None, {}, [], ""):
        return False
    if isinstance(obj, dict):
        if obj.get("error") or obj.get("errors"):
            return False
        if "data" in obj and not obj["data"]:
            return False
        msg = str(obj.get("message", "")).lower()
        if any(w in msg for w in ("forbidden", "denied", "unauthorized", "not allowed")):
            return False
    return True


def classify_response(status, body):
    """authorized | denied | soft-denied | error."""
    if status in (401, 403):
        return "denied"
    if 200 <= status < 300:
        return "authorized" if _has_data(body) else "soft-denied"
    return "error"


def _finding_class(template):
    """bola (object-level) vs bfla (function-level) for a cross-role authorization."""
    cls = str(template.get("class") or "").lower()
    if cls in ("bola", "bfla"):
        return cls
    return "bola" if template.get("object_ref") else "bfla"


def _auth_headers(base_headers, token, opts):
    h = dict(base_headers or {})
    name = opts.get("header_name", "Authorization")
    fmt = opts.get("header_format", "Bearer %s")
    h[name] = fmt % token
    return h


# --------------------------------------------------------------------------- #
# The matrix replay
# --------------------------------------------------------------------------- #
def replay_matrix(requests, store, opts=None):
    """Replay each request template under EVERY role in the store.

    A request template is {id, method, url, headers?, body?, owner_role,
    object_ref?, class?, allowed_roles?}. For every role, the template is sent with
    that role's bearer token via `_http`; the response is classified and a per
    (request x role) evidence record emitted. A role other than the owner (and not
    listed in `allowed_roles`) that gets `authorized` raises a BOLA/BFLA flag.

    Returns {"records": [...], "flags": [...subset that are findings...],
    "summary": {total, authorized_cross_role, bola_flags, bfla_flags}}.
    """
    opts = opts or {}
    proxy = opts.get("proxy")
    timeout = opts.get("timeout", 30)
    roles = store.roles()

    records = []
    for t in requests:
        rid = t.get("id") or t.get("request_id")
        if not rid:
            raise ValueError("every request template needs an 'id'")
        method = str(t.get("method", "GET")).upper()
        url = t["url"]
        owner = t.get("owner_role")
        obj = t.get("object_ref")
        # Roles legitimately allowed besides the owner (default: only the owner).
        allowed = set(t.get("allowed_roles") or [])
        if owner:
            allowed.add(owner)
        fclass = _finding_class(t)

        for role in roles:
            headers = _auth_headers(t.get("headers"), store.get(role), opts)
            resp = _http(method, url, headers, t.get("body"), proxy, timeout)
            status = resp.get("status")
            body = resp.get("body")
            verdict = classify_response(status, body)
            cross_role = bool(owner) and role != owner
            flag = None
            # A role that should NOT reach this object/action, but got in.
            if verdict == "authorized" and role not in allowed:
                flag = fclass
            records.append({
                "evidence_id": evidence_id(rid, role),
                "request_id": rid,
                "as_role": role,
                "owner_role": owner,
                "object_ref": obj,
                "method": method,
                "mutating": method in _MUTATING,
                "status": status,
                "verdict": verdict,
                "bytes": len(body.encode("utf-8")) if isinstance(body, str) else (len(body) if body else 0),
                "cross_role": cross_role,
                "flag": flag,
            })

    flags = [r for r in records if r["flag"]]
    summary = {
        "total": len(records),
        "authorized_cross_role": len(flags),
        "bola_flags": sum(1 for r in flags if r["flag"] == "bola"),
        "bfla_flags": sum(1 for r in flags if r["flag"] == "bfla"),
    }
    return {"records": records, "flags": flags, "summary": summary}


def cross_tenant_probe(request_template, store, opts=None):
    """Replay an object-scoped template across tenants to catch cross-tenant BOLA.

    The template names, per tenant, the object owned by that tenant via
    `objects_by_tenant` = {tenant: object_ref} and a `url` containing an
    `{object_ref}` placeholder. For every ordered (attacker_tenant, target_tenant)
    pair with attacker != target, the target tenant's object is requested under the
    ATTACKER tenant's token. An `authorized` response is a cross-tenant BOLA finding.

    Returns {"records": [...], "flags": [...], "summary": {total,
    cross_tenant_bola_flags}}.
    """
    opts = opts or {}
    proxy = opts.get("proxy")
    timeout = opts.get("timeout", 30)
    rid = request_template.get("id") or request_template.get("request_id") or "cross-tenant"
    method = str(request_template.get("method", "GET")).upper()
    url_tmpl = request_template["url"]
    objects_by_tenant = request_template.get("objects_by_tenant") or {}

    # Tenants with BOTH a usable token and a target object.
    tenants = sorted(t for t in store.tenants() if t in objects_by_tenant)
    records = []
    for attacker in tenants:
        token = store.token_for_tenant(attacker)
        for target in tenants:
            if attacker == target:
                continue
            obj = objects_by_tenant[target]
            url = url_tmpl.replace("{object_ref}", str(obj))
            headers = _auth_headers(request_template.get("headers"), token, opts)
            resp = _http(method, url, headers, request_template.get("body"), proxy, timeout)
            status = resp.get("status")
            body = resp.get("body")
            verdict = classify_response(status, body)
            flag = "bola" if verdict == "authorized" else None
            records.append({
                "evidence_id": evidence_id(rid, "%s->%s" % (attacker, target)),
                "request_id": rid,
                "attacker_tenant": attacker,
                "target_tenant": target,
                "object_ref": obj,
                "status": status,
                "verdict": verdict,
                "bytes": len(body.encode("utf-8")) if isinstance(body, str) else (len(body) if body else 0),
                "flag": flag,
                "cross_tenant": True,
            })

    flags = [r for r in records if r["flag"]]
    return {
        "records": records,
        "flags": flags,
        "summary": {"total": len(records), "cross_tenant_bola_flags": len(flags)},
    }


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #
def _env_lookup(name):
    """Resolve a token by env-var NAME: os.environ first, then .env via env-reader."""
    val = os.environ.get(name)
    if val is not None:
        return val
    try:
        import importlib.util
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "env-reader.py")
        spec = importlib.util.spec_from_file_location("_env_reader", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.parse_env_files().get(name)
    except Exception:
        return None


def build_store(spec):
    """Build a TokenStore from a --tokens spec (dict with 'roles', or a bare list)."""
    roles = spec.get("roles") if isinstance(spec, dict) else spec
    if not isinstance(roles, list):
        raise ValueError("--tokens must provide a 'roles' array")
    store = TokenStore()
    for r in roles:
        role = r["role"]
        tenant = r.get("tenant")
        if r.get("token"):
            token = r["token"]
        elif r.get("token_env"):
            token = _env_lookup(r["token_env"])
            if token is None:
                raise KeyError("role %s: env var %s is not set" % (role, r["token_env"]))
        elif r.get("login_response") is not None and r.get("token_path"):
            token = extract_token(r["login_response"], r["token_path"])
        else:
            raise ValueError(
                "role %s: need token | token_env | login_response+token_path" % role)
        store.add_role(role, token, tenant=tenant)
    return store


def _split_requests(obj):
    """(replay_templates, cross_tenant_templates) from the --requests JSON."""
    if isinstance(obj, list):
        return obj, []
    if isinstance(obj, dict):
        reqs = obj.get("requests") or obj.get("replay") or []
        ct = obj.get("cross_tenant") or []
        return reqs, ct
    raise ValueError("--requests must be a JSON array or object")


def validate_request_template(t, kind="replay"):
    """Return a list of problems with ONE request template ([] == acceptable).

    kind="replay"   -> a replay_matrix template (the --requests[] shape).
    kind="cross_tenant" -> a cross_tenant_probe template.

    Structural checks only. `owner_role`/`object_ref` are OPTIONAL and never flagged
    here, but note the semantics: with no `owner_role` every role is treated as the
    owner (cross_role=False), so the matrix raises NO BOLA/BFLA flags — set
    `owner_role` on templates you want authorization-tested.
    """
    if not isinstance(t, dict):
        return ["template must be a JSON object"]
    problems = []
    if not (t.get("id") or t.get("request_id")):
        problems.append("missing 'id'")
    url = t.get("url")
    if not (isinstance(url, str) and url.strip()):
        problems.append("missing/blank 'url'")
    if not isinstance(t.get("method", "GET"), str):
        problems.append("'method' must be a string")
    if t.get("headers") is not None and not isinstance(t["headers"], dict):
        problems.append("'headers' must be an object")
    if t.get("body") is not None and not isinstance(t["body"], (str, bytes, bytearray)):
        problems.append("'body' must be a string (serialize a JSON body before emitting it)")
    if kind == "cross_tenant":
        obt = t.get("objects_by_tenant")
        if not isinstance(obt, dict) or not obt:
            problems.append("cross_tenant template needs a non-empty 'objects_by_tenant' object")
        elif isinstance(url, str) and "{object_ref}" not in url:
            problems.append("cross_tenant 'url' must contain the {object_ref} placeholder")
    return problems


def validate_requests(requests_obj):
    """Validate a whole --requests payload (bare list OR {requests, cross_tenant}).

    Returns a list of problem strings; an EMPTY list means replay_matrix /
    cross_tenant_probe will accept the payload. Intended for a producer's unit test:
    `assert validate_requests(my_output) == []`.
    """
    try:
        replay, cross = _split_requests(requests_obj)
    except ValueError as e:
        return [str(e)]
    problems = []
    for i, t in enumerate(replay):
        problems += ["requests[%d]: %s" % (i, p) for p in validate_request_template(t, "replay")]
    for i, t in enumerate(cross):
        problems += ["cross_tenant[%d]: %s" % (i, p) for p in validate_request_template(t, "cross_tenant")]
    return problems


def run(requests_obj, tokens_spec, opts=None):
    """Full run: matrix + any cross-tenant probes. Returns the combined payload."""
    opts = opts or {}
    store = build_store(tokens_spec)
    replay_templates, cross_templates = _split_requests(requests_obj)

    matrix = replay_matrix(replay_templates, store, opts)
    cross = [cross_tenant_probe(t, store, opts) for t in cross_templates]

    ct_flags = sum(c["summary"]["cross_tenant_bola_flags"] for c in cross)
    ct_total = sum(c["summary"]["total"] for c in cross)
    summary = {
        "total": matrix["summary"]["total"] + ct_total,
        # cross-role authorizations = matrix findings + cross-tenant findings
        "authorized_cross_role": matrix["summary"]["authorized_cross_role"] + ct_flags,
        # cross-tenant BOLA folds into the BOLA tally
        "bola_flags": matrix["summary"]["bola_flags"] + ct_flags,
        "bfla_flags": matrix["summary"]["bfla_flags"],
        "cross_tenant_bola_flags": ct_flags,
    }
    return {"replay": matrix, "cross_tenant": cross, "summary": summary}


def _exit_code(summary):
    return 1 if summary.get("authorized_cross_role", 0) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--requests", required=True, help="JSON: array of request templates, or {requests, cross_tenant}")
    ap.add_argument("--tokens", required=True, help="JSON: {roles:[{role, token|token_env|login_response+token_path, tenant?}]}")
    ap.add_argument("--proxy", default=None, help="SOCKS/HTTP proxy handle for egress routing (e.g. socks5h://127.0.0.1:1080)")
    ap.add_argument("--out", default=None, help="write the full results JSON here")
    ap.add_argument("--json", action="store_true", help="print the full results JSON to stdout")
    args = ap.parse_args(argv)

    try:
        with open(args.requests) as fh:
            requests_obj = json.load(fh)
        with open(args.tokens) as fh:
            tokens_spec = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print("ERROR: cannot read input: %s" % e, file=sys.stderr)
        return 2

    try:
        payload = run(requests_obj, tokens_spec, {"proxy": args.proxy})
    except (KeyError, ValueError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps({"out": args.out, **payload["summary"]}, indent=2))
    return _exit_code(payload["summary"])


if __name__ == "__main__":
    sys.exit(main())
