#!/usr/bin/env python3
"""fixture_ingest.py — normalize a large API corpus into per-endpoint request-templates.

Turns an OpenAPI/Swagger doc, a Postman collection, or a HAR capture into a flat
list of REQUEST-TEMPLATES that ``tools/auth_replay_harness.py`` consumes as its
``--requests`` input. A multi-thousand-path swagger or a large Postman corpus becomes a
resumable BOLA/BFLA/injection matrix instead of going untested when auth flaps
(the large-API-corpus gap).

A template is a plain dict the harness can replay per-role:

    {
      "id":         "getUserById" | "GET_/users/{id}",   # operationId or METHOD_path
      "method":     "GET",
      "url":        "https://api.example.test/users/1",   # placeholders filled
      "headers":    {...},          # optional, NEVER auth (see below)
      "body":       {...} | "raw",  # optional sampled body
      "owner_role": "admin",        # optional, from x-* role hints / postman auth
      "object_ref": {"in": "path", "name": "id", "value": "1"},  # BOLA candidate
      "auth":       "required" | "public" | "unknown",
      "count":      2,              # HAR only: identical (method,path) collapsed
    }

Secrets are stripped: Authorization / Cookie / API-key headers and bearer tokens
are never carried into a template — the harness injects per-role tokens itself.
Every strip is recorded in ``warnings``.

Stdlib only. OpenAPI in JSON is native; YAML needs pyyaml (guarded import — a
``.yaml`` given without pyyaml warns and degrades rather than crashing).

CLI:
    fixture_ingest.py <source> [--kind auto|openapi|postman|har] [--base-url U]
                      [--vars <json>] [-o OUT] [--json]
Exit 0 clean / 2 usage or unparseable.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse

try:  # OpenAPI YAML needs pyyaml; JSON OpenAPI works without it.
    import yaml as _yaml
except Exception:  # pragma: no cover - environment dependent
    _yaml = None


# --- secret-bearing header/param names never carried into a template ----------
AUTH_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-apikey", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
    "x-session-token", "authentication",
})

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")

# Methods that never carry a request body — a body is dropped for these.
_NO_BODY_METHODS = frozenset({"GET", "HEAD"})

# x-* extension keys that hint at a required role/scope/permission.
ROLE_HINT_RE = re.compile(r"^x-.*(role|scope|permission|grant|privilege)", re.I)

# every {token} in an OpenAPI path template (declared as a param or not).
_PATH_TOKEN_RE = re.compile(r"\{([^{}]+)\}")

# path/query param names that look like an object identifier (BOLA candidates).
_IDLIKE_RE = re.compile(r"(^id$|_id$|id$|uuid|guid)", re.I)
_UUID_PLACEHOLDER = "00000000-0000-0000-0000-000000000001"
# a bare path segment that is itself an id value (Postman/HAR concrete URLs).
_NUMERIC_SEG_RE = re.compile(r"^\d+$")
_UUID_SEG_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# ---------------------------------------------------------------------------
# schema sampling helpers (OpenAPI)
# ---------------------------------------------------------------------------
def _resolve_ref(node, doc, _depth=0):
    """Follow a local ``$ref`` (``#/components/schemas/X`` or ``#/definitions/X``)."""
    if not isinstance(node, dict) or "$ref" not in node or _depth > 20:
        return node
    ref = node["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    cur = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or part not in cur:
            return {}
        cur = cur[part]
    return _resolve_ref(cur, doc, _depth + 1)


def _typed_placeholder(schema):
    """A minimal, type-correct sample value for a leaf schema."""
    schema = schema or {}
    typ = schema.get("type")
    fmt = schema.get("format")
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    if typ in ("integer", "number"):
        return 1
    if typ == "boolean":
        return True
    # strings and anything unknown
    if fmt in ("uuid", "guid"):
        return _UUID_PLACEHOLDER
    if fmt == "email":
        return "test@example.test"
    if fmt in ("date-time", "datetime"):
        return "2020-01-01T00:00:00Z"
    if fmt == "date":
        return "2020-01-01"
    return "test"


def _sample_schema(schema, doc, seen=None):
    """Build a sample body value from a (possibly $ref'd) schema."""
    seen = seen or set()
    schema = _resolve_ref(schema, doc)
    if not isinstance(schema, dict):
        return "test"
    typ = schema.get("type")
    if "example" in schema:
        return schema["example"]
    if typ == "object" or "properties" in schema:
        props = schema.get("properties", {}) or {}
        required = schema.get("required") or []
        # sample required properties; if none declared, sample all (bounded).
        names = required if required else list(props.keys())
        out = {}
        for name in names:
            if name in props:
                key = id(props[name])
                if key in seen:
                    continue
                out[name] = _sample_schema(props[name], doc, seen | {key})
            else:
                out[name] = "test"
        return out
    if typ == "array":
        item = schema.get("items", {})
        key = id(item)
        if key in seen:
            return []
        return [_sample_schema(item, doc, seen | {key})]
    return _typed_placeholder(schema)


def _serialize_body(value, content_type=""):
    """Serialize a sampled body to the STRING form the harness replays.

    The harness (auth_replay_harness) requires ``body`` to be a string it can put
    on the wire verbatim. JSON (and ``+json``) content -> compact JSON text;
    form / multipart content -> urlencoded; an already-string body passes through.
    """
    if value is None or isinstance(value, str):
        return value
    ct = (content_type or "").lower()
    if isinstance(value, dict) and ("urlencoded" in ct or "form-data" in ct
                                    or "multipart" in ct):
        return urllib.parse.urlencode(value)
    return json.dumps(value)


def _ensure_content_type(headers, content_type):
    """Set Content-Type from a serialized body's media type, unless already present.

    The harness reads content type ONLY from ``headers`` (no ``content_type`` key),
    so a serialized body needs its media type carried here to replay correctly.
    """
    if not content_type:
        return
    if any(k.lower() == "content-type" for k in headers):
        return
    headers["Content-Type"] = content_type


def _is_object_ref(name, schema):
    schema = schema or {}
    if _IDLIKE_RE.search(name or ""):
        return True
    return schema.get("format") in ("uuid", "guid")


def _placeholder_schema_for(name):
    """Infer a sampling schema for an UNDECLARED path token from its name.

    A ``{uuid}``/``{guid}`` token -> a uuid placeholder; an id-like token
    (``id``/``*Id``/``*_id``) -> integer (ids are usually numeric, giving
    ``/users/1``); anything else -> a plain string placeholder.
    """
    low = (name or "").lower()
    if "uuid" in low or "guid" in low:
        return {"type": "string", "format": "uuid"}
    if _IDLIKE_RE.search(name or ""):
        return {"type": "integer"}
    return {}


def _role_hint(op):
    """Return the first x-* role/scope/permission hint value as a string, or None."""
    for k, v in op.items():
        if ROLE_HINT_RE.match(k):
            if isinstance(v, list) and v:
                return str(v[0])
            if isinstance(v, (str, int)):
                return str(v)
            if isinstance(v, dict) and v:
                return str(next(iter(v.values())))
    return None


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------
def _openapi_base(doc, base_url):
    if base_url:
        return base_url.rstrip("/")
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "")
        if u:
            return str(u).rstrip("/")
    # swagger 2.0
    host = doc.get("host")
    if host:
        scheme = (doc.get("schemes") or ["https"])[0]
        return ("%s://%s%s" % (scheme, host, doc.get("basePath", ""))).rstrip("/")
    base = doc.get("basePath")
    return str(base).rstrip("/") if base else ""


def _merge_params(path_item, op, doc):
    """Path-level + operation-level parameters, deduped by (name, in), $ref-resolved."""
    merged = {}
    for src in ((path_item or {}).get("parameters", []), (op or {}).get("parameters", [])):
        for p in src or []:
            p = _resolve_ref(p, doc)
            if isinstance(p, dict) and "name" in p:
                merged[(p["name"], p.get("in"))] = p
    return list(merged.values())


def _effective_security(doc, op):
    if "security" in op:
        return op["security"]
    if "security" in doc:
        return doc["security"]
    return None


def _request_body_sample(op, doc):
    """``(body_string, media_type)`` from an OpenAPI3 requestBody, or ``(None, None)``."""
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        rb = _resolve_ref(rb, doc)
        content = rb.get("content", {}) or {}
        mime = ("application/json" if "application/json" in content
                else next(iter(content), None))
        if mime and isinstance(content.get(mime), dict):
            sample = _sample_schema(content[mime].get("schema", {}), doc)
            return _serialize_body(sample, mime), mime
    return None, None


def ingest_openapi(doc, base_url=None):
    """Walk paths x methods -> one request-template per operation.

    Returns ``(templates, warnings)``.
    """
    templates, warnings = [], []
    if not isinstance(doc, dict):
        return templates, ["openapi: document is not an object"]
    base = _openapi_base(doc, base_url)
    paths = doc.get("paths") or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params = _merge_params(path_item, op, doc)
            by_loc = {}
            for p in params:
                by_loc.setdefault(p.get("in"), []).append(p)

            # --- fill EVERY {placeholder} in the path, declared or not ---
            # A bare `/users/{id}` GET with no `parameters` is common; an unfilled
            # {id} makes the replayed URL 404, so fill defensively from the token
            # name when there's no schema. id-like tokens still become object_refs.
            filled = path
            object_ref = None
            declared = {p["name"]: p for p in by_loc.get("path", [])}
            for name in _PATH_TOKEN_RE.findall(path):
                p = declared.get(name)
                if p is not None:
                    schema = p.get("schema") or {k: p[k] for k in ("type", "format")
                                                 if k in p}
                else:  # undeclared: infer a placeholder type from the token name
                    schema = _placeholder_schema_for(name)
                val = _typed_placeholder(schema)
                filled = filled.replace("{%s}" % name, str(val), 1)
                if object_ref is None and _is_object_ref(name, schema):
                    object_ref = {"in": "path", "name": name, "value": str(val)}

            # --- required query params -> query string ---
            query = []
            for p in by_loc.get("query", []):
                if p.get("required"):
                    schema = p.get("schema") or {k: p[k] for k in ("type", "format")
                                                 if k in p}
                    query.append("%s=%s" % (p["name"], _typed_placeholder(schema)))
            url = base + filled
            if query:
                url += ("&" if "?" in url else "?") + "&".join(query)

            # --- non-auth header params -> headers ---
            headers = {}
            for p in by_loc.get("header", []):
                if p["name"].lower() in AUTH_HEADERS:
                    warnings.append("openapi: stripped auth header param %r on %s %s"
                                    % (p["name"], method.upper(), path))
                    continue
                schema = p.get("schema") or {}
                headers[p["name"]] = str(_typed_placeholder(schema))

            # --- body (openapi3 requestBody or swagger2 body/formData) ---
            body, body_ct = _request_body_sample(op, doc)
            if body is None:
                for p in by_loc.get("body", []):  # swagger2 in:body param
                    body = _serialize_body(_sample_schema(p.get("schema", {}), doc),
                                           "application/json")
                    body_ct = "application/json"
                form = {p["name"]: _typed_placeholder(p)
                        for p in by_loc.get("formData", [])}
                if body is None and form:
                    body = _serialize_body(form, "application/x-www-form-urlencoded")
                    body_ct = "application/x-www-form-urlencoded"
            # Invariant: body is a non-empty STRING or omitted entirely — never a
            # list/tuple/dict — and a no-body method never carries one.
            if method.upper() in _NO_BODY_METHODS or not isinstance(body, str):
                body, body_ct = None, None
            if body is not None:
                _ensure_content_type(headers, body_ct)

            # --- security (auth vs public) ---
            sec = _effective_security(doc, op)
            if sec is None:
                auth = "unknown"
            elif isinstance(sec, list) and len(sec) == 0:
                auth = "public"
            else:
                auth = "required"

            tmpl = {
                "id": op.get("operationId") or "%s_%s" % (method.upper(), path),
                "method": method.upper(),
                "url": url,
                "auth": auth,
            }
            if headers:
                tmpl["headers"] = headers
            if body is not None:
                tmpl["body"] = body
            role = _role_hint(op)
            if role:
                tmpl["owner_role"] = role
            if object_ref:
                tmpl["object_ref"] = object_ref
            templates.append(tmpl)
    return templates, warnings


# ---------------------------------------------------------------------------
# Postman
# ---------------------------------------------------------------------------
_VAR_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def _collect_postman_vars(collection, variables):
    env = {}
    for v in collection.get("variable", []) or []:
        if isinstance(v, dict) and "key" in v:
            env[v["key"]] = v.get("value", "")
    if variables:
        env.update({str(k): v for k, v in variables.items()})
    return env


def _resolve_vars(text, env, unresolved):
    if not isinstance(text, str):
        return text

    def repl(m):
        key = m.group(1)
        if key in env:
            return str(env[key])
        unresolved.add(key)
        return m.group(0)

    return _VAR_RE.sub(repl, text)


def _postman_url(url, env, unresolved):
    if isinstance(url, str):
        return _resolve_vars(url, env, unresolved)
    if isinstance(url, dict):
        raw = url.get("raw")
        if raw:
            return _resolve_vars(raw, env, unresolved)
        host = url.get("host", "")
        if isinstance(host, list):
            host = ".".join(host)
        path = url.get("path", "")
        if isinstance(path, list):
            path = "/".join(str(s) for s in path)
        joined = "%s/%s" % (str(host).rstrip("/"), str(path).lstrip("/"))
        return _resolve_vars(joined, env, unresolved)
    return ""


def _object_ref_from_url(url):
    """Detect a concrete id-bearing path segment in a fully-resolved URL."""
    path = url.split("?", 1)[0]
    if "://" in path:
        path = path.split("://", 1)[1]
        path = path[path.find("/"):] if "/" in path else ""
    for seg in reversed([s for s in path.split("/") if s]):
        if _NUMERIC_SEG_RE.match(seg) or _UUID_SEG_RE.match(seg):
            return {"in": "path", "value": seg}
    return None


_PM_RAW_CT = {"json": "application/json", "xml": "application/xml",
              "html": "text/html", "javascript": "application/javascript",
              "text": "text/plain"}


def _postman_body(body, env, unresolved):
    """Return ``(body_string, media_type)`` for a Postman body, or ``(None, None)``."""
    if not isinstance(body, dict):
        return None, None
    mode = body.get("mode")
    if mode == "raw":
        raw = _resolve_vars(body.get("raw", ""), env, unresolved)
        lang = (((body.get("options") or {}).get("raw") or {}).get("language"))
        return raw, _PM_RAW_CT.get(lang)
    if mode in ("urlencoded", "formdata"):
        # formdata is really multipart, but we serialize it urlencoded — so we
        # label it as what we actually produced.
        pairs = [(p["key"], _resolve_vars(p.get("value", ""), env, unresolved))
                 for p in body.get(mode, []) or []
                 if isinstance(p, dict) and "key" in p and not p.get("disabled")]
        return urllib.parse.urlencode(pairs), "application/x-www-form-urlencoded"
    if mode == "graphql":
        gq = body.get("graphql", {}) or {}
        return (json.dumps({"query": _resolve_vars(gq.get("query", ""), env, unresolved),
                            "variables": gq.get("variables", "")}), "application/json")
    return None, None


def _walk_postman(items, env, out, warnings, unresolved):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "item" in item:  # folder / group
            _walk_postman(item["item"], env, out, warnings, unresolved)
            continue
        req = item.get("request")
        if req is None:
            continue
        if isinstance(req, str):  # shorthand: URL only, GET
            req = {"method": "GET", "url": req}
        method = str(req.get("method", "GET")).upper()
        url = _postman_url(req.get("url", ""), env, unresolved)

        headers = {}
        for h in req.get("header", []) or []:
            if not isinstance(h, dict) or h.get("disabled") or "key" not in h:
                continue
            if h["key"].lower() in AUTH_HEADERS:
                warnings.append("postman: stripped auth header %r on %r"
                                % (h["key"], item.get("name", url)))
                continue
            headers[h["key"]] = _resolve_vars(h.get("value", ""), env, unresolved)

        authed = "auth" in req or "auth" in item
        if authed:
            warnings.append("postman: stripped request auth block on %r"
                            % item.get("name", url))

        body, body_ct = _postman_body(req.get("body"), env, unresolved)
        if body is not None:
            _ensure_content_type(headers, body_ct)

        tmpl = {
            "id": item.get("name") or "%s_%s" % (method, url),
            "method": method,
            "url": url,
            "auth": "required" if authed else "unknown",
        }
        if headers:
            tmpl["headers"] = headers
        if body is not None:
            tmpl["body"] = body
        object_ref = _object_ref_from_url(url)
        if object_ref:
            tmpl["object_ref"] = object_ref
        out.append(tmpl)


def ingest_postman(collection, variables=None):
    """Recurse item/item-groups -> one request-template per request.

    Returns ``(templates, warnings)``. ``variables`` overrides collection vars.
    """
    templates, warnings = [], []
    if not isinstance(collection, dict):
        return templates, ["postman: collection is not an object"]
    env = _collect_postman_vars(collection, variables)
    unresolved = set()
    _walk_postman(collection.get("item", []), env, templates, warnings, unresolved)
    for key in sorted(unresolved):
        warnings.append("postman: unresolved variable {{%s}} left as placeholder" % key)
    return templates, warnings


# ---------------------------------------------------------------------------
# HAR
# ---------------------------------------------------------------------------
def _har_body(post_data):
    """Return ``(body_string, media_type)`` for a HAR postData, or ``(None, None)``."""
    if not isinstance(post_data, dict):
        return None, None
    ct = post_data.get("mimeType") or None
    if post_data.get("text"):
        return post_data["text"], ct
    params = post_data.get("params")
    if isinstance(params, list) and params:
        return (urllib.parse.urlencode(
            [(p["name"], p.get("value", "")) for p in params
             if isinstance(p, dict) and "name" in p]),
            ct or "application/x-www-form-urlencoded")
    return None, None


def _url_without_query(url):
    return url.split("?", 1)[0]


def ingest_har(har):
    """Each entry.request -> a template; identical (method, path) deduped w/ count.

    Returns ``(templates, warnings)``.
    """
    templates, warnings = [], []
    if not isinstance(har, dict):
        return templates, ["har: document is not an object"]
    entries = (har.get("log") or {}).get("entries") or []
    index = {}  # (method, url-without-query) -> template
    for entry in entries:
        req = (entry or {}).get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method", "GET")).upper()
        url = req.get("url", "")
        headers = {}
        for h in req.get("headers", []) or []:
            if not isinstance(h, dict) or "name" not in h:
                continue
            if h["name"].lower() in AUTH_HEADERS:
                warnings.append("har: stripped auth header %r on %s %s"
                                % (h["name"], method, _url_without_query(url)))
                continue
            headers[h["name"]] = h.get("value", "")
        # auth cookies live in the cookies[] array too
        if req.get("cookies"):
            warnings.append("har: stripped %d cookie(s) on %s %s"
                            % (len(req["cookies"]), method, _url_without_query(url)))

        key = (method, _url_without_query(url))
        if key in index:
            index[key]["count"] += 1
            continue
        body, body_ct = _har_body(req.get("postData"))
        if body is not None:
            _ensure_content_type(headers, body_ct)
        tmpl = {
            "id": "%s_%s" % (method, _url_without_query(url)),
            "method": method,
            "url": url,
            "auth": "unknown",
            "count": 1,
        }
        if headers:
            tmpl["headers"] = headers
        if body is not None:
            tmpl["body"] = body
        object_ref = _object_ref_from_url(url)
        if object_ref:
            tmpl["object_ref"] = object_ref
        index[key] = tmpl
        templates.append(tmpl)
    return templates, warnings


# ---------------------------------------------------------------------------
# detection + top-level ingest
# ---------------------------------------------------------------------------
def detect_kind(doc):
    if not isinstance(doc, dict):
        return None
    if "openapi" in doc or "swagger" in doc:
        return "openapi"
    info = doc.get("info")
    if isinstance(info, dict) and "postman" in str(info.get("schema", "")).lower():
        return "postman"
    if "item" in doc and isinstance(info, dict):
        return "postman"
    log = doc.get("log")
    if isinstance(log, dict) and "entries" in log:
        return "har"
    return None


class UnparseableError(ValueError):
    """Raised when a source cannot be parsed or its kind cannot be detected."""


def _load_source(path_or_obj):
    """Return ``(doc, warnings)``. Raises UnparseableError on hard parse failure.

    A ``.yaml`` given without pyyaml degrades: returns ``(None, [warning])``.
    """
    if isinstance(path_or_obj, (dict, list)):
        return path_or_obj, []
    if not isinstance(path_or_obj, str):
        raise UnparseableError("source must be a path, JSON/YAML string, or object")

    is_path = os.path.exists(path_or_obj)
    text = None
    if is_path:
        with open(path_or_obj, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = path_or_obj

    try:
        return json.loads(text), []
    except ValueError:
        pass

    looks_yaml = is_path and path_or_obj.lower().endswith((".yaml", ".yml"))
    if _yaml is None:
        if looks_yaml:
            return None, ["pyyaml is not installed; cannot parse YAML source %r — "
                          "provide JSON OpenAPI instead" % path_or_obj]
        raise UnparseableError("source is not valid JSON and pyyaml is unavailable")
    try:
        return _yaml.safe_load(text), []
    except Exception as exc:  # pragma: no cover - malformed yaml
        raise UnparseableError("could not parse source as JSON or YAML: %s" % exc)


def _stats(templates):
    by_method = {}
    public = authed = object_refs = 0
    for t in templates:
        by_method[t["method"]] = by_method.get(t["method"], 0) + 1
        if t.get("auth") == "public":
            public += 1
        else:  # "required" and "unknown" both need a token to be exercised
            authed += 1
        if t.get("object_ref"):
            object_refs += 1
    return {
        "total": len(templates),
        "by_method": by_method,
        "object_ref_count": object_refs,
        "public": public,
        "authed": authed,
    }


def ingest(path_or_obj, kind="auto", base_url=None, variables=None):
    """Normalize a corpus to request-templates.

    Returns ``{"templates": [...], "stats": {...}, "warnings": [...]}``.
    """
    doc, warnings = _load_source(path_or_obj)
    if doc is None:  # degraded (e.g. yaml without pyyaml)
        return {"templates": [], "stats": _stats([]), "warnings": warnings}

    if kind == "auto":
        kind = detect_kind(doc)
        if kind is None:
            raise UnparseableError(
                "could not detect source kind (openapi/postman/har) — pass --kind")

    if kind in ("openapi", "swagger"):
        templates, w = ingest_openapi(doc, base_url=base_url)
    elif kind == "postman":
        templates, w = ingest_postman(doc, variables=variables)
    elif kind == "har":
        templates, w = ingest_har(doc)
    else:
        raise UnparseableError("unknown kind %r" % kind)

    warnings = warnings + w
    return {"templates": templates, "stats": _stats(templates), "warnings": warnings}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Normalize an API corpus (OpenAPI/Postman/HAR) into "
                    "auth_replay_harness request-templates.")
    ap.add_argument("source", help="path to an OpenAPI/Swagger, Postman, or HAR file")
    ap.add_argument("--kind", choices=["auto", "openapi", "postman", "har"],
                    default="auto")
    ap.add_argument("--base-url", default=None,
                    help="override base URL (default: servers[0].url / swagger host)")
    ap.add_argument("--vars", default=None,
                    help="JSON object of Postman variable overrides")
    ap.add_argument("-o", "--out", default=None, help="write the templates doc here")
    ap.add_argument("--json", action="store_true",
                    help="print the full doc to stdout (default when no -o)")
    args = ap.parse_args(argv)

    variables = None
    if args.vars:
        try:
            variables = json.loads(args.vars)
            if not isinstance(variables, dict):
                raise ValueError("--vars must be a JSON object")
        except ValueError as exc:
            sys.stderr.write("error: --vars: %s\n" % exc)
            return 2

    try:
        result = ingest(args.source, kind=args.kind, base_url=args.base_url,
                        variables=variables)
    except UnparseableError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    # The written doc IS the auth_replay_harness --requests input: the templates
    # live under `requests` — the key its _split_requests() reads (a bare list is
    # also accepted). stats/warnings ride along as ignored extras. (ingest() returns
    # the same list under `templates` for programmatic callers, per its contract.)
    out_doc = {"requests": result["templates"],
               "stats": result["stats"],
               "warnings": result["warnings"]}
    out_text = json.dumps(out_doc, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text + "\n")
        sys.stderr.write("wrote %d templates -> %s\n"
                         % (result["stats"]["total"], args.out))
    if args.json or not args.out:
        sys.stdout.write(out_text + "\n")
    for w in result["warnings"]:
        sys.stderr.write("warning: %s\n" % w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
