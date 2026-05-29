"""
Internal helper module shared by the cross-project fetch tools in this
directory. Implements the canonical platform-api auth + HTTP + session-finding
patterns from shared/skills/platform-api/examples/list-sessions.py.

Importing convention: the fetch-*.py scripts in this directory inject this
file's parent directory onto sys.path (the hyphenated script names are not
valid module identifiers), then `from _platform_client import ...`.

Single source of truth for:
- Auth header construction (env vars → session_metadata.json → fallback URL).
- HTTP GET wrapper with timeout, JSON decoding, and a `raw=True` mode for
  binary file downloads.
- Paginated session listing with `created_at` desc sort and project_id +
  status filtering.
- File download by session_id + relative path.
- One-line JSON status emission.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import quote, urlencode

_DEFAULT_BASE_URL = "https://transilience-security-os-dev--security-os-backend-dev-ap-a655b7.modal.run"


def get_auth():
    """Resolve API auth from env vars or session_metadata.json. Precedence
    matches shared/skills/platform-api/examples/list-sessions.py."""
    token = os.environ.get("MCS_API_TOKEN", "")
    org_slug = os.environ.get("MCS_ORG_SLUG", "")
    org_id = os.environ.get("MCS_ORG_ID", "")
    base_url = os.environ.get("MCS_API_BASE_URL", "")

    if not token:
        for meta_path in [Path("outputs/session_metadata.json"), Path("session_metadata.json")]:
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                token = token or meta.get("api_token", "")
                org_slug = org_slug or meta.get("org_slug", "")
                org_id = org_id or meta.get("org_id", "")
                base_url = base_url or meta.get("api_base_url", "")
                break

    if not base_url:
        base_url = _DEFAULT_BASE_URL

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if org_slug:
        headers["X-Org-Slug"] = org_slug
    elif org_id:
        headers["X-Org-ID"] = org_id

    return base_url, headers


def api_get(path, query_params=None, *, raw=False, timeout=60):
    base_url, headers = get_auth()
    url = f"{base_url}{path}"
    if query_params:
        url = f"{url}?{urlencode(query_params)}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        if raw:
            return body
        return json.loads(body.decode())


def find_latest_session(project_id, override_id=None):
    """Return the session_id of the most recently created non-failed session
    for `project_id` in the org scope. Walks all pages, sorts by created_at
    desc with session_id tiebreaker. Returns None when no candidate exists."""
    if override_id:
        return override_id

    candidates = []
    page = 1
    while True:
        data = api_get(
            "/project/sessions",
            query_params={"page": page, "page_size": 50, "scope": "org"},
        )
        for s in data.get("sessions", []):
            if s.get("project_id") != project_id:
                continue
            status = (s.get("status") or "").lower()
            if status in {"failed", "error", "blocked"}:
                continue
            candidates.append(s)
        total_pages = data.get("total_pages", 1) or 1
        if page >= total_pages:
            break
        page += 1

    if not candidates:
        return None
    candidates.sort(key=lambda s: (s.get("created_at") or "", s.get("session_id") or ""), reverse=True)
    return candidates[0]["session_id"]


def list_session_files(session_id, predicate):
    """Return [(path, basename), ...] of files in `session_id` for which
    predicate(path) is True. Deduped by basename — paths under `outputs/...`
    are preferred over bare ones if both shapes appear."""
    encoded = quote(session_id, safe="")
    files = api_get(f"/project/files/{encoded}")
    by_basename = {}
    for f in files.get("files", []):
        path = f.get("path") or ""
        if not predicate(path):
            continue
        basename = Path(path).name
        if basename not in by_basename or path.startswith("outputs/"):
            by_basename[basename] = path
    return [(p, b) for b, p in sorted(by_basename.items())]


def download_file(session_id, file_path):
    encoded = quote(session_id, safe="")
    return api_get(
        f"/project/files/{encoded}",
        query_params={"source": "session", "file_path": file_path},
        raw=True,
    )


def emit_status(task_name, status, **fields):
    payload = {"task": task_name, "status": status}
    payload.update(fields)
    print(json.dumps(payload))


def http_error_payload(e):
    """Stable formatter for urllib HTTP errors — useful for emit_status."""
    try:
        body = e.read().decode()[:200]
    except Exception:
        body = ""
    return f"HTTP {e.code}: {body}"
