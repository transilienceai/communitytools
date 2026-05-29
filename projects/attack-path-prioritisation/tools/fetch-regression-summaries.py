#!/usr/bin/env python3
"""
Pull the most recent regression-{YYYYWww}.json that attacks-validation's task-04
(regression-sweep) wrote, into $OUTPUT_DIR/artifacts/. Used by attack-path-prioritisation task-08
(exec-report) to annotate the executive report with drift information.

This dependency is **optional** for task-08 — if attacks-validation has not yet produced a
regression summary, the tool emits NOOP and task-08 simply renders without
drift annotations. It is never a blocker.

Selection logic:
- Finds the latest non-failed attacks-validation session via /project/sessions?scope=org.
- Among files in that session matching (outputs/)?artifacts/regression-*.json,
  picks the lexicographically last basename (the week tag YYYYWww sorts
  chronologically, so this is the most recent week).

Shared platform-api code lives in `_platform_client.py` alongside this script.

Usage:
    python3 tools/fetch-regression-summaries.py --output-dir "$OUTPUT_DIR"
    python3 tools/fetch-regression-summaries.py --output-dir "$OUTPUT_DIR" --session-id <id>
    python3 tools/fetch-regression-summaries.py --output-dir "$OUTPUT_DIR" --dry-run

Emits a one-line JSON status object on stdout:
    status ∈ {OK, NOOP, FAILED}.
Exits non-zero on FAILED only.
"""

import argparse
import re
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _platform_client import (
    download_file,
    emit_status,
    find_latest_session,
    http_error_payload,
    list_session_files,
)

SOURCE_PROJECT_ID = "attacks-validation"
TASK_NAME = "fetch-regression-summaries"

_REGRESSION_BASENAME_RE = re.compile(r"^regression-\d{4}W\d{2}\.json$")


def is_regression_path(path: str) -> bool:
    """Strict matcher: `artifacts/regression-YYYYWww.json` or its `outputs/`
    prefix. Rejects per-finding rerun logs (those live under findings/) and
    any nested directories."""
    if not path:
        return False
    parts = Path(path).parts
    basename = parts[-1] if parts else ""
    if not _REGRESSION_BASENAME_RE.match(basename):
        return False
    if len(parts) == 2 and parts[0] == "artifacts":
        return True
    if len(parts) == 3 and parts[0] == "outputs" and parts[1] == "artifacts":
        return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, help="$OUTPUT_DIR — org engagement root")
    parser.add_argument("--session-id", default=None, help="Override session discovery with an explicit attacks-validation session_id")
    parser.add_argument("--dry-run", action="store_true", help="List but do not write")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    if not output_dir.exists():
        emit_status(TASK_NAME, "FAILED", error=f"OUTPUT_DIR does not exist: {output_dir}")
        sys.exit(1)

    try:
        session_id = find_latest_session(SOURCE_PROJECT_ID, args.session_id)
    except urllib.error.HTTPError as e:
        emit_status(TASK_NAME, "FAILED", error=f"listing sessions: {http_error_payload(e)}")
        sys.exit(1)
    except urllib.error.URLError as e:
        emit_status(TASK_NAME, "FAILED", error=f"Network error listing sessions: {e.reason}")
        sys.exit(1)

    if not session_id:
        emit_status(TASK_NAME, "NOOP", reason=f"no successful {SOURCE_PROJECT_ID} session for this org")
        sys.exit(0)

    try:
        remote = list_session_files(session_id, is_regression_path)
    except urllib.error.HTTPError as e:
        emit_status(TASK_NAME, "FAILED", session_id=session_id,
                    error=f"listing files: {http_error_payload(e)}")
        sys.exit(1)

    if not remote:
        emit_status(TASK_NAME, "NOOP", session_id=session_id,
                    reason="no regression-*.json in source session")
        sys.exit(0)

    # remote is sorted by basename asc; latest week is last.
    remote_path, basename = remote[-1]
    target_dir = output_dir / "artifacts"
    dest = target_dir / basename

    if args.dry_run:
        emit_status(TASK_NAME, "OK", session_id=session_id,
                    pulled=str(dest.relative_to(output_dir)),
                    source_path=remote_path, dry_run=True)
        sys.exit(0)

    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        body = download_file(session_id, remote_path)
        dest.write_bytes(body)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        emit_status(TASK_NAME, "FAILED", session_id=session_id,
                    file=remote_path, error=str(e))
        sys.exit(1)

    emit_status(TASK_NAME, "OK", session_id=session_id,
                pulled=str(dest.relative_to(output_dir)),
                source_path=remote_path)


if __name__ == "__main__":
    main()
