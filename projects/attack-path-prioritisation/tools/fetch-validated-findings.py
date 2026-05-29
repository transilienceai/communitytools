#!/usr/bin/env python3
"""
Pull validated/*.json findings produced by the attacks-validation project
into the local $OUTPUT_DIR so that chain-merger.py can stitch them. Required because attacks-validation and attack-path-prioritisation run in separate MCS sessions and no longer
share a filesystem mount.

RFP enforcement guarantees:
- Only files matching the strict path shape (outputs/)?validated/<name>.json
  are pulled. Anything under false-positives/, findings/, or nested
  validated/<sub>/... is rejected — attacks-validation's multi-stage confirmation already
  separated these, and attack-path-prioritisation must only see confirmed findings.
- The latest attacks-validation session is selected by `created_at` (descending), not by API
  return order, so the stitcher sees the most recently confirmed corpus.
- Stale local finding-*.json files in $OUTPUT_DIR/validated/ that the latest
  attacks-validation session no longer contains are removed. This prevents a finding that
  attacks-validation has since re-classified to false-positive from contaminating attack-path-prioritisation's
  "confirmed attack paths".

Shared platform-api code lives in `_platform_client.py` alongside this script.

Usage:
    python3 tools/fetch-validated-findings.py --output-dir "$OUTPUT_DIR"
    python3 tools/fetch-validated-findings.py --output-dir "$OUTPUT_DIR" --session-id <id>
    python3 tools/fetch-validated-findings.py --output-dir "$OUTPUT_DIR" --dry-run

Emits a one-line JSON status object on stdout per the attack-path-prioritisation task contract:
    status ∈ {OK, NOOP, FAILED_partial, FAILED}.
Exits non-zero on FAILED / FAILED_partial.
"""

import argparse
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _platform_client import (
    api_get,  # noqa: F401 — kept for completeness; imported by extension scripts
    download_file,
    emit_status,
    find_latest_session,
    http_error_payload,
    list_session_files,
)

SOURCE_PROJECT_ID = "attacks-validation"
TASK_NAME = "fetch-validated-findings"
FINDING_GLOB = "finding-*.json"  # the attacks-validation task-03 naming convention; restricts reconciliation


def is_validated_path(path: str) -> bool:
    """Strict matcher: only `validated/<name>.json` or `outputs/validated/<name>.json`.
    Rejects false-positives/, findings/, nested subdirs, and non-JSON files."""
    if not path or not path.endswith(".json"):
        return False
    parts = Path(path).parts
    if len(parts) == 2 and parts[0] == "validated":
        return True
    if len(parts) == 3 and parts[0] == "outputs" and parts[1] == "validated":
        return True
    return False


def reconcile_stale(target_dir: Path, kept_basenames: set, dry_run: bool):
    """Delete local finding-*.json files in $OUTPUT_DIR/validated/ that are not
    in the latest attacks-validation session. Scoped to the finding-* glob so unrelated files
    are never touched."""
    if not target_dir.exists():
        return []
    removed = []
    for p in sorted(target_dir.glob(FINDING_GLOB)):
        if p.name in kept_basenames:
            continue
        if not dry_run:
            p.unlink()
        removed.append(p.name)
    return removed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, help="$OUTPUT_DIR — org engagement root")
    parser.add_argument("--session-id", default=None, help="Override session discovery with an explicit attacks-validation session_id")
    parser.add_argument("--dry-run", action="store_true", help="List + reconcile in-memory, do not write or delete")
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

    target_dir = output_dir / "validated"

    if not session_id:
        # No attacks-validation session yet — same operational state as "session exists but
        # no findings". Per task-06 spec: NOOP, not BLOCKED.
        removed = reconcile_stale(target_dir, set(), args.dry_run)
        emit_status(TASK_NAME, "NOOP",
                    reason=f"no successful {SOURCE_PROJECT_ID} session for this org",
                    removed_stale=removed)
        sys.exit(0)

    try:
        remote = list_session_files(session_id, is_validated_path)
    except urllib.error.HTTPError as e:
        emit_status(TASK_NAME, "FAILED", session_id=session_id,
                    error=f"listing files: {http_error_payload(e)}")
        sys.exit(1)

    if not remote:
        removed = reconcile_stale(target_dir, set(), args.dry_run)
        emit_status(TASK_NAME, "NOOP", session_id=session_id,
                    reason="no validated/*.json in source session",
                    removed_stale=removed)
        sys.exit(0)

    if not args.dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    pulled = []
    failed = []
    for remote_path, basename in remote:
        dest = target_dir / basename
        if args.dry_run:
            pulled.append(str(dest.relative_to(output_dir)))
            continue
        try:
            body = download_file(session_id, remote_path)
            dest.write_bytes(body)
            pulled.append(str(dest.relative_to(output_dir)))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            failed.append({"file": remote_path, "error": str(e)})

    removed = reconcile_stale(target_dir, {b for _, b in remote}, args.dry_run)

    if failed and pulled:
        emit_status(TASK_NAME, "FAILED_partial", session_id=session_id,
                    pulled=len(pulled), failed=failed,
                    outputs=pulled, removed_stale=removed)
        sys.exit(1)
    if failed:
        emit_status(TASK_NAME, "FAILED", session_id=session_id, failed=failed)
        sys.exit(1)

    emit_status(TASK_NAME, "OK", session_id=session_id,
                files_pulled=len(pulled), outputs=pulled,
                removed_stale=removed, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
