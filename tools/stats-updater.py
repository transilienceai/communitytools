#!/usr/bin/env python3
"""PostToolUse hook on Write|Edit.

Detects writes to engagement-managed files and increments counters in the engagement's
stats.json without asking the model to narrate them. Bookkeeping becomes harness-emitted.

Tracked counters:
  - finding_count       writes to `findings/finding-NNN/...`
  - pivot_count         writes to `attack-chain.md` after the previous batch's experiment was logged
  - experiment_count    rows added to `experiments.md`
  - time_to_first_finding   seconds from engagement start to first finding write
  - goal_attempts (rollup) sum of fail rows in experiments.md

Engagement detection: walks up from the modified file's path looking for a stats.json.
If no stats.json exists, no-op silently.

Exit 0 always — hook must not block the tool call.
"""
import json
import re
import sys
import time
from pathlib import Path


def find_stats_json(path: Path) -> Path | None:
    """Walk up from path looking for a sibling stats.json (engagement root marker)."""
    for parent in [path.parent, *path.parents]:
        candidate = parent / "stats.json"
        if candidate.exists():
            return candidate
    return None


def load_stats(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def save_stats(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def count_experiment_rows(experiments: Path) -> tuple[int, int]:
    """Return (total_rows, fail_rows) by parsing experiments.md table."""
    if not experiments.exists():
        return 0, 0
    total = 0
    fails = 0
    for line in experiments.read_text().splitlines():
        if not line.strip().startswith("|"):
            continue
        parts = [c.strip() for c in line.strip("|").split("|")]
        if len(parts) < 3:
            continue
        # Skip header / divider rows
        if parts[0] in ("ID", "----", "---", "----") or all(set(p) <= set("-:") for p in parts):
            continue
        if parts[0].startswith("E-"):
            total += 1
            for cell in parts:
                if cell.lower() == "fail":
                    fails += 1
                    break
    return total, fails


def update_stats(stats_path: Path, modified_file: Path) -> None:
    stats = load_stats(stats_path)
    engagement_root = stats_path.parent
    rel = modified_file.relative_to(engagement_root) if engagement_root in modified_file.parents else modified_file
    rel_str = str(rel)
    now = time.time()

    if "started_utc" not in stats:
        stats["started_utc"] = now

    if rel_str.startswith("attack-chain.md"):
        stats["pivot_count"] = stats.get("pivot_count", 0) + 1

    if rel_str.startswith("experiments.md") or rel_str == "experiments.md":
        total, fails = count_experiment_rows(modified_file)
        stats["experiment_count"] = total
        stats["goal_attempts_total_fails"] = fails

    m = re.match(r"^findings/finding-(\d+)/", rel_str)
    if m:
        finding_id = m.group(1)
        seen = set(stats.get("findings_seen", []))
        if finding_id not in seen:
            seen.add(finding_id)
            stats["findings_seen"] = sorted(seen)
            stats["finding_count"] = len(seen)
            if "time_to_first_finding" not in stats:
                stats["time_to_first_finding"] = now - stats["started_utc"]

    save_stats(stats_path, stats)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    # PostToolUse payload typically has { tool_name, tool_input: { file_path, ... }, ... }
    tool_input = payload.get("tool_input", {}) if isinstance(payload, dict) else {}
    file_path_raw = tool_input.get("file_path") or tool_input.get("path") or ""
    if not file_path_raw:
        return 0
    fp = Path(file_path_raw)
    if not fp.is_absolute():
        return 0
    stats_path = find_stats_json(fp)
    if stats_path is None:
        return 0
    try:
        update_stats(stats_path, fp)
    except Exception:
        # Hooks must be silent on internal errors; never block.
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
