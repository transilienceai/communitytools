#!/usr/bin/env python3
"""Tests for .claude/settings.json hook + permission wiring.

Guards the deterministic Bash activity-logger PostToolUse hook and the two agent
helper-script permissions, plus a regression guard on the pre-existing Write|Edit
stats-updater hook. Stdlib only; NO network. Run: python3 tools/test_settings_wiring.py

REPO_ROOT is resolved as the parent of the tools/ dir, matching how
tools/session-start.py computes it.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SETTINGS_PATH = os.path.join(REPO_ROOT, ".claude", "settings.json")


def load_settings():
    with open(SETTINGS_PATH) as f:
        return json.load(f)


def _post_tool_use(settings):
    return settings.get("hooks", {}).get("PostToolUse", [])


def _entry_commands(entry):
    return [h.get("command") for h in entry.get("hooks", [])]


def test_settings_is_valid_json():
    settings = load_settings()
    assert isinstance(settings, dict), "settings.json must parse to a JSON object"


def test_bash_activity_logger_hook_present():
    settings = load_settings()
    match = [
        e for e in _post_tool_use(settings)
        if e.get("matcher") == "Bash"
        and "python3 tools/activity-logger.py" in _entry_commands(e)
    ]
    assert match, "PostToolUse must have a Bash entry running python3 tools/activity-logger.py"


def test_write_edit_stats_updater_hook_still_present():
    settings = load_settings()
    match = [
        e for e in _post_tool_use(settings)
        if e.get("matcher") == "Write|Edit"
        and "python3 tools/stats-updater.py" in _entry_commands(e)
    ]
    assert match, "regression: Write|Edit -> python3 tools/stats-updater.py PostToolUse entry must remain"


def test_helper_script_permissions_present():
    settings = load_settings()
    allow = settings.get("permissions", {}).get("allow", [])
    for perm in (
        "Bash(python3 tools/register_source_ip.py:*)",
        "Bash(bash tools/provision_vantage.sh:*)",
    ):
        assert perm in allow, f"permissions.allow must contain {perm!r}"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
