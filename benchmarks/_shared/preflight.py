"""Pre-flight checks shared across benchmark runners."""
from __future__ import annotations

import os
import subprocess
from typing import Dict, List, Optional


DEFAULT_CHECKS: Dict[str, List[str]] = {
    "docker": ["docker", "--version"],
    "docker compose": ["docker", "compose", "version"],
    "claude": ["claude", "--version"],
    "openssl": ["openssl", "version"],
}


def check_prerequisites(extra_checks: Optional[Dict[str, List[str]]] = None) -> bool:
    """Probe that each prerequisite binary is installed and responsive."""
    checks = dict(DEFAULT_CHECKS)
    if extra_checks:
        checks.update(extra_checks)

    all_ok = True
    for name, cmd in checks.items():
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            print(f"  [ok] {name}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"  [MISSING] {name}")
            all_ok = False
    return all_ok


def check_claude_auth(api_key: Optional[str] = None) -> bool:
    """Verify Claude CLI can authenticate with a tiny smoke test."""
    print("Checking Claude CLI authentication...")
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
    try:
        result = subprocess.run(
            ["claude", "--print", "-p", 'Say "auth ok"'],
            capture_output=True, text=True, timeout=30,
            env=env,
        )
        output = result.stdout + result.stderr
        if "Invalid API key" in output or "Please run /login" in output:
            print("ERROR: Claude CLI authentication failed!")
            print("Run from a regular terminal (not Cursor/VS Code IDE).")
            print("Or run: claude login")
            return False
        print("Claude authentication OK")
        return True
    except FileNotFoundError:
        print("ERROR: 'claude' command not found. Install: npm install -g @anthropic-ai/claude-cli")
        return False
    except subprocess.TimeoutExpired:
        print("WARNING: Auth check timed out, proceeding anyway.")
        return True
