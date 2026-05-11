"""Pre-flight checks shared across benchmark runners."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Dict, List, Optional

from .env_loader import resolve_anthropic_key, resolve_openai_key


BASE_CHECKS: Dict[str, List[str]] = {
    "docker": ["docker", "--version"],
    "docker compose": ["docker", "compose", "version"],
    "openssl": ["openssl", "version"],
}

PROVIDER_CHECKS: Dict[str, Dict[str, List[str]]] = {
    "claude": {"claude": ["claude", "--version"]},
    "openai": {"codex": ["codex", "--version"]},
}

DEFAULT_CHECKS: Dict[str, List[str]] = {
    **BASE_CHECKS,
    **PROVIDER_CHECKS["claude"],
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


def check_agent_prerequisites(
    provider: str,
    extra_checks: Optional[Dict[str, List[str]]] = None,
) -> bool:
    """Check shared prerequisites plus the selected provider CLI."""
    checks = dict(BASE_CHECKS)
    checks.update(PROVIDER_CHECKS.get(provider, {}))
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


def check_claude_auth(
    api_key: Optional[str] = None,
    *,
    base_url: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> bool:
    """Verify Claude CLI can authenticate with a tiny smoke test."""
    print("Checking Claude CLI authentication...")
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    resolved_key = resolve_anthropic_key(api_key)
    if resolved_key:
        env["ANTHROPIC_API_KEY"] = resolved_key
    if base_url:
        env["ANTHROPIC_BASE_URL"] = base_url
    if auth_token:
        env["ANTHROPIC_AUTH_TOKEN"] = auth_token
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


def check_codex_auth(api_key: Optional[str] = None) -> bool:
    """Verify Codex CLI can authenticate with a tiny non-interactive smoke test."""
    print("Checking Codex CLI authentication...")
    env = dict(os.environ)
    resolved_key = resolve_openai_key(api_key)
    if resolved_key:
        env["OPENAI_API_KEY"] = resolved_key
        env["CODEX_API_KEY"] = resolved_key
    try:
        with tempfile.TemporaryDirectory(prefix="codex_auth_") as tmpdir:
            result = subprocess.run(
                [
                    "codex",
                    "exec",
                    "--skip-git-repo-check",
                    "--ignore-rules",
                    "--sandbox",
                    "read-only",
                    "-C",
                    tmpdir,
                    'Reply exactly with: auth ok',
                ],
                capture_output=True, text=True, timeout=60,
                env=env,
            )
    except FileNotFoundError:
        print("ERROR: 'codex' command not found. Install the Codex CLI first.")
        return False
    except subprocess.TimeoutExpired:
        print("WARNING: Codex auth check timed out, proceeding anyway.")
        return True

    output = (result.stdout or "") + (result.stderr or "")
    lowered = output.lower()
    if result.returncode == 0 and "auth ok" in lowered:
        print("Codex authentication OK")
        return True

    auth_markers = ("sign in", "login", "authentication", "api key", "codex_api_key")
    if any(marker in lowered for marker in auth_markers):
        print("ERROR: Codex CLI authentication failed!")
        print("Run: codex login")
        print("Or set CODEX_API_KEY for non-interactive runs.")
        return False

    if result.returncode != 0:
        print("WARNING: Codex auth smoke test returned a non-zero exit code.")
        print("Proceeding anyway because the failure was not clearly auth-related.")
    else:
        print("Codex authentication OK")
    return True
