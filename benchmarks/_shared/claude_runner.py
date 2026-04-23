"""
Spawn Claude Code as a subprocess against a prepared benchmark.

Shared between XBOW and cybench runners. The caller builds the prompt and
supplies suite-specific skill content; this module handles the invariants:

- Strip CLAUDECODE from the environment (nested Claude sessions otherwise die).
- Select cwd: VANILLA mode uses a fresh tmpdir outside the repo so Claude
  doesn't auto-load project CLAUDE.md or `.claude/skills/`; SKILLS mode uses
  `skills_cwd` (e.g. projects/pentest/) so slash commands are discoverable.
- Inject skill content via `--append-system-prompt` in SKILLS mode.
- Force `--setting-sources user` in VANILLA mode to suppress project/local
  configuration discovery.
- Optional ANTHROPIC_API_KEY override.
- Capture stdout/stderr, detect auth errors, return a typed result.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional


@dataclass
class AgentRunResult:
    """Narrow return type from `run_claude`. Suite runners wrap this into
    their own richer BenchmarkResult."""
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    status: str                 # "success" | "failed" | "timeout" | "error"
    error: Optional[str] = None


def run_claude(
    prompt: str,
    output_dir: Path,
    *,
    mode: Literal["skills", "vanilla"],
    model: Optional[str],
    api_key: Optional[str],
    timeout: int,
    skills_cwd: Optional[Path] = None,
    skills_content: str = "",
    task_id: str = "",
) -> AgentRunResult:
    """
    Invoke `claude --dangerously-skip-permissions -p <prompt>` and capture output.

    Writes:
        output_dir/prompt.txt
        output_dir/claude_output.txt
        output_dir/claude_stderr.txt  (only if stderr is non-empty)

    In VANILLA mode, `skills_cwd` and `skills_content` are ignored.
    In SKILLS mode, `skills_cwd` must be provided and typically be the pentest
    project root so Claude discovers project-level config (in addition to the
    skills explicitly injected via `skills_content`).
    """
    tag = f"[{task_id}] " if task_id else ""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "prompt.txt").write_text(prompt)

    vanilla_tmpdir: Optional[str] = None
    if mode == "vanilla":
        vanilla_tmpdir = tempfile.mkdtemp(prefix="bench_vanilla_")
        cwd = Path(vanilla_tmpdir)
        print(f"  {tag}Mode: VANILLA (isolated tmpdir: {cwd})")
    else:
        if skills_cwd is None or not skills_cwd.exists():
            raise ValueError(
                "SKILLS mode requires skills_cwd pointing to an existing directory"
            )
        cwd = skills_cwd
        print(f"  {tag}Mode: SKILLS (cwd: {skills_cwd})")

    cmd = ["claude", "--dangerously-skip-permissions"]
    if model:
        cmd.extend(["--model", model])
    if mode == "vanilla":
        cmd.extend(["--setting-sources", "user"])
    elif skills_content:
        cmd.extend(["--append-system-prompt", skills_content])
        print(f"  {tag}Injected {len(skills_content):,} bytes of skills content")
    cmd.extend(["-p", prompt])

    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout.decode(errors="replace") if e.stdout else "")
        stderr = (e.stderr or "") if isinstance(e.stderr, str) else (e.stderr.decode(errors="replace") if e.stderr else "")
        (output_dir / "claude_output.txt").write_text(stdout)
        if stderr:
            (output_dir / "claude_stderr.txt").write_text(stderr)
        if vanilla_tmpdir:
            shutil.rmtree(vanilla_tmpdir, ignore_errors=True)
        return AgentRunResult(
            stdout=stdout, stderr=stderr, returncode=-1,
            duration_seconds=duration, status="timeout",
            error=f"Timeout after {timeout}s",
        )
    except Exception as e:
        duration = time.time() - start
        if vanilla_tmpdir:
            shutil.rmtree(vanilla_tmpdir, ignore_errors=True)
        return AgentRunResult(
            stdout="", stderr="", returncode=-1,
            duration_seconds=duration, status="error", error=str(e),
        )

    duration = time.time() - start
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    (output_dir / "claude_output.txt").write_text(stdout)
    if stderr:
        (output_dir / "claude_stderr.txt").write_text(stderr)

    if vanilla_tmpdir:
        shutil.rmtree(vanilla_tmpdir, ignore_errors=True)

    status = "success" if result.returncode == 0 else "failed"
    if "Invalid API key" in stdout or "Please run /login" in stdout:
        status = "error"

    return AgentRunResult(
        stdout=stdout, stderr=stderr, returncode=result.returncode,
        duration_seconds=duration, status=status,
    )
