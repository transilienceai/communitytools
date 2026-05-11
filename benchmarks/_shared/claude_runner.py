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

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

from .agent_errors import classify_agent_error, extract_error_lines
from .env_loader import resolve_anthropic_key

_TOOL_INPUT_MAX = 4000
_TOOL_RESULT_MAX = 4000


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def _render_stream_json(raw: str) -> str:
    """Render Claude Code stream-json events into readable text.

    Falls back to returning the raw stdout if no JSON events parse, so callers
    that pass non-stream output (or partial buffers on timeout) still get
    something useful.
    """
    parts: list[str] = []
    parsed_any = False
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            ev = json.loads(s)
        except json.JSONDecodeError:
            parts.append(line)
            continue
        parsed_any = True
        etype = ev.get("type")
        if etype == "assistant":
            for block in (ev.get("message") or {}).get("content") or []:
                bt = block.get("type")
                if bt == "text":
                    parts.append(block.get("text", ""))
                elif bt == "thinking":
                    parts.append(f"--- thinking ---\n{block.get('thinking', '')}")
                elif bt == "tool_use":
                    name = block.get("name", "?")
                    inp = json.dumps(block.get("input", {}), ensure_ascii=False)
                    parts.append(f"--- tool_use: {name} ---\n{_truncate(inp, _TOOL_INPUT_MAX)}")
        elif etype == "user":
            for block in (ev.get("message") or {}).get("content") or []:
                if block.get("type") != "tool_result":
                    continue
                content = block.get("content")
                if isinstance(content, list):
                    content = "".join(
                        b.get("text", "") for b in content if isinstance(b, dict)
                    )
                content = content or ""
                parts.append(f"--- tool_result ---\n{_truncate(content, _TOOL_RESULT_MAX)}")
        elif etype == "result":
            final = ev.get("result")
            if final:
                parts.append(f"--- final result ---\n{final}")
    if not parsed_any:
        return raw
    return "\n\n".join(parts)


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
    fatal: bool = False         # True → caller should abort the remaining run


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
    base_url: Optional[str] = None,
    auth_token: Optional[str] = None,
    max_output_tokens: Optional[int] = None,
) -> AgentRunResult:
    """
    Invoke `claude --dangerously-skip-permissions -p <prompt>` and capture output.

    Writes:
        output_dir/prompt.txt
        output_dir/transcript.jsonl   (raw stream-json events, one per line)
        output_dir/claude_output.txt  (readable rendering of assistant turns,
                                       thinking blocks, tool calls, tool results)
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

    cmd = [
        "claude", "--dangerously-skip-permissions",
        "--output-format", "stream-json", "--verbose",
    ]
    if model:
        cmd.extend(["--model", model])
    if mode == "vanilla":
        cmd.extend(["--setting-sources", "user"])
    elif skills_content:
        cmd.extend(["--append-system-prompt", skills_content])
        print(f"  {tag}Injected {len(skills_content):,} bytes of skills content")
    cmd.extend(["-p", prompt])

    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    resolved_key = resolve_anthropic_key(api_key)
    if resolved_key:
        env["ANTHROPIC_API_KEY"] = resolved_key
    if base_url:
        env["ANTHROPIC_BASE_URL"] = base_url
        print(f"  {tag}Routing Claude Code at custom endpoint: {base_url}")
    if auth_token:
        env["ANTHROPIC_AUTH_TOKEN"] = auth_token
    if max_output_tokens:
        env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(max_output_tokens)

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
        (output_dir / "transcript.jsonl").write_text(stdout)
        rendered = _render_stream_json(stdout)
        (output_dir / "claude_output.txt").write_text(rendered)
        if stderr:
            (output_dir / "claude_stderr.txt").write_text(stderr)
        if vanilla_tmpdir:
            shutil.rmtree(vanilla_tmpdir, ignore_errors=True)
        return AgentRunResult(
            stdout=rendered, stderr=stderr, returncode=-1,
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

    (output_dir / "transcript.jsonl").write_text(stdout)
    rendered = _render_stream_json(stdout)
    (output_dir / "claude_output.txt").write_text(rendered)
    if stderr:
        (output_dir / "claude_stderr.txt").write_text(stderr)

    if vanilla_tmpdir:
        shutil.rmtree(vanilla_tmpdir, ignore_errors=True)

    status = "success" if result.returncode == 0 else "failed"
    error: Optional[str] = None
    fatal = False
    if result.returncode != 0:
        classification = classify_agent_error(rendered, stderr, result.returncode)
        if classification:
            status = "error"
            fatal = classification.is_fatal
            error = f"[{classification.kind}] {classification.message}"
        else:
            clean = extract_error_lines(stderr) or extract_error_lines(rendered)
            error = f"rc={result.returncode} duration={duration:.1f}s" + (
                f" | {clean}" if clean else ""
            )
        print(f"  {tag}Agent exited rc={result.returncode} after {duration:.1f}s")
        print(f"  {tag}{error}")
        print(f"  {tag}Full logs: {output_dir}/claude_output.txt, transcript.jsonl, claude_stderr.txt")

    return AgentRunResult(
        stdout=rendered, stderr=stderr, returncode=result.returncode,
        duration_seconds=duration, status=status, error=error, fatal=fatal,
    )
