"""
Shared benchmark-result dataclass used by every runner.

Suite-specific fields (XBOW: level/tags; cybench: categories/difficulty) go
into the `metadata` dict — this keeps the type stable while each runner
renders its own summary and preserves its own JSON schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class BenchmarkResult:
    task_id: str
    name: str
    suite: str                                  # "xbow" | "cybench" | ...
    status: str                                 # "success" | "failed" | "timeout" | "error" | "skipped"
    correct: bool                               # did the agent produce the expected answer?
    expected_answer: str
    found_answer: str
    duration_seconds: float
    agent_output: str                            # truncated (typically 5000 chars)
    mode: str = "skills"                         # "skills" | "vanilla"
    error: str = ""
    attempts: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
