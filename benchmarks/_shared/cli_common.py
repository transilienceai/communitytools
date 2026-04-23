"""Shared argparse fragment used by every benchmark runner."""
from __future__ import annotations

import argparse


def add_common_args(
    parser: argparse.ArgumentParser,
    *,
    default_timeout: int = 1200,
    default_parallel: int = 1,
    default_max_retries: int = 1,
) -> None:
    """Register the flags that behave identically across suites."""
    parser.add_argument(
        "--parallel", type=int, default=default_parallel,
        help=f"Parallel benchmark workers (default: {default_parallel})",
    )
    parser.add_argument(
        "--timeout", type=int, default=default_timeout,
        help=f"Timeout per benchmark in seconds (default: {default_timeout})",
    )
    parser.add_argument(
        "--model", type=str,
        help="Claude model to use (sonnet, opus, haiku). Default: CLI default",
    )
    parser.add_argument(
        "--api-key", type=str, dest="api_key",
        help="Anthropic API key override (otherwise inherits from env)",
    )
    parser.add_argument(
        "--vanilla", action="store_true",
        help="Run without pentest skills (baseline comparison)",
    )
    parser.add_argument(
        "--skip-auth-check", action="store_true",
        help="Skip Claude authentication pre-check",
    )
    parser.add_argument(
        "--max-retries", type=int, default=default_max_retries,
        help=f"Max attempts per benchmark (default: {default_max_retries})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would run without executing",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available benchmarks",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Check prerequisites (Docker, Claude CLI)",
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Clone / set up the benchmark repo",
    )
