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
        "--provider", type=str, choices=["claude", "openai"], default="claude",
        help="Agent provider to use (default: claude)",
    )
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
        help="Provider model to use. Default: CLI/provider default",
    )
    parser.add_argument(
        "--api-key", type=str, dest="api_key",
        help=(
            "Provider API key override. If omitted, reads from environment "
            "or .env (ANTHROPIC_API_KEY for Claude, OPENAI_API_KEY for OpenAI)."
        ),
    )
    parser.add_argument(
        "--base-url", type=str, dest="base_url",
        help=(
            "Claude provider only: route Claude Code at a custom Anthropic-"
            "compatible endpoint (sets ANTHROPIC_BASE_URL). Use with --model "
            "to point at a self-hosted or proxied model."
        ),
    )
    parser.add_argument(
        "--auth-token", type=str, dest="auth_token",
        help=(
            "Claude provider only: bearer token for the custom endpoint "
            "(sets ANTHROPIC_AUTH_TOKEN). Use instead of --api-key when the "
            "endpoint expects an Authorization: Bearer header."
        ),
    )
    parser.add_argument(
        "--max-output-tokens", type=int, dest="max_output_tokens",
        help=(
            "Claude provider only: cap output tokens per request (sets "
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS). Set this when the upstream "
            "model has a smaller context window than Claude's default — "
            "e.g. 16384 for a 131K-context model leaves ~115K for input."
        ),
    )
    parser.add_argument(
        "--vanilla", action="store_true",
        help="Run without pentest skills (baseline comparison)",
    )
    parser.add_argument(
        "--skip-auth-check", action="store_true",
        help="Skip provider authentication pre-check",
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
        help="Check prerequisites (Docker plus provider CLI)",
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Clone / set up the benchmark repo",
    )
