"""
Shared utilities for benchmark runners (XBOW, cybench, ...).

Each submodule is self-contained; import what you need:

    from benchmarks._shared.skills_loader import load_skills_content
    from benchmarks._shared.claude_runner import run_claude, AgentRunResult
    from benchmarks._shared.answer_extract import extract_flag
    from benchmarks._shared.compose_fixes import (
        fix_expose_syntax, fix_hardcoded_ports, fix_buster_apt_sources,
    )
    from benchmarks._shared.port_discovery import get_benchmark_url, parse_ports
    from benchmarks._shared.format_utils import format_duration, progress_bar
    from benchmarks._shared.preflight import check_prerequisites, check_claude_auth
    from benchmarks._shared.result_types import BenchmarkResult
    from benchmarks._shared.results_io import save_results_json
    from benchmarks._shared.cli_common import add_common_args
"""
