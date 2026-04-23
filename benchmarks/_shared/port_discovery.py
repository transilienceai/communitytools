"""Parse and discover host-mapped ports for dockerized benchmarks."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import List, Set


COMMON_CONTAINER_PORTS = [
    "80", "5000", "5003", "8080", "8000", "8081", "8002",
    "3000", "4000", "4567", "9000",
]


def parse_ports(compose_file: Path) -> List[int]:
    """Extract exposed container ports from docker-compose.yml."""
    if not compose_file.exists():
        return []
    ports: List[int] = []
    try:
        content = compose_file.read_text()
        for match in re.finditer(r"- ['\"]?(\d+)(?::\d+)?['\"]?", content):
            ports.append(int(match.group(1)))
    except Exception:
        pass
    return ports


def get_web_services(compose_dir: Path) -> Set[str]:
    """Return service names that expose a `ports:` section in docker-compose.yml."""
    services: Set[str] = set()
    compose_file = compose_dir / "docker-compose.yml"
    if not compose_file.exists():
        return {"app"}
    content = compose_file.read_text()
    current_service = None
    in_ports = False
    for line in content.split("\n"):
        stripped = line.strip()
        if not line.startswith(" ") and not line.startswith("\t"):
            continue
        if line.startswith("  ") and not line.startswith("   ") and stripped.endswith(":"):
            current_service = stripped.rstrip(":")
            in_ports = False
        elif "ports:" in stripped:
            in_ports = True
        elif in_ports and stripped.startswith("-") and current_service:
            services.add(current_service)
            in_ports = False
    return services if services else {"app"}


def get_benchmark_url(compose_dir: Path, task_id: str = "") -> str:
    """
    Discover the accessible URL for a running benchmark's web service.

    Docker Compose maps random host ports when `ports: - 80` is used
    (after fix_hardcoded_ports normalizes the compose file). We query Docker
    to find the actual mapped port across a list of common container ports.

    Falls back to `docker compose ps --format json` parsing, then to a last-
    resort `http://localhost:80`.
    """
    tag = f" [{task_id}]" if task_id else ""
    web_services = get_web_services(compose_dir)

    for service in web_services:
        for port in COMMON_CONTAINER_PORTS:
            try:
                result = subprocess.run(
                    ["docker", "compose", "port", service, port],
                    cwd=compose_dir,
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    host_port = result.stdout.strip()
                    return f"http://{host_port}"
            except Exception:
                continue

    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=compose_dir,
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    container = json.loads(line)
                    publishers = container.get("Publishers", [])
                    for pub in publishers:
                        if pub.get("PublishedPort", 0) > 0:
                            return f"http://localhost:{pub['PublishedPort']}"
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    print(f" {tag} WARNING: Could not detect mapped port, this will likely fail")
    return "http://localhost:80"
