"""
Generic docker-compose / Dockerfile compatibility fixes that apply across
benchmark suites. Suite-specific fixes (Python 3.8 pins, ARM64 MySQL, Node 14,
Composer security blocking) live alongside the suite that needs them.
"""
from __future__ import annotations

import re
from pathlib import Path


def fix_expose_syntax(compose_path: Path) -> None:
    """
    Fix invalid `expose` syntax in docker-compose.yml files.

    Some benchmark docker-compose files use `expose: - 3306:3306` which is
    invalid (expose only accepts port numbers, not host:container mappings).
    Docker Compose fails with: strconv.ParseUint: parsing "3306:3306": invalid
    syntax. This silently prevents the benchmark from starting, causing the
    agent to interact with a stale container from a previous run.

    Converts `- PORT:PORT` under an expose: block to `- "PORT"`.
    """
    if not compose_path.exists():
        return
    try:
        content = compose_path.read_text()
        fixed = re.sub(
            r'(expose:\s*\n(?:\s+-\s+[^\n]*\n)*?\s+-\s+)(\d+):(\d+)',
            lambda m: f'{m.group(1)}"{m.group(2)}"',
            content,
        )
        if fixed != content:
            compose_path.write_text(fixed)
    except Exception:
        pass


def fix_hardcoded_ports(compose_path: Path) -> None:
    """
    Convert hardcoded `HOST:CONTAINER` port mappings to dynamic ones.

    Some benchmarks use `ports: - "5000:5000"` or `- 8000:80` which bind to a
    fixed host port. On macOS, port 5000 conflicts with AirPlay Receiver; other
    ports may conflict with running services or parallel benchmark runs.
    Converting `"HOST:CONTAINER"` to `CONTAINER` lets Docker auto-assign a free
    host port. Runners use `docker port` / `docker compose port` to discover
    the assigned port afterwards.
    """
    if not compose_path.exists():
        return
    try:
        content = compose_path.read_text()
        fixed = re.sub(
            r'(\s+-\s+)"(\d+):(\d+)"',
            r'\g<1>\3',
            content,
        )
        fixed = re.sub(
            r'(\s+-\s+)(\d+):(\d+)\s*$',
            r'\g<1>\3',
            fixed,
            flags=re.MULTILINE,
        )
        if fixed != content:
            compose_path.write_text(fixed)
    except Exception:
        pass


def fix_buster_apt_sources(config_path: Path) -> None:
    """
    Fix EOL Debian apt sources in Dockerfiles (Stretch, Buster).

    Many benchmarks use images based on EOL Debian releases (Debian 9 Stretch:
    php:7.1-apache, python:3.6-slim; Debian 10 Buster: python:2.7.18-slim,
    python:3.8-slim-buster, httpd:2.4.49/50). Those repos moved from
    deb.debian.org to archive.debian.org, so `apt-get update` returns 404.

    Injects conditional seds immediately after every FROM line. The seds only
    fire if `stretch` or `buster` appears in sources.list, so Bullseye/Bookworm
    images are unaffected.
    """
    fix_line = (
        "RUN if [ -f /etc/apt/sources.list ]; then "
        "for codename in stretch buster; do "
        "if grep -q $codename /etc/apt/sources.list; then "
        "sed -i \"/$codename/s|deb.debian.org|archive.debian.org|g\" /etc/apt/sources.list && "
        "sed -i \"/$codename/s|security.debian.org[^ ]*|archive.debian.org/debian-security|g\" /etc/apt/sources.list && "
        "sed -i \"/${codename}-updates/d\" /etc/apt/sources.list; "
        "fi; done; fi"
    )
    try:
        for dockerfile in config_path.rglob("Dockerfile"):
            content = dockerfile.read_text()
            if "apt-get" not in content:
                continue
            if "archive.debian.org" in content:
                continue
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if line.strip().startswith("FROM "):
                    new_lines.append(fix_line)
            dockerfile.write_text("\n".join(new_lines))
    except Exception:
        pass
