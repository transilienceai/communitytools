"""
Transilience Vulnerability MCP Server (local shim).

Exposes Transilience's vulnerability enrichment REST API as MCP tools so that
Claude Desktop can call them directly. The server runs locally on stdio,
keeps the API key in an environment variable, enforces the 20/min free-tier
rate limit, and caches responses on disk to avoid re-paying the quota cost
on repeated calls.

Tools:
  - enrich_cve(cve_id)              -> single CVE, full detail
  - bulk_enrich_cves(cve_ids)       -> many CVEs, returns summarized payload
                                       (full payloads cached to disk)
  - get_cached_cve(cve_id)          -> read from cache without API call
  - cache_stats()                   -> how many CVEs are cached, hit rate

Environment variables:
  TRANSILIENCE_API_KEY    required, your x-api-key
  TRANSILIENCE_CACHE_DIR  optional, defaults to ~/.transilience-mcp-cache
  TRANSILIENCE_RATE_LIMIT optional, requests per minute, defaults to 18
                          (deliberately under the 20/min documented limit)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

API_BASE = "https://vulns.transilienceapi.com"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

API_KEY = os.environ.get("TRANSILIENCE_API_KEY")
CACHE_DIR = Path(
    os.environ.get(
        "TRANSILIENCE_CACHE_DIR",
        Path.home() / ".transilience-mcp-cache",
    )
)
RATE_LIMIT_PER_MIN = int(os.environ.get("TRANSILIENCE_RATE_LIMIT", "18"))

# Logs go to stderr — stdout is reserved for the MCP JSON-RPC stream.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s transilience-mcp: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("transilience-mcp")

if not API_KEY:
    log.error(
        "TRANSILIENCE_API_KEY environment variable is not set. "
        "Set it in claude_desktop_config.json under env."
    )
    # Don't sys.exit — let the server start so Claude Desktop sees it,
    # and surface the error on the first tool call.

CACHE_DIR.mkdir(parents=True, exist_ok=True)
log.info("Cache dir: %s", CACHE_DIR)
log.info("Rate limit: %d req/min", RATE_LIMIT_PER_MIN)

# --------------------------------------------------------------------------- #
# Rate limiter — sliding 60s window
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Sliding-window rate limiter, asyncio-safe."""

    def __init__(self, max_per_min: int):
        self.max = max_per_min
        self.window = 60.0
        self.calls: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            # Drop calls outside the window.
            while self.calls and now - self.calls[0] >= self.window:
                self.calls.popleft()
            if len(self.calls) >= self.max:
                wait = self.window - (now - self.calls[0]) + 0.05
                log.info("Rate limit reached, sleeping %.2fs", wait)
                await asyncio.sleep(wait)
                # Re-check after sleep.
                now = time.monotonic()
                while self.calls and now - self.calls[0] >= self.window:
                    self.calls.popleft()
            self.calls.append(time.monotonic())


limiter = RateLimiter(RATE_LIMIT_PER_MIN)

# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


def cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id.upper()}.json"


def cache_get(cve_id: str) -> dict | None:
    p = cache_path(cve_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        log.warning("Cache read failed for %s: %s", cve_id, e)
        return None


def cache_put(cve_id: str, payload: dict) -> None:
    try:
        cache_path(cve_id).write_text(json.dumps(payload))
    except OSError as e:
        log.warning("Cache write failed for %s: %s", cve_id, e)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

# Reuse a single client — connection pooling matters when fetching hundreds.
_client: httpx.AsyncClient | None = None


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"x-api-key": API_KEY or "", "User-Agent": "transilience-mcp/1.0"},
        )
    return _client


async def fetch_cve_remote(cve_id: str) -> dict:
    """Hit the Transilience API. Caller must have validated cve_id."""
    if not API_KEY:
        raise RuntimeError(
            "TRANSILIENCE_API_KEY is not set. Add it to your "
            "claude_desktop_config.json env block and restart Claude Desktop."
        )

    await limiter.acquire()
    client = await get_client()
    url = f"{API_BASE}/cves/{cve_id.upper()}"

    # Retry once on 429 — the limiter should prevent it, but Transilience may
    # count differently than we do. Server-side errors get one retry too.
    for attempt in range(2):
        try:
            r = await client.get(url)
        except httpx.RequestError as e:
            if attempt == 0:
                log.warning("Request error for %s, retrying: %s", cve_id, e)
                await asyncio.sleep(1.0)
                continue
            return {"cve": cve_id, "error": "network_error", "detail": str(e)}

        if r.status_code == 200:
            try:
                return r.json()
            except ValueError as e:
                return {"cve": cve_id, "error": "bad_json", "detail": str(e)}
        if r.status_code == 404:
            return {"cve": cve_id, "error": "not_found"}
        if r.status_code in (429, 502, 503, 504) and attempt == 0:
            wait = 5.0 if r.status_code == 429 else 2.0
            log.warning(
                "HTTP %d for %s, retrying after %.1fs", r.status_code, cve_id, wait
            )
            await asyncio.sleep(wait)
            continue
        return {
            "cve": cve_id,
            "error": f"http_{r.status_code}",
            "detail": r.text[:500],
        }

    return {"cve": cve_id, "error": "exhausted_retries"}


async def fetch_cve(cve_id: str, *, use_cache: bool = True) -> tuple[dict, str]:
    """Returns (payload, source) where source is 'cache' or 'api'."""
    cve_id = cve_id.upper().strip()
    if not CVE_RE.match(cve_id):
        return {"cve": cve_id, "error": "invalid_format"}, "validation"

    if use_cache:
        cached = cache_get(cve_id)
        if cached is not None:
            return cached, "cache"

    payload = await fetch_cve_remote(cve_id)
    # Only cache successful responses.
    if "error" not in payload:
        cache_put(cve_id, payload)
    return payload, "api"


# --------------------------------------------------------------------------- #
# Summarizer — full CVE payloads are huge (Transilience returns 75+ impact
# attributes plus per-vendor advisory data, which can be hundreds of objects).
# bulk_enrich_cves returns a slimmed-down view by default to keep the chat
# context manageable. Full payloads are still on disk and accessible via
# get_cached_cve.
# --------------------------------------------------------------------------- #


def summarize_cve(payload: dict) -> dict:
    """Extract the fields most useful for prioritization/scoring."""
    if "error" in payload:
        return payload

    out: dict[str, Any] = {"cve": payload.get("cve")}

    # Top-level scoring fields (names follow the documented Transilience schema;
    # we use .get() everywhere so missing fields don't crash the summary).
    for k in (
        "cvss_v3_score",
        "cvss_v3_severity",
        "cvss_v3_vector",
        "epss_score",
        "epss_percentile",
        "kev",
        "kev_date_added",
        "date_published",
        "cwe",
        "description",
    ):
        if k in payload:
            out[k] = payload[k]

    # Impact taxonomy — flatten just the True flags so we see "what can the
    # attacker do" at a glance.
    impact = payload.get("impact") or {}
    impact_flags: list[str] = []
    for category in ("confidentiality", "integrity", "access"):
        for key, value in (impact.get(category) or {}).items():
            if value is True and not key.endswith("_reason"):
                impact_flags.append(f"{category}.{key}")
    avail = (impact.get("availability") or {})
    for sub in ("unreliable_execution", "resource_consumption", "quality_degradation"):
        for key, value in (avail.get(sub) or {}).items():
            if value is True and not key.endswith("_reason"):
                impact_flags.append(f"availability.{sub}.{key}")
    if impact_flags:
        out["impact_flags"] = impact_flags

    # Vendor advisories — return count + the first remediation we see, plus
    # max asset_criticality across vendors as a rough vendor-side signal.
    vendors = payload.get("vendors_exploits_details") or []
    if vendors:
        out["vendor_advisory_count"] = len(vendors)
        crit_levels = [
            v.get("asset.asset_criticality")
            for v in vendors
            if v.get("asset.asset_criticality")
        ]
        if crit_levels:
            order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            out["max_vendor_asset_criticality"] = max(
                crit_levels, key=lambda x: order.get(x, 0)
            )
        # Pull first non-null remediation_steps as a representative fix.
        for v in vendors:
            steps = v.get("remediation.remediation_steps")
            if steps:
                out["sample_remediation"] = steps
                break

    return out


# --------------------------------------------------------------------------- #
# MCP server
# --------------------------------------------------------------------------- #

server = Server("transilience-vuln")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="enrich_cve",
            description=(
                "Fetch full Transilience enrichment for a single CVE: CVSS, "
                "EPSS, KEV status, the 75-attribute impact taxonomy, and "
                "vendor-specific advisory/remediation data. Cached on disk, "
                "so repeated calls for the same CVE don't burn rate limit."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier, e.g. CVE-2024-6387",
                    },
                    "force_refresh": {
                        "type": "boolean",
                        "description": "Bypass cache and re-fetch from API",
                        "default": False,
                    },
                },
                "required": ["cve_id"],
            },
        ),
        Tool(
            name="bulk_enrich_cves",
            description=(
                "Enrich a list of CVEs and return summarized scoring data "
                "(CVSS, EPSS, KEV, impact flags, vendor count, sample "
                "remediation). Full payloads are cached to disk and "
                "retrievable via get_cached_cve. Respects the 20/min rate "
                "limit automatically — for large batches expect ~3.3s per "
                "uncached CVE."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of CVE IDs",
                    },
                    "force_refresh": {
                        "type": "boolean",
                        "description": "Bypass cache for all CVEs",
                        "default": False,
                    },
                },
                "required": ["cve_ids"],
            },
        ),
        Tool(
            name="get_cached_cve",
            description=(
                "Read a previously-fetched CVE from local cache without "
                "calling the API. Returns null if not cached."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "summarized": {
                        "type": "boolean",
                        "description": "Return slimmed-down view instead of full payload",
                        "default": False,
                    },
                },
                "required": ["cve_id"],
            },
        ),
        Tool(
            name="cache_stats",
            description="Show cache size, location, and a few sample entries.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


def _text(obj: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(obj, indent=2, default=str))]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "enrich_cve":
            cve_id = arguments.get("cve_id", "")
            force = arguments.get("force_refresh", False)
            payload, source = await fetch_cve(cve_id, use_cache=not force)
            return _text({"source": source, "data": payload})

        if name == "bulk_enrich_cves":
            cve_ids = arguments.get("cve_ids") or []
            force = arguments.get("force_refresh", False)
            if not isinstance(cve_ids, list) or not cve_ids:
                return _text({"error": "cve_ids must be a non-empty list"})

            # Deduplicate while preserving order.
            seen: set[str] = set()
            unique: list[str] = []
            for c in cve_ids:
                u = str(c).upper().strip()
                if u not in seen:
                    seen.add(u)
                    unique.append(u)

            results: dict[str, dict] = {}
            counts = {"cache": 0, "api": 0, "error": 0}

            for cve_id in unique:
                payload, source = await fetch_cve(cve_id, use_cache=not force)
                if source in counts:
                    counts[source] += 1
                if "error" in payload:
                    counts["error"] += 1
                results[cve_id] = summarize_cve(payload)

            return _text(
                {
                    "summary": {
                        "requested": len(unique),
                        "from_cache": counts["cache"],
                        "from_api": counts["api"],
                        "errors": counts["error"],
                    },
                    "results": results,
                }
            )

        if name == "get_cached_cve":
            cve_id = arguments.get("cve_id", "").upper().strip()
            if not CVE_RE.match(cve_id):
                return _text({"error": "invalid_format", "cve": cve_id})
            cached = cache_get(cve_id)
            if cached is None:
                return _text({"cve": cve_id, "cached": False})
            if arguments.get("summarized"):
                cached = summarize_cve(cached)
            return _text({"cve": cve_id, "cached": True, "data": cached})

        if name == "cache_stats":
            files = list(CACHE_DIR.glob("CVE-*.json"))
            sample = sorted(f.stem for f in files)[:10]
            return _text(
                {
                    "cache_dir": str(CACHE_DIR),
                    "cached_cve_count": len(files),
                    "sample_entries": sample,
                    "rate_limit_per_min": RATE_LIMIT_PER_MIN,
                }
            )

        return _text({"error": f"unknown tool: {name}"})

    except Exception as e:  # noqa: BLE001 — surface unexpected errors to the LLM
        log.exception("Tool %s failed", name)
        return _text({"error": "tool_exception", "tool": name, "detail": str(e)})


async def main() -> None:
    log.info("Starting transilience-vuln MCP server on stdio")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def cli() -> None:
    """Sync entry point for the `transilience-vuln-mcp` console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
