# Transilience Vulnerability MCP Server

A local MCP server that exposes the [Transilience](https://transilienceapi.com)
vulnerability enrichment API (`https://vulns.transilienceapi.com`) as MCP tools.
Drop it into Claude Desktop (or any MCP client) and ask the model to enrich CVEs
directly — no more "let me give you a script to run" ceremony.

## Tools

- **`enrich_cve(cve_id, force_refresh=False)`** — full CVE payload: CVSS v3,
  EPSS, KEV status, the 75-attribute impact taxonomy, and per-vendor advisory
  and remediation data.
- **`bulk_enrich_cves(cve_ids, force_refresh=False)`** — enrich many CVEs at
  once; returns a summarized view tuned for prioritization. Full payloads
  stay on disk and are retrievable via `get_cached_cve`.
- **`get_cached_cve(cve_id, summarized=False)`** — read from the local cache
  without calling the API.
- **`cache_stats()`** — cache size, location, sample entries.

Built in:

- Sliding-window rate limiter (default 18/min, deliberately under the
  documented 20/min free-tier ceiling).
- Disk cache at `~/.transilience-mcp-cache` so repeated calls are free.
- Retry on 429 / 5xx / transient network errors.
- API key is read from `TRANSILIENCE_API_KEY` only — never logged, never
  echoed back in tool output.

## Requirements

- Python 3.10+
- A Transilience API key — sign up at <https://transilienceapi.com>.

## Install

```bash
git clone https://github.com/transilienceai/communitytools.git
cd communitytools/mcp/transilience-vuln
python -m venv .venv
# macOS / Linux:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
pip install -e .
```

## Configure Claude Desktop

Open the Claude Desktop config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Merge in the entry from `claude_desktop_config.snippet.json`, replacing the
two `/ABSOLUTE/PATH/TO/...` placeholders and your API key:

```json
{
  "mcpServers": {
    "transilience-vuln": {
      "command": "/ABSOLUTE/PATH/TO/communitytools/mcp/transilience-vuln/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/TO/communitytools/mcp/transilience-vuln/server.py"],
      "env": {
        "TRANSILIENCE_API_KEY": "your-actual-key-here",
        "TRANSILIENCE_RATE_LIMIT": "18"
      }
    }
  }
}
```

Use absolute paths for both `command` and `args` — Claude Desktop does not
honor your shell's `PATH`. On Windows the Python binary is
`...\.venv\Scripts\python.exe`.

Quit Claude Desktop completely (not just close the window) and relaunch.

## Verify it loaded

In a new chat, ask: *"What MCP tools do you have for vulnerability
enrichment?"* You should see `enrich_cve`, `bulk_enrich_cves`,
`get_cached_cve`, and `cache_stats`.

If they don't show up, check the MCP log:

- macOS: `~/Library/Logs/Claude/mcp*.log`
- Windows: `%APPDATA%\Claude\logs\mcp*.log`

The most common failure is a wrong path to Python or to `server.py`.

## Smoke test from the command line

```bash
TRANSILIENCE_API_KEY=your-key python server.py
```

The server will sit on stdio waiting for JSON-RPC. You should see
`Starting transilience-vuln MCP server on stdio` on stderr — Ctrl-C to exit.

You can also run it as a console script after `pip install -e .`:

```bash
TRANSILIENCE_API_KEY=your-key transilience-vuln-mcp
```

## Environment variables

| Var | Required | Default | Notes |
| --- | --- | --- | --- |
| `TRANSILIENCE_API_KEY` | yes | — | Your `x-api-key` from transilienceapi.com |
| `TRANSILIENCE_CACHE_DIR` | no | `~/.transilience-mcp-cache` | Where CVE JSON is cached |
| `TRANSILIENCE_RATE_LIMIT` | no | `18` | Requests/minute. Free tier is 20; we default to 18 for headroom |

## Security notes

- The API key is only in your local config file and the local process
  environment. It never enters the chat context.
- The disk cache contains CVE enrichment data (public information) — fine
  to back up or share.
- If you rotate your key, update `claude_desktop_config.json` and restart
  Claude Desktop.

## Troubleshooting

**Tools don't show up after restart.** Check the MCP log for stack traces.
Nearly always a wrong Python path — run `which python` (or
`where python` on Windows) inside your activated venv to find the right one.

**429 errors.** Drop `TRANSILIENCE_RATE_LIMIT` to `15` and restart Claude
Desktop. The free tier is documented as 20/min but bursts can trip it.

**Cache too big.** It's just JSON files in `~/.transilience-mcp-cache`.
Delete the directory — the server recreates it on next launch.

**Stale data.** Pass `force_refresh=true` on `enrich_cve` or
`bulk_enrich_cves` to bypass the cache for that call.

## License

MIT. See the repo-level [LICENSE](../../LICENSE).
