"""Transilience Vulnerability MCP server package.

Re-exports the console-script entry point (`cli`) and the underlying
`main` coroutine / `server` instance so they are importable from the
package root, e.g. `from transilience_vuln_mcp import cli`.
"""

from .server import cli, main, server

__all__ = ["cli", "main", "server"]
