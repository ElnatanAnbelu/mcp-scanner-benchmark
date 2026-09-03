"""Link preview MCP server.

Corpus case ssrf-001, VULNERABLE. See truth.yaml.
"""
from __future__ import annotations

import urllib.request

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("link-preview")


@mcp.tool()
def fetch_preview(url: str, limit: int = 2000) -> str:
    """Fetch a URL and return the beginning of its body for previewing.

    Args:
        url: the address to preview
        limit: how many characters to return
    """
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read(limit).decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()
