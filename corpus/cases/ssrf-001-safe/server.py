"""Link preview MCP server.

Corpus case ssrf-001-safe — SAFE. See truth.yaml.

Same shape as ssrf-001: same tool name, same docstring, same urlopen sink.
Only the scheme and destination checks differ.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import urllib.request

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("link-preview")

ALLOWED_SCHEMES = frozenset({"http", "https"})


def _public_url(url: str) -> str:
    """A public http(s) URL, or a ValueError. Blocks file://, loopback and RFC1918."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("no host")
    for info in socket.getaddrinfo(parts.hostname, parts.port or 80, proto=socket.IPPROTO_TCP):
        addr = ipaddress.ip_address(info[4][0])
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            raise ValueError(f"destination not public: {addr}")
    return url


@mcp.tool()
def fetch_preview(url: str, limit: int = 2000) -> str:
    """Fetch a URL and return the beginning of its body for previewing.

    Args:
        url: the address to preview
        limit: how many characters to return
    """
    with urllib.request.urlopen(_public_url(url), timeout=10) as resp:
        return resp.read(limit).decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()
