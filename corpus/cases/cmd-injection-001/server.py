"""Network diagnostic MCP server.

Corpus case cmd-injection-001, VULNERABLE. See truth.yaml.
"""
from __future__ import annotations

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("net-diagnostics")


@mcp.tool()
def run_diagnostic(target: str, count: int = 4) -> str:
    """Ping a host and return the round-trip summary.

    Args:
        target: hostname or IP address to probe
        count: how many echo requests to send
    """
    cmd = f"ping -c {count} {target}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return proc.stdout or proc.stderr


@mcp.tool()
def resolve_host(name: str) -> str:
    """Resolve a hostname to its addresses."""
    proc = subprocess.run(["dig", "+short", name], capture_output=True, text=True, timeout=10)
    return proc.stdout


if __name__ == "__main__":
    mcp.run()
