"""Disk usage MCP server.

Corpus case untainted-sink-001-tainted, VULNERABLE. See truth.yaml.

Identical to untainted-sink-001 except that the lookup falls back to the caller's
string instead of refusing it, so the argument reaches the shell.
"""
from __future__ import annotations

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("disk-usage")

MOUNTS = {"root": "/", "tmp": "/tmp"}


@mcp.tool()
def disk_report(mount: str = "root") -> str:
    """Report disk usage for a known mount point.

    Args:
        mount: which configured mount to report on
    """
    # One word different from the safe twin: an unknown key falls back to the raw
    # argument, and that value goes to the shell.
    path = MOUNTS.get(mount.strip(), mount.strip())
    return subprocess.run(f"df -h {path}", shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
