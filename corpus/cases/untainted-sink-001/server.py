"""Disk usage MCP server.

Corpus case untainted-sink-001, SAFE. See truth.yaml.

A third dimension after reachable/unreachable: the sink is dangerous *and* reachable
from a tool, but no tool argument reaches it. Only taint analysis gets this right.
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
    # The argument selects a key; the value that reaches the shell is a constant from
    # the table above, never the caller's string.
    path = MOUNTS.get(mount.strip())
    if path is None:
        return f"unknown mount {mount.strip()!r}"
    return subprocess.run(f"df -h {path}", shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
