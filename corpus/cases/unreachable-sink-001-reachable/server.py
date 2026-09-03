"""Build status MCP server.

Corpus case unreachable-sink-001-reachable, VULNERABLE. See truth.yaml.

Holds a genuinely dangerous sink (subprocess with shell=True, interpolating its
argument) that one exposed tool reaches. Its twin differs by one line.
"""
from __future__ import annotations

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("build-status")

RECENT = {"main": "passing", "release": "passing", "next": "failing"}


def _run_maintenance(command: str) -> str:
    """Operator-only helper. Kept for the migration runbook."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def build_status(branch: str = "main") -> str:
    """Report the latest build status for a branch.

    Args:
        branch: the branch name to look up
    """
    return RECENT.get(branch.strip(), f"no builds recorded for {branch.strip()!r}")


@mcp.tool()
def list_branches() -> str:
    """List the branches with recorded build status."""
    return "\n".join(sorted(RECENT))


@mcp.tool()
def refresh_cache(branch: str = "main") -> str:
    """Refresh the cached build status for a branch."""
    return _run_maintenance(f"echo refreshing {branch}")


if __name__ == "__main__":
    mcp.run()
