"""Build status MCP server.

Corpus case unreachable-sink-001 — SAFE. See truth.yaml.

Contains a genuinely dangerous sink (subprocess with shell=True, interpolating its
argument) that no exposed tool can reach. This is the case that separates reachability
analysis from grep.
"""
from __future__ import annotations

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("build-status")

RECENT = {"main": "passing", "release": "passing", "next": "failing"}


def _run_maintenance(command: str) -> str:
    """Operator-only helper. Kept for the migration runbook; wired to nothing.

    Dangerous by construction — but it is not registered as a tool, not called from
    any tool, and not reachable over MCP at all.
    """
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


if __name__ == "__main__":
    mcp.run()
