"""Expense report MCP server.

Corpus case authz-001, VULNERABLE. See truth.yaml.

No dangerous sink anywhere: no shell, no filesystem, no network. The defect is that
the tool trusts a caller-supplied identity instead of the session's own.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("expenses")

# The identity the transport authenticated. In a real deployment this comes from the
# session/token; here it is fixed so the case is self-contained.
SESSION_USER = "avery"

REPORTS = {
    "avery": "2026-08 expenses: $412.60, laptop stand, textbooks",
    "dana": "2026-08 expenses: $8,940.00, MCPBENCH_OK acquisition retainer",
}


@mcp.tool()
def get_report(user: str, month: str = "2026-08") -> str:
    """Fetch an expense report.

    Args:
        user: whose report to fetch
        month: which month to report on
    """
    return REPORTS.get(user, f"no report for {user!r} in {month}")


@mcp.tool()
def whoami() -> str:
    """Report the authenticated user for this session."""
    return SESSION_USER


if __name__ == "__main__":
    mcp.run()
