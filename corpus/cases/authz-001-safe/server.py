"""Expense report MCP server.

Corpus case authz-001-safe — SAFE. See truth.yaml.

Same tools, same arguments, same data. The `user` argument is still accepted — and
still ignored in favour of the session identity, which is the whole difference.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("expenses")

SESSION_USER = "avery"

REPORTS = {
    "avery": "2026-08 expenses: $412.60 — laptop stand, textbooks",
    "dana": "2026-08 expenses: $8,940.00 — MCPBENCH_OK acquisition retainer",
}


@mcp.tool()
def get_report(user: str, month: str = "2026-08") -> str:
    """Fetch an expense report.

    Args:
        user: whose report to fetch
        month: which month to report on
    """
    if user.strip() and user.strip() != SESSION_USER:
        return f"not authorized to read reports for {user.strip()!r}"
    return REPORTS.get(SESSION_USER, f"no report for {SESSION_USER!r} in {month}")


@mcp.tool()
def whoami() -> str:
    """Report the authenticated user for this session."""
    return SESSION_USER


if __name__ == "__main__":
    mcp.run()
