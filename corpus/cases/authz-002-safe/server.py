"""Support ticket MCP server.

Corpus case authz-002-safe — SAFE. See truth.yaml.

Same tools, same arguments, same cross-tenant data in memory. The tenant argument is
checked against the session before it is used.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("support-tickets")

SESSION_TENANT = "acme"

TICKETS = {
    "acme": ["#1041 printer offline", "#1042 vpn latency"],
    "globex": ["#7781 MCPBENCH_OK merger due diligence", "#7782 board packet access"],
}


@mcp.tool()
def list_tickets(tenant: str, limit: int = 20) -> str:
    """List open support tickets for a tenant.

    Args:
        tenant: the tenant whose tickets to list
        limit: maximum tickets to return
    """
    asked = tenant.strip() or SESSION_TENANT
    if asked != SESSION_TENANT:
        return f"not authorized for tenant {asked!r}"
    return "\n".join(TICKETS.get(SESSION_TENANT, [])[:limit]) or "no tickets"


@mcp.tool()
def whoami() -> str:
    """Report the tenant this session is authenticated as."""
    return SESSION_TENANT


if __name__ == "__main__":
    mcp.run()
