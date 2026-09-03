"""Support ticket MCP server.

Corpus case authz-002, VULNERABLE. See truth.yaml.

Confused deputy: the server holds privileged credentials and acts on a caller-supplied
tenant id without checking it against the session. No dangerous sink anywhere.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("support-tickets")

# The tenant this session authenticated as.
SESSION_TENANT = "acme"

# The server's own privileged view across every tenant.
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
    return "\n".join(TICKETS.get(tenant, [])[:limit]) or f"no tickets for {tenant!r}"


@mcp.tool()
def whoami() -> str:
    """Report the tenant this session is authenticated as."""
    return SESSION_TENANT


if __name__ == "__main__":
    mcp.run()
