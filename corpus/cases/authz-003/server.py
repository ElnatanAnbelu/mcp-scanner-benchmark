"""Admin console MCP server.

Corpus case authz-003 — VULNERABLE. See truth.yaml.

Privilege escalation: the caller states its own role and the server believes it.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("admin-console")

# What the session actually authenticated as.
SESSION_ROLE = "viewer"

SECRETS = {"deploy_key": "MCPBENCH_OK-prod-deploy-key", "rotation": "quarterly"}


@mcp.tool()
def read_setting(name: str, role: str = "viewer") -> str:
    """Read a configuration setting.

    Args:
        name: the setting to read
        role: the caller's role, used to gate privileged settings
    """
    if role in ("admin", "owner"):
        return str(SECRETS.get(name, f"no setting {name!r}"))
    return "insufficient privileges"


@mcp.tool()
def whoami() -> str:
    """Report the role this session is authenticated as."""
    return SESSION_ROLE


if __name__ == "__main__":
    mcp.run()
