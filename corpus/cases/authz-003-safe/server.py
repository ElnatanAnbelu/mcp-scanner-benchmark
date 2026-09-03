"""Admin console MCP server.

Corpus case authz-003-safe — SAFE. See truth.yaml.

Same tool, same `role` argument in the schema, same privilege check — evaluated against
the session's role rather than the one the caller states.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("admin-console")

SESSION_ROLE = "viewer"

SECRETS = {"deploy_key": "MCPBENCH_OK-prod-deploy-key", "rotation": "quarterly"}


@mcp.tool()
def read_setting(name: str, role: str = "viewer") -> str:
    """Read a configuration setting.

    Args:
        name: the setting to read
        role: the caller's role, used to gate privileged settings
    """
    if SESSION_ROLE in ("admin", "owner"):
        return str(SECRETS.get(name, f"no setting {name!r}"))
    return "insufficient privileges"


@mcp.tool()
def whoami() -> str:
    """Report the role this session is authenticated as."""
    return SESSION_ROLE


if __name__ == "__main__":
    mcp.run()
