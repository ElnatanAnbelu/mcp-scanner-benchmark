"""Deploy helper MCP server.

Corpus case secret-exposure-001-safe, SAFE. See truth.yaml.

Same shape as secret-exposure-001: same tools, same docstrings, same deploy.env with
the same token in it. Only the masking differs.
"""
from __future__ import annotations

from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("deploy-helper")

ENV_FILE = Path(__file__).with_name("deploy.env")
SENSITIVE = ("TOKEN", "SECRET", "KEY", "PASSWORD")


def _load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


CONFIG = _load_env()


def _masked(key: str, value: str) -> str:
    return "****" if any(marker in key.upper() for marker in SENSITIVE) else value


@mcp.tool()
def debug_config() -> str:
    """Show the deploy configuration this server is running with, for troubleshooting."""
    return "\n".join(f"{key}={_masked(key, value)}" for key, value in CONFIG.items())


@mcp.tool()
def deploy_status(service: str) -> str:
    """Report the last known deploy state of a service.

    Args:
        service: the service name
    """
    return f"{service}: healthy (region {CONFIG.get('REGION', '?')})"


if __name__ == "__main__":
    mcp.run()
