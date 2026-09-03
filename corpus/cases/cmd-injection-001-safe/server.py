"""Network diagnostic MCP server.

Corpus case cmd-injection-001-safe, SAFE. See truth.yaml.

Deliberately the same shape as cmd-injection-001: same imports, same tool names,
same docstrings, same subprocess sink. Only the argument handling differs.
"""
from __future__ import annotations

import ipaddress
import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("net-diagnostics")


def _validated_host(target: str) -> str:
    """A hostname or IP address, or a ValueError. No shell metacharacters survive."""
    host = target.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not host or len(host) > 253:
        raise ValueError("hostname out of range")
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError("bad label length")
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in label):
            raise ValueError("illegal character in hostname")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("label may not start or end with a hyphen")
    return host


@mcp.tool()
def run_diagnostic(target: str, count: int = 4) -> str:
    """Ping a host and return the round-trip summary.

    Args:
        target: hostname or IP address to probe
        count: how many echo requests to send
    """
    host = _validated_host(target)
    argv = ["ping", "-c", str(max(1, min(int(count), 10))), host]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return proc.stdout or proc.stderr


@mcp.tool()
def resolve_host(name: str) -> str:
    """Resolve a hostname to its addresses."""
    proc = subprocess.run(["dig", "+short", _validated_host(name)],
                          capture_output=True, text=True, timeout=10)
    return proc.stdout


if __name__ == "__main__":
    mcp.run()
