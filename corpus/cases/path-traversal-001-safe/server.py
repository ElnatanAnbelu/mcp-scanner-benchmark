"""Team notes MCP server.

Corpus case path-traversal-001-safe — SAFE. See truth.yaml.

Same shape as path-traversal-001: same tool names, same docstrings, same open()
sink on a joined path. Only the containment check differs.
"""
from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("team-notes")

NOTES_DIR = Path(__file__).resolve().parent / "notes"


def _contained(name: str) -> Path:
    """A path inside NOTES_DIR, or a ValueError. Resolves symlinks and ".." first."""
    candidate = (NOTES_DIR / name).resolve()
    root = NOTES_DIR.resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("path escapes the notebook")
    return candidate


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the shared team notebook.

    Args:
        name: the note's filename, e.g. "standup.md"
    """
    target = os.path.join(str(_contained(name)))
    with open(target, encoding="utf-8") as fh:
        return fh.read()


@mcp.tool()
def list_notes() -> str:
    """List the notes in the shared team notebook."""
    return "\n".join(sorted(p.name for p in NOTES_DIR.glob("*") if p.is_file()))


if __name__ == "__main__":
    mcp.run()
