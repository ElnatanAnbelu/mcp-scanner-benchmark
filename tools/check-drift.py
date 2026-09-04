#!/usr/bin/env python3
"""Compare the versions the published results were measured against with what upstream
ships today.

A benchmark decays quietly. Numbers stay on the page and keep looking authoritative
while the tools they describe move on, and the only person who finds out is a reader
who checks. This asks the registries once a month instead.

It reads nothing but harness/results-latest.json and the network, changes nothing, and
exits 1 when any scanner has moved so CI can raise an issue.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "harness" / "results-latest.json"
TIMEOUT = 30

# Where each adapter's tool actually comes from. Adapters sharing a tool share a row;
# the key is the part of the adapter name before the slash.
SOURCES = {
    "cisco-mcp-scanner": ("pypi", "cisco-ai-mcp-scanner"),
    "mcp-watch": ("npm", "mcp-watch"),
    "ramparts": ("crates", "ramparts"),
    "snyk-agent-scan": ("pypi", "snyk-agent-scan"),
    "mcts": ("github-head", "MCP-Audit/MCTS"),
    "skillspector": ("github-head", "NVIDIA/SkillSpector"),
    "tencent-mcp-scan": ("github-head", "Tencent/AI-Infra-Guard"),
    "mcpwn": ("github-head", "Teycir/Mcpwn"),
}

# Tools installed from a checkout are compared by commit, not by tag. The GitHub tags API
# orders by name, so it once reported MCTS "v1", a tag from before v0.1.4, as new; the
# branch itself had moved 122 commits and no tag said so.
# ramparts is both: a released binary, plus rules vendored from a commit.
RULES_SOURCE = {"ramparts": ("github-head", "highflame-ai/ramparts")}


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-scanner-benchmark"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def latest(kind: str, ident: str) -> str:
    if kind == "pypi":
        return get(f"https://pypi.org/pypi/{ident}/json")["info"]["version"]
    if kind == "npm":
        return get(f"https://registry.npmjs.org/{ident}/latest")["version"]
    if kind == "crates":
        return get(f"https://crates.io/api/v1/crates/{ident}")["crate"]["max_stable_version"]
    if kind == "github-head":
        commits = get(f"https://api.github.com/repos/{ident}/commits?per_page=1")
        return commits[0]["sha"]
    raise ValueError(kind)


def recorded(version: str) -> tuple[str, str]:
    """Split "0.8.8 (rules @ 70457db)" into its release and its commit."""
    commit = ""
    m = re.search(r"@\s*([0-9a-f]{7,40})", version)
    if m:
        commit = m.group(1)
    release = re.match(r"[0-9][0-9A-Za-z.\-+]*", version.strip())
    return (release.group(0) if release else ""), commit


def main() -> int:
    if not RESULTS.exists():
        print(f"no results at {RESULTS}", file=sys.stderr)
        return 2
    results = json.loads(RESULTS.read_text())

    drifted, unchanged, unchecked = [], [], []
    seen = set()

    for adapter in results["adapters"]:
        tool = adapter["adapter"].split("/")[0]
        if tool in seen:
            continue
        seen.add(tool)
        release, commit = recorded(adapter.get("version", ""))

        for label, source in ((tool, SOURCES.get(tool)), (f"{tool} rules", RULES_SOURCE.get(tool))):
            if not source:
                continue
            kind, ident = source
            # Tools vendored from a checkout are pinned by commit even when they also
            # carry a version number of their own, as Mcpwn's "1.0 @ 6e9e8fc" does.
            pinned = commit if kind == "github-head" else (release or commit)
            if not pinned:
                continue
            try:
                now = latest(kind, ident)
            except (urllib.error.URLError, urllib.error.HTTPError, LookupError, KeyError, IndexError) as e:
                unchecked.append(f"{label}: {type(e).__name__} {e}")
                continue
            # A commit pin records a prefix, so compare on the length we stored.
            same = now.startswith(pinned) if kind == "github-head" else now == pinned
            (unchanged if same else drifted).append((label, pinned, now[:12] if kind == "github-head" else now))

    for label, was, now in drifted:
        print(f"MOVED     {label}: measured {was}, upstream now {now}")
    for label, was, _ in unchanged:
        print(f"current   {label}: {was}")
    for line in unchecked:
        print(f"unchecked {line}")

    if drifted:
        print(f"\n{len(drifted)} of {len(drifted) + len(unchanged)} checked tools have moved. Re-run the harness.")
        return 1
    print(f"\nAll {len(unchanged)} checked tools are at the measured version.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
