"""Scanner adapters.

One adapter per scanner *configuration*, not per scanner. Tools expose several modes
that inspect different surfaces — Cisco's stdio mode reads live tool metadata while its
behavioural mode reads source — and a mode can only find what its surface contains.
Scoring a metadata scanner against a source-level bug measures nothing except the
question being wrong, so each adapter declares its surfaces and the scorer counts it
only against cases those surfaces can reach.

An adapter reports `available` when it can actually run here. Cisco's source analysis
needs an LLM API key, so it is present but unavailable offline — which is itself a
property worth publishing: a benchmark nobody can reproduce without paid credentials
is not much of a benchmark.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VENV_PYTHON = REPO / ".venv" / "bin" / "python"
SURFACES = ("metadata", "source", "runtime")


@dataclass
class Finding:
    """One scanner finding, normalized. `raw` keeps the original for auditing."""
    case: str
    detail: str = ""
    severity: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    adapter: str
    case: str
    findings: list[Finding]
    ran: bool = True
    error: str = ""
    seconds: float = 0.0


class Adapter:
    """Base class. Subclasses set name/surfaces and implement scan()."""

    name = "adapter"
    version = ""
    surfaces: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("python", "javascript", "typescript")
    requires = ""                      # what is missing when unavailable

    def available(self) -> bool:
        raise NotImplementedError

    def scan(self, case_dir: Path) -> ScanResult:
        raise NotImplementedError

    def covers(self, case_surfaces: list[str], language: str = "") -> str:
        """"" when this adapter can score the case, else why it cannot.

        Two independent reasons to skip. Surface: a metadata scanner cannot see a
        source-level bug. Language: mcp-watch parses JS/TS only and returns a clean
        zero on Python, which would otherwise read as a perfect miss rate rather than
        as no coverage at all.
        """
        if not set(self.surfaces) & set(case_surfaces or []):
            return f"surfaces {case_surfaces} outside {list(self.surfaces)}"
        if language and language not in self.languages:
            return f"language {language!r} unsupported (reads {'/'.join(self.languages)})"
        return ""


class CiscoStdioYara(Adapter):
    """cisco-ai-defense/mcp-scanner, stdio mode, YARA analyzer only.

    Launches the corpus server over stdio, enumerates its tools, and matches YARA rules
    against the metadata a client would read. Offline: no API key, no network.
    """

    name = "cisco-mcp-scanner/stdio+yara"
    surfaces = ("metadata",)
    languages = ("python", "javascript", "typescript")   # reads a live server, not source
    requires = "pip install cisco-ai-mcp-scanner"

    def __init__(self) -> None:
        self.binary = shutil.which("mcp-scanner") or str(REPO / ".venv" / "bin" / "mcp-scanner")

    def available(self) -> bool:
        return Path(self.binary).is_file() and VENV_PYTHON.is_file()

    def scan(self, case_dir: Path) -> ScanResult:
        import time
        server, runner = _server_and_runner(case_dir)
        if not server:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="no server file")
        cmd = [self.binary, "--analyzers", "yara", "--format", "raw", "stdio",
               "--stdio-command", runner, "--stdio-arg", str(server)]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                                  cwd=str(REPO), env={**os.environ, "NO_COLOR": "1"})
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="timeout",
                              seconds=time.time() - started)
        seconds = time.time() - started

        payload = _first_json_object(proc.stdout)
        if payload is None:
            detail = (proc.stderr or proc.stdout).strip()[:300]
            return ScanResult(self.name, case_dir.name, [], ran=False,
                              error=detail or f"exit {proc.returncode}, no JSON", seconds=seconds)

        findings: list[Finding] = []
        for item in payload.get("scan_results", payload.get("results", [])) or []:
            if not isinstance(item, dict):
                continue
            # Two independent signals: a per-analyzer finding count, and an is_safe
            # verdict. Trust either one flagging, and record when they disagree —
            # a scanner contradicting itself is worth reporting, not silently resolving.
            total = _total_findings(item.get("findings") or {})
            is_safe = item.get("is_safe")
            flagged = bool(total) or is_safe is False
            if not flagged:
                continue
            note = "" if (bool(total) == (is_safe is False)) else " [is_safe/count disagree]"
            findings.append(Finding(
                case=case_dir.name,
                detail=f"{item.get('tool_name') or item.get('item_type') or ''}: "
                       f"{total} finding(s){note}"[:160],
                severity=str(item.get("severity", "")),
                raw=item,
            ))
        return ScanResult(self.name, case_dir.name, findings, seconds=seconds)


class CiscoBehavioural(Adapter):
    """cisco-ai-defense/mcp-scanner, behavioural mode — source-level.

    Present for completeness and unavailable without credentials: the CLI refuses with
    "LLM provider API key is required for alignment verification".
    """

    name = "cisco-mcp-scanner/behavioural"
    surfaces = ("source",)
    requires = "MCP_SCANNER_LLM_API_KEY (or AWS Bedrock credentials)"

    def available(self) -> bool:
        return bool(os.environ.get("MCP_SCANNER_LLM_API_KEY"))

    def scan(self, case_dir: Path) -> ScanResult:
        return ScanResult(self.name, case_dir.name, [], ran=False, error="no LLM API key")


class McpWatchLocal(Adapter):
    """kapilduraphe/mcp-watch, scan-local mode — source-level, JS/TS only.

    Twelve vulnerability categories including tool poisoning and ANSI escape injection.
    Measured here to read JavaScript and TypeScript only: the same poisoned tool
    description scores 1 finding as JS and 0 as Python, so Python cases are skipped
    for lack of coverage rather than scored as misses.
    """

    name = "mcp-watch/scan-local"
    surfaces = ("source",)
    languages = ("javascript", "typescript")
    requires = "npm install mcp-watch"

    def __init__(self) -> None:
        # node_modules lives at the repo root: ESM resolution walks up from the case
        # directories, so the corpus servers and the proof runner both find the SDK.
        self.binary = REPO / "node_modules" / ".bin" / "mcp-watch"

    def available(self) -> bool:
        return self.binary.is_file()

    def scan(self, case_dir: Path) -> ScanResult:
        import time
        started = time.time()
        try:
            proc = subprocess.run(
                [str(self.binary), "scan-local", str(case_dir), "-f", "json"],
                capture_output=True, text=True, timeout=300, cwd=str(REPO),
                env={**os.environ, "NO_COLOR": "1"},
            )
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="timeout",
                              seconds=time.time() - started)
        seconds = time.time() - started

        # The JSON object sits between an emoji progress banner and a trailing summary.
        payload = _first_json_object(proc.stdout)
        if payload is None:
            detail = (proc.stderr or proc.stdout).strip()[:300]
            return ScanResult(self.name, case_dir.name, [], ran=False,
                              error=detail or f"exit {proc.returncode}, no JSON", seconds=seconds)

        findings = [
            Finding(case=case_dir.name,
                    detail=f"{v.get('category', '')}: {v.get('type') or v.get('description', '')}"[:160],
                    severity=str(v.get("severity", "")),
                    raw=v)
            for v in (payload.get("vulnerabilities") or []) if isinstance(v, dict)
        ]
        return ScanResult(self.name, case_dir.name, findings, seconds=seconds)


class Ramparts(Adapter):
    """highflame-ai/ramparts — connects to a live server and reads its tools.

    Two things worth recording about how it deploys. `cargo install ramparts` ships no
    YARA rules ("Pattern-based detection is DISABLED for this run"), and the LLM
    analyser's api_key is empty in the generated config, so a default install has both
    detection engines off and reports a clean bill of health on anything. Scored here
    with the rules fetched from the repository — its intended configuration — via
    tools/setup-ramparts.sh.

    It takes a URL rather than a command, so each case is handed over as a generated
    mcp.json and scanned with `scan-config --root`.
    """

    name = "ramparts/scan-config"
    surfaces = ("metadata",)
    languages = ("python", "javascript", "typescript")   # reads a live server, not source
    requires = "cargo install ramparts && tools/setup-ramparts.sh"

    def __init__(self) -> None:
        self.binary = shutil.which("ramparts") or ""
        self.rules = Path(os.environ.get("RAMPARTS_RULES_DIR")
                          or REPO / "vendor" / "ramparts-rules")

    def available(self) -> bool:
        return bool(self.binary) and self.rules.is_dir()

    def scan(self, case_dir: Path) -> ScanResult:
        import tempfile
        import time
        server, command = _server_and_runner(case_dir)
        if not server:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="no server file")
        args = [str(server)]

        started = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "mcp.json").write_text(
                json.dumps({"mcpServers": {case_dir.name: {"command": command, "args": args}}}),
                encoding="utf-8",
            )
            try:
                proc = subprocess.run(
                    [self.binary, "scan-config", "--root", tmp, "--format", "json"],
                    capture_output=True, text=True, timeout=300, cwd=str(REPO),
                    env={**os.environ, "RAMPARTS_RULES_DIR": str(self.rules), "NO_COLOR": "1"},
                )
            except subprocess.TimeoutExpired:
                return ScanResult(self.name, case_dir.name, [], ran=False, error="timeout",
                                  seconds=time.time() - started)
        seconds = time.time() - started

        payload = _first_json_object(proc.stdout)
        results = (payload or {}).get("results") or []
        if not results:
            detail = (proc.stderr or proc.stdout).strip()[:300]
            return ScanResult(self.name, case_dir.name, [], ran=False,
                              error=detail or "no results in output", seconds=seconds)

        result = results[0]
        if str(result.get("status")) != "Success":
            return ScanResult(self.name, case_dir.name, [], ran=False,
                              error=str(result.get("status"))[:200], seconds=seconds)

        findings: list[Finding] = []
        issues = result.get("security_issues") or {}
        for bucket in ("tool_issues", "prompt_issues", "resource_issues"):
            for issue in issues.get(bucket) or []:
                findings.append(Finding(case_dir.name, f"{bucket}: {str(issue)[:120]}",
                                        raw=issue if isinstance(issue, dict) else {"issue": issue}))
        for hit in result.get("yara_results") or []:
            if isinstance(hit, dict) and str(hit.get("status", "")).lower() in ("warning", "fail", "error"):
                findings.append(Finding(
                    case_dir.name,
                    f"yara: {hit.get('rule_name') or hit.get('target_name') or 'match'}"[:160],
                    severity=str(hit.get("status", "")), raw=hit))
        return ScanResult(self.name, case_dir.name, findings, seconds=seconds)


class Mcts(Adapter):
    """MCP-Audit/MCTS — local-first source scanner with behavioural taint analysis.

    The only working source-surface scanner found that reads Python, which makes it the
    one tool able to reach most of this corpus.

    Target the entrypoint file, not the case directory: pointed at a directory it
    returns a single generic "Stdio MCP server trust boundary" note and nothing else,
    while the same case as a file yields nine findings including the taint path. That
    is a usability trap worth recording — a user scanning a repo directory gets a clean
    bill of health for a server with a critical injection in it.
    """

    name = "mcts/scan"
    surfaces = ("source",)
    languages = ("python", "javascript", "typescript")
    requires = "pip install -e vendor/mcts (git clone MCP-Audit/MCTS)"

    def __init__(self) -> None:
        self.binary = shutil.which("mcts") or str(REPO / ".venv" / "bin" / "mcts")

    def available(self) -> bool:
        return Path(self.binary).is_file()

    def scan(self, case_dir: Path) -> ScanResult:
        import tempfile
        import time
        server, _ = _server_and_runner(case_dir)
        if not server:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="no server file")

        started = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scan.json"
            try:
                proc = subprocess.run(
                    [self.binary, "scan", str(server), "-f", "json", "-o", str(out)],
                    capture_output=True, text=True, timeout=300, cwd=tmp,
                    env={**os.environ, "NO_COLOR": "1"},
                )
            except subprocess.TimeoutExpired:
                return ScanResult(self.name, case_dir.name, [], ran=False, error="timeout",
                                  seconds=time.time() - started)
            seconds = time.time() - started
            if not out.is_file():
                detail = (proc.stderr or proc.stdout).strip()[:300]
                return ScanResult(self.name, case_dir.name, [], ran=False,
                                  error=detail or f"exit {proc.returncode}, no report",
                                  seconds=seconds)
            payload = json.loads(out.read_text(encoding="utf-8"))

        # Every case — vulnerable or safe — draws the same low-severity architectural
        # notes ("Stdio MCP server trust boundary"). Counting those as detections would
        # make any scanner look perfect, so only critical/high findings count as a flag.
        findings = [
            Finding(case_dir.name, str(f.get("title", ""))[:160],
                    severity=str(f.get("severity", "")), raw=f)
            for f in (payload.get("findings") or [])
            if isinstance(f, dict) and str(f.get("severity", "")).lower() in ("critical", "high")
        ]
        return ScanResult(self.name, case_dir.name, findings, seconds=seconds)


class Mcpwn(Adapter):
    """Teycir/Mcpwn — live exploitation against a running server (the runtime surface).

    Zero-dependency Python that drives a real server, injects payloads and confirms by
    semantic oracle (uid=, root:x:, private-key headers, timing deviation, DNS callback).
    It is the only tool surveyed that tests the runtime surface at all.

    At HEAD (6e9e8fc) it crashes before reaching any of that: tests/state_desync.py line
    63 calls `self.pentester.send_notification(...)`, which is defined nowhere in the
    repository, and the desync test runs unconditionally ahead of everything else — so
    `--quick` and `--rce-only` crash too. The scan is still attempted per case and the
    crash recorded as an error rather than a miss, because a tool that cannot run is a
    different result from a tool that runs and finds nothing.
    """

    name = "mcpwn/live"
    surfaces = ("runtime",)
    languages = ("python", "javascript", "typescript")
    requires = "git clone https://github.com/Teycir/Mcpwn.git vendor/mcpwn"

    def __init__(self) -> None:
        self.entry = REPO / "vendor" / "mcpwn" / "mcpwn.py"

    def available(self) -> bool:
        return self.entry.is_file()

    def scan(self, case_dir: Path) -> ScanResult:
        import tempfile
        import time
        server, runner = _server_and_runner(case_dir)
        if not server:
            return ScanResult(self.name, case_dir.name, [], ran=False, error="no server file")

        started = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "findings.json"
            try:
                proc = subprocess.run(
                    [str(VENV_PYTHON), str(self.entry), runner, str(server),
                     "--quick", "--safe-mode", "--output-json", str(out)],
                    capture_output=True, text=True, timeout=300, cwd=str(REPO),
                    env={**os.environ, "NO_COLOR": "1"},
                )
            except subprocess.TimeoutExpired:
                return ScanResult(self.name, case_dir.name, [], ran=False, error="timeout",
                                  seconds=time.time() - started)
            seconds = time.time() - started
            payload = None
            if out.is_file():
                try:
                    payload = json.loads(out.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    payload = None

        if payload is None:
            tail = (proc.stderr or proc.stdout).strip().splitlines()
            reason = next((ln for ln in reversed(tail) if ln.strip()), "")[:200]
            return ScanResult(self.name, case_dir.name, [], ran=False,
                              error=reason or f"exit {proc.returncode}, no findings file",
                              seconds=seconds)

        items = payload.get("findings", payload) if isinstance(payload, dict) else payload
        findings = [
            Finding(case_dir.name,
                    f"{f.get('title') or f.get('name') or f.get('type', '')}"[:160],
                    severity=str(f.get("severity", "")), raw=f)
            for f in (items or []) if isinstance(f, dict)
        ]
        return ScanResult(self.name, case_dir.name, findings, seconds=seconds)


def _server_and_runner(case_dir: Path) -> tuple[Path | None, str]:
    """The case's server file and the interpreter that launches it."""
    js, py = case_dir / "server.js", case_dir / "server.py"
    if js.is_file():
        return js, shutil.which("node") or "node"
    if py.is_file():
        return py, str(VENV_PYTHON)
    return None, ""


def _total_findings(analysis: dict) -> int:
    """Cisco nests the count under per-analyzer keys; sum whatever is there."""
    if not isinstance(analysis, dict):
        return 0
    total = 0
    for value in analysis.values():
        if isinstance(value, dict):
            n = value.get("total_findings")
            if isinstance(n, int):
                total += n
            else:
                total += _total_findings(value)
    return total


def _first_json_object(text: str) -> dict | None:
    """The first top-level JSON object in stdout, ignoring any banner around it."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i, ch in enumerate(text[start:], start):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


ALL: list[Adapter] = [CiscoStdioYara(), CiscoBehavioural(), McpWatchLocal(), Ramparts(), Mcts(), Mcpwn()]


if __name__ == "__main__":
    for a in ALL:
        state = "available" if a.available() else f"unavailable — needs {a.requires}"
        print(f"{a.name:32} surfaces={','.join(a.surfaces):10} langs={','.join(a.languages):28} {state}")
    sys.exit(0)
