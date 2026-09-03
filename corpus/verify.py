#!/usr/bin/env python3
"""Verify every corpus label by executing it.

A benchmark whose ground truth is asserted rather than demonstrated is worth nothing , 
the first reviewer to find a mislabeled case discards the whole leaderboard. So every
case carries a `proof` block, and this runs it:

    vulnerable + expect: present  →  the payload's oracle string must appear
    safe       + expect: absent   →  the same payload must not produce it

It also lints the schema: required fields, sink line pointing at real code, pairs
resolving in both directions, and the field combinations that are contradictory
(a vulnerable case with no sink, a safe case with a class).

Cases run in-process against the FastMCP tool functions. Payloads stay local and
inert, an echo of a marker string, never a real attack.

Usage:  python3 corpus/verify.py [case-id ...]
Exit:   0 all verified, 1 something failed.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:                                    # pragma: no cover
    sys.exit("verify.py needs pyyaml: pip install pyyaml")

CASES_DIR = Path(__file__).resolve().parent / "cases"
REQUIRED = ("id", "language", "verdict", "title", "entry", "pair")
VERDICTS = ("vulnerable", "safe")


@dataclass
class Result:
    case: str
    errors: list[str] = field(default_factory=list)
    checks: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def load_truth(case_dir: Path) -> dict[str, Any]:
    return yaml.safe_load((case_dir / "truth.yaml").read_text(encoding="utf-8")) or {}


def lint(truth: dict[str, Any], case_dir: Path, r: Result) -> None:
    for key in REQUIRED:
        if key not in truth:
            r.errors.append(f"missing required field: {key}")
    r.checks += len(REQUIRED)

    verdict, cls, sink = truth.get("verdict"), truth.get("class"), truth.get("sink")
    if verdict not in VERDICTS:
        r.errors.append(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    r.checks += 1

    # A vulnerable case without a class or sink is unscoreable; a safe case with
    # either is a contradiction the harness would silently mis-score.
    if verdict == "vulnerable":
        if not cls:
            r.errors.append("vulnerable case has no class")
        if not sink:
            r.errors.append("vulnerable case has no sink")
    elif verdict == "safe":
        if cls:
            r.errors.append(f"safe case declares class {cls!r}")
        if sink:
            r.errors.append("safe case declares a sink")
    r.checks += 2

    if isinstance(sink, dict):
        src = case_dir / str(sink.get("file", ""))
        line_no = sink.get("line")
        if not src.is_file():
            r.errors.append(f"sink.file does not exist: {sink.get('file')!r}")
        elif not isinstance(line_no, int):
            r.errors.append(f"sink.line must be an int, got {line_no!r}")
        else:
            lines = src.read_text(encoding="utf-8").splitlines()
            if not 1 <= line_no <= len(lines):
                r.errors.append(f"sink.line {line_no} out of range ({len(lines)} lines)")
            else:
                fn = str(sink.get("function", "")).split(".")[-1]
                if fn and fn not in lines[line_no - 1]:
                    r.errors.append(
                        f"sink.line {line_no} does not contain {fn!r}: {lines[line_no - 1].strip()!r}"
                    )
        r.checks += 3

    pair = truth.get("pair")
    if pair:
        pair_truth = CASES_DIR / str(pair) / "truth.yaml"
        if not pair_truth.is_file():
            r.errors.append(f"pair {pair!r} does not exist")
        else:
            back = (yaml.safe_load(pair_truth.read_text(encoding="utf-8")) or {}).get("pair")
            if back != truth.get("id"):
                r.errors.append(f"pair {pair!r} points back at {back!r}, not {truth.get('id')!r}")
        r.checks += 1


JS_PROOF = Path(__file__).resolve().parent / "js_proof.mjs"


def run_js_proof(case_dir: Path, tool: str, args: dict[str, Any]) -> tuple[str, str]:
    """Drive a JavaScript case over stdio. Returns (stdout, error).

    A JS server cannot be imported into Python, so its proof runs through a real MCP
    client, the same transport an attacker would use, which makes it the stronger
    proof of the two paths rather than a concession.
    """
    server = case_dir / "server.js"
    if not server.is_file():
        return "", f"no server.js in {case_dir.name}"
    node = shutil.which("node")
    if not node:
        return "", "node not installed"
    try:
        proc = subprocess.run(
            [node, str(JS_PROOF), str(server), tool, json.dumps(args)],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
    except subprocess.TimeoutExpired:
        return "", "timeout"
    return proc.stdout, ("" if proc.returncode == 0 else (proc.stderr or "").strip()[:200])


def load_server(case_dir: Path):
    """Import the case's server.py under a unique module name."""
    path = case_dir / "server.py"
    spec = importlib.util.spec_from_file_location(f"corpus_{case_dir.name.replace('-', '_')}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def call_tool(module: Any, name: str, args: dict[str, Any]) -> str:
    result = await module.mcp.call_tool(name, args)
    return "".join(str(part) for part in _flatten(result))


async def tool_metadata(module: Any) -> str:
    """Everything a client sees before calling anything: names, descriptions, schemas.

    Tool poisoning hides its payload here rather than in behaviour, so this is the
    surface to search for those cases.
    """
    tools = await module.mcp.list_tools()
    parts: list[str] = []
    for t in tools:
        parts += [str(getattr(t, "name", "")), str(getattr(t, "description", "") or "")]
        schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
        if schema:
            parts.append(str(schema))
    return "\n".join(parts)


def _substitute(value: Any, case_dir: Path) -> Any:
    """{case_dir} in a proof argument becomes this case's absolute path.

    Payloads that need a real filesystem path (file:// URLs, traversal targets) can
    then stay machine-independent and inside the case directory.
    """
    if isinstance(value, str):
        return value.replace("{case_dir}", str(case_dir))
    if isinstance(value, dict):
        return {k: _substitute(v, case_dir) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, case_dir) for v in value]
    return value


def _flatten(value: Any):
    """FastMCP returns nested content objects across versions; get to the text."""
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten(item)
    elif hasattr(value, "text"):
        yield value.text
    elif isinstance(value, dict):
        yield from _flatten(list(value.values()))
    else:
        yield value


def prove(truth: dict[str, Any], case_dir: Path, r: Result) -> None:
    proof = truth.get("proof")
    if not proof:
        r.errors.append("no proof block, every label must be demonstrated, not asserted")
        r.checks += 1
        return

    oracle, expect = str(proof.get("oracle", "")), proof.get("expect")
    mode = proof.get("mode", "call")
    if expect not in ("present", "absent"):
        r.errors.append(f"proof.expect must be present|absent, got {expect!r}")
        return
    if mode not in ("call", "metadata"):
        r.errors.append(f"proof.mode must be call|metadata, got {mode!r}")
        return

    # A payload containing the oracle proves nothing: a tool that echoes its input back
    # produces the marker without executing anything. Shell payloads split the marker
    # ('echo MCPBENCH""_OK') so only the shell can reassemble it.
    if mode == "call" and oracle:
        for key, value in (proof.get("args") or {}).items():
            if oracle in str(value):
                r.errors.append(
                    f"proof.args[{key}] contains the oracle {oracle!r} literally, "
                    "reflected input would pass without executing anything"
                )
        r.checks += 1

    # A vulnerable case must prove the payload works; a safe one must prove it doesn't.
    wanted = "present" if truth.get("verdict") == "vulnerable" else "absent"
    if expect != wanted:
        r.errors.append(f"{truth.get('verdict')} case expects {expect!r}, should be {wanted!r}")

    language = str(truth.get("language", "python"))
    args = _substitute(dict(proof.get("args") or {}), case_dir)

    if language in ("javascript", "typescript"):
        # "--metadata" makes the runner list tools instead of calling one, matching the
        # Python metadata path: tool poisoning hides in what a client reads, not in
        # what the code does.
        tool = "--metadata" if mode == "metadata" else str(proof["tool"])
        output, err = run_js_proof(case_dir, tool, {} if mode == "metadata" else args)
        # A payload the server refuses is a valid safe outcome; a server that never
        # started is not. Distinguish them the way the Python path does.
        if err and not output and "not installed" in err or "no server.js" in err:
            r.errors.append(f"could not run the JS proof: {err}")
            r.checks += 1
            return
        raised = err or None
    else:
        # Loading is a separate step on purpose. A server that cannot import produces no
        # output, which would otherwise read as "payload absent" and pass every safe case.
        try:
            module = load_server(case_dir)
        except Exception as exc:
            r.errors.append(f"server.py failed to load: {exc!r}")
            r.checks += 1
            return

        try:
            if mode == "metadata":
                output = asyncio.run(tool_metadata(module))
            else:
                output = asyncio.run(call_tool(module, str(proof["tool"]), args))
            raised = None
        except Exception as exc:                   # a rejected payload is a valid safe outcome
            output, raised = "", exc

    hit = oracle in output
    r.checks += 1
    if expect == "present" and not hit:
        r.errors.append(
            f"payload did not fire: {oracle!r} absent from output"
            + (f" (raised {raised!r})" if raised else f" (got {output[:120]!r})")
        )
    elif expect == "absent" and hit:
        r.errors.append(f"payload fired on a safe case: {oracle!r} present in output")


def verify(case_dir: Path) -> Result:
    r = Result(case=case_dir.name)
    try:
        truth = load_truth(case_dir)
    except Exception as exc:
        r.errors.append(f"unreadable truth.yaml: {exc}")
        return r
    if truth.get("id") != case_dir.name:
        r.errors.append(f"id {truth.get('id')!r} does not match directory {case_dir.name!r}")
    r.checks += 1
    lint(truth, case_dir, r)
    prove(truth, case_dir, r)
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cases", nargs="*", help="case ids to verify (default: all)")
    ns = ap.parse_args(argv)

    dirs = ([CASES_DIR / c for c in ns.cases] if ns.cases
            else sorted(p for p in CASES_DIR.glob("*") if (p / "truth.yaml").is_file()))
    if not dirs:
        print("no cases found", file=sys.stderr)
        return 1

    results = [verify(d) for d in dirs]
    checks = sum(r.checks for r in results)
    for r in results:
        print(f"{'ok  ' if r.ok else 'FAIL'}  {r.case}")
        for err in r.errors:
            print(f"        {err}")
    failed = [r for r in results if not r.ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} cases verified, {checks} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
