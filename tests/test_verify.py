"""Tests for the corpus verifier.

The verifier is what lets this project claim its labels are executed rather than
asserted, so its own failure modes are pinned here, including the two real bugs it
shipped with, both of which made a case pass for the wrong reason.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "corpus"))

import verify  # noqa: E402

VULNERABLE = """\
id: {id}
language: python
verdict: vulnerable
class: CWE-78
title: test case

sink:
  file: server.py
  line: 8
  function: subprocess.run
  argument: cmd

surfaces: [source, runtime]

entry:
  tool: run_it
  parameter: value
  reachable: true

proof:
  tool: run_it
  args:
    value: '; echo MCPBENCH""_OK'
  oracle: MCPBENCH_OK
  expect: present

pair: {pair}
notes: test
"""

SERVER = '''\
"""Test server."""
from __future__ import annotations

import subprocess

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("test")


@mcp.tool()
def run_it(value: str) -> str:
    """Run it."""
    cmd = f"echo start {value}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
'''


def write_case(tmp_path: Path, cid: str, truth: str, server: str = SERVER) -> Path:
    d = tmp_path / cid
    d.mkdir(parents=True, exist_ok=True)
    (d / "truth.yaml").write_text(truth, encoding="utf-8")
    (d / "server.py").write_text(server, encoding="utf-8")
    return d


@pytest.fixture
def cases_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(verify, "CASES_DIR", tmp_path)
    return tmp_path


def test_a_real_vulnerable_case_verifies(cases_dir):
    d = write_case(cases_dir, "v", VULNERABLE.format(id="v", pair="s"))
    write_case(cases_dir, "s", VULNERABLE.format(id="s", pair="v"))
    result = verify.verify(d)
    # The pair's twin is also vulnerable here, so only the proof and sink matter.
    assert not [e for e in result.errors if "payload" in e], result.errors
    assert result.checks > 0


def test_a_payload_containing_its_own_oracle_is_rejected(cases_dir):
    """Shipped bug: a tool echoing its input produced the marker without executing."""
    truth = VULNERABLE.format(id="v", pair="s").replace(
        """value: '; echo MCPBENCH""_OK'""", """value: '; echo MCPBENCH_OK'""")
    d = write_case(cases_dir, "v", truth)
    write_case(cases_dir, "s", VULNERABLE.format(id="s", pair="v"))
    result = verify.verify(d)
    assert any("contains the oracle" in e for e in result.errors), result.errors


def test_a_server_that_cannot_load_is_a_hard_failure(cases_dir):
    """Shipped bug: an import error read as "payload absent" and passed safe cases."""
    truth = VULNERABLE.format(id="v", pair="s").replace(
        "verdict: vulnerable", "verdict: safe").replace(
        "class: CWE-78", "class: null").replace(
        "expect: present", "expect: absent").replace("""sink:
  file: server.py
  line: 8
  function: subprocess.run
  argument: cmd""", "sink: null")
    d = write_case(cases_dir, "v", truth, server="import does_not_exist\n")
    write_case(cases_dir, "s", VULNERABLE.format(id="s", pair="v"))
    result = verify.verify(d)
    assert any("failed to load" in e for e in result.errors), result.errors


def test_a_vulnerable_case_without_a_class_or_sink_is_rejected(cases_dir):
    truth = VULNERABLE.format(id="v", pair="s").replace(
        "class: CWE-78", "class: null").replace("""sink:
  file: server.py
  line: 8
  function: subprocess.run
  argument: cmd""", "sink: null")
    d = write_case(cases_dir, "v", truth)
    result = verify.verify(d)
    assert any("no class" in e for e in result.errors)
    assert any("no sink" in e for e in result.errors)


def test_a_safe_case_declaring_a_class_is_rejected(cases_dir):
    truth = VULNERABLE.format(id="v", pair="s").replace("verdict: vulnerable", "verdict: safe")
    d = write_case(cases_dir, "v", truth)
    result = verify.verify(d)
    assert any("declares class" in e for e in result.errors)
    assert any("declares a sink" in e for e in result.errors)


def test_a_sink_line_not_containing_its_function_is_rejected(cases_dir):
    truth = VULNERABLE.format(id="v", pair="s").replace("  line: 8", "  line: 3")
    d = write_case(cases_dir, "v", truth)
    result = verify.verify(d)
    assert any("does not contain" in e for e in result.errors), result.errors


def test_a_pair_that_does_not_point_back_is_rejected(cases_dir):
    d = write_case(cases_dir, "v", VULNERABLE.format(id="v", pair="s"))
    write_case(cases_dir, "s", VULNERABLE.format(id="s", pair="somewhere-else"))
    result = verify.verify(d)
    assert any("points back at" in e for e in result.errors), result.errors


def test_an_id_not_matching_its_directory_is_rejected(cases_dir):
    d = write_case(cases_dir, "v", VULNERABLE.format(id="mismatched", pair="s"))
    result = verify.verify(d)
    assert any("does not match directory" in e for e in result.errors)


def test_a_case_with_no_proof_is_rejected(cases_dir):
    truth = VULNERABLE.format(id="v", pair="s").split("proof:")[0] + "pair: s\n"
    d = write_case(cases_dir, "v", truth)
    result = verify.verify(d)
    assert any("no proof block" in e for e in result.errors), result.errors


def test_substitution_expands_the_case_directory(tmp_path):
    got = verify._substitute({"url": "file://{case_dir}/SECRET.txt"}, tmp_path)
    assert got["url"] == f"file://{tmp_path}/SECRET.txt"


JS_SAFE = """\
id: {id}
language: javascript
verdict: safe
class: null
title: js test case

sink: null

surfaces: [source, runtime]

entry:
  tool: run_it
  parameter: value
  reachable: false

proof:
  tool: run_it
  args:
    value: 'x'
  oracle: MCPBENCH_OK
  expect: absent

pair: {pair}
notes: test
"""


def test_a_js_server_that_cannot_start_is_a_hard_failure(cases_dir):
    """The Python path guards this; the JS path did not, and a broken safe twin passed.

    A server that fails to boot produces no output, which reads as "payload absent" and
    passes a safe case for the wrong reason. js_proof.mjs now exits 3 when the server
    never starts, which is distinct from exiting 1 when a tool refuses the payload.
    """
    d = cases_dir / "jsbroken"
    d.mkdir(parents=True, exist_ok=True)
    (d / "truth.yaml").write_text(JS_SAFE.format(id="jsbroken", pair="jsbroken-pair"),
                                  encoding="utf-8")
    (d / "server.js").write_text('import { nope } from "does-not-exist";\n', encoding="utf-8")
    pair = cases_dir / "jsbroken-pair"
    pair.mkdir(parents=True, exist_ok=True)
    (pair / "truth.yaml").write_text(JS_SAFE.format(id="jsbroken-pair", pair="jsbroken"),
                                     encoding="utf-8")
    (pair / "server.js").write_text("// unused\n", encoding="utf-8")

    result = verify.verify(d)
    assert any("failed to run" in e for e in result.errors), result.errors
