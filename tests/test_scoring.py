"""Tests for the instrument itself.

Every published number depends on this scorer being right, so the failure modes it was
built to avoid are pinned here: counting a case an adapter cannot see, treating a crash
as a miss, and, the one that matters most, calling it a detection when a scanner flags
a vulnerability and its fix identically.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

import adapters  # noqa: E402
import run  # noqa: E402


class FakeAdapter(adapters.Adapter):
    """Flags exactly the cases named, so scoring can be tested without a scanner."""

    name = "fake/test"
    surfaces = ("source",)
    languages = ("python",)
    requires = "nothing"

    def __init__(self, flags: set[str] = frozenset(), crashes: set[str] = frozenset()) -> None:
        self.flags, self.crashes = set(flags), set(crashes)

    def available(self) -> bool:
        return True

    def resolve_version(self) -> str:
        return "0.0.0-test"

    def scan(self, case_dir: Path) -> adapters.ScanResult:
        name = case_dir.name
        if name in self.crashes:
            return adapters.ScanResult(self.name, name, [], ran=False, error="boom")
        findings = [adapters.Finding(name, "test finding")] if name in self.flags else []
        return adapters.ScanResult(self.name, name, findings)


def case(cid: str, verdict: str, pair: str, *, language: str = "python",
         surfaces: tuple[str, ...] = ("source",), cls: str | None = "CWE-78") -> dict:
    return {"id": cid, "verdict": verdict, "pair": pair, "language": language,
            "surfaces": list(surfaces), "class": cls if verdict == "vulnerable" else None,
            "_dir": Path("/nonexistent") / cid}


PAIR = [case("v", "vulnerable", "s"), case("s", "safe", "v")]


def test_flagging_only_the_vulnerable_twin_is_a_discriminated_pair():
    result = run.score(FakeAdapter(flags={"v"}), PAIR)
    assert result["counts"]["tp"] == 1 and result["counts"]["tn"] == 1
    assert result["pairs_discriminated"] == 1
    assert result["precision"] == 1.0 and result["recall"] == 1.0


def test_flagging_both_twins_scores_a_true_positive_but_discriminates_nothing():
    """The failure this benchmark exists to expose: a tp that detected nothing."""
    result = run.score(FakeAdapter(flags={"v", "s"}), PAIR)
    assert result["counts"] == {"tp": 1, "fp": 1, "tn": 0, "fn": 0, "skipped": 0, "errors": 0}
    assert result["recall"] == 1.0          # looks perfect
    assert result["pairs_discriminated"] == 0   # and is worthless
    assert result["pairs_scored"] == 1


def test_flagging_nothing_discriminates_nothing():
    result = run.score(FakeAdapter(), PAIR)
    assert result["counts"]["fn"] == 1 and result["counts"]["tn"] == 1
    assert result["recall"] == 0.0
    assert result["pairs_discriminated"] == 0


def test_flagging_only_the_safe_twin_is_not_discrimination():
    result = run.score(FakeAdapter(flags={"s"}), PAIR)
    assert result["counts"]["fp"] == 1 and result["counts"]["fn"] == 1
    assert result["pairs_discriminated"] == 0


def test_a_case_outside_the_adapters_surface_is_skipped_not_missed():
    cases = [case("v", "vulnerable", "s", surfaces=("metadata",)),
             case("s", "safe", "v", surfaces=("metadata",))]
    result = run.score(FakeAdapter(flags={"v"}), cases)
    assert result["counts"]["skipped"] == 2
    assert result["counts"]["fn"] == 0
    assert result["recall"] is None          # never scored, never blamed
    assert result["pairs_scored"] == 0


def test_a_case_in_an_unsupported_language_is_skipped_not_missed():
    cases = [case("v", "vulnerable", "s", language="javascript"),
             case("s", "safe", "v", language="javascript")]
    result = run.score(FakeAdapter(), cases)
    assert result["counts"]["skipped"] == 2 and result["counts"]["fn"] == 0
    assert "language" in result["rows"][0]["why"]


def test_a_crash_is_an_error_not_a_false_negative():
    result = run.score(FakeAdapter(crashes={"v", "s"}), PAIR)
    assert result["counts"]["errors"] == 2
    assert result["counts"]["fn"] == 0 and result["counts"]["tn"] == 0
    assert result["recall"] is None
    assert result["pairs_scored"] == 0       # a crashed pair is not a failed pair


def test_a_half_scored_pair_is_not_counted():
    """One twin skipped means the pair cannot be judged either way."""
    cases = [case("v", "vulnerable", "s"), case("s", "safe", "v", language="javascript")]
    result = run.score(FakeAdapter(flags={"v"}), cases)
    assert result["counts"]["tp"] == 1 and result["counts"]["skipped"] == 1
    assert result["pairs_scored"] == 0


def test_precision_and_recall_are_none_rather_than_zero_when_undefined():
    result = run.score(FakeAdapter(), [])
    assert result["precision"] is None and result["recall"] is None and result["f1"] is None


@pytest.mark.parametrize("surfaces,language,expected", [
    (["source"], "python", ""),
    (["metadata"], "python", "surfaces"),
    (["source"], "javascript", "language"),
])
def test_covers_reports_why_it_cannot_score(surfaces, language, expected):
    why = FakeAdapter().covers(surfaces, language)
    assert (expected in why) if expected else (why == "")


def test_git_commit_refuses_a_copied_tree(tmp_path):
    """A vendored copy has no .git; walking up would report the enclosing repo's hash."""
    copied = tmp_path / "rules"
    copied.mkdir()
    assert adapters._git_commit(copied) == ""


def test_pinned_source_reads_the_recorded_upstream_commit(tmp_path):
    (tmp_path / ".source-commit").write_text("70457db\n", encoding="utf-8")
    assert adapters._pinned_source(tmp_path) == "70457db"
    assert adapters._pinned_source(tmp_path / "missing") == ""


def test_first_json_object_ignores_surrounding_banner_text():
    """Scanners wrap their JSON in progress banners and trailing summaries."""
    text = '🔍 scanning...\n{"a": {"b": [1, 2]}, "s": "}"}\n✅ done\n'
    assert adapters._first_json_object(text) == {"a": {"b": [1, 2]}, "s": "}"}


def test_first_json_object_returns_none_when_there_is_no_object():
    assert adapters._first_json_object("no json here") is None


def test_a_partial_run_refuses_to_overwrite_a_fuller_results_file(tmp_path, monkeypatch, capsys):
    """A run with scanners missing must not silently replace published results."""
    out = tmp_path / "results.json"
    out.write_text(json.dumps({"adapters": [
        {"adapter": "a", "counts": {"tp": 1}},
        {"adapter": "b", "counts": {"tp": 2}},
    ]}), encoding="utf-8")
    before = out.read_text(encoding="utf-8")

    monkeypatch.setattr(adapters, "ALL", [FakeAdapter(flags={"v"})])
    monkeypatch.setattr(run, "load_cases", lambda only: PAIR)

    assert run.main(["--json", str(out)]) == 1
    assert out.read_text(encoding="utf-8") == before        # untouched
    assert "refusing to overwrite" in capsys.readouterr().err

    assert run.main(["--json", str(out), "--force"]) == 0   # asked twice, writes
    assert out.read_text(encoding="utf-8") != before


def test_findings_keep_their_raw_payload_in_the_result():
    """Three documents promise raw output; it has to survive into the result."""
    class RawAdapter(FakeAdapter):
        def scan(self, case_dir):
            return adapters.ScanResult(
                self.name, case_dir.name,
                [adapters.Finding(case_dir.name, "d", "high", {"rule": "X", "line": 7})])

    result = run.score(RawAdapter(), [case("v", "vulnerable", "s")])
    assert result["rows"][0]["raw"] == [{"rule": "X", "line": 7}]


def test_raw_output_has_the_local_path_redacted():
    """Scanners report absolute paths; publishing them leaks a home directory."""
    root = str(adapters.REPO)
    assert run.redact(f"{root}/corpus/cases/x/server.py") == "<repo>/corpus/cases/x/server.py"
    assert run.redact({"file": f"{root}/a", "n": [f"{root}/b", 3]}) == {
        "file": "<repo>/a", "n": ["<repo>/b", 3]}
