#!/usr/bin/env python3
"""Run every available scanner adapter over the corpus and score it.

Scoring rule that makes the numbers mean something: an adapter is scored only on cases
whose `surfaces` it can actually inspect. Asking a metadata scanner about a source-level
bug measures the question, not the scanner. Cases outside an adapter's surfaces are
reported as `skipped`, never as misses.

    tp  vulnerable case, flagged        fn  vulnerable case, missed
    tn  safe case, not flagged          fp  safe case, flagged

Usage:  python3 harness/run.py [--json out.json] [--adapter NAME] [case-id ...]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import adapters  # noqa: E402

try:
    import yaml
except ModuleNotFoundError:                                    # pragma: no cover
    sys.exit("run.py needs pyyaml: pip install pyyaml")

CASES_DIR = Path(__file__).resolve().parent.parent / "corpus" / "cases"


def load_cases(only: list[str]) -> list[dict]:
    cases = []
    for path in sorted(CASES_DIR.glob("*/truth.yaml")):
        truth = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        truth["_dir"] = path.parent
        if not only or truth.get("id") in only:
            cases.append(truth)
    return cases


def score(adapter: adapters.Adapter, cases: list[dict]) -> dict:
    rows, counts = [], {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "skipped": 0, "errors": 0}
    per_class: dict[str, dict[str, int]] = {}

    for truth in cases:
        case_id = str(truth.get("id"))
        skip = adapter.covers(truth.get("surfaces") or [], str(truth.get("language") or ""))
        if skip:
            counts["skipped"] += 1
            rows.append({"case": case_id, "outcome": "skipped",
                         "why": skip})
            continue

        result = adapter.scan(truth["_dir"])
        if not result.ran:
            counts["errors"] += 1
            rows.append({"case": case_id, "outcome": "error", "why": result.error})
            continue

        flagged = bool(result.findings)
        vulnerable = truth.get("verdict") == "vulnerable"
        outcome = ("tp" if flagged else "fn") if vulnerable else ("fp" if flagged else "tn")
        counts[outcome] += 1

        cls = str(truth.get("class") or f"safe-pair-of:{truth.get('pair')}")
        per_class.setdefault(cls, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})[outcome] += 1

        rows.append({"case": case_id, "outcome": outcome, "findings": len(result.findings),
                     "seconds": round(result.seconds, 2),
                     "detail": [f.detail for f in result.findings][:5]})

    # Pair discrimination: the metric raw counts hide.
    #
    # A scanner that flags both twins of a pair scores a true positive on the vulnerable
    # one — but it did not detect the vulnerability, it flagged something present in both
    # and got the label right by accident. MCTS flags authz-001 and authz-001-safe
    # identically, so its "tp" there says nothing about authorization at all.
    #
    # A pair counts as discriminated only when the vulnerable twin is flagged and the
    # safe twin is not. This is the number that says whether a tool can tell the
    # difference, which is the only thing a user actually needs from it.
    outcomes = {row["case"]: row["outcome"] for row in rows}
    pairs: dict[str, dict] = {}
    for truth in cases:
        case_id, pair_id = str(truth.get("id")), str(truth.get("pair") or "")
        if truth.get("verdict") != "vulnerable" or not pair_id:
            continue
        vuln, safe = outcomes.get(case_id), outcomes.get(pair_id)
        if vuln in ("tp", "fn") and safe in ("tn", "fp"):
            pairs[case_id] = {"class": truth.get("class"),
                              "discriminated": vuln == "tp" and safe == "tn",
                              "vulnerable": vuln, "safe": safe}
    discriminated = sum(1 for p in pairs.values() if p["discriminated"])

    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) else None)
    return {"adapter": adapter.name, "surfaces": list(adapter.surfaces),
            "counts": counts, "precision": precision, "recall": recall, "f1": f1,
            "per_class": per_class, "rows": rows,
            "pairs": pairs, "pairs_scored": len(pairs), "pairs_discriminated": discriminated}


def pct(value: float | None) -> str:
    return "  n/a" if value is None else f"{value * 100:5.1f}%"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cases", nargs="*")
    ap.add_argument("--adapter", help="run only adapters whose name contains this")
    ap.add_argument("--json", type=Path, help="write the full result to this file")
    ns = ap.parse_args(argv)

    cases = load_cases(ns.cases)
    if not cases:
        print("no cases found", file=sys.stderr)
        return 1

    selected = [a for a in adapters.ALL if not ns.adapter or ns.adapter in a.name]
    report = {"cases": len(cases), "adapters": []}

    for adapter in selected:
        if not adapter.available():
            print(f"— {adapter.name}: unavailable, needs {adapter.requires}")
            report["adapters"].append({"adapter": adapter.name, "unavailable": adapter.requires})
            continue

        print(f"\n{adapter.name}  (surfaces: {', '.join(adapter.surfaces)})")
        result = score(adapter, cases)
        report["adapters"].append(result)
        for row in result["rows"]:
            mark = {"tp": "✓ tp", "tn": "✓ tn", "fp": "✗ fp", "fn": "✗ fn",
                    "skipped": "· skip", "error": "! err"}[row["outcome"]]
            extra = row.get("why") or (f"{row.get('findings', 0)} finding(s)"
                                       if row["outcome"] in ("tp", "fp") else "")
            print(f"  {mark:6} {row['case']:34} {extra}")
        c = result["counts"]
        print(f"  tp={c['tp']} fp={c['fp']} tn={c['tn']} fn={c['fn']} "
              f"skipped={c['skipped']} errors={c['errors']}")
        print(f"  precision {pct(result['precision'])}   recall {pct(result['recall'])}   "
              f"f1 {pct(result['f1'])}")
        if result["pairs_scored"]:
            failed = [c for c, p in result["pairs"].items() if not p["discriminated"]]
            print(f"  pairs discriminated {result['pairs_discriminated']}/{result['pairs_scored']}"
                  + (f"   cannot tell apart: {', '.join(failed)}" if failed else ""))

    if ns.json:
        ns.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {ns.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
