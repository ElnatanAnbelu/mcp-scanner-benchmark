# Contributing

## If your tool is scored here and you think the score is wrong

That is the most useful issue this project can receive, and it is welcome without
qualification. Please open one.

Every result is reproducible in one command, and every finding keeps the scanner's raw output
under `raw` in `harness/results-latest.json`, so a disagreement can be settled by looking
rather than arguing. Useful things to point at:

- **Wrong invocation.** If the adapter runs your tool in a way that undersells it — a missing
  flag, the wrong mode, a config it needs — say so and it gets fixed. This has already
  happened once: MCTS returns one generic finding when handed a directory and nine when
  handed the entrypoint file, and the adapter was corrected to use the file.
- **Wrong configuration.** Tools are scored in their intended configuration, not their
  defaults. ramparts is scored with its YARA rules fetched, because a default `cargo install`
  ships without them. If your tool needs setup to work properly, that setup belongs in the
  adapter.
- **A mislabeled case.** If you believe a case's ground truth is wrong, run
  `python3 corpus/verify.py <case-id>`; the label is executed, not asserted. If the proof is
  weak or proves the wrong thing, that is a real bug and a serious one.
- **An unfair case.** If a case is contrived in a way no real server would be, argue it. The
  corpus is synthetic and that is its main limitation, documented in
  [METHODOLOGY.md](METHODOLOGY.md#6-threats-to-validity).

Scores are not a verdict on a tool. Most of what shows up here is a gap between what a tool
tries to do and what its default deployment actually does.

## Adding a scanner

Implement an `Adapter` in `harness/adapters.py`:

```python
class YourScanner(Adapter):
    name = "yourtool/mode"          # tool and mode: one adapter per configuration
    surfaces = ("source",)          # metadata | source | runtime
    languages = ("python",)         # what it actually parses
    requires = "how to install it"  # shown when unavailable

    def available(self) -> bool: ...
    def scan(self, case_dir: Path) -> ScanResult: ...
```

Two rules that keep the numbers meaningful:

- **Declare surfaces and languages honestly.** An adapter is scored only where its coverage
  overlaps a case. Over-declaring turns absent coverage into false negatives; under-declaring
  hides real misses.
- **A crash is `ran=False`, not an empty result.** A tool that cannot run is a different
  outcome from one that runs and finds nothing, and collapsing them misreports both.

If your tool needs a severity filter to avoid counting architectural notes as detections, put
it in the adapter and say why in the docstring — that is a judgement call and it should be
visible.

## Adding a case

Every case needs a **safe twin**. A vulnerable case alone measures recall and nothing else:
a scanner that flags every file scores 100%.

1. `corpus/cases/<id>/` with `server.py` (or `server.js` plus `package.json`)
2. `corpus/cases/<id>-safe/` — the same shape, the same imports, the same sink, differing only
   in whether the vulnerability is real. Make it hard to separate by surface features.
3. A `truth.yaml` in each, per [corpus/SCHEMA.md](corpus/SCHEMA.md), with a `proof` block
4. `python3 corpus/verify.py` must pass before you open the PR

Payloads stay local and inert — echo a marker string, never a real attack, never anything
that leaves the case directory.

A claim about a whole vulnerability class needs at least three variants of it. One pair is an
anecdote; that lesson is recorded in the methodology.
