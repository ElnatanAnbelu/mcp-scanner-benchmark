---
name: My tool is scored wrong
about: For maintainers whose scanner appears in the results
title: "[score] "
labels: scoring
---

**Which adapter**
e.g. `mcts/scan`, version as reported in `harness/results-latest.json`.

**What the benchmark reports**
Paste the row or the relevant entry from `harness/results-latest.json`.

**What you expect instead, and why**
The most common causes, in order:

- [ ] **Wrong invocation** — a flag, mode or config the adapter is missing
- [ ] **Wrong configuration** — the tool needs setup the adapter does not do
- [ ] **Mislabeled case** — run `python3 corpus/verify.py <case-id>`; labels are executed
- [ ] **Unfair case** — the case is contrived in a way no real server would be

**Command that shows it**
The invocation you would expect the adapter to use, and its output.

---
This issue type is welcome without qualification. A score here is not a verdict on a tool, and
most of what shows up is a gap between what a tool does and what its default install does.
