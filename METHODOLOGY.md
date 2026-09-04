# Methodology

How this is built, how it scores, and where it can be wrong.

Written for someone deciding whether to trust the numbers, including the author of a tool that
scored badly here. Decisions that could bias a result are called out as such.

**What this is not.** It is not a survey of the field. Five tools are measured across six
adapter configurations, four of which produced scores; several other scanners exist and are not
here. It is not a verdict on any tool's overall quality, and the sample is
small enough that no result should be read as a confidence interval.

---

## 0. Prior work

[MCPTox-Benchmark][mcptox] is the closest thing to this and predates it, scoped to tool
poisoning. pipelock ships `agent-egress-bench`, which benchmarks egress behaviour rather than
scanners. Neither compares general-purpose MCP scanners against shared ground truth, which is
the gap this fills, but "no comparison exists" would be too strong a claim and is not made
here.

[mcptox]: https://github.com/zhiqiangwang4/MCPTox-Benchmark

---

## 1. What is being measured

**Question:** given an MCP server, can a scanner tell whether it is vulnerable?

Not "does the scanner produce findings", and not "does it mention the right CWE". The
question is discrimination: a tool that flags everything and a tool that flags nothing are
equally useless to a user, and conventional precision/recall over an unbalanced corpus can
make either look good.

**Non-goals.** This does not measure runtime cost beyond wall-clock, rule counts, report
quality, remediation advice, or how a tool behaves on real-world repositories at scale. It
measures detection on a controlled corpus with known answers.

---

## 2. Corpus construction

### 2.1 Cases come in pairs

Every vulnerable case has a **safe twin**: the same defect class, same imports, same tool
names, same docstrings, same sink, differing only in whether the vulnerability is real.

A corpus of vulnerable servers alone measures recall and nothing else. A scanner that emits
a finding for every file scores 100%. The twin makes that failure visible: flagging both
halves scores one true positive *and* one false positive, and discriminates nothing.

The twins are written to be **hard to separate by surface features**. `cmd-injection-001` and
its safe twin both import `subprocess` and both call it on a tool argument; only the shell
handling differs. The tool-poisoning safe twin is deliberately stuffed with the vocabulary a
keyword matcher keys on, audit, compliance, credentials, "important", while instructing the
client to do nothing.

### 2.2 Classes and dimensions

Four classes the field already claims to detect, so the benchmark is measuring the same thing
the tools advertise:

| Class | Pairs |
|-------|-------|
| CWE-78 command injection | `cmd-injection-001` (Python), `cmd-injection-002-js` (JavaScript) |
| CWE-22 path traversal | `path-traversal-001` (Python), `path-traversal-002-js` (JavaScript) |
| CWE-918 SSRF | `ssrf-001` (Python) |
| tool poisoning | `tool-poisoning-001` (Python), `tool-poisoning-002-js` (JavaScript) |

Then three dimensions that separate real analysis from pattern matching:

| Dimension | Pair | The question |
|-----------|------|--------------|
| Reachability | `unreachable-sink-001` | The same `shell=True` helper and the same three tools in both twins, differing in one line: whether `refresh_cache` passes its argument to the helper. *Can the sink be reached at all?* |
| Taint | `untainted-sink-001` | A live shell call both twins reach; one passes a constant from a lookup table, the other falls back to the caller's string. *Does attacker input reach it?* |
| Semantics | `authz-001/002/003`, `authz-004-js` | Broken object-level access, confused deputy, privilege escalation, and the JavaScript twin of the first. No shell, no filesystem, no network. *Is this class modelled at all?* |

### 2.2.1 Language coverage is a dimension, not a detail

Four of the classes carry a JavaScript twin of the Python case, because a result measured in
one language invites the obvious objection that it is an artifact of that language. It also
exposed a real property: mcp-watch returns a clean zero on Python and finds things in
JavaScript, which is absent coverage rather than a detection failure and has to be scored as
such (§4.1). SSRF remains Python-only, which is a gap.

### 2.3 Why three authorization variants

Because one was nearly an overclaim. On `authz-001` alone, MCTS flags both twins identically
and the result reads as a categorical "no scanner detects authorization flaws". Adding
`authz-002` and `authz-003` showed MCTS discriminating one of the three, for the wrong
reason, but discriminating. A single case would have supported a stronger claim than the
evidence does.

**Rule adopted:** a claim about a class requires at least three variants of that class. Any
class-level statement resting on one pair is an anecdote.

### 2.4 Synthetic, and what that costs

Every case is written for this benchmark rather than harvested from real repositories. That
buys unambiguous ground truth, no disclosure burden, and twins that differ in exactly one
respect. It costs realism: real servers are longer, messier, and carry framework indirection
that may defeat analysis these cases do not exercise.

This is the most serious limitation and it is not resolved. See §6.

---

## 3. Ground truth is executed, not asserted

A benchmark whose labels are wrong is worse than none: the first mislabeled case a reviewer
finds discards the whole leaderboard. So no label is a claim by the author.

Every case carries a `proof` block, and `corpus/verify.py` runs it:

- a **vulnerable** case must demonstrate its payload firing, so the oracle string appears
- its **safe** twin must demonstrate the same payload failing, so the oracle does not appear

Python cases are called in-process. JavaScript cases are driven over stdio by a real MCP
client (`corpus/js_proof.mjs`), which is the more faithful of the two paths since it crosses
the same transport an attacker would.

### 3.1 Two rules that make a proof mean something

**A payload may not contain its own oracle.** A tool that echoes its input back produces the
marker without executing anything. This was caught when `unreachable-sink-001` "failed" for
reflecting its argument, which meant the *passing* shell cases were unproven too. Shell
payloads split the marker (`echo MCPBENCH""_OK`, which only a shell reassembles) and the
verifier rejects any `call` proof whose arguments contain the oracle literally.

**A server that cannot start is a hard failure, not a passing safe case.** An import error
produces no output, which reads as "payload absent" and would pass every safe case. Loading
is a separate step with its own error.

### 3.2 Schema linting

`verify.py` also rejects: missing required fields, a `vulnerable` case with no class or sink,
a `safe` case declaring either, a `sink.line` that does not contain the named function, and
pairs that do not resolve in both directions.

### 3.3 Self-test

The verifier has been checked against a deliberately falsified label (flipping a `safe` case
to `vulnerable`) and against a deliberately weakened payload (one containing its oracle). It
rejects both.

---

## 4. Scoring

### 4.1 Surface and language gating

Each case declares the `surfaces` it lives on (`metadata`, `source` or `runtime`), and each
adapter declares the surfaces it inspects and the languages it parses. **An adapter is scored
only where those overlap.** Everything else is `skipped`, never counted as a miss.

This is the rule most likely to be disputed, so the reasoning is explicit. Cisco's stdio mode
reads live tool metadata; its source analysis is a *different mode* behind a paid API key.
Scoring the metadata mode against a source-level command injection would measure the question,
not the scanner. Likewise mcp-watch parses JS/TS only and returns a clean zero on Python. That is absent
coverage rather than a detection failure, and reporting it as 0% recall would be a smear.

The cost of this rule is that a tool can look good by covering little. `pairs_scored` is
therefore reported alongside every score: two-for-two on a two-pair surface is not the same
achievement as thirteen-for-thirteen.

### 4.2 Counting

```
tp vulnerable case, flagged fn vulnerable case, missed
tn safe case, not flagged fp safe case, flagged
```

"Flagged" means the adapter returned at least one finding after its own severity filter. For
MCTS only `critical` and `high` count: every case, vulnerable or safe, draws the same
low-severity architectural notes ("Stdio MCP server trust boundary"), and counting those as
detections would make any scanner look perfect. This filter is a per-adapter decision recorded
in that adapter's docstring.

### 4.3 Pair discrimination

**A pair is discriminated only when the vulnerable twin is flagged and the safe twin is not.**

This is the headline metric because precision and recall hide the failure this benchmark
exists to expose. MCTS scores 69% recall and discriminates 1 of 13 pairs. It flags both twins
alike, so nearly every true positive is a coincidence: something present in both files, with the
label happening to match.

Pair discrimination answers the only question a user actually has: *can this tool tell a
vulnerability from its fix?*

### 4.4 Errors are not misses

A tool that crashes is recorded as an error, never as a false negative. Mcpwn crashes on every
case; reporting that as 0% recall would conflate "cannot run" with "runs and finds nothing".

### 4.5 Availability is a result

A capability behind a paid API key is listed and unscored rather than omitted. Three of the
eight tools measured fall here: Cisco's behavioural mode, Snyk's agent-scan (an account token,
and the analysis is a cloud call), and Tencent's mcp-scan (one of three LLM keys, with no
static-only path despite a documented regex pre-scan stage). That is not a footnote about
three tools; it is a property of the field, and it is why every score in this table is
reproducible by anyone and those three are absent.

Both scored metadata adapters run with their LLM analyser off, and each says so in a
`scored_with` line printed above its score and recorded in the results file. ramparts is
scored on its YARA rules with `llm.api_key` empty; Cisco is scored with `--analyzers yara`.
That is the same condition for which Cisco's behavioural mode is marked unavailable, so
naming it keeps one table from treating two tools differently. Neither number should be read
as what the tool does with everything switched on.

---

## 5. Reproducibility

### 5.0 Every scanner gets its own environment

Scanners pin their own dependencies and some of those conflict with the corpus.
`snyk-agent-scan` requires `mcp<2`, and installing it alongside the corpus downgraded mcp
from 2.1.1 to 1.28.1, which broke 20 of the 28 cases: the servers import `MCPServer`, which
exists only in 2.x. `corpus/verify.py` failed loudly rather than letting the harness produce
wrong numbers against half-broken servers, but a benchmark should not be one `pip install`
away from corrupting its own ground truth.

So `tools/setup-adapters.sh` builds one virtualenv per scanner under `.envs/<slug>/`, and
`.venv` belongs to the corpus alone.

```console
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
npm install # JS corpus cases and mcp-watch
tools/setup-ramparts.sh # ramparts ships no YARA rules; fetch them
.venv/bin/python corpus/verify.py # every label must pass before any score is quoted
.venv/bin/python harness/run.py --json harness/results-latest.json
```

Scanner versions are pinned by whatever the install produces and recorded in the result JSON.
Every finding retains its raw payload under `raw`, so any scored outcome can be audited back
to what the tool actually said.

**Scanners are scored in their intended configuration**, not their broken defaults. ramparts
with a default `cargo install` detects nothing at all; it is scored with the rules fetched, and
the default-install gap is reported as a separate finding rather than as a bad score.

---

## 6. Threats to validity

**The corpus targets one SDK generation, and it is the new one.** Every Python case uses
`MCPServer` from `mcp` 2.x, which is where `FastMCP` was renamed. Scanners written against
`FastMCP` may under-detect these servers for that reason alone rather than for anything to do
with their analysis. MCTS is 0.1.4 and probably predates the rename. This is the most likely
explanation a maintainer will reach for, and it is a fair one: a tool that identifies MCP
servers by matching `FastMCP(` would find nothing to analyse in 22 of the 26 cases. The
JavaScript cases use `@modelcontextprotocol/sdk` 1.30.0, where `McpServer` is current, so the
two halves of the corpus are not on equal footing here either. `requirements.txt` pins `mcp==2.1.1` so the corpus cannot shift underneath a result.

The objection was tested rather than left standing. `cmd-injection-001` was rewritten to import
`FastMCP` from `mcp.server.fastmcp` and construct `FastMCP(...)`, changing nothing else, and
scanned again. MCTS returned an identical result: 9 findings, 5 of them critical or high, with
the same five titles. On this evidence the SDK generation does not explain its numbers. The
experiment covers one tool on one case and is worth repeating more broadly, but the obvious
version of this objection does not hold.

**Synthetic corpus.** The cases are small and written by one author who also knows what the
scanners look for. Even without intent, that risks cases shaped to the expected answer. The
mitigation is that twins differ minimally and the labels are executed, but a real-world
corpus would be stronger and does not exist yet.

**Author is not neutral.** These cases were written by someone who had already read what the
tools detect. A tool author who believes a case is unfair should be able to demonstrate it
from the repository, which is why proofs and raw findings are kept.

**Small n.** Thirteen pairs. Class-level claims rest on two or three variants, which is enough to
avoid the n=1 anecdote and not enough for a confidence interval.

**Severity filters are judgement.** The MCTS critical/high filter is defensible and is still a
choice made by the benchmark author, which shifts that tool's numbers.

**Version drift.** Every result is a snapshot, though not every finding is version-bound:
Mcpwn's crash traces to its initial commit and reproduces at `v1.0.0`. ramparts'
missing rules are as of the crate published at the time of the run. Any of this can be fixed
upstream tomorrow, which is the intended outcome.

**One machine.** All results are from a single macOS host with one Python, Node and Rust
toolchain. Nothing here is cross-platform verified.

---

## 7. Responsible reporting

Findings that reflect badly on a tool, ramparts shipping without rules, Mcpwn crashing at
HEAD, MCTS returning almost nothing when pointed at a directory, are defects worth reporting
upstream before or alongside publication, not gotchas to be sprung. Every one is reproducible
from this repository with a single command, which is the point: a maintainer should be able to
confirm or refute it in minutes.

Nothing in this repository scans, probes, or touches a third-party system. Every server is
written here, every payload echoes a marker string, and every proof stays inside its own case
directory.
