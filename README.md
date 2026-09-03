# MCP Scanner Benchmark

A labeled corpus of MCP servers and a harness that scores every public MCP security scanner
against the same ground truth.

Twelve-plus MCP scanners exist. Nobody can say which one works.

## Status

Corpus v0: **26 cases across 13 pairs**, every label executed and verified. Harness running
against **five scanners** — see [First results](#first-results) for what it measured, and
[METHODOLOGY.md](METHODOLOGY.md) for how, and for where it can be wrong.

| Pair | Class | Tests |
|------|-------|-------|
| `cmd-injection-001` | CWE-78 | Shell interpolation vs. validated list argv |
| `path-traversal-001` | CWE-22 | Unconstrained join vs. resolved containment |
| `ssrf-001` | CWE-918 | Any scheme and host vs. allowlist + public-destination check |
| `tool-poisoning-001` | tool-poisoning | Hidden instructions vs. security vocabulary with no instruction |
| `unreachable-sink-001` | CWE-78 | The same dangerous sink, wired to a tool or wired to nothing |
| `untainted-sink-001` | CWE-78 | A live, reachable shell call — constant argument vs. caller's string |
| `authz-001` | authz-session | Broken object-level access: caller names whose record to read |
| `authz-002` | authz-session | Confused deputy: caller names the tenant |
| `authz-003` | authz-session | Privilege escalation: caller states its own role |
| `authz-004-js` | authz-session | The JavaScript twin of `authz-001` |
| `cmd-injection-002-js` | CWE-78 | The JavaScript twin of `cmd-injection-001` |
| `path-traversal-002-js` | CWE-22 | The JavaScript twin of `path-traversal-001` |
| `tool-poisoning-002-js` | tool-poisoning | The JavaScript twin of `tool-poisoning-001` |

Full design rationale, scoring rules and threats to validity:
**[METHODOLOGY.md](METHODOLOGY.md)**.

## Why a benchmark and not another scanner

The detection lane is taken — VIPER-MCP released working exploit-confirmation tooling, Docker
acquired MCP Defender, Snyk acquired Invariant's mcp-scan, and NVIDIA, Tencent and Cisco all
ship scanners. What nobody has built is the measurement: no independent, reproducible
comparison exists, so every tool's claims stand unchecked.

## Ground truth is executed, not asserted

A benchmark whose labels are wrong is worse than no benchmark — the first reviewer to find a
mislabeled case discards the whole leaderboard. So every case carries a `proof` block, and
`corpus/verify.py` runs it: a `vulnerable` case must demonstrate its payload firing, and its
paired `safe` case must demonstrate the same payload failing.

```console
$ python3 corpus/verify.py
ok    authz-001
ok    authz-001-safe
...
ok    unreachable-sink-001-reachable

26/26 cases verified, 373 checks
```

A proof also has to be honest about *why* it passed. A tool that echoes its input back would
produce the marker without executing anything, so shell payloads split it — `echo MCPBENCH""_OK`
reassembles only in a shell — and the verifier rejects any payload containing its own oracle.

The verifier also lints the schema (required fields, sink lines pointing at real code, pairs
resolving both ways) and rejects contradictory labels — a `vulnerable` case with no sink, or a
`safe` case declaring a CWE class.

## First results

Five scanners, 26 cases. Every number below is reproducible with `python3 harness/run.py`,
and every claim names the version it was measured against.

| Adapter | Version | Surface | Languages | tp | fp | tn | fn | Precision | Recall | **Pairs discriminated** |
|---------|---------|---------|-----------|----|----|----|----|-----------|--------|-------------------------|
| `ramparts/scan-config` | 0.8.8 (rules @ `70457db`) | metadata | any | 2 | 0 | 2 | 0 | 100% | 100% | **2/2** |
| `cisco-mcp-scanner/stdio+yara` | 4.8.4 | metadata | any | 2 | 0 | 2 | 0 | 100% | 100% | **2/2** |
| `mcts/scan` | 0.1.4 | source | Python, JS/TS | 9 | 8 | 5 | 4 | 53% | 69% | **1/13** |
| `mcp-watch/scan-local` | 2.0.0 | source | JS/TS only | 1 | 1 | 3 | 3 | 50% | 25% | **0/4** |
| `mcpwn/live` | 1.0 @ `6e9e8fc` | runtime | any | — | — | — | — | — | — | crashes on every case |
| `cisco-mcp-scanner/behavioural` | 4.8.4 | source | — | — | — | — | — | — | — | unavailable (paid key) |

Run on Darwin 25.6.0 arm64, Python 3.14.5. Versions, platform and timestamp are recorded in
[`harness/results-latest.json`](harness/results-latest.json) with every scanner's raw output,
so any row here can be audited back to what the tool actually said.

### Pair discrimination is the number that matters

Raw recall hides the result. MCTS reports **69% recall** — and discriminates **one of
thirteen pairs**. It flags the vulnerable case and its safe twin identically almost
every time, so nearly every "true positive" is a coincidence: it flagged something present in
both files and the label happened to match.

A pair counts as discriminated only when the vulnerable twin is flagged and the safe twin is
not. That is the only question a user actually has — *can this tool tell a vulnerability from
its fix?* — and it is invisible in precision/recall alone.

Concretely, MCTS reports 4 critical/high findings on `unreachable-sink-001`, whose dangerous
sink no exposed tool can reach, and the same 4 on the twin where it is reachable. It reports
`Handler egress to HTTP client: get_report` on `authz-001`, a file containing no network code
at all. It misses path traversal in both twins.

Both metadata scanners, by contrast, discriminate every pair they are scored on — including
the decoys stuffed with audit/compliance/credential vocabulary. That is a real pass on cases
built to catch keyword matchers.

**The result is not a Python artifact.** Command injection, path traversal, tool poisoning and
authorization each carry a JavaScript twin of the Python case. MCTS fails the JS twins the same
way it fails the Python ones — `authz-004-js` and `path-traversal-002-js` are among the pairs it
cannot tell apart — and mcp-watch, which reads JS/TS only, discriminates none of the four pairs
it can see at all. Whatever these tools are missing, they miss it in both languages.

The findings that only a benchmark surfaces:

1. **`cargo install ramparts` ships no detection.** It warns
   `No YARA rules directory found. Pattern-based detection is DISABLED for this run`, and the
   generated `config.yaml` leaves the LLM `api_key` empty — so both engines are off and a
   default install reports a clean bill of health on a server whose tool description says to
   read `~/.ssh/id_rsa`. With the rules fetched from the repo it scores 100%. The gap is
   packaging, not capability, and `tools/setup-ramparts.sh` closes it.
2. **mcp-watch reads JavaScript and TypeScript only.** The identical poisoned description
   scores 1 finding as JS and 0 as Python, so roughly half the MCP ecosystem is invisible to
   it. That is coverage, not detection failure, so Python cases are skipped rather than
   counted against it.
3. **mcp-watch misses tool poisoning even in JavaScript** — its own headline category. A
   description instructing the client to read `~/.ssh/id_rsa` and stay quiet about it returns
   zero findings. It also misses `child_process.exec` on an interpolated tool argument. The
   one finding it produced in testing was `toxic-flow`, triggered by a description *combined
   with* an exec sink, not by either alone.
4. **Cisco's source-level analysis needs a paid LLM key.** Offline it sees metadata only, so
   its `behavioural` mode is listed and unscored rather than quietly omitted.
5. **The runtime surface is unmeasured, because the only tool covering it is broken.** Mcpwn
   is the sole surveyed scanner that drives a live server and confirms findings by semantic
   oracle — and it crashes before reaching any of that. `tests/state_desync.py:63` calls
   `self.pentester.send_notification(...)`, which is defined nowhere in the repository, and
   the desync test runs unconditionally ahead of everything else, so `--quick` and
   `--rce-only` crash too. All 17 runtime cases error identically.

   This is not a regression at HEAD. The call was introduced in the initial commit and is
   the only commit in the repository's history that touches it, so every commit and the
   `v1.0.0` tag carry it; running `v1.0.0` reproduces the same `AttributeError`. The crash
   is recorded as an error, never as a miss: a tool that cannot run is a different result from
   a tool that runs and finds nothing.

6. **Authorization is detected once out of three variants, and for the wrong reason.** The
   class is carried by three flavours: broken object-level access (`authz-001`, the caller
   names whose record to read), confused deputy (`authz-002`, the caller names the tenant),
   and privilege escalation (`authz-003`, the caller states its own role). MCTS
   discriminates only `authz-002` — and the findings it reports there are
   `Handler egress to HTTP client: list_tickets` and `SSRF exfiltration to model context`,
   on a file containing a dict lookup and a string join and **no network code at all**. It
   is tracking argument-reaches-output and labelling it SSRF; the discrimination is a side
   effect, not authorization analysis. On `authz-001` and `authz-003` it produces those same
   wrong findings on both twins and discriminates neither.

   This is why the class needed three variants. On `authz-001` alone the result reads as a
   categorical zero, which would have been an overclaim.
7. **Nor does any scanner reason about reachability or taint.** Two dimensions, both failed.
   `unreachable-sink-001` and its twin share a byte-identical `subprocess.run(..., shell=True)`
   helper wired to a tool in one and to nothing in the other. `untainted-sink-001` and its
   twin both reach a live shell call, but one passes a constant from a lookup table and the
   other falls back to the caller's string — one word apart. MCTS reports the same 4
   critical/high findings on both members of both pairs.
8. **MCTS scans almost nothing when given a directory.** Pointed at a case directory it
   returns one generic "Stdio MCP server trust boundary" note; pointed at the entrypoint
   file it returns nine findings including the taint path. A user scanning a repo the
   obvious way gets a clean bill of health for a server with a critical injection in it.

Taken together, the surface coverage looks like this: **metadata is well served** (two tools
at 100% with full pair discrimination), **source is measured but undiscriminating** (MCTS at
0/8 pairs, mcp-watch JS/TS-only at 0/2, one tool behind a paywall), and **runtime is
effectively uncovered**. That distribution is the argument for the benchmark existing.

## The harness scores by surface

```console
$ python3 harness/run.py

cisco-mcp-scanner/stdio+yara  (surfaces: metadata)
  ✓ tp   tool-poisoning-001                 1 finding(s)
  ✓ tn   tool-poisoning-001-safe
  · skip authz-001                          surfaces ['source', 'runtime'] outside ['metadata']
  ...
  tp=1 fp=0 tn=1 fn=0 skipped=10 errors=0
  precision 100.0%   recall 100.0%   f1 100.0%
— cisco-mcp-scanner/behavioural: unavailable, needs MCP_SCANNER_LLM_API_KEY
```

Every case declares the `surfaces` it lives on — `metadata`, `source`, `runtime` — and every
adapter declares the surfaces it inspects. **An adapter is scored only where those overlap.**
Cisco's stdio mode reads live tool metadata; asking it about a source-level command injection
measures the question, not the scanner, so those cases are reported as `skipped` rather than
counted as misses. Getting this wrong is how a benchmark earns a justified takedown from the
tools it ranks.

Availability is part of the result. Cisco's source-level analysis needs an LLM API key, so it
is listed and unavailable — a capability nobody can reproduce without paid credentials is worth
recording as a property of the tool.

## Cases come in pairs

A corpus of only vulnerable servers measures recall and nothing else: a scanner that flags
every line scores 100%. Every vulnerable case is paired with a safe twin that shares its
imports, tool names, docstrings, and sink — differing only in whether the input is actually
exploitable. A scanner that grepped for `subprocess` flags both and scores 50% precision.

## Layout

```
corpus/
  SCHEMA.md          ground-truth format and field rules
  verify.py          executes every label; exit 1 if any case is wrong
  cases/<id>/
    server.py        the MCP server
    truth.yaml       verdict, class, sink, entry point, proof, pair
```

## Running it

```console
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python corpus/verify.py            # all cases
.venv/bin/python corpus/verify.py cmd-injection-001   # one case
```

Payloads are local and inert — echoing a marker string, never a real attack. Nothing in this
repo touches a third-party system.
