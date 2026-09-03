# Corpus ground-truth schema

Every case is a directory under `corpus/cases/<case-id>/` holding the server source and a
`truth.yaml`. The harness reads `truth.yaml`; nothing else in the directory is load-bearing.

## Why negative cases exist

A corpus of only vulnerable servers measures **recall** and nothing else. A scanner that flags
every line scores 100%. Precision needs servers that are *safe but look dangerous*: the same
sink reached through a validated path, an `exec` on a hardcoded constant, a traversal-shaped
join that resolves inside a jail. Those are the cases that separate a real scanner from a
grep for `subprocess`.

Target mix: roughly 60% positive, 40% negative, with negatives deliberately paired to
positives so a scanner cannot pass by pattern-matching the filename or the tool description.

## truth.yaml

```yaml
id: cmd-injection-001              # unique, kebab-case, class-prefixed
language: python                   # python | typescript | javascript
verdict: vulnerable                # vulnerable | safe
class: CWE-78                      # null when verdict is safe
title: Shell command injection via unvalidated tool argument

sink:                              # null when verdict is safe
  file: server.py
  line: 24
  function: subprocess.run
  argument: cmd                    # the tainted parameter at the sink

entry:                             # how attacker-controlled input arrives
  tool: run_diagnostic             # the MCP tool name
  parameter: target
  reachable: true                  # false = sink exists but no path from any tool

pair: cmd-injection-001-safe       # the paired case testing the opposite verdict
notes: >
  The paired safe case runs the same subprocess.run sink but shell=False with a list
  argv, so the argument cannot break out. A scanner that flags both has a precision
  problem, not a detection win.
```

## The proof block

`corpus/verify.py` executes every label. Two modes:

- **`mode: call`** (default), invoke `tool` with `args` and search the result for `oracle`.
- **`mode: metadata`**, list the tools and search their names, descriptions and schemas.
  Tool poisoning hides in what a client reads before calling anything, so behaviour-based
  proof cannot see it.

Two rules make a proof mean something:

**The oracle must not appear in the payload.** A tool that echoes its input back produces the
marker without executing anything, `unreachable-sink-001` did exactly that and passed for the
wrong reason until it was caught. Shell payloads therefore split the marker:

```yaml
args:
  branch: '; echo MCPBENCH""_OK'   # only a shell reassembles this into MCPBENCH_OK
oracle: MCPBENCH_OK
```

The verifier rejects any `call` proof whose arguments contain the oracle literally.

**`{case_dir}` expands to the case's absolute path**, so payloads needing a real filesystem
path (`file://` URLs, traversal targets) stay machine-independent and inside the case
directory. Nothing in a proof may touch anything outside it.

## Field rules

- **`verdict`** is the scored label. `vulnerable` means an attacker controlling the tool
  argument can reach the sink and cause the class's effect. `safe` means they cannot.
- **`reachable: false`** marks a dangerous-looking sink with no path from any exposed tool.
  Flagging it is a false positive. This is the single most common scanner failure and worth
  testing explicitly.
- **`sink.line`** must point at the executing line, not the import or the wrapper.
- **`pair`** is required on every case. Unpaired cases skew the score.

## Classes in v1

| Class | What it is | Field coverage |
|-------|-----------|----------------|
| CWE-78 | Command injection | Well covered. Every scanner claims it |
| CWE-22 | Path traversal | Well covered |
| CWE-918 | SSRF | Well covered |
| tool-poisoning | Malicious instructions in tool descriptions | Well covered |
| **authz-session** | OAuth token passthrough, confused deputy, session hijack, DNS rebinding | **Not covered by any scanner found** |

The first four establish the benchmark is measuring the same thing the field claims to detect.
The fifth is the finding: every existing tool is expected to score near zero on it.
