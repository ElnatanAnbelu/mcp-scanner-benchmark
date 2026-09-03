# Corpus ground-truth schema

Every case is a directory under `corpus/cases/<case-id>/` holding the server source and a
`truth.yaml`. The harness reads `truth.yaml`; nothing else in the directory is load-bearing.

## Why negative cases exist

A corpus of only vulnerable servers measures **recall** and nothing else. A scanner that flags
every line scores 100%. Precision needs servers that are *safe but look dangerous*: the same
sink reached through a validated path, an `exec` on a hardcoded constant, a traversal-shaped
join that resolves inside a jail. Those are the cases that separate a real scanner from a
grep for `subprocess`.

Pairing fixes the balance at 50/50: every vulnerable case has exactly one safe twin, so the
corpus cannot drift toward either label. The twins are written to resist pattern matching on
the filename, the tool name or the description, since those are identical across a pair.

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
  reachable: true                  # vulnerable cases only; safe cases have no sink

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

**`listener: true` stands up an HTTP server on 127.0.0.1** and expands `{listener}` in the
arguments to its URL. SSRF is reaching an address the caller cannot, so proving it needs
something listening on one; a `file://` payload proves arbitrary file read instead, which is a
different weakness. The listener serves the oracle to any GET and is closed afterwards, and it
never binds anything but loopback.

**`{case_dir}` expands to the case's absolute path**, so payloads needing a real filesystem
path (`file://` URLs, traversal targets) stay machine-independent and inside the case
directory. Nothing in a proof may touch anything outside it.

## Field rules

- **`verdict`** is the scored label. `vulnerable` means an attacker controlling the tool
  argument can reach the sink and cause the class's effect. `safe` means they cannot.
- **`entry.reachable`** answers whether the sink can be reached from an exposed tool, so it
  appears on vulnerable cases only. A safe case has no sink and the field would say nothing;
  the verifier rejects it there. `unreachable-sink-001` is the pair that tests reachability,
  and it does so through its twin rather than through this flag.
- **`sink.line`** must point at the executing line, not the import or the wrapper.
- **`pair`** is required on every case. Unpaired cases skew the score.

## Classes in v1

| Class | What it is | Field coverage |
|-------|-----------|----------------|
| CWE-78 | Command injection | Well covered. Every scanner claims it |
| CWE-22 | Path traversal | Well covered |
| CWE-918 | SSRF | Well covered |
| tool-poisoning | Malicious instructions in tool descriptions | Well covered |
| **authz-session** | Broken object-level access, confused deputy, privilege escalation | **Barely covered** |

The first four establish that the benchmark measures the same thing the field claims to detect.
The fifth is where the results landed: of the scanners measured, only MCTS discriminated any
authorization pair, and it did so on one of three variants while reporting SSRF findings for a
file with no network code in it.
