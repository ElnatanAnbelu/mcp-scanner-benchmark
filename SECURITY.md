# Security

## What lives in this repository

Deliberately vulnerable MCP servers. That is the point of it — they are the cases scanners are
measured against.

They are safe to hold and safe to run under `corpus/verify.py`, which is what CI does on every
push:

- Nothing here scans, probes or contacts a third-party system.
- Every payload is inert. They echo a marker string (`MCPBENCH_OK`); none is a real attack.
- Every proof stays inside its own case directory. The path-traversal cases read a `SECRET.txt`
  one level up from a notes folder, inside the case; the SSRF case reads that file over
  `file://`. Neither leaves the corpus.
- No case opens a network listener, writes outside its directory, or persists anything.

**Do not deploy a corpus server as a real MCP server.** `cmd-injection-001` will run whatever
a caller puts in its argument, and that is exactly what it is for.

## Reporting a problem with this repository

If you find something here that is unsafe in a way the above does not describe — a case that
escapes its directory, a payload that is not inert, a proof that touches something outside the
corpus — open an issue. There is nothing secret in this repository and no user data, so a
public issue is fine and faster.

## Findings about other people's tools

Results here sometimes show a scanner behaving worse than its documentation suggests. Those are
reported upstream to the tool's own tracker, reproducible in one command, rather than published
as a surprise. If a finding about your tool is wrong or unfairly configured, the
"My tool is scored wrong" issue template exists for exactly that and is welcome.
