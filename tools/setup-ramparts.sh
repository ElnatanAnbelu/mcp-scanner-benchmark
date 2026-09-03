#!/usr/bin/env bash
# ramparts ships no YARA rules through `cargo install`; both of its detection engines
# are off in a default install (rules missing, LLM key empty). Fetch the rules so the
# scanner is scored in its intended configuration rather than in its broken default.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone --depth 1 -q https://github.com/highflame-ai/ramparts.git "$tmp/ramparts"
rm -rf "$here/vendor/ramparts-rules"
mkdir -p "$here/vendor"
cp -R "$tmp/ramparts/rules" "$here/vendor/ramparts-rules"
echo "rules at $here/vendor/ramparts-rules ($(find "$here/vendor/ramparts-rules" -name '*.yar' | wc -l | tr -d ' ') files)"
