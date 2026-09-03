#!/usr/bin/env bash
# ramparts ships no YARA rules through `cargo install`; both of its detection engines
# are off in a default install (rules missing, LLM key empty). Fetch the rules so the
# scanner is scored in its intended configuration rather than in its broken default.
#
# The upstream commit is recorded in .source-commit: the rules are copied rather than
# cloned, so they have no .git of their own and every result must still name the
# version it was produced against.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone --depth 1 -q https://github.com/highflame-ai/ramparts.git "$tmp/ramparts"
commit="$(git -C "$tmp/ramparts" rev-parse --short HEAD)"
rm -rf "$here/vendor/ramparts-rules"
mkdir -p "$here/vendor"
cp -R "$tmp/ramparts/rules" "$here/vendor/ramparts-rules"
printf '%s\n' "$commit" > "$here/vendor/ramparts-rules/.source-commit"
echo "rules at $here/vendor/ramparts-rules @ $commit ($(find "$here/vendor/ramparts-rules" -name '*.yar' | wc -l | tr -d ' ') files)"
