#!/usr/bin/env bash
# Build one isolated environment per scanner, under .envs/<slug>/.
#
# Scanners pin their own dependencies and some conflict with the corpus. Installing
# snyk-agent-scan into the shared environment downgraded mcp from 2.1.1 to 1.28.1 and
# broke 20 of 28 cases, because the corpus servers import MCPServer, which exists only
# in 2.x. A benchmark should not be one `pip install` away from corrupting its own
# ground truth, so nothing shares an environment with the corpus.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
mkdir -p .envs
status=0

make_env() {                       # slug, then pip args
  slug="$1"; shift
  echo "== $slug"
  python3 -m venv ".envs/$slug" >/dev/null 2>&1 || { echo "   venv failed"; status=1; return; }
  if ".envs/$slug/bin/pip" install -q --upgrade pip "$@" >/dev/null 2>&1; then
    echo "   installed: $*"
  else
    echo "   FAILED to install: $*"; status=1
  fi
}

make_env cisco cisco-ai-mcp-scanner
make_env mcts  -e vendor/mcts
make_env snyk  snyk-agent-scan
make_env skillspector "git+https://github.com/NVIDIA/SkillSpector.git"

# Mcpwn is vendored and dependency-free, but give it an interpreter of its own so a
# future dependency cannot reach the corpus.
make_env mcpwn

echo
echo "corpus environment is .venv and is left alone:"
.venv/bin/python -c "import importlib.metadata as m; print('   mcp', m.version('mcp'))" 2>/dev/null \
  || echo "   (.venv not built yet)"
exit "$status"
