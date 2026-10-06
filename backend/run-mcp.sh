#!/usr/bin/env bash
# Launch the Sentinel AI SOC Agent MCP server from any working directory.
#
# Resolves the backend directory (so `app.*` imports and the local `.env` load),
# activates ./venv if present, picks a Python interpreter (venv, else python3,
# else python), and passes all arguments through, e.g.:
#
#   ./run-mcp.sh                                   # stdio (local clients)
#   ./run-mcp.sh --check                           # self-diagnose this install
#   ./run-mcp.sh --print-config claude-desktop     # client config snippet
#   ./run-mcp.sh --transport streamable-http       # http://127.0.0.1:8800/mcp, no auth
#   MCP_AUTH_MODE=entra ./run-mcp.sh --transport streamable-http --host 0.0.0.0
#
# Point Claude Desktop / Claude Code / VS Code at this script for stdio use.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ -f "venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "venv/bin/activate"
fi
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "run-mcp.sh: no python3/python interpreter found on PATH" >&2
  exit 127
fi
exec "$PY" -m app.mcp_server "$@"
