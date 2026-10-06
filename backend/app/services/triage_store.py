"""
Shared in-memory store for generated triage reports.

Kept in a dependency-free module so both the REST/WebSocket API and the MCP
server can share the same cache without the MCP server importing the HTTP/auth
layer (whose import has side effects such as printing the first-run credential
banner — which must never reach stdout on the MCP stdio transport).

Keys are canonical namespaced incident refs ("<workspace_id>::<incident_guid>").
This is process-local; for multi-replica deployments back it with Redis/Postgres.
"""

from typing import Any, Dict

TRIAGE_REPORTS_CACHE: Dict[str, Dict[str, Any]] = {}
