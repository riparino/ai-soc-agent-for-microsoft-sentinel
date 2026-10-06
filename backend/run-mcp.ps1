<#
.SYNOPSIS
  Launch the Sentinel AI SOC Agent MCP server from any working directory (Windows).

.DESCRIPTION
  Switches to the backend folder (so the local .env loads and app.* imports resolve),
  activates .\venv if present, and passes all arguments through, e.g.:

    .\run-mcp.ps1                               # stdio (local MCP clients)
    .\run-mcp.ps1 --check                       # self-diagnose this install
    .\run-mcp.ps1 --print-config claude-desktop # config snippet for Claude Desktop
    .\run-mcp.ps1 --transport streamable-http   # http://127.0.0.1:8800/mcp, no auth

  If scripts are blocked: powershell -ExecutionPolicy Bypass -File .\run-mcp.ps1 --check
#>
Set-Location -Path $PSScriptRoot
if (Test-Path ".\venv\Scripts\Activate.ps1") { . ".\venv\Scripts\Activate.ps1" }
python -m app.mcp_server @args
exit $LASTEXITCODE
