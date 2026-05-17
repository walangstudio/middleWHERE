# middleWHERE Claude Code skill installer (Windows).
#
# Copies the middlewhere skill into ~/.claude/skills/ and records the path of
# the mwsql client binary. Idempotent.
#
# Usage:
#   .\install.ps1
#   $env:CLAUDE_SKILLS_DIR = 'C:\path'; .\install.ps1
#   $env:MIDDLEWHERE_BIN = 'C:\path\mwsql.exe'; .\install.ps1
$ErrorActionPreference = 'Stop'

$bundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $bundleDir 'skills'
$target = if ($env:CLAUDE_SKILLS_DIR) { $env:CLAUDE_SKILLS_DIR } else { Join-Path $HOME '.claude\skills' }

if (-not (Test-Path $src)) { Write-Error "expected bundle at $src" }

$bin = $env:MIDDLEWHERE_BIN
if (-not $bin) {
    $cmd = Get-Command mwsql -ErrorAction SilentlyContinue
    if ($cmd) { $bin = $cmd.Source }
}
if (-not $bin) {
    Write-Warning "'mwsql' not found on PATH and MIDDLEWHERE_BIN not set; skill still installs."
}

New-Item -ItemType Directory -Force -Path $target | Out-Null
Copy-Item -Recurse -Force (Join-Path $src 'middlewhere') $target
if ($bin) {
    Set-Content -Encoding utf8 -Path (Join-Path $target 'middlewhere\BIN_PATH') -Value $bin
    Write-Host "Recorded mwsql binary: $bin"
}
Write-Host "Installed middlewhere skill into $target\middlewhere"
Write-Host 'Use it in Claude Code as: /middlewhere <env> -e "SELECT 1"'
