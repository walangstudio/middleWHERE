#Requires -Version 5.1
# middleWHERE installer for Windows. Downloads the prebuilt binaries
# (mwsqld.exe, mwsqlctl.exe, mwsql.exe) from GitHub Releases, verifies the
# archive's SHA-256, installs all three, and adds them to your user PATH.
# Re-running upgrades in place.
#   irm https://raw.githubusercontent.com/walangstudio/middleWHERE/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm .../install.ps1))) -Version v0.2.0
#   & ([scriptblock]::Create((irm .../install.ps1))) -Uninstall
[CmdletBinding()]
param(
  [switch]$Uninstall,
  [switch]$PreRelease,
  [string]$Version = ''
)

$ErrorActionPreference = 'Stop'

$Repo     = 'walangstudio/middleWHERE'
$Binaries = @('mwsqld.exe', 'mwsqlctl.exe', 'mwsql.exe')
$Probe    = 'mwsql.exe'

function Write-Info    { Write-Host "==> $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "ok $args" -ForegroundColor Green }
function Write-Warn    { Write-Host "warning: $args" -ForegroundColor Yellow }
function Write-Fatal   { Write-Host "error: $args" -ForegroundColor Red; exit 1 }

function Get-Target {
  switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { return 'x86_64-pc-windows-msvc' }
    'ARM64' { Write-Fatal "No Windows arm64 build is published. Build from source: cargo install --git https://github.com/$Repo" }
    default { Write-Fatal "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
  }
}

function Get-InstallDir { return "$env:LOCALAPPDATA\Programs\middleWHERE" }

function Get-TargetVersion {
  if ($Version) {
    $tag = $Version.Trim(); if (-not $tag.StartsWith('v')) { $tag = "v$tag" }
    try { $r = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/tags/$tag" -ErrorAction Stop }
    catch { Write-Fatal "Version $tag not found" }
    if (-not $r.tag_name) { Write-Fatal "Version $tag not found" }
    return $r.tag_name
  }
  if ($PreRelease) {
    try { $list = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases?per_page=100" -ErrorAction Stop }
    catch { Write-Fatal "Could not query GitHub releases (rate limit or network?): $_" }
    $r = $list | Where-Object { $_.prerelease -and -not $_.draft } | Select-Object -First 1
    if (-not $r) { Write-Fatal "No pre-release found" }
    return $r.tag_name
  }
  try { return (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -ErrorAction Stop).tag_name }
  catch { Write-Fatal "Could not query the latest GitHub release (rate limit or network?): $_" }
}

function Get-InstalledVersion {
  # Prefer our own install dir; fall back to the .exe on PATH (never a bare
  # `mwsql` alias/function/script).
  $known = Join-Path (Get-InstallDir) $Probe
  if (Test-Path $known) {
    $bin = $known
  } else {
    $cmd = Get-Command $Probe -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    $bin = $cmd.Source
  }
  if ([string]::IsNullOrEmpty($bin)) { return $null }
  try {
    $out = & $bin --version 2>&1
    if ($out -match '(\d+\.\d+\.\d+)') { return "v$($Matches[1])" }
  } catch {}
  return $null
}

function Add-ToUserPath {
  param([string]$Dir)
  $current = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not [string]::IsNullOrEmpty($current) -and (($current -split ';') -contains $Dir)) { return }
  $trimmed = if ($null -eq $current) { '' } else { $current.TrimEnd(';') }
  $newPath = if ([string]::IsNullOrEmpty($trimmed)) { $Dir } else { "$trimmed;$Dir" }
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
  $env:PATH = "$env:PATH;$Dir"
  Write-Warn "$Dir added to your user PATH (restart the terminal to take effect)"
}

function Confirm-Checksum {
  param([string]$Archive, [string]$SumsFile)
  $name = Split-Path $Archive -Leaf
  $entry = Get-Content $SumsFile | Where-Object { $_ -match "\s$([regex]::Escape($name))$" } | Select-Object -First 1
  if (-not $entry) { Write-Warn "No checksum entry for $name, skipping verification"; return }
  $expected = ($entry -split '\s+')[0].ToLower()
  $actual   = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLower()
  if ($actual -ne $expected) { Write-Fatal "Checksum mismatch!`n  expected: $expected`n  got:      $actual" }
  Write-Success "Checksum verified"
}

function Invoke-Uninstall {
  $dir = Get-InstallDir
  $removed = $false
  # Only remove from our own install dir; a same-named binary elsewhere on PATH
  # is not ours to delete.
  foreach ($bin in $Binaries) {
    $path = Join-Path $dir $bin
    if (Test-Path $path) { Write-Info "Removing $path..."; Remove-Item $path -Force; $removed = $true }
  }
  if (Test-Path $dir) {
    if ((Get-ChildItem $dir -ErrorAction SilentlyContinue).Count -eq 0) { Remove-Item $dir -Force -ErrorAction SilentlyContinue }
  }
  if ($removed) { Write-Success "middleWHERE uninstalled" } else { Write-Warn "middleWHERE is not installed" }
}

function Main {
  if ($Uninstall) { Invoke-Uninstall; return }
  if ($PreRelease -and $Version) { Write-Fatal "-PreRelease and -Version cannot be combined" }

  $target = Get-Target

  Write-Info "Fetching release info..."
  $version = Get-TargetVersion
  if (-not $version) { Write-Fatal "Could not determine target version" }

  $installed = Get-InstalledVersion
  if ($installed) {
    if ($installed -eq $version) {
      if (-not $PreRelease -and -not $Version) {
        Write-Success "middleWHERE $version is already installed - nothing to do"; exit 0
      }
      Write-Warn "middleWHERE $version is already installed; reinstalling."
    } else {
      Write-Info "Updating middleWHERE $installed -> $version"
    }
  } else {
    Write-Info "Installing middleWHERE $version"
  }

  $asset   = "middlewhere-$version-$target.zip"
  $baseUrl = "https://github.com/$Repo/releases/download/$version"
  $tmpDir  = (New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()) -Force).FullName
  $archive = Join-Path $tmpDir $asset
  $sums    = Join-Path $tmpDir 'SHA256SUMS'

  try {
    Write-Info "Downloading $asset..."
    Invoke-WebRequest "$baseUrl/$asset"      -OutFile $archive -UseBasicParsing
    Invoke-WebRequest "$baseUrl/SHA256SUMS"  -OutFile $sums    -UseBasicParsing

    Write-Info "Verifying checksum..."
    Confirm-Checksum $archive $sums

    Write-Info "Extracting..."
    Expand-Archive $archive -DestinationPath $tmpDir -Force

    # Validate the whole set before touching the install dir, so a malformed
    # archive can't leave a half-installed, version-skewed toolset.
    foreach ($bin in $Binaries) {
      if (-not (Test-Path (Join-Path $tmpDir $bin))) { Write-Fatal "Binary '$bin' not found in archive" }
    }

    $installDir = Get-InstallDir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    foreach ($bin in $Binaries) {
      $extracted = Join-Path $tmpDir $bin
      $dest = Join-Path $installDir $bin
      $backup = "$dest.old"; $hasBackup = $false
      if (Test-Path $dest) {
        Remove-Item $backup -Force -ErrorAction SilentlyContinue
        try { Rename-Item $dest $backup -Force; $hasBackup = $true }
        catch { Write-Fatal "Cannot replace $bin - is it running? Close it and retry." }
      }
      try {
        Copy-Item $extracted $dest -Force
        if ($hasBackup) { Remove-Item $backup -Force -ErrorAction SilentlyContinue }
      } catch {
        if ($hasBackup) { Write-Warn "Install of $bin failed, restoring previous version..."; Rename-Item $backup $dest -Force -ErrorAction SilentlyContinue }
        Write-Fatal "Installation of $bin failed: $_"
      }
    }

    Add-ToUserPath $installDir

    if ($installed -and $installed -ne $version) { Write-Success "middleWHERE updated $installed -> $version  (mwsqld, mwsqlctl, mwsql)" }
    else { Write-Success "middleWHERE $version installed successfully  (mwsqld, mwsqlctl, mwsql)" }
    Write-Host ""
    # Best-effort version echo; never fail the (already successful) install on it.
    try { & (Join-Path $installDir $Probe) --version } catch { Write-Warn "installed, but '$Probe --version' could not run yet" }
  } finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Main
