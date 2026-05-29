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

# Newest published pre-release tag (skips drafts). Pure; testable without network.
function Select-PreReleaseTag {
  param($Releases)
  ($Releases | Where-Object { $_.prerelease -and -not $_.draft } | Select-Object -First 1).tag_name
}

# Compute the user PATH after adding $Dir. Pure; returns $Current unchanged if
# already present, trims a trailing ';' so we never write a ';;' empty entry.
function Get-NewUserPath {
  param([string]$Current, [string]$Dir)
  if (-not [string]::IsNullOrEmpty($Current) -and (($Current -split ';') -contains $Dir)) { return $Current }
  $trimmed = if ($null -eq $Current) { '' } else { $Current.TrimEnd(';') }
  if ([string]::IsNullOrEmpty($trimmed)) { return $Dir } else { return "$trimmed;$Dir" }
}

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
    $tag = Select-PreReleaseTag $list
    if (-not $tag) { Write-Fatal "No pre-release found" }
    return $tag
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
  $newPath = Get-NewUserPath $current $Dir
  if ($newPath -eq $current) { return }
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
  $env:PATH = "$env:PATH;$Dir"
  Write-Warn "$Dir added to your user PATH (restart the terminal to take effect)"
}

function Confirm-Checksum {
  param([string]$Archive, [string]$SumsFile)
  $name = Split-Path $Archive -Leaf
  # Accept text-mode ("<hash>  name") and binary-mode ("<hash> *name") output.
  $entry = Get-Content $SumsFile | Where-Object { $_ -match "\s\*?$([regex]::Escape($name))$" } | Select-Object -First 1
  if (-not $entry) { Write-Warn "No checksum entry for $name, skipping verification"; return }
  $expected = ($entry -split '\s+')[0].ToLower()
  $actual   = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLower()
  if ($actual -ne $expected) { Write-Fatal "Checksum mismatch!`n  expected: $expected`n  got:      $actual" }
  Write-Success "Checksum verified"
}

# Install every binary from $SrcDir into $InstallDir atomically: rename each
# existing one to .old, copy all three in, and on ANY failure restore the prior
# set (or remove freshly-copied ones on a first install). Throws on failure so
# the caller can decide how to report; never leaves a version-skewed toolset.
function Install-Binaries {
  param([string]$SrcDir, [string]$InstallDir)
  $backedUp = @()   # bins whose prior version was moved to .old
  $copied   = @()   # bins copied this run
  try {
    foreach ($bin in $Binaries) {
      $dest = Join-Path $InstallDir $bin
      if (Test-Path $dest) {
        Remove-Item "$dest.old" -Force -ErrorAction SilentlyContinue
        Rename-Item $dest "$dest.old" -Force   # throws if locked (binary running)
        $backedUp += $bin
      }
    }
    foreach ($bin in $Binaries) {
      Copy-Item (Join-Path $SrcDir $bin) (Join-Path $InstallDir $bin) -Force
      $copied += $bin
    }
  } catch {
    foreach ($bin in $copied)   { Remove-Item (Join-Path $InstallDir $bin) -Force -ErrorAction SilentlyContinue }
    foreach ($bin in $backedUp) { Rename-Item (Join-Path $InstallDir "$bin.old") (Join-Path $InstallDir $bin) -Force -ErrorAction SilentlyContinue }
    throw "Installation failed; previous state restored. (Is a middleWHERE binary still running?)"
  }
  foreach ($bin in $backedUp) { Remove-Item (Join-Path $InstallDir "$bin.old") -Force -ErrorAction SilentlyContinue }
}

function Invoke-Uninstall {
  $dir = Get-InstallDir
  $removed = $false
  # Only remove from our own install dir; a same-named binary elsewhere on PATH
  # is not ours to delete.
  foreach ($bin in $Binaries) {
    foreach ($p in @((Join-Path $dir $bin), (Join-Path $dir "$bin.old"))) {
      if (Test-Path $p) { Write-Info "Removing $p..."; Remove-Item $p -Force; $removed = $true }
    }
  }
  # @(...) forces an array so .Count is reliable when 0 or 1 items remain.
  if (Test-Path $dir) {
    if (@(Get-ChildItem $dir -Force -ErrorAction SilentlyContinue).Count -eq 0) { Remove-Item $dir -Force -ErrorAction SilentlyContinue }
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
    try { Install-Binaries $tmpDir $installDir } catch { Write-Fatal $_.Exception.Message }

    Add-ToUserPath $installDir

    if ($installed -and $installed -ne $version) { Write-Success "middleWHERE updated $installed -> $version  (mwsqld, mwsqlctl, mwsql)" }
    else { Write-Success "middleWHERE $version installed successfully  (mwsqld, mwsqlctl, mwsql)" }
    Write-Host ""
    # Best-effort version echo; never fail the (already successful) install on it.
    try { & (Join-Path $installDir $Probe) --version } catch { Write-Warn "installed, but '$Probe --version' could not run yet" }

    Write-Host ""
    Write-Host "Next steps" -ForegroundColor White
    Write-Host "  1. Initialize a state directory (one time):"
    Write-Host "       mwsqlctl --state-dir <dir> --file-keystore init" -ForegroundColor Cyan
    Write-Host "  2. Add a credential + environment, then run the daemon:"
    Write-Host "       mwsqld --state-dir <dir> --file-keystore run" -ForegroundColor Cyan
    Write-Host "  Service install? See https://github.com/$Repo#running-as-a-service"
    Write-Host "  Guide: https://github.com/$Repo#getting-started"
  } finally {
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# Skip the entrypoint when dot-sourced by the test harness; normal
# `irm ... | iex` execution leaves $env:MW_INSTALL_NO_MAIN unset.
if ($env:MW_INSTALL_NO_MAIN -ne '1') { Main }
