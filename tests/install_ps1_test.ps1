# Unit tests for install.ps1. Dot-sources the script (MW_INSTALL_NO_MAIN=1 skips
# the entrypoint) and exercises the pure/extracted functions. Covers each
# code-review finding. Runs on Windows PowerShell 5.1 and pwsh.
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function Ok  ($m){ $script:pass++; Write-Host "ok   - $m" }
function Bad ($m,$d){ $script:fail++; Write-Host "FAIL - $m`n     $d" }
function Eq  ($m,$got,$want){ if ($got -eq $want){ Ok $m } else { Bad $m "expected [$want], got [$got]" } }

$env:MW_INSTALL_NO_MAIN = '1'
. (Join-Path $PSScriptRoot '..\install.ps1')

# --- Get-Target ---
$env:PROCESSOR_ARCHITECTURE = 'AMD64'
Eq "Get-Target amd64" (Get-Target) 'x86_64-pc-windows-msvc'

# --- Select-PreReleaseTag: skips drafts and stable, picks newest published pre-release ---
$rels = @(
  [pscustomobject]@{ tag_name='v0.4.0-draft'; prerelease=$true;  draft=$true  },
  [pscustomobject]@{ tag_name='v0.3.0';       prerelease=$false; draft=$false },
  [pscustomobject]@{ tag_name='v0.3.0-rc.1';  prerelease=$true;  draft=$false },
  [pscustomobject]@{ tag_name='v0.2.0';       prerelease=$false; draft=$false }
)
Eq "Select-PreReleaseTag skips draft+stable" (Select-PreReleaseTag $rels) 'v0.3.0-rc.1'
$none = @([pscustomobject]@{ tag_name='v1.0.0'; prerelease=$false; draft=$false })
Eq "Select-PreReleaseTag none -> null" (Select-PreReleaseTag $none) $null

# --- Get-NewUserPath: empty, null, trailing ';', already-present, normal append ---
Eq "Get-NewUserPath empty -> Dir"        (Get-NewUserPath ''  'C:\mw') 'C:\mw'
Eq "Get-NewUserPath null -> Dir"         (Get-NewUserPath $null 'C:\mw') 'C:\mw'
Eq "Get-NewUserPath trailing ; no ;;"    (Get-NewUserPath 'C:\a;' 'C:\mw') 'C:\a;C:\mw'
Eq "Get-NewUserPath normal append"       (Get-NewUserPath 'C:\a' 'C:\mw') 'C:\a;C:\mw'
Eq "Get-NewUserPath already present"     (Get-NewUserPath 'C:\a;C:\mw' 'C:\mw') 'C:\a;C:\mw'

# --- Confirm-Checksum: text mode, binary mode, multi-entry literal match ---
$work = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
  $asset = 'middlewhere-v0.2.0-x86_64-pc-windows-msvc.zip'
  $apath = Join-Path $work $asset
  Set-Content -Path $apath -Value 'payload' -NoNewline
  $hash = (Get-FileHash -Algorithm SHA256 $apath).Hash.ToLower()
  # text mode + a decoy whose name is a regex-superset of the real one
  $textSums = Join-Path $work 'SUMS_text'
  Set-Content $textSums -Value @("deadbeef  middlewhereXv0X2X0-x86_64-pc-windows-msvc.zip", "$hash  $asset")
  try { Confirm-Checksum $apath $textSums | Out-Null; Ok "Confirm-Checksum text mode verifies" }
  catch { Bad "Confirm-Checksum text mode verifies" $_ }
  # binary mode ("<hash> *name")
  $binSums = Join-Path $work 'SUMS_bin'
  Set-Content $binSums -Value "$hash *$asset"
  try { Confirm-Checksum $apath $binSums | Out-Null; Ok "Confirm-Checksum binary mode verifies" }
  catch { Bad "Confirm-Checksum binary mode verifies" $_ }
} finally { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }

# --- Install-Binaries: success replaces all, leaves no .old ---
function New-Set($dir, $prefix){ foreach($b in $Binaries){ Set-Content (Join-Path $dir $b) -Value "$prefix-$b" -NoNewline } }
$src = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$dst = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $src,$dst -Force | Out-Null
try {
  New-Set $src 'NEW'; New-Set $dst 'OLD'
  Install-Binaries $src $dst
  Eq "Install-Binaries success new content" (Get-Content (Join-Path $dst 'mwsql.exe') -Raw) 'NEW-mwsql.exe'
  Eq "Install-Binaries success no .old" (@(Get-ChildItem $dst -Filter *.old).Count) 0
} finally { Remove-Item $src,$dst -Recurse -Force -ErrorAction SilentlyContinue }

# --- Install-Binaries: rollback on mid-set failure (3rd source missing) ---
$src2 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$dst2 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $src2,$dst2 -Force | Out-Null
try {
  New-Set $dst2 'OLD'
  # src has only the first two binaries -> Copy-Item of the third throws
  Set-Content (Join-Path $src2 'mwsqld.exe')   -Value 'NEW-mwsqld.exe'   -NoNewline
  Set-Content (Join-Path $src2 'mwsqlctl.exe') -Value 'NEW-mwsqlctl.exe' -NoNewline
  $threw = $false
  try { Install-Binaries $src2 $dst2 } catch { $threw = $true }
  Eq "Install-Binaries rollback throws"            $threw $true
  Eq "Install-Binaries rollback restores mwsqld"   (Get-Content (Join-Path $dst2 'mwsqld.exe') -Raw)   'OLD-mwsqld.exe'
  Eq "Install-Binaries rollback restores mwsqlctl" (Get-Content (Join-Path $dst2 'mwsqlctl.exe') -Raw) 'OLD-mwsqlctl.exe'
  Eq "Install-Binaries rollback restores mwsql"    (Get-Content (Join-Path $dst2 'mwsql.exe') -Raw)    'OLD-mwsql.exe'
  Eq "Install-Binaries rollback no .old"           (@(Get-ChildItem $dst2 -Filter *.old).Count) 0
} finally { Remove-Item $src2,$dst2 -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "`n$($script:pass) passed, $($script:fail) failed"
if ($script:fail -ne 0) { exit 1 }
