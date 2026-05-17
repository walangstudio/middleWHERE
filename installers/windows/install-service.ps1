# Run elevated (Administrator). Installs the mwsqld Windows service.
$ErrorActionPreference = 'Stop'

$svc   = 'mwsqld'
$exe   = 'C:\Program Files\middlewhere\mwsqld.exe'
$state = 'C:\ProgramData\middlewhere'
$acct  = "NT SERVICE\$svc"

New-Item -ItemType Directory -Force -Path $state | Out-Null

# Create the service bound to a virtual service account.
sc.exe create $svc binPath= "`"$exe`" service --state-dir `"$state`" --file-keystore" obj= $acct start= auto
sc.exe description $svc "middleWHERE secure SQL gateway daemon"
sc.exe failure $svc reset= 86400 actions= restart/5000/restart/5000/restart/5000

# Lock the state dir: only the service account and Administrators. The
# AI/client user is a different principal and is denied by omission.
icacls $state /inheritance:r | Out-Null
icacls $state /grant:r "${acct}:(OI)(CI)F" | Out-Null
icacls $state /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

Write-Host "Installed. Start with:  sc.exe start $svc"
Write-Host "First run 'mwsqlctl --state-dir `"$state`" --file-keystore init' AS the service"
Write-Host "account context, or pre-seed the sealed config, before starting."
