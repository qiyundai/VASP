#Requires -RunAsAdministrator
param()
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$projectRoot = Split-Path $PSScriptRoot -Parent
$cli = Join-Path $projectRoot 'dist\broker-ipc\vasp.exe'
if (-not (Test-Path -LiteralPath $cli)) { $cli = Join-Path $projectRoot 'dist\vasp.exe' }
$data = Join-Path $projectRoot 'data\broker-service-test'
if (Get-Service VaspBroker -ErrorAction SilentlyContinue) { throw 'Use a disposable VM with no existing VaspBroker installation.' }
& $cli --data $data init
if ($LASTEXITCODE -ne 0) { throw 'Endpoint initialization failed.' }
$endpoint = & $cli --data $data status | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Endpoint status failed.' }
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$installed = $false
try {
    & (Join-Path $PSScriptRoot 'Install-Broker.ps1') -DeviceId $endpoint.device_id -OperatorSid $userSid -AllowUnsignedPreview
    $installed = $true
    foreach ($op in @('status','inventory','stop','remove-blocks')) {
        $r = & $cli --data $data broker $op | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $r.accepted -or $r.automatic_blocking -or $r.active_blocks -ne 0) { throw "Unsafe or failed broker response: $op" }
    }
    Restart-Service VaspBroker
    $r = & $cli --data $data broker status | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $r.accepted -or $r.automatic_blocking) { throw 'Service restart failed closed-state verification.' }
    Stop-Service VaspBroker
    & $cli --data $data broker status 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Client accepted an unavailable broker.' }
    Write-Output 'SCM identity, typed operations, stop/restart, and no-blocking checks passed. WFP recovery is still untested.'
} finally {
    if ($installed) {
        Stop-Service VaspBroker -ErrorAction SilentlyContinue
        & "$env:SystemRoot\System32\sc.exe" delete VaspBroker | Out-Null
        # Keep protected journal/binaries for diagnostics. No recursive deletion.
    }
}
