#Requires -RunAsAdministrator
param([switch]$DisposableEnvironment)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $DisposableEnvironment) { throw 'Use a disposable Windows VM and pass -DisposableEnvironment. This creates temporary loopback test filters and kills fixture processes.' }
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot
try {
    & "$PSScriptRoot/cargo.ps1" build -p vasp-platform --example wfp-recovery --features wfp-recovery-tests --locked
    if ($LASTEXITCODE -ne 0) { throw 'WFP fixture build failed.' }
    & "$projectRoot/target/debug/examples/wfp-recovery.exe" suite --disposable-vm
    if ($LASTEXITCODE -ne 0) { throw 'Native WFP/watchdog recovery suite failed.' }
    $previousOptIn = $env:VASP_DISPOSABLE_WFP_TEST
    try {
        $env:VASP_DISPOSABLE_WFP_TEST = '1'
        & "$PSScriptRoot/cargo.ps1" test -p vasp-platform --features wfp-recovery-tests --locked expiry_failure_closes_every_filter_and_invalidates_session '--' --ignored
        if ($LASTEXITCODE -ne 0) { throw 'Native expiry-failure test failed.' }
    } finally { $env:VASP_DISPOSABLE_WFP_TEST = $previousOptIn }
} finally { Pop-Location }
