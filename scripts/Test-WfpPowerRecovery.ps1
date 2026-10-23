#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Verify')][string]$Phase,
    [Parameter(Mandatory)][ValidateSet('Reboot','Sleep')][string]$Transition,
    [switch]$DisposableEnvironment
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $DisposableEnvironment) { throw 'Only use this harness inside a disposable Windows VM.' }
$projectRoot = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $projectRoot 'target/debug/examples/wfp-recovery.exe'
$directory = Join-Path $projectRoot "data/wfp-power-$($Transition.ToLowerInvariant())"
$checkpoint = Join-Path $directory 'armed.json'
$metadata = Join-Path $directory 'host.json'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Build the wfp-recovery example with the wfp-recovery-tests feature first.' }
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
if ($Phase -eq 'Prepare') {
    if (Test-Path -LiteralPath $directory) { throw 'A prior power test exists. Preserve its evidence and use a fresh VM snapshot for a new test.' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    $record = [ordered]@{transition=$Transition;boot=$boot;machine=$env:COMPUTERNAME;binary_sha256=$hash;prepared_utc=[DateTime]::UtcNow.ToString('o')}
    $record | ConvertTo-Json | Set-Content -LiteralPath $metadata
    $process = Start-Process -FilePath $exe -ArgumentList @('power-arm','--disposable-vm',('"' + $checkpoint + '"')) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $directory 'stdout.log') -RedirectStandardError (Join-Path $directory 'stderr.log')
    $end = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $checkpoint)) {
        if ($process.HasExited -or [DateTime]::UtcNow -ge $end) { throw 'Power fixture failed to arm; inspect its local logs.' }
        Start-Sleep -Milliseconds 100
    }
    $armed = Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
    if (-not $armed.key -or $armed.armed_at -le 0) { throw 'Invalid power checkpoint.' }
    Write-Output "ARMED: $Transition fixture. Within 60 seconds, manually $Transition this disposable VM. For Sleep, remain asleep at least 10 seconds. Then run this script with -Phase Verify -Transition $Transition -DisposableEnvironment."
    Write-Output 'The script never reboots or suspends your development computer. This is not yet a passed test.'
    exit 0
}
$record = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
$armed = Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
if ($record.transition -ne $Transition -or $record.machine -ne $env:COMPUTERNAME -or $record.binary_sha256 -ne $hash) { throw 'Machine, transition, or fixture binary changed.' }
$armedAt = [DateTimeOffset]::FromUnixTimeSeconds([long]$armed.armed_at).UtcDateTime
if ($Transition -eq 'Reboot') {
    if ($boot -eq $record.boot -or $os.LastBootUpTime.ToUniversalTime() -le $armedAt) { throw 'No reboot after arming was observed.' }
    if (($os.LastBootUpTime.ToUniversalTime() - $armedAt).TotalSeconds -gt 90) { throw 'Reboot was too late to prove an active fixture crossed the transition.' }
    if (Test-Path -LiteralPath "$checkpoint.result") { throw 'Fixture finished before reboot; use a fresh snapshot and repeat.' }
} else {
    if ($boot -ne $record.boot) { throw 'Machine rebooted; this does not validate sleep/resume.' }
    # Actual Windows power events are required; a delayed clock sample is not a physical test.
    $sleep = Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';Id=42;StartTime=$armedAt} -MaxEvents 1 -ErrorAction Stop
    $resume = Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Power-Troubleshooter';Id=1;StartTime=$armedAt} -MaxEvents 1 -ErrorAction Stop
    if ($sleep.TimeCreated -ge $resume.TimeCreated -or ($sleep.TimeCreated.ToUniversalTime() - $armedAt).TotalSeconds -gt 60 -or ($resume.TimeCreated - $sleep.TimeCreated).TotalSeconds -lt 10) { throw 'No qualifying sleep/resume transition; requires entry within 60 seconds and at least ten seconds asleep.' }
    $result = Get-Content -LiteralPath "$checkpoint.result" -Raw | ConvertFrom-Json
    $eventXml = [xml]$resume.ToXml()
    $wakeText = ($eventXml.Event.EventData.Data | Where-Object Name -eq 'WakeTime').'#text'
    if (-not $wakeText) { throw 'Resume event has no actual wake timestamp.' }
    $wakeTime = [DateTimeOffset]::Parse($wakeText)
    if ($result.removed -ne $true -or $result.reason -ne 'heartbeat deadline missed' -or [long]$result.checked_at -lt $wakeTime.ToUnixTimeSeconds()) { throw 'Watchdog did not confirm recovery after resume.' }
}
& $exe absent $armed.key
if ($LASTEXITCODE -ne 0) { throw 'Dynamic WFP filter survived the transition.' }
# A new run must start with the same hard-disabled production gate and healthy WFP cleanup.
& $exe suite --disposable-vm
if ($LASTEXITCODE -ne 0) { throw 'Post-transition native suite failed.' }
[ordered]@{transition=$Transition;passed=$true;checked_utc=[DateTime]::UtcNow.ToString('o');binary_sha256=$hash;boot=$boot} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'verified.json')
Write-Output "PASS: actual $Transition transition, old filter absent, fresh native recovery suite passed. Production blocking remains disabled."
