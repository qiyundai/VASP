param([double]$Hours = 72, [int]$SampleSeconds = 60, [string]$DataDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if ($Hours -le 0 -or $Hours -gt 72 -or $SampleSeconds -lt 5) { throw 'Use 0 < Hours <= 72 and SampleSeconds >= 5.' }
if (-not $DataDirectory) { $DataDirectory = Join-Path $projectRoot 'data\soak' }
$executable = Join-Path $projectRoot 'dist\vasp.exe'
if (-not (Test-Path -LiteralPath $executable)) { $executable = Join-Path $projectRoot 'target\debug\vasp.exe' }
New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null
$lockPath = Join-Path $DataDirectory 'soak.lock'
$lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
$stopPath = Join-Path $DataDirectory 'stop.request'
$report = Join-Path $DataDirectory 'soak.csv'
$out = Join-Path $DataDirectory 'watch.stdout.log'
$err = Join-Path $DataDirectory 'watch.stderr.log'
$process = $null
$timer = [System.Diagnostics.Stopwatch]::StartNew()
$cancelled = $false
try {
    $process = Start-Process -FilePath $executable -ArgumentList @('--data',('"' + $DataDirectory + '"'),'watch') -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    [ordered]@{observer_pid=$process.Id;supervisor_pid=$PID;started_utc=[DateTime]::UtcNow.ToString('o');duration_hours=$Hours;executable_sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash;scope='Observe-only observer process metrics; excludes completed worker CPU and does not validate containment'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataDirectory 'soak-run.json')
    while ($timer.Elapsed.TotalHours -lt $Hours) {
        if (Test-Path -LiteralPath $stopPath) { $cancelled = $true; break }
        $process.Refresh()
        if ($process.HasExited) { throw "Observer exited unexpectedly: $($process.ExitCode). See $err" }
        $bytes = (Get-ChildItem -LiteralPath $DataDirectory -File | Measure-Object -Property Length -Sum).Sum
        [pscustomobject]@{utc=[DateTime]::UtcNow.ToString('o');elapsed_seconds=$timer.Elapsed.TotalSeconds;cpu_seconds=$process.TotalProcessorTime.TotalSeconds;working_set_bytes=$process.WorkingSet64;private_bytes=$process.PrivateMemorySize64;storage_bytes=$bytes} | Export-Csv -LiteralPath $report -NoTypeInformation -Append
        Start-Sleep -Seconds $SampleSeconds
    }
} finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) { Stop-Process -Id $process.Id }
    }
    $lock.Dispose()
}
& $executable --data $DataDirectory verify-audit
if ($LASTEXITCODE -ne 0) { throw 'Soak audit verification failed.' }
& $executable --data $DataDirectory status | Set-Content -LiteralPath (Join-Path $DataDirectory 'final-status.json')
if ($LASTEXITCODE -ne 0) { throw 'Soak final status failed.' }
[ordered]@{status=$(if($cancelled){'stopped'}else{'completed'});elapsed_hours=$timer.Elapsed.TotalHours;requested_hours=$Hours;audit_verified=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataDirectory 'soak-result.json')
Write-Output "Soak $(if($cancelled){'stopped early'}else{'completed'}). Measurements: $report. This does not validate privileged containment."
