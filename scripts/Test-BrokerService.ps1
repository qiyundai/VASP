#Requires -RunAsAdministrator
param([switch]$DisposableEnvironment)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $DisposableEnvironment) { throw 'This suite kills its broker and corrupts its test state. Use a disposable VM and pass -DisposableEnvironment.' }
$projectRoot = Split-Path $PSScriptRoot -Parent
$cli = Join-Path $projectRoot 'dist\broker-ipc\vasp.exe'
if (-not (Test-Path -LiteralPath $cli)) { $cli = Join-Path $projectRoot 'dist\vasp.exe' }
$data = Join-Path $projectRoot 'data\broker-service-test'
$state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VASP\Broker'
$policyFile = Join-Path $state 'policy.json'
$expectedBinary = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'VASP Broker\vasp-broker.exe'
if (Get-Service VaspBroker -ErrorAction SilentlyContinue) { throw 'Use a disposable VM with no existing VaspBroker installation.' }
if (Test-Path -LiteralPath (Split-Path $state -Parent)) { throw 'Use a disposable VM with no existing VASP service state.' }
& $cli --data $data init
if ($LASTEXITCODE -ne 0) { throw 'Endpoint initialization failed.' }
$endpoint = & $cli --data $data status | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Endpoint status failed.' }
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$results = [Collections.Generic.List[object]]::new()
$installed = $false
$policyBackup = $null
$policyAcl = $null

function Passed([string]$name) {
    $results.Add([ordered]@{name=$name;passed=$true})
    Write-Output "PASS: $name"
}
function Assert-Receipt($receipt, [bool]$accepted) {
    if ($null -eq $receipt -or $receipt.schema -ne 1 -or $receipt.accepted -ne $accepted -or
        $receipt.automatic_blocking -ne $false -or $receipt.active_blocks -ne 0 -or
        $receipt.device_id -ne $endpoint.device_id) { throw 'Unexpected or unsafe broker receipt.' }
}
function Assert-Healthy {
    $r = & $cli --data $data broker status | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Authenticated production client failed.' }
    Assert-Receipt $r $true
}
function Start-TestBroker {
    Start-Service VaspBroker
    (Get-Service VaspBroker).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    Assert-Healthy
}
function Stop-TestBroker {
    $service = Get-Service VaspBroker
    $service.Stop()
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
}
function Assert-StartupDenied {
    $started = $false
    try {
        Start-Service VaspBroker -ErrorAction Stop
        (Get-Service VaspBroker).WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
        $started = $true
    } catch { }
    if ($started -or (Get-Service VaspBroker).Status -eq 'Running') { throw 'Invalid state was accepted by the service.' }
    & $cli --data $data broker status 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Client accepted a failed broker.' }
}
function Open-TestPipe {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'VASP.Broker.v1', [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
    try { $pipe.Connect(3000); return $pipe } catch { $pipe.Dispose(); throw }
}
function Write-Bytes($pipe, [byte[]]$bytes) {
    $task = $pipe.WriteAsync($bytes, 0, $bytes.Length)
    if (-not $task.Wait(6500)) { $pipe.Dispose(); throw 'Write timed out.' }
}
function Read-Bytes($pipe, [int]$count) {
    $bytes = [byte[]]::new($count)
    $offset = 0
    while ($offset -lt $count) {
        $task = $pipe.ReadAsync($bytes, $offset, $count - $offset)
        if (-not $task.Wait(6500)) { $pipe.Dispose(); throw 'Read timed out.' }
        $read = $task.GetAwaiter().GetResult()
        if ($read -eq 0) { throw 'Pipe closed.' }
        $offset += $read
    }
    return ,$bytes
}
function Write-Frame($pipe, [string]$text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $header = [BitConverter]::GetBytes([uint32]$bytes.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($header) }
    Write-Bytes $pipe ($header + $bytes)
}
function Read-Frame($pipe) {
    $header = Read-Bytes $pipe 4
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($header) }
    $size = [BitConverter]::ToUInt32($header, 0)
    if ($size -eq 0 -or $size -gt 16384) { throw 'Invalid response size.' }
    return [Text.Encoding]::UTF8.GetString((Read-Bytes $pipe $size)) | ConvertFrom-Json
}
function Invoke-Wire([hashtable]$command, [hashtable]$overrides = @{}) {
    # Test fixture only: production authentication is exercised separately via the CLI.
    $pipe = Open-TestPipe
    try {
        Write-Frame $pipe 'VASP1'
        $hello = Read-Frame $pipe
        $request = @{schema=1;session=$hello.session;id=[Guid]::NewGuid().ToString();device_id=$endpoint.device_id;
            policy_version=$hello.policy_version;issued_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();command=$command}
        foreach ($key in $overrides.Keys) { $request[$key] = $overrides[$key] }
        Write-Frame $pipe ($request | ConvertTo-Json -Depth 12 -Compress)
        return Read-Frame $pipe
    } finally { $pipe.Dispose() }
}
try {
    & (Join-Path $PSScriptRoot 'Install-Broker.ps1') -DeviceId $endpoint.device_id -OperatorSid $userSid -AllowUnsignedPreview
    $installed = $true
    $policyBackup = [IO.File]::ReadAllBytes($policyFile)
    $policyAcl = Get-Acl -LiteralPath $policyFile
    foreach ($op in @('status','inventory','stop','remove-blocks')) {
        $r = & $cli --data $data broker $op | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw "Production client failed: $op" }
        Assert-Receipt $r $true
    }
    Passed 'SCM-authenticated production client and typed operations'
    foreach ($overrides in @(@{device_id=[Guid]::NewGuid().ToString()}, @{session=[Guid]::NewGuid().ToString()},
        @{policy_version=999}, @{issued_at=1})) {
        Assert-Receipt (Invoke-Wire @{operation='status'} $overrides) $false
    }
    Passed 'Cross-device, session, policy and stale-request rejection'
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $proposal = @{schema=1;id=[Guid]::NewGuid().ToString();device_id=$endpoint.device_id;rule='defender_destination';policy_version=1;
        target=@{kind='destination';application='C:\VASP-Test\fixture.exe';address='203.0.113.1';port=443};
        evidence_ids=@([Guid]::NewGuid().ToString());created_at=$now;expires_at=$now+60}
    Assert-Receipt (Invoke-Wire @{operation='propose_block';proposal=$proposal}) $false
    Passed 'Fabricated evidence cannot activate a block'
    $replayId = [Guid]::NewGuid().ToString()
    Assert-Receipt (Invoke-Wire @{operation='status'} @{id=$replayId}) $true
    Stop-TestBroker
    Start-TestBroker
    Assert-Receipt (Invoke-Wire @{operation='status'} @{id=$replayId}) $false
    Passed 'Replay rejected across clean service restart'
    # Kill only the verified PID of this suite's installed broker, never a name wildcard.
    $service = Get-CimInstance Win32_Service -Filter "Name='VaspBroker'"
    $brokerProcess = Get-Process -Id $service.ProcessId
    if ($brokerProcess.Path -ne $expectedBinary) { throw 'Refusing to terminate an unexpected process.' }
    Stop-Process -Id $brokerProcess.Id -Force
    (Get-Service VaspBroker).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
    Start-TestBroker
    Assert-Receipt (Invoke-Wire @{operation='status'} @{id=$replayId}) $false
    Passed 'Forced broker termination, journal recovery and durable replay rejection'
    $silent = Open-TestPipe
    try {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Stop-TestBroker
        if ($timer.Elapsed.TotalSeconds -gt 9) { throw 'Stalled client prevented bounded service stop.' }
    } finally { $silent.Dispose() }
    Start-TestBroker
    Passed 'Stalled client cannot prevent bounded stop and restart'
    $rejected = $false
    try { Invoke-Wire @{operation='status';arbitrary_command='whoami'} | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unknown command fields accepted.' }
    Start-Sleep -Milliseconds 100
    Assert-Healthy
    Passed 'Malformed command rejected without losing service availability'
    Stop-TestBroker
    $policy = [Text.Encoding]::UTF8.GetString($policyBackup) | ConvertFrom-Json
    $policy.policy.enabled = $true
    [IO.File]::WriteAllText($policyFile, ($policy | ConvertTo-Json -Depth 8))
    Assert-StartupDenied
    [IO.File]::WriteAllBytes($policyFile, $policyBackup)
    Start-TestBroker
    Passed 'Enabled policy rejected at startup and valid policy recovers'
    Stop-TestBroker
    $loose = [Security.AccessControl.FileSecurity]::new()
    $loose.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
    Set-Acl -LiteralPath $policyFile -AclObject $loose
    Assert-StartupDenied
    Set-Acl -LiteralPath $policyFile -AclObject $policyAcl
    Start-TestBroker
    Passed 'Over-permissive policy ACL rejected and repaired state recovers'
    Stop-TestBroker
    $policy = [Text.Encoding]::UTF8.GetString($policyBackup) | ConvertFrom-Json
    $policy.callers[0].role = 'observer'
    [IO.File]::WriteAllText($policyFile, ($policy | ConvertTo-Json -Depth 8))
    Start-TestBroker
    Assert-Receipt (Invoke-Wire @{operation='stop_automatic_actions'}) $false
    Assert-Receipt (Invoke-Wire @{operation='remove_temporary_blocks'}) $false
    Passed 'Observer identity cannot use operator commands'
    Stop-TestBroker
    [IO.File]::WriteAllBytes($policyFile, $policyBackup)
    $journalFile = Join-Path $state 'broker.db'
    $journalBackup = [IO.File]::ReadAllBytes($journalFile)
    try {
        [IO.File]::WriteAllBytes($journalFile, [Text.Encoding]::UTF8.GetBytes('invalid sqlite fixture'))
        Assert-StartupDenied
    } finally { [IO.File]::WriteAllBytes($journalFile, $journalBackup) }
    Start-TestBroker
    Passed 'Corrupt journal prevents startup; restored journal recovers disabled'
    Stop-TestBroker
    & $cli --data $data broker status 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'Client accepted an unavailable broker.' }
    Passed 'Unavailable service has no client fallback'
} finally {
    if ($installed) {
        Stop-Service VaspBroker -ErrorAction SilentlyContinue
        if ($policyBackup) { [IO.File]::WriteAllBytes($policyFile, $policyBackup) }
        if ($policyAcl) { Set-Acl -LiteralPath $policyFile -AclObject $policyAcl }
        & "$env:SystemRoot\System32\sc.exe" delete VaspBroker | Out-Null
        # Preserve protected files for diagnostics; no recursive deletion.
    }
    [ordered]@{schema=1;automatic_blocking=$false;tests=@($results.ToArray());
        untested=@('WFP filters','hung broker process','reboot','sleep/resume','standard-user client','remote SMB');
        source_commit=(git -C $projectRoot rev-parse HEAD)} | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $data 'service-test-results.json') -Encoding utf8NoBOM
}
