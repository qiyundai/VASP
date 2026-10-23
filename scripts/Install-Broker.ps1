#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][Guid]$DeviceId,
    [Parameter(Mandatory)][string]$OperatorSid,
    [switch]$AllowUnsignedPreview
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$source = Join-Path $projectRoot 'dist\vasp-broker.exe'
if (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\broker-ipc\vasp-broker.exe')) { $source = Join-Path $projectRoot 'dist\broker-ipc\vasp-broker.exe' }
if (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\broker-recovery\vasp-broker.exe')) { $source = Join-Path $projectRoot 'dist\broker-recovery\vasp-broker.exe' }
if ($DeviceId -eq [Guid]::Empty) { throw 'Use the endpoint device UUID shown by vasp identity.' }
$sid = [System.Security.Principal.SecurityIdentifier]::new($OperatorSid)
if ($sid.Value -ne $OperatorSid -or $OperatorSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Select one explicit local/domain user SID, not a group or service identity.' }
if (-not (Test-Path -LiteralPath $source)) { throw 'Build and package vasp-broker.exe first.' }
if (-not $AllowUnsignedPreview) { throw 'This development broker is not a signed release. VM testing requires the explicit -AllowUnsignedPreview flag.' }
if (Get-Service -Name VaspBroker -ErrorAction SilentlyContinue) { throw 'VaspBroker already exists. Stop and review the existing installation before replacing it.' }
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'VASP Broker'
$state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VASP\Broker'
$stateParent = Split-Path $state -Parent
foreach ($path in @($install, $stateParent, $state)) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite existing broker directory: $path" }
    $ancestor = Split-Path $path -Parent
    while ($ancestor) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse-point ancestor rejected: $ancestor" }
        $ancestor = Split-Path $ancestor -Parent
    }
}
# Only SYSTEM and Administrators may read/modify service code and broker policy/journal.
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
foreach ($path in @($install, $stateParent, $state)) {
    # Set the ACL at creation, avoiding an initially user-accessible state directory.
    [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $acl)
}
$binary = Join-Path $install 'vasp-broker.exe'
Copy-Item -LiteralPath $source -Destination $binary
$policy = [ordered]@{schema=1;policy=[ordered]@{version=1;device_id=$DeviceId.ToString();enabled=$false;defender_destination=$false;unapproved_listener=$false;protected_addresses=@();protected_applications=@();approved_listeners=@()};callers=@([ordered]@{sid=$OperatorSid;role='operator'})}
$policyFile = Join-Path $state 'policy.json'
$policy | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding utf8NoBOM
foreach ($file in @($binary,$policyFile)) {
    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $file -AclObject $fileAcl
}
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) { throw 'Installed broker checksum mismatch.' }
# Fixed quoted executable and fixed argument. No user-configurable command line runs as SYSTEM.
New-Service -Name VaspBroker -BinaryPathName ('"' + $binary + '" --service') -StartupType Manual -DisplayName 'VASP local security broker' -Description 'Local authenticated VASP broker; automatic blocking disabled.' | Out-Null
# LocalSystem is the SCM default. Installation is manual-start; it does not enable enforcement.
try {
    Start-Service -Name VaspBroker
    (Get-Service -Name VaspBroker).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
} catch {
    # Roll back only the service registered by this invocation; preserve files for diagnosis.
    Stop-Service -Name VaspBroker -ErrorAction SilentlyContinue
    & "$env:SystemRoot\System32\sc.exe" delete VaspBroker | Out-Null
    throw
}
Write-Output "Broker installed and running. State: $state. Automatic blocking remains disabled."
