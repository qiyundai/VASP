param([switch]$SkipBuild, [string]$DestinationDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot
try {
    if (-not $SkipBuild) {
        & (Join-Path $PSScriptRoot 'cargo.ps1') build --workspace --release --locked
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    }
    $destination = if ($DestinationDirectory) { [IO.Path]::GetFullPath($DestinationDirectory) } else { Join-Path $projectRoot 'dist' }
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    foreach ($name in @('vasp.exe','vasp-desktop.exe','vasp-broker.exe')) {
        $source = Join-Path $projectRoot "target\release\$name"
        if (-not (Test-Path -LiteralPath $source)) { throw "Missing release binary: $source" }
        $target = Join-Path $destination $name
        if (-not (Test-Path -LiteralPath $target) -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) {
            Copy-Item -LiteralPath $source -Destination $target
        }
    }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md'),(Join-Path $projectRoot 'SECURITY.md') -Destination $destination
    foreach ($folder in @('docs','configs')) {
        $outputFolder = Join-Path $destination $folder
        New-Item -ItemType Directory -Force -Path $outputFolder | Out-Null
        Get-ChildItem -LiteralPath (Join-Path $projectRoot $folder) -File | Copy-Item -Destination $outputFolder
    }
    @'
VASP unsigned observe-only preview

Open vasp-desktop.exe to start. Keep vasp.exe beside it; this is the isolated worker executable.
For an explicit data directory: .\vasp-desktop.exe --data C:\path\to\private-data
The README contains source-checkout build instructions; the source scripts are in the parent repository.
Cloud is disabled by default. Public advisory polling is enabled. Automatic blocking is unavailable.
The window closes to the tray; choose Quit VASP to stop monitoring.
Read SECURITY.md and docs/IMPLEMENTATION.md for limitations and unfinished release gates.
'@ | Set-Content -LiteralPath (Join-Path $destination 'START-HERE.txt') -Encoding utf8
    $artifacts = foreach ($name in @('vasp.exe','vasp-desktop.exe','vasp-broker.exe')) {
        $file = Get-Item -LiteralPath (Join-Path $destination $name)
        [ordered]@{file=$name;size=$file.Length;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    [ordered]@{schema=1;kind='UNSIGNED_OBSERVE_ONLY_PREVIEW';created_utc=[DateTime]::UtcNow.ToString('o');toolchain=(Get-Content rust-toolchain.toml -Raw);lockfile_sha256=(Get-FileHash Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant();artifacts=@($artifacts)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $destination 'preview-checksums.json') -Encoding utf8
    Write-Output "Preview staged in $destination. Checksums are not signatures; this is not an authenticated release."
} finally { Pop-Location }
