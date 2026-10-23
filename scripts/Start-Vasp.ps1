param([string]$DataDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $DataDirectory) { $DataDirectory = Join-Path $projectRoot 'data\local' }
$executable = Join-Path $projectRoot 'dist\vasp-desktop.exe'
if (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\broker-ipc\vasp-desktop.exe')) { $executable = Join-Path $projectRoot 'dist\broker-ipc\vasp-desktop.exe' }
if (-not (Test-Path -LiteralPath $executable)) { $executable = Join-Path $projectRoot 'target\debug\vasp-desktop.exe' }
if (-not (Test-Path -LiteralPath $executable)) { throw 'Build VASP first with scripts\cargo.ps1 build --workspace --locked.' }
Start-Process -FilePath $executable -ArgumentList @('--data',('"' + $DataDirectory + '"')) -WorkingDirectory $projectRoot -WindowStyle Hidden
