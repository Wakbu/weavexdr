param(
    [string]$Version = "20260809.1"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $projectRoot "dist"
$stageRoot = Join-Path $distRoot "weavexdr-$Version-windows"
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw "Project virtual environment was not found." }
& (Join-Path $PSScriptRoot "build_local_executable.ps1")
New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
& $pythonPath -m pip wheel $projectRoot --no-deps --wheel-dir $distRoot
if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stageRoot | Out-Null
$wheel = Get-ChildItem -LiteralPath $distRoot -Filter "personal_xdr_graph-*.whl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item -LiteralPath $wheel.FullName -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $projectRoot "WeaveXDR.exe") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install.ps1") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall.ps1") -Destination $stageRoot
$manifest = @{ version = $Version; format = "weavexdr-windows-package-v1" } | ConvertTo-Json
Set-Content -LiteralPath (Join-Path $stageRoot "weavexdr-release.json") -Value $manifest -Encoding utf8
$archivePath = Join-Path $distRoot "weavexdr-$Version-windows.zip"
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
# Compress-Archive는 대괄호와 비 ASCII 문자가 함께 있는 경로를 wildcard로
# 잘못 해석할 수 있어, 리터럴 디렉터리를 받는 .NET ZIP API를 사용한다.
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $stageRoot,
    $archivePath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)
Write-Host $archivePath
