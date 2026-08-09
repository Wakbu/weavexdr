param(
    [string]$InstallRoot = "$env:ProgramFiles\WeaveXDR",
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$pythonPath = Join-Path $InstallRoot "venv\Scripts\python.exe"
if (Test-Path -LiteralPath $pythonPath -PathType Leaf) {
    & $pythonPath -m xdr_graph.windows_service stop
    & $pythonPath -m xdr_graph.windows_service remove
}
if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
if ($RemoveData) {
    $dataRoot = Join-Path $env:ProgramData "WeaveXDR"
    if (Test-Path -LiteralPath $dataRoot) { Remove-Item -LiteralPath $dataRoot -Recurse -Force }
}
Write-Host "WeaveXDR uninstall complete / 제거 완료"
