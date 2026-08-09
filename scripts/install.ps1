param(
    [string]$InstallRoot = "$env:ProgramFiles\WeaveXDR",
    [string]$WheelPath = ""
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "관리자 PowerShell에서 설치해야 합니다. Run this installer from an elevated PowerShell."
}
foreach ($secretName in @("WEAVEXDR_API_TOKEN", "WEAVEXDR_PRIVACY_SALT")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, "Machine"))) {
        throw "$secretName must be configured as a machine environment variable before installation."
    }
}
if ([string]::IsNullOrWhiteSpace($WheelPath)) {
    $WheelPath = (Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.whl" | Select-Object -First 1).FullName
}
if (-not (Test-Path -LiteralPath $WheelPath -PathType Leaf)) { throw "WeaveXDR wheel was not found." }

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$venvPath = Join-Path $InstallRoot "venv"
py -3.11 -m venv $venvPath
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
& $pythonPath -m pip install --upgrade $WheelPath
& $pythonPath -m xdr_graph.windows_service --startup auto install
& $pythonPath -m xdr_graph.windows_service start
Write-Host "WeaveXDR installation complete / 설치 완료"
