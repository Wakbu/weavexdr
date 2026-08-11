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
        # 일반 사용자가 API 비밀 값을 직접 만들거나 입력하지 않도록
        # Windows 암호학 RNG로 설치 전용 값을 생성해 머신 환경에 보관한다.
        $bytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [Environment]::SetEnvironmentVariable($secretName, [Convert]::ToBase64String($bytes), "Machine")
    }
}
if ([string]::IsNullOrWhiteSpace($WheelPath)) {
    $WheelPath = (Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.whl" | Select-Object -First 1).FullName
}
if (-not (Test-Path -LiteralPath $WheelPath -PathType Leaf)) { throw "WeaveXDR wheel was not found." }

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$portableExecutable = Join-Path $PSScriptRoot "WeaveXDR.exe"
if (Test-Path -LiteralPath $portableExecutable -PathType Leaf) {
    Copy-Item -LiteralPath $portableExecutable -Destination (Join-Path $InstallRoot "WeaveXDR.exe") -Force
}
$venvPath = Join-Path $InstallRoot "venv"
py -3.11 -m venv $venvPath
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
& $pythonPath -m pip install --upgrade $WheelPath
# 설치만으로 백그라운드 보호가 시작되지 않게 서비스도 수동 시작으로 등록한다.
# 사용자가 앱 또는 서비스 시작을 명시적으로 선택한 경우에만 실행한다.
& $pythonPath -m xdr_graph.windows_service --startup demand install
Write-Host "WeaveXDR installation complete (manual start) / 설치 완료 (수동 시작)"
