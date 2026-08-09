$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
$workRoot = Join-Path $projectRoot "build\pyinstaller"
$temporaryOutput = Join-Path $workRoot "output"
$targetExecutable = Join-Path $projectRoot "WeaveXDR.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw "Project virtual environment was not found." }

& $pythonPath -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name WeaveXDR `
    --paths (Join-Path $projectRoot "src") `
    --add-data "$(Join-Path $projectRoot 'config');xdr_graph/config" `
    --add-data "$(Join-Path $projectRoot 'src\xdr_graph\static');xdr_graph/static" `
    --collect-all langgraph `
    --collect-all charset_normalizer `
    --distpath $temporaryOutput `
    --workpath (Join-Path $workRoot "work") `
    --specpath (Join-Path $workRoot "spec") `
    (Join-Path $PSScriptRoot "weavexdr_launcher.py")

$builtExecutable = Join-Path $temporaryOutput "WeaveXDR.exe"
if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)) { throw "Executable build did not produce WeaveXDR.exe." }
# 빌드가 끝까지 성공한 뒤에만 기존 실행본을 교체해 실패한 빌드가 현재 버전을 지우지 못하게 한다.
Copy-Item -LiteralPath $builtExecutable -Destination $targetExecutable -Force
$checksum = (Get-FileHash -LiteralPath $targetExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Local executable replaced / 로컬 실행 파일 교체: $targetExecutable"
Write-Host "SHA-256: $checksum"
