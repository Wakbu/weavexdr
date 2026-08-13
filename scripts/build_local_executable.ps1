$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
$workRoot = Join-Path $projectRoot "build\pyinstaller"
$temporaryOutput = Join-Path $workRoot "output"
$targetExecutable = Join-Path $projectRoot "WeaveXDR.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw "Project virtual environment was not found." }

# 이전 빌드 산출물이 남아 있으면 PyInstaller 실패를 새 결과로 오인할 수 있다.
# 삭제 범위는 검증된 build/pyinstaller/output 하위로만 제한하고 현재 루트 EXE는 보존한다.
if (Test-Path -LiteralPath $temporaryOutput) {
    Remove-Item -LiteralPath $temporaryOutput -Recurse -Force
}

# Uvicorn과 AnyIO는 실행 중 하위 모듈을 동적 import하므로 전체 패키지를 포함해야 한다.
Push-Location -LiteralPath $projectRoot
try {
    & $pythonPath -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --name WeaveXDR `
        --icon (Join-Path $projectRoot "src\xdr_graph\static\weavexdr.ico") `
        --paths (Join-Path $projectRoot "src") `
        --add-data "$(Join-Path $projectRoot 'config');xdr_graph/config" `
        --add-data "$(Join-Path $projectRoot 'src\xdr_graph\static');xdr_graph/static" `
        --add-data "$(Join-Path $projectRoot 'rules');xdr_graph/rules" `
        --add-data "$(Join-Path $projectRoot 'scripts\configure_sysmon_access.ps1');xdr_graph/tools" `
        --add-data "$(Join-Path $projectRoot 'scripts\apply_update.ps1');xdr_graph/tools" `
        --collect-all langgraph `
        --collect-all charset_normalizer `
        --collect-all uvicorn `
        --collect-all anyio `
        --collect-all yaml `
        --collect-all reportlab `
        --hidden-import win32api `
        --hidden-import win32con `
        --hidden-import win32gui `
        --distpath $temporaryOutput `
        --workpath (Join-Path $workRoot "work") `
        --specpath (Join-Path $workRoot "spec") `
        (Join-Path $PSScriptRoot "weavexdr_launcher.py")
    $pyInstallerExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
if ($pyInstallerExitCode -ne 0) { throw "PyInstaller build failed with exit code $pyInstallerExitCode." }

$builtExecutable = Join-Path $temporaryOutput "WeaveXDR.exe"
if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)) { throw "Executable build did not produce WeaveXDR.exe." }
# 빌드가 끝까지 성공한 뒤에만 기존 실행본을 교체해 실패한 빌드가 현재 버전을 지우지 못하게 한다.
Copy-Item -LiteralPath $builtExecutable -Destination $targetExecutable -Force
$previousSmokeTest = $env:WEAVEXDR_SMOKE_TEST
$previousNoBrowser = $env:WEAVEXDR_NO_BROWSER
$previousApiToken = $env:WEAVEXDR_API_TOKEN
$previousPort = $env:WEAVEXDR_PORT
$env:WEAVEXDR_SMOKE_TEST = "1"
$env:WEAVEXDR_NO_BROWSER = "1"
try {
    # windowed EXE는 직접 호출하면 PowerShell이 종료를 기다리지 않는다.
    # .NET API를 사용하면 프로젝트 경로의 대괄호도 wildcard로 해석되지 않는다.
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $targetExecutable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $smokeProcess = [System.Diagnostics.Process]::Start($startInfo)
    $smokeProcess.WaitForExit()
    if ($smokeProcess.ExitCode -ne 0) {
        throw "Packaged executable smoke test failed with exit code $($smokeProcess.ExitCode)."
    }
}
finally {
    $env:WEAVEXDR_SMOKE_TEST = $previousSmokeTest
    $env:WEAVEXDR_NO_BROWSER = $previousNoBrowser
}

# 스모크 모드는 내부 서버 모듈만 확인하므로, 일반 실행 모드도 별도로 띄워
# 인증 API와 종료 요청이 실제 EXE 프로세스까지 정상적으로 닫는지 검증한다.
$verificationToken = "weavexdr-local-build-verification-token"
$env:WEAVEXDR_API_TOKEN = $verificationToken
$env:WEAVEXDR_NO_BROWSER = "1"
# 현재 사용 중인 8765 인스턴스를 건드리지 않도록 OS에서 빈 loopback 포트를
# 임시 배정받는다. EXE 자체는 환경 변수가 없을 때 계속 8765를 사용한다.
$portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$verificationPort = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()
$env:WEAVEXDR_PORT = [string]$verificationPort
$baseUrl = "http://127.0.0.1:$verificationPort"
$runtimeProcess = $null
$serverProcess = $null
try {
    $runtimeInfo = New-Object System.Diagnostics.ProcessStartInfo
    $runtimeInfo.FileName = $targetExecutable
    $runtimeInfo.UseShellExecute = $false
    $runtimeInfo.CreateNoWindow = $true
    $runtimeProcess = [System.Diagnostics.Process]::Start($runtimeInfo)
    $headers = @{ Authorization = "Bearer $verificationToken" }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/health" -TimeoutSec 2
        }
        catch {
            $health = $null
            Start-Sleep -Milliseconds 200
        }
    } while (-not $health -and [DateTime]::UtcNow -lt $deadline)
    if (-not $health -or $health.StatusCode -ne 200) { throw "Normal-mode executable health check failed." }
    # one-file PyInstaller는 부트로더와 실제 서버 프로세스가 다를 수 있으므로
    # Start() 반환값이 아니라 검증 포트를 소유한 프로세스를 종료 대상으로 삼는다.
    $serverConnection = Get-NetTCPConnection -LocalPort $verificationPort -State Listen -ErrorAction Stop | Select-Object -First 1
    $serverProcess = Get-Process -Id $serverConnection.OwningProcess -ErrorAction Stop
    if ($serverProcess.Path -ne (Get-Item -LiteralPath $targetExecutable).FullName) {
        throw "Verification port is not owned by the packaged WeaveXDR executable."
    }
    $dashboard = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/dashboard" -TimeoutSec 3
    if ($dashboard.StatusCode -ne 200 -or $dashboard.Content -notmatch 'data-nav="overview"') {
        throw "Normal-mode executable dashboard check failed."
    }
    $status = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/status" -Headers $headers -TimeoutSec 3
    if ($status.StatusCode -ne 200) { throw "Authenticated status check failed." }
    # 브라우저는 Bearer 토큰을 계속 보관하지 않고 프로세스 전용 HttpOnly 세션으로
    # 교환하므로 실제 EXE에서도 쿠키 인증 경로를 별도로 확인한다.
    $sessionBody = @{ token = $verificationToken } | ConvertTo-Json
    $sessionResponse = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$baseUrl/session" -ContentType "application/json" -Body $sessionBody -SessionVariable browserSession -TimeoutSec 3
    if ($sessionResponse.StatusCode -ne 200) { throw "Browser session exchange failed." }
    $cookieStatus = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/status" -WebSession $browserSession -TimeoutSec 3
    if ($cookieStatus.StatusCode -ne 200) { throw "Browser cookie authentication failed." }
    # 쿠키 인증 변경 요청은 실제 브라우저와 동일하게 정확한 loopback Origin을 제시해야 한다.
    $shutdown = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$baseUrl/shutdown" -Headers @{ Origin = $baseUrl } -WebSession $browserSession -TimeoutSec 3
    if ($shutdown.StatusCode -ne 200) { throw "Executable shutdown request failed." }
    # 정상 종료 감시 스레드의 최대 20초 정리 시간보다 짧게 잘라 거짓 실패를 만들지 않는다.
    if (-not $serverProcess.WaitForExit(25000)) { throw "Executable did not stop after shutdown request." }
}
finally {
    # 이 스크립트가 시작했고 경로까지 확인한 서버만 실패 정리 대상으로 제한한다.
    if ($serverProcess -and -not $serverProcess.HasExited -and $serverProcess.Path -eq (Get-Item -LiteralPath $targetExecutable).FullName) {
        $serverProcess.Kill()
    }
    $env:WEAVEXDR_API_TOKEN = $previousApiToken
    $env:WEAVEXDR_NO_BROWSER = $previousNoBrowser
    $env:WEAVEXDR_PORT = $previousPort
}
$checksum = (Get-FileHash -LiteralPath $targetExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Local executable replaced / 로컬 실행 파일 교체: $targetExecutable"
Write-Host "SHA-256: $checksum"
