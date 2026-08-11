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
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install_wizard.ps1") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall.ps1") -Destination $stageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "configure_sysmon_access.ps1") -Destination $stageRoot
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

# dist는 로컬 전달·검증용 공간이므로 최신 세 버전만 유지한다. GitHub 릴리스는
# 별도 보존되며, wheel처럼 버전 폴더 규칙과 무관한 파일은 삭제하지 않는다.
$releaseEntries = Get-ChildItem -LiteralPath $distRoot | ForEach-Object {
    if ($_.Name -match '^weavexdr-(\d{8})\.(\d+)-windows(?:\.zip)?$') {
        [pscustomobject]@{
            Entry = $_
            Date = [int64]$Matches[1]
            Patch = [int]$Matches[2]
            Version = "$($Matches[1]).$($Matches[2])"
        }
    }
}
$expiredVersions = $releaseEntries |
    Sort-Object Date, Patch -Descending |
    Group-Object Version |
    ForEach-Object { $_.Group[0] } |
    Select-Object -Skip 3
foreach ($expiredVersion in $expiredVersions) {
    $releaseEntries | Where-Object Version -eq $expiredVersion.Version | ForEach-Object {
        $target = $_.Entry
        # 재귀 삭제 전에 대상의 절대 부모와 이름을 다시 검사해 dist 밖의 경로가
        # 계산 오류로 삭제되는 일을 막는다.
        $targetParent = if ($target -is [System.IO.DirectoryInfo]) { $target.Parent.FullName } else { $target.DirectoryName }
        if ($targetParent -ne $distRoot -or $target.Name -notmatch '^weavexdr-\d{8}\.\d+-windows(?:\.zip)?$') {
            throw "Unsafe release cleanup target: $($target.FullName)"
        }
        Remove-Item -LiteralPath $target.FullName -Recurse -Force
        Write-Host "Removed expired local release: $($target.Name)"
    }
}
Write-Host $archivePath
