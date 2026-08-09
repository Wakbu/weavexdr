param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'
$eventIds = @(1, 3, 11)

if ($Cleanup) {
    # 이 스크립트가 생성하는 고정 파일명만 삭제한다. 폴더 전체 재귀 삭제를
    # 사용하지 않아 호출자가 잘못된 경로를 전달해도 다른 파일은 건드리지 않는다.
    foreach ($eventId in $eventIds) {
        $sampleFile = Join-Path $OutputDirectory "event-$eventId.xml"
        if (Test-Path -LiteralPath $sampleFile) {
            Remove-Item -LiteralPath $sampleFile -Force
        }
    }
    return
}

# 실제 이벤트 XML에는 사용자명, 명령줄과 파일 경로가 포함될 수 있다.
# 지정된 로컬 진단 폴더에 이벤트 유형별 최신 1건만 임시 저장하고,
# 호환성 확인 후 호출 측에서 즉시 삭제하는 용도로만 사용한다.
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

foreach ($eventId in $eventIds) {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = $logName
        Id = $eventId
    } -MaxEvents 1

    if ($null -eq $event) {
        throw "No Sysmon Event ID $eventId was found"
    }

    $outputFile = Join-Path $OutputDirectory "event-$eventId.xml"
    [System.IO.File]::WriteAllText($outputFile, $event.ToXml(), $utf8WithoutBom)
}
