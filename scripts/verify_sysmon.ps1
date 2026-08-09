param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'

# Sysmon 로그는 일반 사용자에게 읽기 권한이 없을 수 있으므로 이 스크립트는
# 관리자 PowerShell에서 실행한다. 결과에는 이벤트 본문이나 명령줄을 넣지 않고
# 동작 확인에 필요한 시각, ID와 공급자만 저장해 민감 정보 노출을 줄인다.
$logDetails = Get-WinEvent -ListLog $logName
$recentTelemetry = Get-WinEvent -FilterHashtable @{
    LogName = $logName
    # 현재 최소 설정이 사용하는 프로세스, 네트워크와 파일 생성 이벤트다.
    Id = @(1, 3, 11)
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 20

$verification = [ordered]@{
    log_name = $logDetails.LogName
    enabled = $logDetails.IsEnabled
    record_count = $logDetails.RecordCount
    observed_event_ids = @($recentTelemetry.Id | Sort-Object -Unique)
    recent_events = @(
        $recentTelemetry | ForEach-Object {
            [ordered]@{
                time_created = $_.TimeCreated.ToString('o')
                event_id = $_.Id
                provider = $_.ProviderName
            }
        }
    )
}

# UAC로 실행된 별도 프로세스의 결과를 호출 측에서 읽을 수 있도록 지정된
# 진단 파일에 UTF-8 JSON을 기록한다. 경로는 호출자가 명시적으로 전달한다.
$verification | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
