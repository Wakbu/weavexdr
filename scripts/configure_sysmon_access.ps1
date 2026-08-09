param(
    [switch]$Restore,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$logName = "Microsoft-Windows-Sysmon/Operational"
$backupRoot = Join-Path $env:ProgramData "WeaveXDR"
$backupPath = Join-Path $backupRoot "sysmon-channel-access.backup.txt"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Restore) {
    if (-not $isAdministrator) {
        throw "관리자 PowerShell에서 실행해야 합니다. Run this script from an elevated PowerShell."
    }
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        throw "백업된 Sysmon 채널 권한을 찾을 수 없습니다: $backupPath"
    }
    $savedAccess = (Get-Content -LiteralPath $backupPath -Raw).Trim()
    & wevtutil.exe sl $logName "/ca:$savedAccess"
    if ($LASTEXITCODE -ne 0) { throw "Sysmon 채널 권한 복원에 실패했습니다." }
    Write-Host "Sysmon 채널 권한 복원 완료 / Channel access restored"
    exit 0
}

# UAC에 사용한 관리자 계정이 아니라 현재 데스크톱에 로그인한 실제 사용자를
# 대상으로 읽기 권한을 부여한다. 다른 사용자로 설치할 때는 그 계정으로 로그인해 실행한다.
$interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
if ([string]::IsNullOrWhiteSpace($interactiveUser)) {
    throw "현재 로그인한 Windows 사용자를 확인할 수 없습니다."
}
$account = New-Object Security.Principal.NTAccount($interactiveUser)
$userSid = $account.Translate([Security.Principal.SecurityIdentifier]).Value

[xml]$channelConfig = (& wevtutil.exe gl $logName /f:xml | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Sysmon 로그 채널을 찾을 수 없습니다." }
# wevtutil의 XML에서 channelAccess는 별도 요소가 아니라 channel 요소의 속성이다.
# local-name()을 사용해 Windows 버전에 따라 기본 XML namespace가 있어도 동일하게 읽는다.
$accessNode = $channelConfig.SelectSingleNode("/*[local-name()='channel']/@channelAccess")
$accessValue = if ($null -ne $accessNode) { [string]$accessNode.Value } else { "" }
# PowerShell 5의 XML 어댑터에서는 XmlAttribute.InnerText가 비어 있어도 Value에는
# 실제 SDDL이 들어 있다. 속성 값은 반드시 Value로 읽어 버전별 동작 차이를 피한다.
if ([string]::IsNullOrWhiteSpace($accessValue)) {
    throw "Sysmon 채널의 기존 보안 설명자를 읽을 수 없습니다."
}
$currentAccess = $accessValue.Trim()
$readAce = "(A;;0x1;;;$userSid)"
$alreadyConfigured = $currentAccess.Contains($readAce)

if ($CheckOnly) {
    # 채널 ACL을 바꾸지 않고 관리자 권한, 사용자 SID와 기존 설정을 점검한다.
    Write-Host "Sysmon 채널 확인 완료 / Channel check completed"
    Write-Host "대상 사용자 / Target user: $interactiveUser"
    Write-Host "관리자 실행 여부 / Elevated: $isAdministrator"
    Write-Host "읽기 권한 설정 여부 / Read access configured: $alreadyConfigured"
    exit 0
}
if (-not $isAdministrator) {
    throw "관리자 PowerShell에서 실행해야 합니다. Run this script from an elevated PowerShell."
}
if ($alreadyConfigured) {
    Write-Host "이미 Sysmon 읽기 권한이 있습니다 / Read access already configured"
    exit 0
}

New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $backupPath)) {
    Set-Content -LiteralPath $backupPath -Value $currentAccess -Encoding UTF8
}
$updatedAccess = "$currentAccess$readAce"
& wevtutil.exe sl $logName "/ca:$updatedAccess"
if ($LASTEXITCODE -ne 0) { throw "Sysmon 채널 읽기 권한 설정에 실패했습니다." }

Write-Host "Sysmon 읽기 권한 설정 완료: $interactiveUser"
Write-Host "WeaveXDR를 완전히 종료한 뒤 다시 실행하세요."
Write-Host "복원: .\configure_sysmon_access.ps1 -Restore"
