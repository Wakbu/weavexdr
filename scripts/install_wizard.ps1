param([string]$InstallRoot = "$env:ProgramFiles\WeaveXDR")

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Test-SysmonChannel {
    & wevtutil.exe gl "Microsoft-Windows-Sysmon/Operational" 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Test-PendingReboot {
    return (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}

$form = New-Object Windows.Forms.Form
$form.Text = "WeaveXDR 설치 마법사 / Setup Wizard"
$form.Size = New-Object Drawing.Size(560, 350)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$title = New-Object Windows.Forms.Label
$title.Text = "WeaveXDR 설치 준비"
$title.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold)
$title.Location = New-Object Drawing.Point(24, 20)
$title.AutoSize = $true
$form.Controls.Add($title)

$sysmonInstalled = Test-SysmonChannel
$status = New-Object Windows.Forms.Label
$status.Text = if ($sysmonInstalled) { "Sysmon: 감지됨 · 수집 권한은 앱에서 설정할 수 있습니다." } else { "Sysmon: 미설치 · Microsoft Sysinternals 공식 Sysmon을 먼저 설치하세요." }
$status.Location = New-Object Drawing.Point(26, 72)
$status.Size = New-Object Drawing.Size(500, 52)
$form.Controls.Add($status)

$startup = New-Object Windows.Forms.CheckBox
$startup.Text = "Windows 로그인 시 WeaveXDR 시작 (기본 꺼짐)"
$startup.Location = New-Object Drawing.Point(28, 138)
$startup.AutoSize = $true
$startup.Checked = $false
$form.Controls.Add($startup)

$reboot = New-Object Windows.Forms.Label
$reboot.Text = if (Test-PendingReboot) { "현재 Windows에 재부팅 대기 작업이 있습니다." } else { "현재 확인된 재부팅 필요 사항이 없습니다." }
$reboot.Location = New-Object Drawing.Point(28, 176)
$reboot.AutoSize = $true
$form.Controls.Add($reboot)

$install = New-Object Windows.Forms.Button
$install.Text = "설치 시작"
$install.Location = New-Object Drawing.Point(385, 245)
$install.Size = New-Object Drawing.Size(125, 34)
$install.Add_Click({
    # Program Files·서비스 등록이 필요한 실제 설치 단계에서만 UAC를 요청한다.
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\install.ps1`" -InstallRoot `"$InstallRoot`""
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -Wait
    if ($startup.Checked) {
        $executable = Join-Path $InstallRoot 'WeaveXDR.exe'
        New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WeaveXDR' -Value "`"$executable`"" -PropertyType String -Force | Out-Null
    } else {
        # 재설치에서 선택을 해제했을 때 과거 자동 시작 값도 반드시 정리한다.
        Remove-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WeaveXDR' -ErrorAction SilentlyContinue
    }
    [Windows.Forms.MessageBox]::Show("설치가 완료되었습니다. / Installation complete", 'WeaveXDR') | Out-Null
    $form.Close()
})
$form.Controls.Add($install)

$cancel = New-Object Windows.Forms.Button
$cancel.Text = "취소"
$cancel.Location = New-Object Drawing.Point(280, 245)
$cancel.Size = New-Object Drawing.Size(90, 34)
$cancel.Add_Click({ $form.Close() })
$form.Controls.Add($cancel)

[void]$form.ShowDialog()
