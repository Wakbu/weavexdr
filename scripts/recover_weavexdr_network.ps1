[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

$ErrorActionPreference = 'Stop'
$rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object DisplayName -Like 'WeaveXDR-*'
if (-not $rules) {
    Write-Output 'No WeaveXDR firewall rules were found.'
    exit 0
}

# 제품이 만든 규칙만 제거한다. 사용자의 기존 방화벽 설정이나 네트워크 어댑터는
# 건드리지 않아 오프라인 복구가 또 다른 연결 장애를 만들지 않게 한다.
foreach ($rule in $rules) {
    if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove WeaveXDR firewall block')) {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
    }
}
Write-Output ("Removed {0} WeaveXDR firewall rule(s)." -f $rules.Count)
