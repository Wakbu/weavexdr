[CmdletBinding()]
param([string]$FilePath)
$ErrorActionPreference = 'Stop'
if (-not $FilePath) { $FilePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'WeaveXDR.exe' }
$resolved = (Resolve-Path -LiteralPath $FilePath).Path
$signature = Get-AuthenticodeSignature -LiteralPath $resolved
$hasTimestamp = $null -ne $signature.TimeStamperCertificate
$passed = $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and $hasTimestamp
[pscustomobject]@{
    file = $resolved
    status = [string]$signature.Status
    signer_present = $null -ne $signature.SignerCertificate
    timestamp_present = $hasTimestamp
    trust_validation = if ($passed) { 'passed' } else { 'incomplete' }
    smartscreen_reputation = 'manual-external-validation-required'
} | ConvertTo-Json
if (-not $passed) { exit 2 }
