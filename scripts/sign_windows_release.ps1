[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$FilePath, [string]$Thumbprint = $env:WEAVEXDR_SIGNING_THUMBPRINT)
$ErrorActionPreference = 'Stop'
if (-not $Thumbprint) { throw 'WEAVEXDR_SIGNING_THUMBPRINT is not configured.' }
$resolved = (Resolve-Path -LiteralPath $FilePath).Path
$certificate = Get-ChildItem -LiteralPath Cert:\CurrentUser\My\$Thumbprint -ErrorAction Stop
$result = Set-AuthenticodeSignature -FilePath $resolved -Certificate $certificate -TimestampServer 'http://timestamp.digicert.com' -HashAlgorithm SHA256
if ($result.Status -ne 'Valid') { throw "Code signing failed: $($result.StatusMessage)" }
$result
