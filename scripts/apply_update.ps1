[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][int]$CurrentPid,
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$InstallRoot
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$install = (Resolve-Path -LiteralPath $InstallRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $install 'weavexdr-release.json') -PathType Leaf)) { throw 'Refusing to update an unmarked directory.' }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Update archive checksum mismatch.' }
$staging = Join-Path ([IO.Path]::GetTempPath()) ("weavexdr-update-" + [guid]::NewGuid().ToString('N'))
$currentManifest = Get-Content -LiteralPath (Join-Path $install 'weavexdr-release.json') -Raw | ConvertFrom-Json
$currentVersion = [string]$currentManifest.version
if ($currentVersion -notmatch '^\d{8}\.\d+$') { throw 'Installed release version is invalid.' }
$backup = Join-Path $install ('.update-rollback-' + $currentVersion)
try {
    $process = Get-Process -Id $CurrentPid -ErrorAction SilentlyContinue
    if ($process) { $process.WaitForExit(30000) }
    New-Item -ItemType Directory -Path $staging | Out-Null
    $package = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        foreach ($entry in $package.Entries) {
            $destination = [IO.Path]::GetFullPath((Join-Path $staging $entry.FullName))
            if (-not $destination.StartsWith($staging + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Update archive contains an unsafe path.' }
        }
    } finally { $package.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $staging)
    if (-not (Test-Path -LiteralPath (Join-Path $staging 'weavexdr-release.json'))) { throw 'Update manifest is missing.' }
    if (Test-Path -LiteralPath $backup) { throw 'A previous rollback backup still exists.' }
    New-Item -ItemType Directory -Path $backup | Out-Null
    foreach ($name in @('WeaveXDR.exe','weavexdr-release.json')) { $old=Join-Path $install $name; if(Test-Path -LiteralPath $old){Copy-Item -LiteralPath $old -Destination $backup} }
    foreach ($name in @('WeaveXDR.exe','weavexdr-release.json','install.ps1','install_wizard.ps1','uninstall.ps1','apply_update.ps1','recover_weavexdr_network.ps1')) { $new=Join-Path $staging $name; if(Test-Path -LiteralPath $new){Copy-Item -LiteralPath $new -Destination (Join-Path $install $name) -Force} }
    Start-Process -FilePath (Join-Path $install 'WeaveXDR.exe') -WindowStyle Hidden
} catch {
    if (Test-Path -LiteralPath $backup) { Get-ChildItem -LiteralPath $backup -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $install $_.Name) -Force } }
    throw
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
