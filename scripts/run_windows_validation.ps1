param(
    [ValidateSet('baseline','sleep-resume','user-switch','network-change','install-update-remove')]
    [string]$Scenario = 'baseline',
    [int]$DurationSeconds = 60,
    [int]$ProcessId = $PID,
    [string]$OutputRoot = 'artifacts/windows-validation'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Project virtual environment was not found.' }
$resolvedOutput = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputRoot))
if (-not $resolvedOutput.StartsWith(($projectRoot.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) { throw 'OutputRoot must stay inside the project.' }
New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$output = Join-Path $resolvedOutput "$Scenario-$stamp.json"
& $python (Join-Path $PSScriptRoot 'run_operational_matrix.py') --scenario $Scenario --duration-seconds $DurationSeconds --sample-seconds 1 --pid $ProcessId --output $output
if ($LASTEXITCODE -ne 0) { throw "Windows validation failed for $Scenario." }
Write-Host "Windows validation evidence: $output"
