from __future__ import annotations

import base64
import json
import os
import subprocess


_DIALOG_SCRIPT = r"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
$paths = @()
$owner = [System.Windows.Forms.Form]::new()
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
$owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$owner.Size = [System.Drawing.Size]::new(1, 1)
$owner.Opacity = 0
$owner.Show()
$owner.Activate()
if ('{kind}' -eq 'files') {{
    $dialog = [System.Windows.Forms.OpenFileDialog]::new()
    try {{
        $dialog.Title = '검사할 파일 선택'
        $dialog.Filter = '모든 파일 (*.*)|*.*'
        $dialog.Multiselect = $true
        $dialog.CheckFileExists = $true
        if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
            $paths = @($dialog.FileNames)
        }}
    }} finally {{
        $dialog.Dispose()
    }}
}} else {{
    $dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
    try {{
        $dialog.Description = '검사할 폴더를 선택하세요.'
        $dialog.ShowNewFolderButton = $false
        if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
            $paths = @($dialog.SelectedPath)
        }}
    }} finally {{
        $dialog.Dispose()
    }}
}}
$owner.Close()
$owner.Dispose()
ConvertTo-Json -InputObject @($paths) -Compress
"""


def select_scan_paths(kind: str) -> list[str]:
    """Windows 기본 선택창을 열고 사용자가 고른 기존 파일/폴더만 반환한다."""

    if kind not in {"files", "folder"}:
        raise ValueError("unknown path dialog kind")
    if os.name != "nt":
        raise RuntimeError("native path selection is only available on Windows")

    encoded_script = base64.b64encode(
        _DIALOG_SCRIPT.format(kind=kind).encode("utf-16-le")
    ).decode("ascii")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-EncodedCommand",
                encoded_script,
            ],
            capture_output=True,
            check=True,
            creationflags=creation_flags,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("Windows path selection failed") from error

    output = completed.stdout.decode("utf-8-sig", errors="strict").strip()
    if not output:
        return []
    try:
        values = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows path selection returned invalid data") from error
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise RuntimeError("Windows path selection returned invalid paths")
    return [value for value in values if value]
