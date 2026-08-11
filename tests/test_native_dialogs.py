import base64

from xdr_graph import native_dialogs


class CompletedDialog:
    stdout = '["C:\\\\검사\\\\sample.exe","D:\\\\자료"]'.encode("utf-8")


def test_windows_file_dialog_returns_utf8_paths_without_console(monkeypatch):
    captured = {}

    def fake_run(command, **options):
        captured["command"] = command
        captured["options"] = options
        return CompletedDialog()

    monkeypatch.setattr(native_dialogs.os, "name", "nt")
    monkeypatch.setattr(native_dialogs.subprocess, "run", fake_run)
    monkeypatch.setattr(native_dialogs.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    assert native_dialogs.select_scan_paths("files") == ["C:\\검사\\sample.exe", "D:\\자료"]
    assert captured["command"][:5] == [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-STA"
    ]
    script = base64.b64decode(captured["command"][-1]).decode("utf-16-le")
    assert "OpenFileDialog" in script
    assert "Multiselect = $true" in script
    assert "TopMost = $true" in script
    assert "ShowDialog($owner)" in script
    assert captured["options"]["creationflags"] == 0x08000000
    assert captured["options"]["timeout"] == 600


def test_path_dialog_rejects_unknown_kind_before_launch():
    try:
        native_dialogs.select_scan_paths("drive")
    except ValueError as error:
        assert "unknown path dialog kind" in str(error)
    else:
        raise AssertionError("unknown dialog kind was accepted")
