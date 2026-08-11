from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path


class WindowsTray:
    """Small Win32 tray host; imports pywin32 only in the packaged Windows runtime."""

    def __init__(
        self,
        *,
        open_dashboard: Callable[[], None],
        toggle_collection: Callable[[], bool],
        shutdown: Callable[[], None],
    ) -> None:
        self.open_dashboard = open_dashboard
        self.toggle_collection = toggle_collection
        self.shutdown = shutdown
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._collection_paused = False
        self._tooltip = "WeaveXDR · 시작 중"
        self._icon_handle = None

    def start(self) -> None:
        if os.name != "nt" or self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="weavexdr-tray", daemon=True)
        self._thread.start()

    def update_status(self, label: str) -> None:
        self._tooltip = f"WeaveXDR · {label}"[:63]
        self._notify(1)

    def stop(self) -> None:
        if self._hwnd:
            try:
                import win32api
                import win32con

                win32api.PostMessage(self._hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass

    def _notify(self, action: int) -> None:
        if not self._hwnd:
            return
        import win32con
        import win32gui

        if self._icon_handle is None:
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                icon_path = Path(sys._MEIPASS) / "xdr_graph" / "static" / "weavexdr.ico"
            else:
                icon_path = Path(__file__).parent / "static" / "weavexdr.ico"
            try:
                # EXE와 동일한 번들 ICO를 사용해 작업 표시줄·트레이·웹 브랜드를 통일한다.
                self._icon_handle = win32gui.LoadImage(
                    0,
                    str(icon_path),
                    win32con.IMAGE_ICON,
                    0,
                    0,
                    win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE,
                )
            except Exception:
                self._icon_handle = win32gui.LoadIcon(0, 32512)
        icon = self._icon_handle
        win32gui.Shell_NotifyIcon(action, (self._hwnd, 0, 7, 1025, icon, self._tooltip))

    def _run(self) -> None:
        import win32api
        import win32con
        import win32gui

        callback_message = win32con.WM_USER + 1

        def handle_message(hwnd, message, wparam, lparam):
            if message == callback_message and lparam in (win32con.WM_LBUTTONUP, win32con.WM_RBUTTONUP):
                menu = win32gui.CreatePopupMenu()
                win32gui.AppendMenu(menu, win32con.MF_STRING, 1001, "대시보드 열기")
                pause_label = "수집 재개" if self._collection_paused else "수집 일시정지"
                win32gui.AppendMenu(menu, win32con.MF_STRING, 1002, pause_label)
                win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
                win32gui.AppendMenu(menu, win32con.MF_STRING, 1003, "WeaveXDR 종료")
                x, y = win32gui.GetCursorPos()
                win32gui.SetForegroundWindow(hwnd)
                command = win32gui.TrackPopupMenu(
                    menu, win32con.TPM_LEFTALIGN | win32con.TPM_RETURNCMD, x, y, 0, hwnd, None
                )
                if command == 1001:
                    self.open_dashboard()
                elif command == 1002:
                    self._collection_paused = self.toggle_collection()
                elif command == 1003:
                    self.shutdown()
                win32gui.DestroyMenu(menu)
            elif message == win32con.WM_DESTROY:
                self._notify(2)
                win32gui.PostQuitMessage(0)
            return 0

        window_class = win32gui.WNDCLASS()
        window_class.hInstance = win32api.GetModuleHandle(None)
        window_class.lpszClassName = "WeaveXDRTrayWindow"
        window_class.lpfnWndProc = handle_message
        try:
            atom = win32gui.RegisterClass(window_class)
        except win32gui.error:
            atom = window_class.lpszClassName
        self._hwnd = win32gui.CreateWindow(atom, "WeaveXDR", 0, 0, 0, 0, 0, 0, 0, window_class.hInstance, None)
        self._notify(0)
        win32gui.PumpMessages()
        self._hwnd = None
