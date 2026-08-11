from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(payload: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(payload)
    return _DataBlob(len(payload), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect_user_secret(value: str) -> str:
    """Protect a per-user runtime secret without persisting recoverable plaintext on Windows."""

    payload = value.encode("utf-8")
    if os.name != "nt":
        return "local:" + base64.b64encode(payload).decode("ascii")
    source, source_buffer = _blob(payload)
    entropy, entropy_buffer = _blob(b"WeaveXDR.instance.v1")
    output = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "WeaveXDR runtime", ctypes.byref(entropy), None, None,
        0x1, ctypes.byref(output),
    ):
        raise ctypes.WinError()
    try:
        protected = ctypes.string_at(output.pbData, output.cbData)
        return "dpapi:" + base64.b64encode(protected).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)
        del source_buffer, entropy_buffer


def unprotect_user_secret(value: str) -> str:
    prefix, separator, encoded = value.partition(":")
    if not separator:
        # 한 번의 호환 읽기 후 다음 publish에서 DPAPI 형식으로 교체된다.
        return value
    payload = base64.b64decode(encoded, validate=True)
    if prefix == "local" and os.name != "nt":
        return payload.decode("utf-8")
    if prefix != "dpapi" or os.name != "nt":
        raise ValueError("protected secret format is not valid on this platform")
    source, source_buffer = _blob(payload)
    entropy, entropy_buffer = _blob(b"WeaveXDR.instance.v1")
    output = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, ctypes.byref(entropy), None, None,
        0x1, ctypes.byref(output),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)
        del source_buffer, entropy_buffer


def harden_data_permissions(path: str | Path) -> None:
    """Restrict new application data to the current user and LocalSystem."""

    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(target, 0o700)
        return
    import win32api
    import win32con
    import win32security
    import ntsecuritycon

    process_token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    user_sid = win32security.GetTokenInformation(
        process_token, win32security.TokenUser
    )[0]
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    access = ntsecuritycon.FILE_ALL_ACCESS
    inheritance = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inheritance, access, user_sid)
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inheritance, access, system_sid)
    win32security.SetNamedSecurityInfo(
        str(target), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None,
    )
