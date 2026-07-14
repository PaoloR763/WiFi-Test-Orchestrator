from __future__ import annotations

from pathlib import Path

SERVICE_NAME = "WiFiTestOrchestratorAgent"
SERVICE_ACCOUNT = r"NT AUTHORITY\LocalService"


def directory_sddl(service_sid: str, *, writable: bool) -> str:
    service_rights = "0x1301bf" if writable else "0x1200a9"
    return f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{service_rights};;;{service_sid})"


def pipe_sddl(service_sid: str) -> str:
    return f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{service_sid})"


def apply_directory_acl(path: Path, service_sid: str, *, writable: bool) -> None:
    import win32security

    path.mkdir(parents=True, exist_ok=True)
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        directory_sddl(service_sid, writable=writable),
        win32security.SDDL_REVISION_1,
    )
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, descriptor)


def lookup_service_sid() -> str:
    import win32security

    sid, _, _ = win32security.LookupAccountName(None, rf"NT SERVICE\{SERVICE_NAME}")
    return str(win32security.ConvertSidToStringSid(sid))
