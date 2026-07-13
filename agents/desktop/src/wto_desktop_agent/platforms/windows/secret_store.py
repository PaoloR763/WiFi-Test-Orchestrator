from __future__ import annotations

import win32cred

from wto_desktop_agent.domain.errors import SecureStoreUnavailableError
from wto_desktop_agent.domain.models import DoctorCheck


class WindowsCredentialManagerStore:
    _PREFIX = "WiFiTestOrchestrator/DesktopAgent/"

    @property
    def secure(self) -> bool:
        return True

    def put(self, key: str, value: str) -> None:
        try:
            win32cred.CredWrite(
                {
                    "Type": win32cred.CRED_TYPE_GENERIC,
                    "TargetName": self._PREFIX + key,
                    "CredentialBlob": value,
                    "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                    "UserName": "wto-desktop-agent",
                },
                0,
            )
        except Exception as error:
            raise SecureStoreUnavailableError("Windows Credential Manager write failed") from error

    def get(self, key: str) -> str | None:
        try:
            credential = win32cred.CredRead(self._PREFIX + key, win32cred.CRED_TYPE_GENERIC, 0)
        except Exception as error:
            if getattr(error, "winerror", None) == 1168:
                return None
            raise SecureStoreUnavailableError("Windows Credential Manager read failed") from error
        blob = credential["CredentialBlob"]
        return bytes(blob).decode("utf-16-le") if isinstance(blob, bytes) else str(blob)

    def delete(self, key: str) -> None:
        try:
            win32cred.CredDelete(self._PREFIX + key, win32cred.CRED_TYPE_GENERIC, 0)
        except Exception as error:
            if getattr(error, "winerror", None) != 1168:
                raise SecureStoreUnavailableError(
                    "Windows Credential Manager delete failed"
                ) from error

    def doctor(self) -> DoctorCheck:
        return DoctorCheck(
            name="secret_store",
            status="OK",
            detail="Windows Credential Manager is available",
        )
