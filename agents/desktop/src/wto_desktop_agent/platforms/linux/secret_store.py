from __future__ import annotations

from wto_desktop_agent.domain.errors import SecureStoreUnavailableError
from wto_desktop_agent.domain.models import DoctorCheck


class LinuxSecretServiceStore:
    _SERVICE = "org.wifi_test_orchestrator.DesktopAgent"

    def __init__(self) -> None:
        try:
            import secretstorage

            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)
            if collection.is_locked():
                dismissed = collection.unlock()
                if dismissed or collection.is_locked():
                    raise SecureStoreUnavailableError("Linux Secret Service collection is locked")
            self._collection = collection
        except SecureStoreUnavailableError:
            raise
        except Exception as error:
            raise SecureStoreUnavailableError("Linux Secret Service is unavailable") from error

    @property
    def secure(self) -> bool:
        return True

    def _attributes(self, key: str) -> dict[str, str]:
        return {"application": self._SERVICE, "key": key}

    def put(self, key: str, value: str) -> None:
        self._collection.create_item(
            f"WTO desktop agent {key}",
            self._attributes(key),
            value.encode("utf-8"),
            replace=True,
        )

    def get(self, key: str) -> str | None:
        item = next(self._collection.search_items(self._attributes(key)), None)
        if item is None:
            return None
        return item.get_secret().decode("utf-8")

    def delete(self, key: str) -> None:
        for item in self._collection.search_items(self._attributes(key)):
            item.delete()

    def doctor(self) -> DoctorCheck:
        return DoctorCheck(
            name="secret_store", status="OK", detail="Linux Secret Service is available"
        )
