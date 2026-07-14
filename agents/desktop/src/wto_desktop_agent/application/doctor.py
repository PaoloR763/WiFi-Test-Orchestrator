from __future__ import annotations

from urllib.parse import urlparse

from wto_desktop_agent.config import AgentSettings
from wto_desktop_agent.domain.models import DoctorCheck
from wto_desktop_agent.infrastructure.contracts import contract_root, schema_store
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.platform import PlatformAdapter


class DoctorService:
    def __init__(
        self, settings: AgentSettings, store: SQLiteStore, platform: PlatformAdapter
    ) -> None:
        self.settings = settings
        self.store = store
        self.platform = platform

    def run(self) -> list[DoctorCheck]:
        checks: list[DoctorCheck] = []
        parsed = urlparse(self.settings.server_url)
        checks.append(
            DoctorCheck(
                name="transport_tls",
                status="OK" if parsed.scheme == "https" else "DEGRADED",
                detail=(
                    "HTTPS configured"
                    if parsed.scheme == "https"
                    else "Plain HTTP allowed only by explicit local development/test configuration"
                ),
            )
        )
        try:
            schemas, _ = schema_store()
            fixture_count = len(
                __import__("json").loads(
                    (contract_root() / "examples" / "manifest.json").read_text(encoding="utf-8")
                )["fixtures"]
            )
            valid = len(schemas) == 14 and fixture_count == 25
            checks.append(
                DoctorCheck(
                    name="contracts",
                    status="OK" if valid else "BLOCKED",
                    detail=(
                        f"Packaged contracts: {len(schemas)} schemas and {fixture_count} fixtures"
                    ),
                )
            )
        except Exception:
            checks.append(
                DoctorCheck(
                    name="contracts",
                    status="BLOCKED",
                    detail="Packaged contracts are unavailable",
                )
            )
        try:
            self.store.initialize()
            checks.append(
                DoctorCheck(
                    name="sqlite",
                    status="OK",
                    detail="SQLite schema and quick_check passed",
                )
            )
        except Exception:
            checks.append(
                DoctorCheck(name="sqlite", status="BLOCKED", detail="SQLite validation failed")
            )
        checks.append(self.platform.secret_store.doctor())
        checks.append(self.platform.service_manager.doctor())
        if self.platform.platform_id == "windows":
            connection_override = self.platform.wifi_collector.capability_overrides().get(
                "wifi.connection.read", {}
            )
            permission = connection_override.get("permission_requirement")
            denied = isinstance(permission, dict) and permission.get("status") == "denied"
            checks.append(
                DoctorCheck(
                    name="windows_wifi_privacy",
                    status="BLOCKED" if denied else "DEGRADED",
                    detail=(
                        "Windows denied Wi-Fi location/privacy access; enable Location services "
                        "and permit the service account before retrying"
                        if denied
                        else "Wi-Fi association, BSSID and scan depend on Windows Location "
                        "privacy permission; Session 0 never opens consent UI"
                    ),
                )
            )
        return checks
