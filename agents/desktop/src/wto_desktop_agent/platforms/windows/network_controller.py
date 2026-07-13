from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from wto_desktop_agent.domain.telemetry import ObservationReason, WifiScanSnapshot
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError
from wto_desktop_agent.ports.plugins import CancellationToken

_TERMINAL = {"completed", "failed", "cancelled", "rolled_back"}


class WindowsNetworkController:
    def __init__(
        self,
        native_wifi: Any,
        wifi_collector: Any,
        store: SQLiteStore,
        *,
        allowed_interface_guids: Iterable[str],
        allowed_profiles: Iterable[str],
        enabled: bool,
        administrator_check: Callable[[], bool] | None = None,
    ) -> None:
        self.native_wifi = native_wifi
        self.wifi_collector = wifi_collector
        self.store = store
        self.allowed_interface_guids = {self._guid(value) for value in allowed_interface_guids}
        self.allowed_profiles = frozenset(allowed_profiles)
        self.enabled = enabled
        self._administrator_check = administrator_check or _is_process_administrator

    @staticmethod
    def _guid(value: str) -> str:
        return str(UUID(value.strip("{}")))

    def _authorize(self, interface_guid: str, confirmed: bool) -> str:
        if not self.enabled:
            raise PermissionError("local Wi-Fi control is disabled by policy")
        if not confirmed:
            raise PermissionError("explicit administrative confirmation is required")
        if not self._administrator_check():
            raise PermissionError("local Wi-Fi control requires an elevated administrator")
        normalized = self._guid(interface_guid)
        if normalized not in self.allowed_interface_guids:
            raise PermissionError("interface GUID is not locally allowlisted")
        return normalized

    def _available_profiles(self, interface_guid: str) -> list[str]:
        return [
            profile
            for profile in self.native_wifi.profiles(interface_guid)
            if profile in self.allowed_profiles
        ]

    def list_profiles(self, interface_guid: str, *, confirmed: bool) -> list[str]:
        normalized = self._authorize(interface_guid, confirmed)
        return self._available_profiles(normalized)

    def _current_profile(self, interface_guid: str) -> str | None:
        try:
            connection = self.native_wifi.connection(interface_guid)
            value = str(connection.get("profile_name") or "")
            return value or None
        except NativeWifiError as error:
            if error.category == "invalid_state":
                return None
            raise

    async def connect(
        self,
        *,
        interface_guid: str,
        profile_name: str,
        idempotency_key: str,
        confirmed: bool,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> dict[str, object]:
        normalized = self._authorize(interface_guid, confirmed)
        UUID(idempotency_key)
        if profile_name not in self.allowed_profiles:
            raise PermissionError("profile is not locally allowlisted")
        profiles = await asyncio.to_thread(self._available_profiles, normalized)
        if profile_name not in profiles:
            raise PermissionError("allowlisted profile does not exist on interface")
        previous = await asyncio.to_thread(self._current_profile, normalized)
        operation = self.store.begin_windows_operation(
            operation_id=str(uuid4()),
            idempotency_key=idempotency_key,
            action="connect",
            interface_guid=normalized,
            target_profile=profile_name,
            previous_profile=previous,
        )
        if str(operation["state"]) in _TERMINAL:
            return operation
        if previous == profile_name:
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"intent_recorded", "running", "reconciling"},
                target="completed",
                reconciliation_result="target_already_connected",
            )
        self.store.transition_windows_operation(
            idempotency_key, current={"intent_recorded", "reconciling"}, target="running"
        )
        try:
            if cancellation.cancelled:
                raise asyncio.CancelledError
            await asyncio.to_thread(self.native_wifi.connect, normalized, profile_name)
            await self._wait_for_profile(normalized, profile_name, timeout_seconds, cancellation)
            return self.store.transition_windows_operation(
                idempotency_key, current={"running"}, target="completed"
            )
        except asyncio.CancelledError:
            await self._rollback(normalized, previous, timeout_seconds)
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"running"},
                target="cancelled",
                reconciliation_result="rollback_attempted",
            )
        except Exception as error:
            rolled_back = await self._rollback(normalized, previous, timeout_seconds)
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"running"},
                target="rolled_back" if rolled_back else "failed",
                reconciliation_result=("previous_profile_restored" if rolled_back else None),
                last_error=type(error).__name__,
            )

    async def disconnect(
        self,
        *,
        interface_guid: str,
        idempotency_key: str,
        confirmed: bool,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> dict[str, object]:
        normalized = self._authorize(interface_guid, confirmed)
        UUID(idempotency_key)
        previous = await asyncio.to_thread(self._current_profile, normalized)
        operation = self.store.begin_windows_operation(
            operation_id=str(uuid4()),
            idempotency_key=idempotency_key,
            action="disconnect",
            interface_guid=normalized,
            target_profile=None,
            previous_profile=previous,
        )
        if str(operation["state"]) in _TERMINAL:
            return operation
        if previous is None:
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"intent_recorded", "running", "reconciling"},
                target="completed",
                reconciliation_result="interface_already_disconnected",
            )
        self.store.transition_windows_operation(
            idempotency_key, current={"intent_recorded", "reconciling"}, target="running"
        )
        try:
            if cancellation.cancelled:
                raise asyncio.CancelledError
            await asyncio.to_thread(self.native_wifi.disconnect, normalized)
            await self._wait_for_profile(normalized, None, timeout_seconds, cancellation)
            return self.store.transition_windows_operation(
                idempotency_key, current={"running"}, target="completed"
            )
        except asyncio.CancelledError:
            rolled_back = await self._rollback(normalized, previous, timeout_seconds)
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"running"},
                target="rolled_back" if rolled_back else "cancelled",
                reconciliation_result=("previous_profile_restored" if rolled_back else None),
            )
        except Exception as error:
            rolled_back = await self._rollback(normalized, previous, timeout_seconds)
            return self.store.transition_windows_operation(
                idempotency_key,
                current={"running"},
                target="rolled_back" if rolled_back else "failed",
                reconciliation_result=("previous_profile_restored" if rolled_back else None),
                last_error=type(error).__name__,
            )

    async def _wait_for_profile(
        self,
        interface_guid: str,
        expected: str | None,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> None:
        async with asyncio.timeout(timeout_seconds):
            while True:
                if cancellation.cancelled:
                    raise asyncio.CancelledError
                current = await asyncio.to_thread(self._current_profile, interface_guid)
                if current == expected:
                    return
                await asyncio.sleep(0.2)

    async def _rollback(
        self, interface_guid: str, previous_profile: str | None, timeout_seconds: float
    ) -> bool:
        if previous_profile is None or previous_profile not in self.allowed_profiles:
            return False
        try:
            await asyncio.to_thread(self.native_wifi.connect, interface_guid, previous_profile)
            await self._wait_for_profile(
                interface_guid, previous_profile, timeout_seconds, CancellationToken()
            )
            return True
        except Exception:
            return False

    async def reconcile_incomplete(self, timeout_seconds: float = 10.0) -> int:
        reconciled = 0
        for operation in self.store.incomplete_windows_operations():
            key = str(operation["idempotency_key"])
            self.store.transition_windows_operation(
                key,
                current={"intent_recorded", "running", "reconciling"},
                target="reconciling",
            )
            current = await asyncio.to_thread(
                self._current_profile, str(operation["interface_guid"])
            )
            if operation["action"] == "connect" and current == operation.get("target_profile"):
                state, result = "completed", "target_connected_after_restart"
            elif operation["action"] == "disconnect" and current is None:
                state, result = "completed", "interface_disconnected_after_restart"
            else:
                rolled_back = await self._rollback(
                    str(operation["interface_guid"]),
                    operation.get("previous_profile"),
                    timeout_seconds,
                )
                state = "rolled_back" if rolled_back else "failed"
                result = "previous_profile_restored" if rolled_back else "state_ambiguous"
            self.store.transition_windows_operation(
                key,
                current={"reconciling"},
                target=state,
                reconciliation_result=result,
            )
            reconciled += 1
        return reconciled

    async def request_scan(
        self,
        *,
        interface_guid: str,
        idempotency_key: str,
        confirmed: bool,
        cancellation: CancellationToken,
    ) -> WifiScanSnapshot:
        normalized = self._authorize(interface_guid, confirmed)
        UUID(idempotency_key)
        operation = self.store.begin_windows_operation(
            operation_id=str(uuid4()),
            idempotency_key=idempotency_key,
            action="scan",
            interface_guid=normalized,
            target_profile=None,
            previous_profile=None,
        )
        if str(operation["state"]) in _TERMINAL:
            now = datetime.now(UTC)
            return WifiScanSnapshot(
                interface_guid=normalized,
                started_at=now,
                finished_at=now,
                entries=[],
                reason=ObservationReason(
                    code="skipped",
                    detail="idempotency key already reached a terminal state",
                ),
            )
        self.store.transition_windows_operation(
            idempotency_key, current={"intent_recorded", "reconciling"}, target="running"
        )
        try:
            result = cast(
                WifiScanSnapshot,
                await self.wifi_collector.scan(normalized, cancellation),
            )
            self.store.transition_windows_operation(
                idempotency_key,
                current={"running"},
                target="completed" if result.reason is None else "failed",
                last_error=result.reason.code if result.reason else None,
            )
            return result
        except asyncio.CancelledError:
            self.store.transition_windows_operation(
                idempotency_key, current={"running"}, target="cancelled"
            )
            raise

    def capability_overrides(self) -> dict[str, dict[str, object]]:
        return {}


def _is_process_administrator() -> bool:
    """Evaluate the caller token only when a local control operation is requested."""
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False
