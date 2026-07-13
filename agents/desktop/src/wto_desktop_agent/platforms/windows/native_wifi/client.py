from __future__ import annotations

import ctypes
import threading
from contextlib import AbstractContextManager
from ctypes import wintypes
from types import TracebackType
from typing import Any, Protocol, cast

from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError, raise_for_code
from wto_desktop_agent.platforms.windows.native_wifi.structures import (
    DOT11_BSS_TYPE_ANY,
    GUID,
    MAX_BSS_ENTRIES,
    MAX_IE_BYTES,
    MAX_INTERFACES,
    MAX_PHY_TYPES,
    MAX_PROFILES,
    WLAN_API_VERSION_2_0,
    WLAN_BSS_ENTRY,
    WLAN_BSS_LIST_HEADER,
    WLAN_CONNECTION_ATTRIBUTES,
    WLAN_CONNECTION_MODE_PROFILE,
    WLAN_CONNECTION_PARAMETERS,
    WLAN_INTERFACE_CAPABILITY_HEADER,
    WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST_HEADER,
    WLAN_INTF_OPCODE_CHANNEL_NUMBER,
    WLAN_INTF_OPCODE_CURRENT_CONNECTION,
    WLAN_INTF_OPCODE_INTERFACE_STATE,
    WLAN_NOTIFICATION_ACM_SCAN_COMPLETE,
    WLAN_NOTIFICATION_ACM_SCAN_FAIL,
    WLAN_NOTIFICATION_CALLBACK,
    WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_NOTIFICATION_SOURCE_NONE,
    WLAN_PROFILE_INFO,
    WLAN_PROFILE_INFO_LIST_HEADER,
    checked_array,
    mac_address,
    parse_ssid,
)


class Bindings(Protocol):
    WlanOpenHandle: Any
    WlanCloseHandle: Any
    WlanEnumInterfaces: Any
    WlanGetInterfaceCapability: Any
    WlanQueryInterface: Any
    WlanGetNetworkBssList: Any
    WlanScan: Any
    WlanRegisterNotification: Any
    WlanGetProfileList: Any
    WlanConnect: Any
    WlanDisconnect: Any
    WlanFreeMemory: Any


class NativeBuffer(AbstractContextManager[int]):
    def __init__(self, bindings: Bindings, address: int) -> None:
        if not address:
            raise ValueError("native buffer is null")
        self._bindings = bindings
        self._address = address
        self._released = False

    def __enter__(self) -> int:
        return self._address

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()

    def release(self) -> None:
        if not self._released:
            self._bindings.WlanFreeMemory(ctypes.c_void_p(self._address))
            self._released = True


class NativeWifiSession(AbstractContextManager["NativeWifiSession"]):
    def __init__(self, bindings: Bindings) -> None:
        self.bindings = bindings
        negotiated = wintypes.DWORD()
        handle = wintypes.HANDLE()
        code = int(
            bindings.WlanOpenHandle(
                WLAN_API_VERSION_2_0, None, ctypes.byref(negotiated), ctypes.byref(handle)
            )
        )
        raise_for_code("WlanOpenHandle", code)
        if not handle.value:
            raise NativeWifiError("WlanOpenHandle", 6, "failed")
        self.handle = handle
        self.negotiated_version = int(negotiated.value)
        self._closed = False

    def __enter__(self) -> NativeWifiSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            code = int(self.bindings.WlanCloseHandle(self.handle, None))
            self._closed = True
            raise_for_code("WlanCloseHandle", code)


class NativeWifiClient:
    def __init__(self, bindings: Bindings | None = None) -> None:
        if bindings is None:
            from wto_desktop_agent.platforms.windows.native_wifi.bindings import (
                NativeWifiBindings,
            )

            bindings = NativeWifiBindings()
        self.bindings = bindings

    def session(self) -> NativeWifiSession:
        return NativeWifiSession(self.bindings)

    def interfaces(self) -> list[dict[str, object]]:
        with self.session() as session:
            pointer = ctypes.c_void_p()
            raise_for_code(
                "WlanEnumInterfaces",
                int(self.bindings.WlanEnumInterfaces(session.handle, None, ctypes.byref(pointer))),
            )
            with NativeBuffer(self.bindings, int(pointer.value or 0)) as address:
                header = WLAN_INTERFACE_INFO_LIST_HEADER.from_address(address)
                items = checked_array(
                    address,
                    ctypes.sizeof(header),
                    WLAN_INTERFACE_INFO,
                    int(header.dwNumberOfItems),
                    MAX_INTERFACES,
                )
                return [
                    {
                        "guid": cast(WLAN_INTERFACE_INFO, item).InterfaceGuid.canonical(),
                        "description": str(cast(WLAN_INTERFACE_INFO, item).strInterfaceDescription),
                        "state": int(cast(WLAN_INTERFACE_INFO, item).isState),
                    }
                    for item in items
                ]

    def interface_capability(self, interface_guid: str) -> dict[str, object]:
        guid = GUID.from_string(interface_guid)
        with self.session() as session:
            pointer = ctypes.c_void_p()
            raise_for_code(
                "WlanGetInterfaceCapability",
                int(
                    self.bindings.WlanGetInterfaceCapability(
                        session.handle, ctypes.byref(guid), None, ctypes.byref(pointer)
                    )
                ),
            )
            with NativeBuffer(self.bindings, int(pointer.value or 0)) as address:
                header = WLAN_INTERFACE_CAPABILITY_HEADER.from_address(address)
                count = int(header.dwNumberOfSupportedPhys)
                if count < 0 or count > MAX_PHY_TYPES:
                    raise ValueError("native PHY count exceeds limit")
                start = address + ctypes.sizeof(header)
                phys = [wintypes.DWORD.from_address(start + i * 4).value for i in range(count)]
                return {
                    "interface_type": int(header.interfaceType),
                    "dot11d_supported": bool(header.bDot11DSupported),
                    "max_ssids": int(header.dwMaxDesiredSsidListSize),
                    "max_bssids": int(header.dwMaxDesiredBssidListSize),
                    "phy_types": [int(value) for value in phys],
                }

    def query_interface(self, interface_guid: str, opcode: int) -> bytes:
        guid = GUID.from_string(interface_guid)
        with self.session() as session:
            size = wintypes.DWORD()
            pointer = ctypes.c_void_p()
            opcode_type = wintypes.DWORD()
            raise_for_code(
                "WlanQueryInterface",
                int(
                    self.bindings.WlanQueryInterface(
                        session.handle,
                        ctypes.byref(guid),
                        opcode,
                        None,
                        ctypes.byref(size),
                        ctypes.byref(pointer),
                        ctypes.byref(opcode_type),
                    )
                ),
            )
            if int(size.value) <= 0 or int(size.value) > 1_048_576:
                raise ValueError("native query buffer size exceeds limit")
            with NativeBuffer(self.bindings, int(pointer.value or 0)) as address:
                return ctypes.string_at(address, int(size.value))

    def connection(self, interface_guid: str) -> dict[str, object]:
        raw = self.query_interface(interface_guid, WLAN_INTF_OPCODE_CURRENT_CONNECTION)
        if len(raw) < ctypes.sizeof(WLAN_CONNECTION_ATTRIBUTES):
            raise ValueError("current connection buffer is truncated")
        value = WLAN_CONNECTION_ATTRIBUTES.from_buffer_copy(raw)
        association = value.wlanAssociationAttributes
        ssid = parse_ssid(association.dot11Ssid)
        return {
            "state": int(value.isState),
            "profile_name": str(value.strProfileName),
            "ssid_bytes": ssid.raw,
            "ssid_display": ssid.display,
            "bssid": mac_address(association.dot11Bssid),
            "phy_type": int(association.dot11PhyType),
            "signal_quality": int(association.wlanSignalQuality),
            "rx_rate_kbps": int(association.ulRxRate),
            "tx_rate_kbps": int(association.ulTxRate),
        }

    def interface_state(self, interface_guid: str) -> int:
        raw = self.query_interface(interface_guid, WLAN_INTF_OPCODE_INTERFACE_STATE)
        if len(raw) < 4:
            raise ValueError("interface state buffer is truncated")
        return int.from_bytes(raw[:4], "little")

    def channel(self, interface_guid: str) -> int:
        raw = self.query_interface(interface_guid, WLAN_INTF_OPCODE_CHANNEL_NUMBER)
        if len(raw) < 4:
            raise ValueError("channel buffer is truncated")
        return int.from_bytes(raw[:4], "little")

    def supports_opcode(self, interface_guid: str, opcode: int) -> bool | None:
        """Probe an opcode without inferring support from the Windows version."""
        try:
            self.query_interface(interface_guid, opcode)
            return True
        except NativeWifiError as error:
            if error.category == "unsupported":
                return False
            if error.category in {"access_denied", "invalid_state", "service_stopped"}:
                return None
            raise

    def bss_entries(self, interface_guid: str) -> list[dict[str, object]]:
        guid = GUID.from_string(interface_guid)
        with self.session() as session:
            pointer = ctypes.c_void_p()
            raise_for_code(
                "WlanGetNetworkBssList",
                int(
                    self.bindings.WlanGetNetworkBssList(
                        session.handle,
                        ctypes.byref(guid),
                        None,
                        DOT11_BSS_TYPE_ANY,
                        False,
                        None,
                        ctypes.byref(pointer),
                    )
                ),
            )
            with NativeBuffer(self.bindings, int(pointer.value or 0)) as address:
                header = WLAN_BSS_LIST_HEADER.from_address(address)
                total_size = int(header.dwTotalSize)
                if total_size < ctypes.sizeof(header) or total_size > 32 * 1024 * 1024:
                    raise ValueError("native BSS buffer size exceeds limit")
                entries = checked_array(
                    address,
                    ctypes.sizeof(header),
                    WLAN_BSS_ENTRY,
                    int(header.dwNumberOfItems),
                    MAX_BSS_ENTRIES,
                )
                required = ctypes.sizeof(header) + len(entries) * ctypes.sizeof(WLAN_BSS_ENTRY)
                if required > total_size:
                    raise ValueError("native BSS entry array exceeds buffer bounds")
                result: list[dict[str, object]] = []
                for raw_entry in entries:
                    entry = cast(WLAN_BSS_ENTRY, raw_entry)
                    ie_offset = int(entry.ulIeOffset)
                    ie_size = int(entry.ulIeSize)
                    entry_address = ctypes.addressof(entry)
                    ie_end = entry_address + ie_offset + ie_size
                    if (
                        ie_size > MAX_IE_BYTES
                        or (ie_size and ie_offset < ctypes.sizeof(WLAN_BSS_ENTRY))
                        or ie_end > address + total_size
                    ):
                        raise ValueError("native BSS IE bounds are invalid")
                    ssid = parse_ssid(entry.dot11Ssid)
                    result.append(
                        {
                            "ssid_bytes": ssid.raw,
                            "ssid_display": ssid.display,
                            "bssid": mac_address(entry.dot11Bssid),
                            "phy_type": int(entry.dot11BssPhyType),
                            "rssi_dbm": int(entry.lRssi),
                            "signal_quality": int(entry.uLinkQuality),
                            "frequency_khz": int(entry.ulChCenterFrequency),
                        }
                    )
                return result

    def scan(self, interface_guid: str, timeout_seconds: float) -> None:
        guid = GUID.from_string(interface_guid)
        complete = threading.Event()
        outcome: list[str] = []

        def notification(data: Any, _: int) -> None:
            if not data:
                return
            event = data.contents
            if event.InterfaceGuid.canonical() != interface_guid:
                return
            if int(event.NotificationCode) == WLAN_NOTIFICATION_ACM_SCAN_COMPLETE:
                outcome.append("complete")
                complete.set()
            elif int(event.NotificationCode) == WLAN_NOTIFICATION_ACM_SCAN_FAIL:
                outcome.append("failed")
                complete.set()

        callback = WLAN_NOTIFICATION_CALLBACK(notification)
        with self.session() as session:
            previous = wintypes.DWORD()
            raise_for_code(
                "WlanRegisterNotification",
                int(
                    self.bindings.WlanRegisterNotification(
                        session.handle,
                        WLAN_NOTIFICATION_SOURCE_ACM,
                        False,
                        callback,
                        None,
                        None,
                        ctypes.byref(previous),
                    )
                ),
            )
            try:
                raise_for_code(
                    "WlanScan",
                    int(
                        self.bindings.WlanScan(session.handle, ctypes.byref(guid), None, None, None)
                    ),
                )
                if not complete.wait(timeout_seconds):
                    raise NativeWifiError("WlanScan", 1460, "timeout")
                if not outcome or outcome[-1] != "complete":
                    raise NativeWifiError("WlanScan", 31, "failed")
            finally:
                self.bindings.WlanRegisterNotification(
                    session.handle,
                    WLAN_NOTIFICATION_SOURCE_NONE,
                    False,
                    callback,
                    None,
                    None,
                    ctypes.byref(previous),
                )

    def profiles(self, interface_guid: str) -> list[str]:
        guid = GUID.from_string(interface_guid)
        with self.session() as session:
            pointer = ctypes.c_void_p()
            raise_for_code(
                "WlanGetProfileList",
                int(
                    self.bindings.WlanGetProfileList(
                        session.handle, ctypes.byref(guid), None, ctypes.byref(pointer)
                    )
                ),
            )
            with NativeBuffer(self.bindings, int(pointer.value or 0)) as address:
                header = WLAN_PROFILE_INFO_LIST_HEADER.from_address(address)
                items = checked_array(
                    address,
                    ctypes.sizeof(header),
                    WLAN_PROFILE_INFO,
                    int(header.dwNumberOfItems),
                    MAX_PROFILES,
                )
                return [str(cast(WLAN_PROFILE_INFO, item).strProfileName) for item in items]

    def connect(self, interface_guid: str, profile_name: str) -> None:
        guid = GUID.from_string(interface_guid)
        parameters = WLAN_CONNECTION_PARAMETERS(
            wlanConnectionMode=WLAN_CONNECTION_MODE_PROFILE,
            strProfile=profile_name,
            pDot11Ssid=None,
            pDesiredBssidList=None,
            dot11BssType=DOT11_BSS_TYPE_ANY,
            dwFlags=0,
        )
        with self.session() as session:
            raise_for_code(
                "WlanConnect",
                int(
                    self.bindings.WlanConnect(
                        session.handle, ctypes.byref(guid), ctypes.byref(parameters), None
                    )
                ),
            )

    def disconnect(self, interface_guid: str) -> None:
        guid = GUID.from_string(interface_guid)
        with self.session() as session:
            raise_for_code(
                "WlanDisconnect",
                int(self.bindings.WlanDisconnect(session.handle, ctypes.byref(guid), None)),
            )
