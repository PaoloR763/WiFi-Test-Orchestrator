from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from types import TracebackType

from wto_desktop_agent.platforms.windows.native_wifi.structures import GUID

MAX_INTERFACES = 4096


class MIB_IF_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceGuid", GUID),
        ("Alias", wintypes.WCHAR * 257),
        ("Description", wintypes.WCHAR * 257),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", wintypes.ULONG),
        ("Type", wintypes.ULONG),
        ("TunnelType", wintypes.DWORD),
        ("MediaType", wintypes.DWORD),
        ("PhysicalMediumType", wintypes.DWORD),
        ("AccessType", wintypes.DWORD),
        ("DirectionType", wintypes.DWORD),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", wintypes.DWORD),
        ("AdminStatus", wintypes.DWORD),
        ("MediaConnectState", wintypes.DWORD),
        ("NetworkGuid", GUID),
        ("ConnectionType", wintypes.DWORD),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


class MIB_IF_TABLE2_HEADER(ctypes.Structure):
    _fields_ = [("NumEntries", wintypes.ULONG)]


class MibTable:
    def __init__(self, free: object, address: int) -> None:
        if not address:
            raise ValueError("IP Helper returned a null table")
        self.free = free
        self.address = address
        self.released = False

    def __enter__(self) -> int:
        return self.address

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if not self.released:
            self.free(ctypes.c_void_p(self.address))  # type: ignore[operator]
            self.released = True


class IpHelperClient:
    def __init__(self) -> None:
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            raise RuntimeError("SystemRoot is unavailable")
        system32 = Path(system_root).resolve() / "System32"
        dll_path = (system32 / "iphlpapi.dll").resolve()
        if dll_path.parent != system32.resolve() or not dll_path.is_file():
            raise RuntimeError("canonical System32 iphlpapi.dll is unavailable")
        dll = ctypes.WinDLL(str(dll_path), use_last_error=True)
        self.get_if_table2 = dll.GetIfTable2
        self.get_if_table2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self.get_if_table2.restype = wintypes.ULONG
        self.free_mib_table = dll.FreeMibTable
        self.free_mib_table.argtypes = [ctypes.c_void_p]
        self.free_mib_table.restype = None

    def interfaces(self) -> list[dict[str, object]]:
        pointer = ctypes.c_void_p()
        code = int(self.get_if_table2(ctypes.byref(pointer)))
        if code != 0:
            raise RuntimeError(f"GetIfTable2 failed with Win32 code {code}")
        with MibTable(self.free_mib_table, int(pointer.value or 0)) as address:
            count = int(MIB_IF_TABLE2_HEADER.from_address(address).NumEntries)
            if count < 0 or count > MAX_INTERFACES:
                raise ValueError("IP Helper interface count exceeds limit")
            start = address + ctypes.sizeof(MIB_IF_TABLE2_HEADER)
            result: list[dict[str, object]] = []
            for index in range(count):
                row = MIB_IF_ROW2.from_address(start + index * ctypes.sizeof(MIB_IF_ROW2))
                result.append(
                    {
                        "guid": row.InterfaceGuid.canonical(),
                        "interface_index": int(row.InterfaceIndex),
                        "name": str(row.Alias),
                        "description": str(row.Description),
                        "state": int(row.OperStatus),
                        "type": int(row.Type),
                        "physical_medium": int(row.PhysicalMediumType),
                        "tx_link_speed_bps": int(row.TransmitLinkSpeed),
                        "rx_link_speed_bps": int(row.ReceiveLinkSpeed),
                        "received_bytes": int(row.InOctets),
                        "sent_bytes": int(row.OutOctets),
                        "received_packets": int(row.InUcastPkts + row.InNUcastPkts),
                        "sent_packets": int(row.OutUcastPkts + row.OutNUcastPkts),
                        "received_errors": int(row.InErrors),
                        "sent_errors": int(row.OutErrors),
                        "received_discards": int(row.InDiscards),
                        "sent_discards": int(row.OutDiscards),
                    }
                )
            return result
