from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from uuid import UUID

MAX_INTERFACES = 64
MAX_BSS_ENTRIES = 4096
MAX_PROFILES = 1024
MAX_PHY_TYPES = 64
MAX_IE_BYTES = 2324
DOT11_SSID_MAX_LENGTH = 32

WLAN_API_VERSION_2_0 = 2
WLAN_NOTIFICATION_SOURCE_NONE = 0
WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 7
WLAN_NOTIFICATION_ACM_SCAN_FAIL = 8
WLAN_INTF_OPCODE_INTERFACE_STATE = 6
WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
WLAN_INTF_OPCODE_CHANNEL_NUMBER = 8
WLAN_CONNECTION_MODE_PROFILE = 0
DOT11_BSS_TYPE_ANY = 3


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_string(cls, value: str) -> GUID:
        raw = UUID(value).bytes_le
        result = cls()
        ctypes.memmove(ctypes.byref(result), raw, len(raw))
        return result

    def canonical(self) -> str:
        return str(UUID(bytes_le=bytes(memoryview(self))))


class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", wintypes.WCHAR * 256),
        ("isState", wintypes.DWORD),
    ]


class WLAN_INTERFACE_INFO_LIST_HEADER(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", wintypes.DWORD),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11PhyType", wintypes.DWORD),
        ("uDot11PhyIndex", wintypes.ULONG),
        ("wlanSignalQuality", wintypes.ULONG),
        ("ulRxRate", wintypes.ULONG),
        ("ulTxRate", wintypes.ULONG),
    ]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("bSecurityEnabled", wintypes.BOOL),
        ("bOneXEnabled", wintypes.BOOL),
        ("dot11AuthAlgorithm", wintypes.DWORD),
        ("dot11CipherAlgorithm", wintypes.DWORD),
    ]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("isState", wintypes.DWORD),
        ("wlanConnectionMode", wintypes.DWORD),
        ("strProfileName", wintypes.WCHAR * 256),
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),
    ]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", wintypes.USHORT * 126),
    ]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", wintypes.DWORD),
        ("dot11BssPhyType", wintypes.DWORD),
        ("lRssi", wintypes.LONG),
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", wintypes.BOOLEAN),
        ("usBeaconPeriod", wintypes.USHORT),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", wintypes.USHORT),
        ("ulChCenterFrequency", wintypes.ULONG),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),
        ("ulIeSize", wintypes.ULONG),
    ]


class WLAN_BSS_LIST_HEADER(ctypes.Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD), ("dwNumberOfItems", wintypes.DWORD)]


class WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("strProfileName", wintypes.WCHAR * 256), ("dwFlags", wintypes.DWORD)]


class WLAN_PROFILE_INFO_LIST_HEADER(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD)]


class WLAN_INTERFACE_CAPABILITY_HEADER(ctypes.Structure):
    _fields_ = [
        ("interfaceType", wintypes.DWORD),
        ("bDot11DSupported", wintypes.BOOL),
        ("dwMaxDesiredSsidListSize", wintypes.DWORD),
        ("dwMaxDesiredBssidListSize", wintypes.DWORD),
        ("dwNumberOfSupportedPhys", wintypes.DWORD),
    ]


class WLAN_CONNECTION_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("wlanConnectionMode", wintypes.DWORD),
        ("strProfile", wintypes.LPCWSTR),
        ("pDot11Ssid", ctypes.POINTER(DOT11_SSID)),
        ("pDesiredBssidList", ctypes.c_void_p),
        ("dot11BssType", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
    ]


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("NotificationSource", wintypes.DWORD),
        ("NotificationCode", wintypes.DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", wintypes.DWORD),
        ("pData", ctypes.c_void_p),
    ]


_CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
WLAN_NOTIFICATION_CALLBACK = _CALLBACK_FACTORY(
    None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), ctypes.c_void_p
)


@dataclass(frozen=True)
class Ssid:
    raw: bytes
    display: str | None


def parse_ssid(value: DOT11_SSID) -> Ssid:
    length = int(value.uSSIDLength)
    if length < 0 or length > DOT11_SSID_MAX_LENGTH:
        raise ValueError("invalid DOT11_SSID length")
    raw = bytes(value.ucSSID[:length])
    try:
        decoded = raw.decode("utf-8")
        display = decoded if decoded.isprintable() else None
    except UnicodeDecodeError:
        display = None
    return Ssid(raw=raw, display=display)


def mac_address(value: ctypes.Array[ctypes.c_ubyte]) -> str:
    return ":".join(f"{part:02x}" for part in value)


def checked_array(
    address: int, header_size: int, item_type: type[ctypes.Structure], count: int, maximum: int
) -> list[ctypes.Structure]:
    if address == 0:
        raise ValueError("native buffer is null")
    if count < 0 or count > maximum:
        raise ValueError("native array count exceeds limit")
    start = address + header_size
    return [
        item_type.from_address(start + index * ctypes.sizeof(item_type)) for index in range(count)
    ]
