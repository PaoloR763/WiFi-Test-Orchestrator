from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

from wto_desktop_agent.platforms.windows.native_wifi.structures import (
    DOT11_SSID,
    GUID,
    WLAN_CONNECTION_PARAMETERS,
    WLAN_NOTIFICATION_CALLBACK,
)


class NativeWifiBindings:
    """Typed wlanapi.dll bindings. This module is Windows-only by design."""

    def __init__(self) -> None:
        system_root_value = os.environ.get("SystemRoot")
        if not system_root_value:
            raise RuntimeError("SystemRoot is unavailable")
        system_root = Path(system_root_value).resolve()
        dll_path = (system_root / "System32" / "wlanapi.dll").resolve()
        if dll_path.parent != (system_root / "System32").resolve() or not dll_path.is_file():
            raise RuntimeError("canonical System32 wlanapi.dll is unavailable")
        self.dll_path = dll_path
        self._dll = ctypes.WinDLL(str(dll_path), use_last_error=True)
        self._declare()

    def _declare(self) -> None:
        self.WlanOpenHandle = self._dll.WlanOpenHandle
        self.WlanOpenHandle.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self.WlanOpenHandle.restype = wintypes.DWORD

        self.WlanCloseHandle = self._dll.WlanCloseHandle
        self.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.WlanCloseHandle.restype = wintypes.DWORD

        self.WlanEnumInterfaces = self._dll.WlanEnumInterfaces
        self.WlanEnumInterfaces.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.WlanEnumInterfaces.restype = wintypes.DWORD

        self.WlanGetInterfaceCapability = self._dll.WlanGetInterfaceCapability
        self.WlanGetInterfaceCapability.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.WlanGetInterfaceCapability.restype = wintypes.DWORD

        self.WlanQueryInterface = self._dll.WlanQueryInterface
        self.WlanQueryInterface.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.WlanQueryInterface.restype = wintypes.DWORD

        self.WlanGetNetworkBssList = self._dll.WlanGetNetworkBssList
        self.WlanGetNetworkBssList.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.POINTER(DOT11_SSID),
            wintypes.DWORD,
            wintypes.BOOL,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.WlanGetNetworkBssList.restype = wintypes.DWORD

        self.WlanScan = self._dll.WlanScan
        self.WlanScan.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.POINTER(DOT11_SSID),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.WlanScan.restype = wintypes.DWORD

        self.WlanRegisterNotification = self._dll.WlanRegisterNotification
        self.WlanRegisterNotification.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.BOOL,
            WLAN_NOTIFICATION_CALLBACK,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.WlanRegisterNotification.restype = wintypes.DWORD

        self.WlanGetProfileList = self._dll.WlanGetProfileList
        self.WlanGetProfileList.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.WlanGetProfileList.restype = wintypes.DWORD

        self.WlanConnect = self._dll.WlanConnect
        self.WlanConnect.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(GUID),
            ctypes.POINTER(WLAN_CONNECTION_PARAMETERS),
            ctypes.c_void_p,
        ]
        self.WlanConnect.restype = wintypes.DWORD

        self.WlanDisconnect = self._dll.WlanDisconnect
        self.WlanDisconnect.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p]
        self.WlanDisconnect.restype = wintypes.DWORD

        self.WlanFreeMemory = self._dll.WlanFreeMemory
        self.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        self.WlanFreeMemory.restype = None
