from __future__ import annotations

import ctypes

import pytest

from wto_desktop_agent.platforms.windows.native_wifi.client import NativeBuffer
from wto_desktop_agent.platforms.windows.native_wifi.errors import NativeWifiError, raise_for_code
from wto_desktop_agent.platforms.windows.native_wifi.structures import (
    DOT11_SSID,
    WLAN_INTERFACE_INFO,
    checked_array,
    parse_ssid,
)


class FakeBindings:
    def __init__(self) -> None:
        self.freed: list[int] = []

    def WlanFreeMemory(self, pointer: ctypes.c_void_p) -> None:  # noqa: N802
        self.freed.append(int(pointer.value or 0))


def test_native_buffer_frees_exactly_once() -> None:
    bindings = FakeBindings()
    buffer = NativeBuffer(bindings, 1234)  # type: ignore[arg-type]
    with buffer as address:
        assert address == 1234
    buffer.release()
    assert bindings.freed == [1234]


def test_native_buffer_frees_once_when_parser_raises() -> None:
    bindings = FakeBindings()
    with pytest.raises(RuntimeError):
        with NativeBuffer(bindings, 1234):  # type: ignore[arg-type]
            raise RuntimeError("synthetic parser failure")
    assert bindings.freed == [1234]


def test_native_buffer_and_counts_fail_closed() -> None:
    with pytest.raises(ValueError, match="null"):
        NativeBuffer(FakeBindings(), 0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="count"):
        checked_array(1, 0, WLAN_INTERFACE_INFO, 65, 64)


def test_ssid_preserves_bytes_and_safe_display() -> None:
    value = DOT11_SSID()
    value.uSSIDLength = 3
    value.ucSSID[:3] = (0x66, 0x6F, 0x80)
    parsed = parse_ssid(value)
    assert parsed.raw == b"fo\x80"
    assert parsed.display is None
    value.uSSIDLength = 33
    with pytest.raises(ValueError, match="SSID"):
        parse_ssid(value)


def test_win32_errors_are_translated_without_localized_text() -> None:
    with pytest.raises(NativeWifiError) as captured:
        raise_for_code("WlanScan", 5)
    assert captured.value.category == "access_denied"
    assert captured.value.code == 5
    assert "Access is denied" not in str(captured.value)
