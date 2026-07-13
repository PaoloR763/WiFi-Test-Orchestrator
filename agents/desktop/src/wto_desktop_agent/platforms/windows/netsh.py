from __future__ import annotations

import ctypes
import locale
import re
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class NetshInterface:
    name: str | None
    description: str | None
    guid: str | None
    state: str | None
    ssid: str | None
    bssid: str | None
    signal_quality: int | None
    channel: int | None
    receive_rate_mbps: float | None
    transmit_rate_mbps: float | None


_LABELS = {
    "name": {"name", "nombre"},
    "description": {"description", "descripción", "descripcion"},
    "guid": {"guid"},
    "state": {"state", "estado"},
    "ssid": {"ssid"},
    "bssid": {"bssid"},
    "signal": {"signal", "señal", "senal"},
    "channel": {"channel", "canal"},
    "rx": {"receive rate (mbps)", "velocidad de recepción (mbps)", "velocidad de recepcion (mbps)"},
    "tx": {
        "transmit rate (mbps)",
        "velocidad de transmisión (mbps)",
        "velocidad de transmision (mbps)",
    },
}


def decode_netsh(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="strict")
    candidates = ["utf-8", "cp1252"]
    if hasattr(ctypes, "windll"):
        try:
            candidates.append(f"cp{int(ctypes.windll.kernel32.GetOEMCP())}")
        except (AttributeError, OSError, ValueError):
            pass
    preferred = locale.getpreferredencoding(False)
    if preferred:
        candidates.append(preferred)
    for encoding in dict.fromkeys(candidates):
        try:
            return raw.decode(encoding, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    raise ValueError("netsh output encoding is unsupported")


def _canonical_label(label: str) -> str | None:
    normalized = " ".join(label.strip().casefold().split())
    for canonical, variants in _LABELS.items():
        if normalized in variants:
            return canonical
    return None


def parse_netsh_interfaces(raw: bytes) -> list[NetshInterface]:
    text = decode_netsh(raw)
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        label = _canonical_label(match.group(1))
        if label is None:
            continue
        if label == "name" and current:
            blocks.append(current)
            current = {}
        current[label] = match.group(2)
    if current:
        blocks.append(current)
    result: list[NetshInterface] = []
    for block in blocks:
        signal_text = block.get("signal", "")
        signal_match = re.fullmatch(r"\s*(\d{1,3})\s*%\s*", signal_text)
        channel_text = block.get("channel", "")
        channel = int(channel_text) if channel_text.isdigit() else None
        guid = block.get("guid")
        if guid:
            try:
                guid = str(UUID(guid.strip("{}")))
            except ValueError:
                guid = None
        signal_quality = int(signal_match.group(1)) if signal_match else None
        if signal_quality is not None and signal_quality > 100:
            signal_quality = None
        if channel is not None and not 1 <= channel <= 233:
            channel = None
        result.append(
            NetshInterface(
                name=block.get("name"),
                description=block.get("description"),
                guid=guid,
                state=block.get("state"),
                ssid=block.get("ssid") or None,
                bssid=block.get("bssid", "").lower() or None,
                signal_quality=signal_quality,
                channel=channel,
                receive_rate_mbps=_float_or_none(block.get("rx")),
                transmit_rate_mbps=_float_or_none(block.get("tx")),
            )
        )
    return result


def _float_or_none(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value.replace(",", "."))
    except ValueError:
        return None
