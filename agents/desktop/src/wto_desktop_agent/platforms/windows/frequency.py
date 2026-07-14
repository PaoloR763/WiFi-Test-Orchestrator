from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChannelInfo:
    frequency_mhz: int
    channel: int
    band: str


def frequency_to_channel(frequency_mhz: int) -> ChannelInfo | None:
    if frequency_mhz == 2484:
        return ChannelInfo(frequency_mhz, 14, "2.4GHz")
    if 2412 <= frequency_mhz <= 2472 and (frequency_mhz - 2407) % 5 == 0:
        channel = (frequency_mhz - 2407) // 5
        if 1 <= channel <= 13:
            return ChannelInfo(frequency_mhz, channel, "2.4GHz")
    if frequency_mhz == 5935:
        return ChannelInfo(frequency_mhz, 2, "6GHz")
    if 5955 <= frequency_mhz <= 7115 and (frequency_mhz - 5950) % 5 == 0:
        channel = (frequency_mhz - 5950) // 5
        if 1 <= channel <= 233:
            return ChannelInfo(frequency_mhz, channel, "6GHz")
    if 5000 <= frequency_mhz <= 5895 and (frequency_mhz - 5000) % 5 == 0:
        channel = (frequency_mhz - 5000) // 5
        if 1 <= channel <= 179:
            return ChannelInfo(frequency_mhz, channel, "5GHz")
    return None
