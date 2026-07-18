from __future__ import annotations

from dataclasses import dataclass

from wto_desktop_agent.domain.capture_policy import (
    SUPPORTED_CAPTURE_WIDTHS_MHZ as SUPPORTED_CAPTURE_WIDTHS_MHZ,
)

SUPPORTED_WIDTHS_BY_BAND: dict[str, frozenset[int]] = {
    "2.4GHz": frozenset({20}),
    "5GHz": SUPPORTED_CAPTURE_WIDTHS_MHZ,
    "6GHz": SUPPORTED_CAPTURE_WIDTHS_MHZ,
    # The mapper still exposes 802.11ad channel information for inventory, but
    # Phase 07 has no complete iw capture command for 60 GHz channel widths.
    "60GHz": frozenset(),
}

IW_WIDTH_TOKENS: dict[int, str] = {20: "HT20", 80: "80", 160: "160"}
CHANNEL_GEOMETRY_VERSION = "linux-channel-geometry-v1"

# These are geometry tables, not a regulatory allowlist.  Policy, wiphy and
# driver support are checked separately before any interface mutation.
_FIVE_GHZ_PRIMARY_CHANNELS = frozenset(
    {
        36,
        40,
        44,
        48,
        52,
        56,
        60,
        64,
        *range(100, 145, 4),
        149,
        153,
        157,
        161,
        165,
        169,
        173,
        177,
    }
)
_SIX_GHZ_PRIMARY_CHANNELS = frozenset({2, *range(1, 234, 4)})
_WIDE_CENTERS_BY_BAND_AND_WIDTH: dict[tuple[str, int], tuple[int, ...]] = {
    ("5GHz", 80): (42, 58, 106, 122, 138, 155, 171),
    ("5GHz", 160): (50, 114, 163),
    ("6GHz", 80): tuple(range(7, 216, 16)),
    ("6GHz", 160): tuple(range(15, 208, 32)),
}
_PRIMARY_OFFSETS_BY_WIDTH: dict[int, tuple[int, ...]] = {
    80: (-6, -2, 2, 6),
    160: (-14, -10, -6, -2, 2, 6, 10, 14),
}


@dataclass(frozen=True)
class LinuxChannelInfo:
    channel: int
    band: str


@dataclass(frozen=True)
class LinuxChannelDefinition:
    band: str
    primary_channel: int
    control_frequency_mhz: int
    width_mhz: int
    center_frequency_1_mhz: int
    center_frequency_2_mhz: int | None
    geometry_version: str = CHANNEL_GEOMETRY_VERSION

    def as_fingerprint_document(self) -> dict[str, object]:
        return {
            "band": self.band,
            "primary_channel": self.primary_channel,
            "control_frequency_mhz": self.control_frequency_mhz,
            "width_mhz": self.width_mhz,
            "center_frequency_1_mhz": self.center_frequency_1_mhz,
            "center_frequency_2_mhz": self.center_frequency_2_mhz,
            "geometry_version": self.geometry_version,
        }


def _channel_frequency_mhz(band: str, channel: int) -> int:
    if band == "5GHz":
        return 5000 + (5 * channel)
    if band == "6GHz":
        return 5935 if channel == 2 else 5950 + (5 * channel)
    raise ValueError("wide channel centers are supported only in 5 and 6 GHz")


def _primary_channels(band: str) -> frozenset[int]:
    if band == "2.4GHz":
        return frozenset(range(1, 15))
    if band == "5GHz":
        return _FIVE_GHZ_PRIMARY_CHANNELS
    if band == "6GHz":
        return _SIX_GHZ_PRIMARY_CHANNELS
    return frozenset()


def capture_channel_definition(
    *, frequency_mhz: int, channel: int, width_mhz: int
) -> LinuxChannelDefinition:
    """Resolve a closed 20/80/160 MHz channel geometry.

    This function deliberately does not answer whether a channel is legal in
    the current country or supported by a particular radio.
    """

    information = frequency_to_channel(frequency_mhz)
    if information is None or information.channel != channel:
        raise ValueError("channel and frequency are not a known matching pair")
    if width_mhz not in SUPPORTED_WIDTHS_BY_BAND[information.band]:
        raise ValueError("capture width is not supported for the selected frequency band")
    if channel not in _primary_channels(information.band):
        raise ValueError("capture control channel is not an aligned primary channel")
    if frequency_mhz == 5935 and width_mhz != 20:
        raise ValueError("5935 MHz channel 2 capture is supported only at 20 MHz")
    if width_mhz == 20:
        return LinuxChannelDefinition(
            band=information.band,
            primary_channel=channel,
            control_frequency_mhz=frequency_mhz,
            width_mhz=width_mhz,
            center_frequency_1_mhz=frequency_mhz,
            center_frequency_2_mhz=None,
        )
    offsets = _PRIMARY_OFFSETS_BY_WIDTH.get(width_mhz)
    centers = _WIDE_CENTERS_BY_BAND_AND_WIDTH.get((information.band, width_mhz))
    if offsets is None or centers is None:
        raise ValueError("capture channel width has no closed geometry table")
    matching = [center for center in centers if channel in {center + offset for offset in offsets}]
    if len(matching) != 1:
        raise ValueError("capture control channel does not belong to one wide-channel block")
    return LinuxChannelDefinition(
        band=information.band,
        primary_channel=channel,
        control_frequency_mhz=frequency_mhz,
        width_mhz=width_mhz,
        center_frequency_1_mhz=_channel_frequency_mhz(information.band, matching[0]),
        center_frequency_2_mhz=None,
    )


def validate_complete_channel_definition(
    *,
    frequency_mhz: int,
    channel: int,
    width_mhz: int,
    center_frequency_1_mhz: int | None,
    center_frequency_2_mhz: int | None,
) -> LinuxChannelDefinition:
    expected = capture_channel_definition(
        frequency_mhz=frequency_mhz,
        channel=channel,
        width_mhz=width_mhz,
    )
    if center_frequency_1_mhz is None:
        raise ValueError("channel definition lacks center_frequency_1")
    if center_frequency_2_mhz is not None:
        raise ValueError("80+80 MHz channel definitions are not supported")
    if center_frequency_1_mhz != expected.center_frequency_1_mhz:
        raise ValueError("channel definition center_frequency_1 is inconsistent")
    return expected


def frequency_to_channel(frequency_mhz: int) -> LinuxChannelInfo | None:
    if frequency_mhz == 2484:
        return LinuxChannelInfo(14, "2.4GHz")
    if 2412 <= frequency_mhz <= 2472 and (frequency_mhz - 2407) % 5 == 0:
        return LinuxChannelInfo((frequency_mhz - 2407) // 5, "2.4GHz")
    if 5000 <= frequency_mhz <= 5895 and (frequency_mhz - 5000) % 5 == 0:
        channel = (frequency_mhz - 5000) // 5
        if 1 <= channel <= 179:
            return LinuxChannelInfo(channel, "5GHz")
    if frequency_mhz == 5935:
        return LinuxChannelInfo(2, "6GHz")
    if 5955 <= frequency_mhz <= 7115 and (frequency_mhz - 5950) % 5 == 0:
        return LinuxChannelInfo((frequency_mhz - 5950) // 5, "6GHz")
    if 58_320 <= frequency_mhz <= 69_120 and (frequency_mhz - 56_160) % 2160 == 0:
        return LinuxChannelInfo((frequency_mhz - 56_160) // 2160, "60GHz")
    return None


def validate_frequency_channel_width(
    *, frequency_mhz: int, channel: int, width_mhz: int
) -> LinuxChannelInfo:
    definition = capture_channel_definition(
        frequency_mhz=frequency_mhz,
        channel=channel,
        width_mhz=width_mhz,
    )
    return LinuxChannelInfo(definition.primary_channel, definition.band)


def iw_width_token(width_mhz: int) -> str:
    try:
        return IW_WIDTH_TOKENS[width_mhz]
    except KeyError as error:
        raise ValueError("capture width is not supported by the iw command policy") from error
