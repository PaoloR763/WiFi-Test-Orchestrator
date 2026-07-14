from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from wto_desktop_agent.domain.telemetry import (
    NormalizedObservation,
    ObservationReason,
    ObservationSource,
)
from wto_desktop_agent.platforms.windows.frequency import frequency_to_channel
from wto_desktop_agent.platforms.windows.phy import phy_type_to_standard

SOURCE = ObservationSource(
    plane="telemetry", producer="test-source", method="fixture", version="1.0.0"
)
NOW = datetime(2026, 7, 12, tzinfo=UTC)


def test_null_never_means_zero() -> None:
    missing = NormalizedObservation.missing(
        "1", SOURCE, NOW, ObservationReason(code="not_exposed_by_platform")
    )
    zero = NormalizedObservation.measured(0, "1", SOURCE, NOW)
    assert missing.value is None
    assert zero.value == 0
    assert missing.availability == "unavailable"
    with pytest.raises(ValidationError):
        NormalizedObservation(
            value=None,
            unit="1",
            source=SOURCE,
            availability="measured",
            confidence="high",
            reason=None,
            collected_at=NOW,
        )


@pytest.mark.parametrize(
    ("frequency", "channel", "band"),
    [
        (2412, 1, "2.4GHz"),
        (2484, 14, "2.4GHz"),
        (5180, 36, "5GHz"),
        (5935, 2, "6GHz"),
        (5955, 1, "6GHz"),
        (7115, 233, "6GHz"),
    ],
)
def test_frequency_mapping(frequency: int, channel: int, band: str) -> None:
    value = frequency_to_channel(frequency)
    assert value is not None
    assert (value.channel, value.band) == (channel, band)


def test_invalid_frequency_is_not_invented() -> None:
    assert frequency_to_channel(2400) is None
    assert frequency_to_channel(5940) is None
    assert frequency_to_channel(7120) is None


def test_phy_mapping_is_explicit_and_unknown_remains_absent() -> None:
    assert phy_type_to_standard(7) == "802.11n"
    assert phy_type_to_standard(10) == "802.11ax"
    assert phy_type_to_standard(999) is None
