from __future__ import annotations

_PHY_STANDARDS = {
    1: "802.11-fhss",
    2: "802.11-dsss",
    3: "802.11-ir",
    4: "802.11a",
    5: "802.11b",
    6: "802.11g",
    7: "802.11n",
    8: "802.11ac",
    9: "802.11ad",
    10: "802.11ax",
    11: "802.11be",
}


def phy_type_to_standard(phy_type: int) -> str | None:
    return _PHY_STANDARDS.get(phy_type)
