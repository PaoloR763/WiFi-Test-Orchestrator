from __future__ import annotations

import unicodedata
from typing import Literal, cast
from uuid import UUID

CaptureInterfaceType = Literal["managed", "monitor", "AP", "mesh"]
IwInterfaceTypeCommandToken = Literal["managed", "monitor", "mesh", "__ap"]
IW_INTERFACE_TYPE_COMMAND_MAPPER_VERSION = "iw-interface-type-command-v1"

_IW_COMMAND_TOKEN_BY_CANONICAL_INTERFACE_TYPE: dict[
    CaptureInterfaceType, IwInterfaceTypeCommandToken
] = {
    "managed": "managed",
    "monitor": "monitor",
    "mesh": "mesh",
    "AP": "__ap",
}
_CANONICAL_INTERFACE_TYPES = frozenset(_IW_COMMAND_TOKEN_BY_CANONICAL_INTERFACE_TYPE)
_LEGACY_INTERFACE_TYPE_ALIASES = {"mesh point": "mesh"}
_MAXIMUM_CONNECTION_ID_BYTES = 255


def parse_capture_interface_type(value: object) -> CaptureInterfaceType:
    """Return the internal canonical type for an observed ``iw`` value.

    ``mesh point`` is the sole accepted provider/legacy spelling. Deliberately
    do not strip or case-fold here: accepting another lexical spelling would
    make a snapshot look restorable when the command model cannot emit it.
    Canonical values are journal data and presentation labels, never argv.
    """

    if type(value) is not str:
        raise ValueError("capture interface type is not a string")
    normalized = _LEGACY_INTERFACE_TYPE_ALIASES.get(value, value)
    if normalized not in _CANONICAL_INTERFACE_TYPES:
        raise ValueError("capture interface type is not safely restorable")
    return cast(CaptureInterfaceType, normalized)


def canonical_interface_type_to_iw_command_token(
    value: object,
) -> IwInterfaceTypeCommandToken:
    """Translate a canonical snapshot type to the exact supported ``iw`` token."""

    if type(value) is not str or value not in _CANONICAL_INTERFACE_TYPES:
        raise ValueError("canonical interface type has no supported iw command token")
    canonical = cast(CaptureInterfaceType, value)
    return _IW_COMMAND_TOKEN_BY_CANONICAL_INTERFACE_TYPE[canonical]


def validate_networkmanager_uuid(value: object) -> str:
    """Validate NetworkManager's stable identity without normalizing it."""

    if type(value) is not str:
        raise ValueError("NetworkManager connection UUID is not a string")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ValueError("NetworkManager connection UUID is invalid") from error
    if str(parsed) != value:
        raise ValueError("NetworkManager connection UUID is not canonical")
    return value


def validate_networkmanager_connection_id(value: object) -> str:
    """Validate a display-only NetworkManager connection ID.

    IDs are never used as command selectors. The validation only bounds journal
    metadata and rejects control characters; spaces, punctuation and Unicode
    remain valid NetworkManager display names.
    """

    if type(value) is not str or not value:
        raise ValueError("NetworkManager connection ID is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("NetworkManager connection ID is not valid Unicode") from error
    if len(encoded) > _MAXIMUM_CONNECTION_ID_BYTES:
        raise ValueError("NetworkManager connection ID is too long")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("NetworkManager connection ID contains a control character")
    return value
