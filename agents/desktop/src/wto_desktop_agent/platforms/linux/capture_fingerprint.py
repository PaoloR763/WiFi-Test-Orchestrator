from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wto_desktop_agent.platforms.linux.capture import CaptureRequest

_CAPTURE_FINGERPRINT_VERSION = "capture-functional-v2"
_LEGACY_CAPTURE_FINGERPRINT_VERSION = "capture-functional-v1"

# This closed classification is deliberately adjacent to fingerprint creation.
# Adding a CaptureRequest field without deciding whether it changes bytes,
# logical identity, or presentation makes fingerprinting fail closed.
CAPTURE_REQUEST_FIELD_CLASSIFICATION: dict[str, frozenset[str]] = {
    "functional": frozenset(
        {
            "interface",
            "channel",
            "frequency_mhz",
            "width_mhz",
            "duration_seconds",
            "max_size_bytes",
            "capture_format",
            "radiotap",
            "snapshot_length",
        }
    ),
    "logical_identity": frozenset({"task_id", "execution_id", "idempotency_key"}),
    "presentation_non_functional": frozenset(),
}


@dataclass(frozen=True)
class CaptureExecutionPlan:
    provider: str
    method: str
    effective_dumpcap_arguments: tuple[str, ...]
    effective_size_limit_bytes: int
    link_type: str = "IEEE802_11_RADIO"
    snapshot_policy: str = "linux-interface-snapshot-v2"
    rollback_policy: str = "linux-interface-rollback-by-uuid-v2"

    def __post_init__(self) -> None:
        if not self.provider or not self.method:
            raise ValueError("capture execution plan provider is invalid")
        if self.effective_size_limit_bytes <= 0:
            raise ValueError("capture execution plan size limit is invalid")
        if not self.effective_dumpcap_arguments or any(
            not isinstance(argument, str) or "\x00" in argument
            for argument in self.effective_dumpcap_arguments
        ):
            raise ValueError("capture execution plan arguments are invalid")


@dataclass(frozen=True)
class CanonicalCaptureFingerprint:
    version: str
    sha256: str
    document: dict[str, object]


def _assert_capture_request_classification(request: CaptureRequest) -> None:
    categories = tuple(CAPTURE_REQUEST_FIELD_CLASSIFICATION.values())
    classified = frozenset().union(*categories)
    duplicated = {
        field for field in classified if sum(field in category for category in categories) != 1
    }
    actual = frozenset(type(request).model_fields)
    if duplicated or classified != actual:
        missing = sorted(actual - classified)
        stale = sorted(classified - actual)
        raise RuntimeError(
            "CaptureRequest fingerprint classification is incomplete "
            f"(missing={missing}, stale={stale}, duplicated={sorted(duplicated)})"
        )


def _frequency_band(frequency_mhz: int) -> str:
    if 2_400 <= frequency_mhz < 3_000:
        return "2.4-ghz"
    if 3_000 <= frequency_mhz < 5_925:
        return "5-ghz"
    if 5_925 <= frequency_mhz <= 7_125:
        return "6-ghz"
    return "60-ghz"


def canonical_capture_fingerprint(
    request: CaptureRequest,
    plan: CaptureExecutionPlan,
) -> CanonicalCaptureFingerprint:
    _assert_capture_request_classification(request)
    functional = CAPTURE_REQUEST_FIELD_CLASSIFICATION["functional"]
    request_values = request.model_dump(mode="json")
    from wto_desktop_agent.platforms.linux.frequency import capture_channel_definition

    channel_definition = capture_channel_definition(
        frequency_mhz=request.frequency_mhz,
        channel=request.channel,
        width_mhz=request.width_mhz,
    )
    document: dict[str, object] = {
        "version": _CAPTURE_FINGERPRINT_VERSION,
        "request": {field: request_values[field] for field in sorted(functional)},
        "derived": channel_definition.as_fingerprint_document(),
        "capture_semantics": {
            "requested_max_bytes": request.max_size_bytes,
            "effective_dumpcap_limit_bytes": plan.effective_size_limit_bytes,
            "format": request.capture_format,
            "link_type": plan.link_type,
            "radiotap": request.radiotap,
            "snapshot_length": request.snapshot_length,
            "snapshot_policy": plan.snapshot_policy,
            "rollback_policy": plan.rollback_policy,
            "provider": plan.provider,
            "method": plan.method,
            "effective_dumpcap_arguments": list(plan.effective_dumpcap_arguments),
        },
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return CanonicalCaptureFingerprint(
        version=_CAPTURE_FINGERPRINT_VERSION,
        sha256=hashlib.sha256(encoded).hexdigest(),
        document=document,
    )


def canonical_capture_fingerprint_v1(
    request: CaptureRequest,
    plan: CaptureExecutionPlan,
) -> CanonicalCaptureFingerprint:
    """Reproduce the historical fingerprint only for demonstrable 20 MHz reuse."""

    if request.width_mhz != 20:
        raise ValueError("legacy wide-channel fingerprints are ambiguous")
    _assert_capture_request_classification(request)
    functional = CAPTURE_REQUEST_FIELD_CLASSIFICATION["functional"]
    request_values = request.model_dump(mode="json")
    document: dict[str, object] = {
        "version": _LEGACY_CAPTURE_FINGERPRINT_VERSION,
        "request": {field: request_values[field] for field in sorted(functional)},
        "derived": {"band": _frequency_band(request.frequency_mhz)},
        "capture_semantics": {
            "requested_max_bytes": request.max_size_bytes,
            "effective_dumpcap_limit_bytes": plan.effective_size_limit_bytes,
            "format": request.capture_format,
            "link_type": plan.link_type,
            "radiotap": request.radiotap,
            "snapshot_length": request.snapshot_length,
            "snapshot_policy": plan.snapshot_policy,
            "rollback_policy": plan.rollback_policy,
            "provider": plan.provider,
            "method": plan.method,
            "effective_dumpcap_arguments": list(plan.effective_dumpcap_arguments),
        },
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return CanonicalCaptureFingerprint(
        version=_LEGACY_CAPTURE_FINGERPRINT_VERSION,
        sha256=hashlib.sha256(encoded).hexdigest(),
        document=document,
    )
