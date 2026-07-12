from __future__ import annotations

import json

import pytest

from wto_desktop_agent.application.capabilities import CapabilityRegistry
from wto_desktop_agent.infrastructure.contracts import (
    ContractValidationError,
    contract_root,
    schema_store,
    validate_contract,
)
from wto_desktop_agent.platforms.simulated.adapter import SimulatedPlatformAdapter


def test_all_25_golden_fixtures_use_14_packaged_schemas() -> None:
    root = contract_root()
    schemas, _ = schema_store()
    manifest = json.loads((root / "examples" / "manifest.json").read_text(encoding="utf-8"))
    assert len(schemas) == 14
    assert len(manifest["fixtures"]) == 25
    for entry in manifest["fixtures"]:
        payload = json.loads((root / "examples" / entry["path"]).read_text(encoding="utf-8"))
        if entry["valid"]:
            validate_contract(entry["schema"], payload)
        else:
            with pytest.raises(ContractValidationError):
                validate_contract(entry["schema"], payload)


def test_capability_registry_has_exactly_15_ids_and_seven_dimensions() -> None:
    entries = CapabilityRegistry(SimulatedPlatformAdapter()).entries()
    assert len(entries) == 15
    expected = {
        "technical_support",
        "implementation_status",
        "permission_requirement",
        "user_interaction",
        "background_execution",
        "provider",
        "limitations",
    }
    for entry in entries:
        assert set(entry) - {"id", "version"} == expected
        assert "availability_reason" not in json.dumps(entry)
        assert entry["implementation_status"]["status"] != "implemented"  # type: ignore[index]
