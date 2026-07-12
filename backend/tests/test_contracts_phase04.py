from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from wto_backend.api.agent_schemas import (
    AgentCredentialResponse,
    AgentRegistrationRequest,
    DesktopHeartbeatRequest,
    EnrollmentTokenCreateRequest,
    MobilePresenceRequest,
)
from wto_backend.contracts import (
    ContractValidationError,
    canonical_json,
    contract_root,
    validate_contract,
)
from wto_backend.security.agent_credentials import (
    new_agent_credential,
    new_enrollment_token,
    parse_machine_secret,
    verify_secret,
)
from wto_backend.security.secret_replay import SecretReplayCipher


def fixture_manifest() -> tuple[Path, dict[str, object]]:
    root = contract_root() / "examples"
    return root, json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def test_all_normative_python_fixtures() -> None:
    root, manifest = fixture_manifest()
    for entry in manifest["fixtures"]:  # type: ignore[index]
        payload = json.loads((root / entry["path"]).read_text(encoding="utf-8"))
        if entry["valid"]:
            validate_contract(entry["schema"], payload)
        else:
            with pytest.raises(ContractValidationError):
                validate_contract(entry["schema"], payload)


@pytest.mark.parametrize(
    ("fixture", "model"),
    [
        ("agent-registration-request.json", AgentRegistrationRequest),
        ("agent-credential.json", AgentCredentialResponse),
        ("desktop-heartbeat.json", DesktopHeartbeatRequest),
        ("mobile-presence.json", MobilePresenceRequest),
    ],
)
def test_pydantic_models_accept_normative_fixtures(fixture: str, model: object) -> None:
    path = contract_root() / "examples" / "valid" / fixture
    payload = json.loads(path.read_text(encoding="utf-8"))
    model.model_validate(payload)  # type: ignore[attr-defined]


def test_machine_secrets_have_locator_and_independent_hmac() -> None:
    from uuid import uuid4

    locator = uuid4()
    enrollment, enrollment_secret = new_enrollment_token(locator)
    credential, credential_secret = new_agent_credential(locator)
    assert parse_machine_secret(enrollment, prefix="wto_enr_1").locator == locator
    assert parse_machine_secret(credential, prefix="wto_ac_1").locator == locator
    expected = __import__("hmac").new(b"e" * 48, enrollment_secret.encode(), "sha256").digest()
    assert verify_secret("e" * 48, enrollment_secret, expected)
    assert not verify_secret("c" * 48, enrollment_secret, expected)
    assert enrollment_secret != credential_secret


def test_secret_replay_aead_is_bound_to_record() -> None:
    cipher = SecretReplayCipher("s" * 48)
    body = {"schema_version": "1.0.0", "synthetic": True}
    ciphertext, nonce = cipher.encrypt(body, associated_data=b"record-a")
    assert body == cipher.decrypt(ciphertext, nonce, associated_data=b"record-a")
    with pytest.raises(InvalidTag):
        cipher.decrypt(ciphertext, nonce, associated_data=b"record-b")


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_enrollment_platform_restrictions_are_unique() -> None:
    with pytest.raises(ValueError):
        EnrollmentTokenCreateRequest(allowed_platforms=["simulated", "simulated"])
