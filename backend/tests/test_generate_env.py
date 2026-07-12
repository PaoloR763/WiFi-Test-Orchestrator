from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_generate_env() -> ModuleType:
    script = next(
        candidate
        for parent in Path(__file__).resolve().parents
        if (candidate := parent / "scripts" / "generate_env.py").is_file()
    )
    spec = importlib.util.spec_from_file_location("generate_env", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generate_env = load_generate_env()


def env_values(content: bytes) -> dict[str, str]:
    return {
        key: value
        for line in content.decode("utf-8").splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }


def test_add_missing_preserves_existing_bytes_and_is_idempotent(
    tmp_path: Path, monkeypatch: object, capsys: object
) -> None:
    target = tmp_path / ".env"
    original = (
        b"# preserve comments and CRLF\r\n"
        b"WTO_JWT_SIGNING_KEY=do-not-rotate\r\n"
        b"WTO_ENROLLMENT_TOKEN_HMAC_KEY=existing-phase04-value\r\n"
        b"CUSTOM_VALUE=spaces are preserved  \r\n"
    )
    target.write_bytes(original)
    monkeypatch.setattr(generate_env, "TARGET", target)  # type: ignore[attr-defined]

    generate_env.main(["--add-missing"])
    upgraded = target.read_bytes()
    first_output = capsys.readouterr().out  # type: ignore[attr-defined]
    values = env_values(upgraded)

    assert upgraded.startswith(original)
    assert values["WTO_JWT_SIGNING_KEY"] == "do-not-rotate"
    assert values["WTO_ENROLLMENT_TOKEN_HMAC_KEY"] == "existing-phase04-value"
    assert values["CUSTOM_VALUE"] == "spaces are preserved  "
    assert set(generate_env.PHASE04_SECRET_KEYS) <= values.keys()
    assert values["WTO_AGENT_CREDENTIAL_HMAC_KEY"] not in first_output
    assert values["WTO_SECRET_REPLAY_ENCRYPTION_KEY"] not in first_output
    assert "Added 2 missing Phase 04 secret variable(s)" in first_output

    generate_env.main(["--add-missing"])
    second_output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert target.read_bytes() == upgraded
    assert "No Phase 04 secrets were missing" in second_output
