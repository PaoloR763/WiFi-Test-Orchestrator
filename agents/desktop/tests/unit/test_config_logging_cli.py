from __future__ import annotations

import logging
from pathlib import Path

import pytest

from wto_desktop_agent.cli import parser
from wto_desktop_agent.config import AgentSettings, load_settings
from wto_desktop_agent.logging import JsonFormatter, redact_value
from wto_desktop_agent.platforms.factory import create_platform_adapter


def test_strict_toml_and_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "agent.toml"
    config.write_text(
        '[agent]\nenvironment="test"\nserver_url="http://testserver"\n'
        f'state_dir="{tmp_path.as_posix()}"\nmax_concurrency=1\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("WTO_AGENT_MAX_CONCURRENCY", "3")
    monkeypatch.setenv("WTO_AGENT_WINDOWS_INVENTORY_TIMEOUT_SECONDS", "45")
    settings = load_settings(config, {"max_concurrency": 2})
    assert settings.max_concurrency == 2
    assert settings.windows_inventory_timeout_seconds == 45.0
    assert "token" not in AgentSettings.model_fields


def test_config_rejects_plain_http_and_memory_store_in_production(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError):
        AgentSettings(
            server_url="http://server.example",
            state_dir=tmp_path,
            allow_in_memory_secret_store=True,
        )


def test_cli_has_no_visible_token_argument() -> None:
    assert "--token " not in parser().format_help()
    with pytest.raises(SystemExit):
        parser().parse_args(["enroll", "--display-name", "x", "--token", "secret"])


def test_logging_redacts_nested_secrets_and_exception_text() -> None:
    secret = "wto_ac_1.20000000-0000-4000-8000-000000000001." + "A" * 43
    assert redact_value({"Authorization": f"Bearer {secret}"}) == {"Authorization": "[REDACTED]"}
    record = logging.LogRecord(
        "test",
        logging.ERROR,
        __file__,
        1,
        f"credential={secret}",
        (),
        None,
    )
    formatted = JsonFormatter().format(record)
    assert secret not in formatted
    assert "[REDACTED]" in formatted


def test_in_memory_store_requires_explicit_test_or_development(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AgentSettings(
            environment="production",
            server_url="https://server.example",
            state_dir=tmp_path,
            allow_in_memory_secret_store=True,
        )
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=tmp_path,
        allow_in_memory_secret_store=True,
    )
    assert settings.allow_in_memory_secret_store
    assert not create_platform_adapter(in_memory=True).secret_store.secure
