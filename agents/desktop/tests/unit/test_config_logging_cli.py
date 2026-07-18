from __future__ import annotations

import logging
import os
import re
import stat
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

import wto_desktop_agent.cli as cli_module
from wto_desktop_agent.application.doctor import DoctorService
from wto_desktop_agent.cli import _prepare_state_directory, parser
from wto_desktop_agent.config import AgentSettings, load_settings
from wto_desktop_agent.domain.capture_policy import SUPPORTED_CAPTURE_WIDTHS_MHZ
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.logging import JsonFormatter, redact_value
from wto_desktop_agent.platforms.factory import create_platform_adapter
from wto_desktop_agent.platforms.simulated.adapter import SimulatedPlatformAdapter


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


def test_capture_width_allowlist_matches_phase_07_iw_policy() -> None:
    state_dir = Path("/var/lib/wto-agent")
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=state_dir,
        allowed_capture_widths_mhz=frozenset({20, 80, 160}),
    )
    assert settings.allowed_capture_widths_mhz == frozenset({20, 80, 160})

    for unsupported in (40, 320, 2160):
        with pytest.raises(ValueError, match="unsupported width"):
            AgentSettings(
                environment="test",
                server_url="http://testserver",
                state_dir=state_dir,
                allowed_capture_widths_mhz=frozenset({unsupported}),
            )


def test_capture_node_runbook_toml_uses_the_runtime_width_policy() -> None:
    repository_root = Path(__file__).resolve().parents[4]
    runbook = (repository_root / "docs" / "phase07" / "capture-node-runbook.md").read_text(
        encoding="utf-8"
    )
    matched = re.search(r"```toml\s*(.*?)```", runbook, flags=re.DOTALL)
    assert matched is not None
    documented = tomllib.loads(matched.group(1))

    assert frozenset(documented["allowed_capture_widths_mhz"]) == (SUPPORTED_CAPTURE_WIDTHS_MHZ)
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=Path("/var/lib/wto-agent-capture"),
        **documented,
    )
    assert settings.allowed_capture_widths_mhz == SUPPORTED_CAPTURE_WIDTHS_MHZ


def test_doctor_does_not_create_or_migrate_sqlite(tmp_path: Path) -> None:
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=tmp_path,
    )
    path = tmp_path / "agent.sqlite3"
    absent = DoctorService(
        settings,
        SQLiteStore(path),
        SimulatedPlatformAdapter(),
    ).run()
    assert {item.name: item for item in absent}["sqlite"].status == "BLOCKED"
    assert not path.exists()

    store = SQLiteStore(path)
    store.initialize()
    with store.connection() as connection:
        connection.execute("DROP TABLE windows_network_operations")
        connection.execute("DELETE FROM schema_migrations WHERE version=2")
        connection.execute("PRAGMA user_version=1")
    checks = DoctorService(settings, store, SimulatedPlatformAdapter()).run()

    assert {item.name: item for item in checks}["sqlite"].status == "BLOCKED"
    with store._connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    assert not path.with_suffix(path.suffix + ".pre-migrate.bak").exists()


@pytest.mark.asyncio
async def test_cli_doctor_does_not_bootstrap_an_absent_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    config = tmp_path / "agent.toml"
    config.write_text(
        '[agent]\nenvironment="test"\nserver_url="http://testserver"\n'
        f'state_dir="{state.as_posix()}"\nallow_in_memory_secret_store=true\n',
        encoding="utf-8",
    )

    def unexpected_platform(**_kwargs: object) -> None:
        raise AssertionError("doctor must not compose a platform over an absent database")

    monkeypatch.setattr(cli_module, "create_platform_adapter", unexpected_platform)
    result = await cli_module._run(SimpleNamespace(command="doctor", config=config, as_json=True))

    assert result == 1
    assert not (state / "agent.sqlite3").exists()


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


def test_non_linux_state_directory_preparation_preserves_portable_mkdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "nested" / "state"
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=state,
    )
    monkeypatch.setattr(sys, "platform", "win32")

    _prepare_state_directory(settings)

    assert state.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes are required")
def test_linux_prepares_state_and_artifact_siblings_independently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts-on-independent-root"
    settings = AgentSettings(
        environment="test",
        server_url="http://testserver",
        state_dir=state,
        artifacts_dir=artifacts,
    )
    monkeypatch.setattr(sys, "platform", "linux")

    _prepare_state_directory(settings)

    assert state.is_dir()
    assert artifacts.is_dir()
    assert not (state / "artifacts").exists()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifacts.stat().st_mode) == 0o700
