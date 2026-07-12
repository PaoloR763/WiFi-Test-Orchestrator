from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from wto_backend.config import Settings


def test_configuration_builds_urls_without_exposing_them(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(postgres_password="contains space")
    assert "contains+space" in settings.database_url
    assert settings.celery_broker_url == "redis://redis.invalid:6379/0"


def test_configuration_rejects_unknown_environment(
    settings_factory: Callable[..., Settings],
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(environment="staging")
