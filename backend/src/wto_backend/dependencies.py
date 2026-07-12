from __future__ import annotations

from typing import Protocol

from redis import Redis
from sqlalchemy import Engine, create_engine, text

from wto_backend.artifact_store import LocalFilesystemArtifactStore
from wto_backend.config import Settings


class ReadinessCheck(Protocol):
    def check(self) -> None: ...


class PostgresCheck:
    def __init__(self, database_url: str) -> None:
        self._engine: Engine = create_engine(database_url, pool_pre_ping=True)

    def check(self) -> None:
        with self._engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def close(self) -> None:
        self._engine.dispose()


class RedisCheck:
    def __init__(self, host: str, port: int, database: int) -> None:
        self._client: Redis[bytes] = Redis(host=host, port=port, db=database, socket_timeout=2)

    def check(self) -> None:
        if not self._client.ping():
            raise ConnectionError("redis ping failed")

    def close(self) -> None:
        self._client.close()


class ArtifactStoreCheck:
    def __init__(self, store: LocalFilesystemArtifactStore) -> None:
        self._store = store

    def check(self) -> None:
        self._store.check_readiness()


class RuntimeDependencies:
    def __init__(self, settings: Settings) -> None:
        self.postgres = PostgresCheck(settings.database_url)
        self.redis = RedisCheck(settings.redis_host, settings.redis_port, settings.redis_db)
        self.artifact_store = ArtifactStoreCheck(
            LocalFilesystemArtifactStore(settings.artifact_root)
        )

    def checks(self) -> dict[str, ReadinessCheck]:
        return {
            "postgresql": self.postgres,
            "redis": self.redis,
            "artifact_store": self.artifact_store,
        }

    def close(self) -> None:
        self.postgres.close()
        self.redis.close()
