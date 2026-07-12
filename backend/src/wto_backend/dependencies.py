from __future__ import annotations

from typing import Protocol

from redis import Redis
from sqlalchemy import Engine, text

from wto_backend.artifact_store import LocalFilesystemArtifactStore
from wto_backend.config import Settings
from wto_backend.db.session import Database


class ReadinessCheck(Protocol):
    def check(self) -> None: ...


class PostgresCheck:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def check(self) -> None:
        with self._engine.connect() as connection:
            connection.execute(text("SELECT 1"))


class RedisCheck:
    def __init__(self, client: Redis[bytes]) -> None:
        self._client = client

    def check(self) -> None:
        if not self._client.ping():
            raise ConnectionError("redis ping failed")


class ArtifactStoreCheck:
    def __init__(self, store: LocalFilesystemArtifactStore) -> None:
        self._store = store

    def check(self) -> None:
        self._store.check_readiness()


class RuntimeDependencies:
    def __init__(self, settings: Settings) -> None:
        self.database = Database(settings.database_url)
        self.redis_client: Redis[bytes] = Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            socket_timeout=2,
        )
        self.postgres = PostgresCheck(self.database.engine)
        self.redis = RedisCheck(self.redis_client)
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
        self.database.close()
        self.redis_client.close()
