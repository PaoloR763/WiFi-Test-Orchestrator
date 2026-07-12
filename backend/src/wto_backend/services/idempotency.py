from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from wto_backend.domain.models import IdempotencyRecord, SecretReplay
from wto_backend.repositories.agents import AgentRepository
from wto_backend.security.secret_replay import SecretReplayCipher
from wto_backend.services.errors import (
    IdempotencyConflictError,
    IdempotencyInProgressError,
    SecretReplayExpiredError,
)


@dataclass(frozen=True)
class IdempotencyStart:
    record: IdempotencyRecord
    replay_body: dict[str, Any] | None
    replay_status: int | None
    is_new: bool


class IdempotencyService:
    pending_window = timedelta(minutes=15)
    terminal_retention = timedelta(days=7)
    secret_window = timedelta(minutes=15)

    def __init__(self, session: Session, cipher: SecretReplayCipher) -> None:
        self.session = session
        self.repo = AgentRepository(session)
        self.cipher = cipher

    @staticmethod
    def fingerprint(payload: bytes) -> bytes:
        return hashlib.sha256(payload).digest()

    @staticmethod
    def _lock_id(scope: str) -> int:
        raw = hashlib.sha256(scope.encode("utf-8")).digest()[:8]
        return int.from_bytes(raw, signed=True)

    def begin(
        self,
        *,
        principal_type: str,
        principal_id: UUID,
        operation_id: str,
        idempotency_key: UUID,
        request_fingerprint: bytes,
        secret_response: bool,
    ) -> IdempotencyStart:
        scope = f"{principal_type}:{principal_id}:{operation_id}:{idempotency_key}"
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": self._lock_id(scope)},
        )
        record = self.repo.idempotency(
            principal_type=principal_type,
            principal_id=principal_id,
            operation_id=operation_id,
            idempotency_key=idempotency_key,
            lock=True,
        )
        now = datetime.now(UTC)
        if record is None:
            record = IdempotencyRecord(
                principal_type=principal_type,
                principal_id=principal_id,
                operation_id=operation_id,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                state="pending",
                created_at=now,
                updated_at=now,
                expires_at=now + self.terminal_retention,
            )
            self.session.add(record)
            self.session.flush()
            return IdempotencyStart(record, None, None, True)
        if record.request_fingerprint != request_fingerprint:
            raise IdempotencyConflictError
        if record.state == "pending":
            if record.updated_at + self.pending_window <= now:
                record.state = "failed"
                record.updated_at = now
                self.session.flush()
            else:
                raise IdempotencyInProgressError
        if secret_response:
            replay = self.repo.secret_replay(record.id)
            if replay is None or replay.expires_at <= now:
                raise SecretReplayExpiredError
            body = self.cipher.decrypt(
                replay.ciphertext, replay.nonce, associated_data=record.id.bytes
            )
            return IdempotencyStart(record, body, record.response_status, False)
        if record.response_body is None or record.response_status is None:
            raise IdempotencyInProgressError
        return IdempotencyStart(record, record.response_body, record.response_status, False)

    def complete_public(
        self, record: IdempotencyRecord, *, body: dict[str, Any], status: int
    ) -> None:
        now = datetime.now(UTC)
        record.state = "completed"
        record.response_body = body
        record.response_status = status
        record.updated_at = now
        record.expires_at = now + self.terminal_retention

    def complete_secret(
        self, record: IdempotencyRecord, *, body: dict[str, Any], status: int
    ) -> None:
        now = datetime.now(UTC)
        ciphertext, nonce = self.cipher.encrypt(body, associated_data=record.id.bytes)
        record.state = "completed"
        record.response_status = status
        record.response_body = {"secret_response": True}
        record.updated_at = now
        record.expires_at = now + self.terminal_retention
        self.session.add(
            SecretReplay(
                idempotency_record_id=record.id,
                ciphertext=ciphertext,
                nonce=nonce,
                encryption_key_version=self.cipher.key_version,
                expires_at=now + self.secret_window,
            )
        )
