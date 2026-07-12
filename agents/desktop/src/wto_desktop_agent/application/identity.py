from __future__ import annotations

import hashlib
from datetime import UTC
from typing import Any
from uuid import UUID, uuid4

from wto_desktop_agent import __version__
from wto_desktop_agent.domain.errors import (
    IdentityNotEnrolledError,
    SecureStoreUnavailableError,
)
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore
from wto_desktop_agent.ports.platform import PlatformAdapter
from wto_desktop_agent.ports.time import Clock
from wto_desktop_agent.ports.transport import AgentTransport


def credential_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class IdentityManager:
    def __init__(
        self,
        store: SQLiteStore,
        platform: PlatformAdapter,
        transport: AgentTransport,
        clock: Clock,
        *,
        allow_insecure_development_store: bool = False,
    ) -> None:
        self.store = store
        self.platform = platform
        self.transport = transport
        self.clock = clock
        self.allow_insecure_development_store = allow_insecure_development_store

    def _require_secure_store(self) -> None:
        if not self.platform.secret_store.secure and not self.allow_insecure_development_store:
            raise SecureStoreUnavailableError("a persistent secure credential store is required")

    async def enroll(self, *, token: str, display_name: str) -> dict[str, Any]:
        self._require_secure_store()
        existing = self.store.identity()
        if existing and existing.get("agent_id"):
            raise IdentityNotEnrolledError("agent is already enrolled")
        reported_at = (
            str(existing["enrollment_reported_at"])
            if existing
            else self.clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
        identity = self.store.ensure_identity(
            installation_id=(str(existing["installation_id"]) if existing else str(uuid4())),
            display_name=display_name,
            platform=self.platform.platform_id,
            platform_version=self.platform.platform_version,
            agent_version=__version__,
            enrollment_idempotency_key=(
                str(existing["enrollment_idempotency_key"]) if existing else str(uuid4())
            ),
            enrollment_reported_at=reported_at,
        )
        key = UUID(str(identity["enrollment_idempotency_key"]))
        payload = {
            "schema_version": "1.0.0",
            "idempotency_key": str(key),
            "enrollment_token": token,
            "installation_id": str(identity["installation_id"]),
            "display_name": str(identity["display_name"]),
            "platform": str(identity["platform"]),
            "platform_version": str(identity["platform_version"]),
            "agent_version": str(identity["agent_version"]),
            "protocol_min_version": "1.0.0",
            "protocol_max_version": "1.0.0",
            "agent_reported_at": str(identity["enrollment_reported_at"]),
        }
        try:
            response = await self.transport.enroll(payload, key)
        finally:
            payload.pop("enrollment_token", None)
        credential = str(response["credential"]["credential"])
        credential_id = str(response["credential"]["credential_id"])
        reference = f"credential.active.{credential_id}"
        self.platform.secret_store.put(reference, credential)
        self.store.update_identity(
            {
                "device_id": str(response["device_id"]),
                "agent_id": str(response["agent_id"]),
                "protocol_version": str(response["protocol_version"]),
                "enrolled_at": str(response["server_received_at"]),
                "active_credential_id": credential_id,
                "active_credential_version": int(response["credential"]["credential_version"]),
                "active_credential_fingerprint": credential_fingerprint(credential),
                "active_credential_ref": reference,
                "active_credential_expires_at": str(response["credential"]["expires_at"]),
                "rotation_state": "none",
            }
        )
        del credential
        del token
        enrolled = self.store.identity()
        assert enrolled is not None
        return enrolled

    def active_credential(self) -> str:
        identity = self.store.identity()
        if not identity or not identity.get("agent_id") or identity.get("revoked_at"):
            raise IdentityNotEnrolledError("agent has no active identity")
        reference = identity.get("active_credential_ref")
        if not reference:
            raise IdentityNotEnrolledError("agent has no active credential metadata")
        credential = self.platform.secret_store.get(str(reference))
        if credential is None:
            raise IdentityNotEnrolledError("active credential is unavailable")
        if credential_fingerprint(credential) != identity.get("active_credential_fingerprint"):
            raise IdentityNotEnrolledError("active credential fingerprint mismatch")
        return credential

    async def rotate(self) -> dict[str, Any]:
        self._require_secure_store()
        identity = self.store.identity()
        if not identity or not identity.get("agent_id"):
            raise IdentityNotEnrolledError("agent is not enrolled")
        state = str(identity["rotation_state"])
        if state == "activated":
            self._finalize_activated(identity)
            identity = self.store.identity()
            assert identity is not None
            return identity
        if state == "none":
            self.store.update_identity(
                {
                    "rotation_idempotency_key": str(uuid4()),
                    "activation_idempotency_key": str(uuid4()),
                    "rotation_state": "requested",
                }
            )
            identity = self.store.identity()
            assert identity is not None
            state = "requested"
        if state == "requested":
            active = self.active_credential()
            rotation_key = UUID(str(identity["rotation_idempotency_key"]))
            response = await self.transport.create_rotation(
                active,
                {"schema_version": "1.0.0", "idempotency_key": str(rotation_key)},
                rotation_key,
            )
            pending = str(response["pending_credential"]["credential"])
            pending_id = str(response["pending_credential"]["credential_id"])
            pending_ref = f"credential.pending.{pending_id}"
            self.platform.secret_store.put(pending_ref, pending)
            self.store.update_identity(
                {
                    "pending_credential_id": pending_id,
                    "pending_credential_version": int(
                        response["pending_credential"]["credential_version"]
                    ),
                    "pending_credential_fingerprint": credential_fingerprint(pending),
                    "pending_credential_ref": pending_ref,
                    "pending_credential_expires_at": str(
                        response["pending_credential"]["expires_at"]
                    ),
                    "rotation_id": str(response["rotation_id"]),
                    "rotation_state": "pending_stored",
                }
            )
            del pending
            del active
            identity = self.store.identity()
            assert identity is not None
            state = "pending_stored"
        if state in {"pending_stored", "activation_uncertain"}:
            pending_ref = str(identity["pending_credential_ref"])
            pending_value = self.platform.secret_store.get(pending_ref)
            if pending_value is None or credential_fingerprint(pending_value) != identity.get(
                "pending_credential_fingerprint"
            ):
                raise IdentityNotEnrolledError("pending credential is unavailable")
            activation_key = UUID(str(identity["activation_idempotency_key"]))
            rotation_id = UUID(str(identity["rotation_id"]))
            self.store.update_identity({"rotation_state": "activation_uncertain"})
            await self.transport.activate_rotation(
                pending_value,
                rotation_id,
                {"schema_version": "1.0.0", "idempotency_key": str(activation_key)},
                activation_key,
            )
            old_ref = str(identity["active_credential_ref"])
            self.store.update_identity(
                {
                    "previous_credential_id": identity["active_credential_id"],
                    "previous_credential_ref": old_ref,
                    "active_credential_id": identity["pending_credential_id"],
                    "active_credential_version": identity["pending_credential_version"],
                    "active_credential_fingerprint": identity["pending_credential_fingerprint"],
                    "active_credential_ref": pending_ref,
                    "active_credential_expires_at": identity["pending_credential_expires_at"],
                    "rotation_state": "activated",
                }
            )
            del pending_value
            identity = self.store.identity()
            assert identity is not None
            self._finalize_activated(identity)
        result = self.store.identity()
        assert result is not None
        return result

    def _finalize_activated(self, identity: dict[str, Any]) -> None:
        previous = identity.get("previous_credential_ref")
        active = identity.get("active_credential_ref")
        if previous and previous != active:
            self.platform.secret_store.delete(str(previous))
        self.store.update_identity(
            {
                "previous_credential_id": None,
                "previous_credential_ref": None,
                "pending_credential_id": None,
                "pending_credential_version": None,
                "pending_credential_fingerprint": None,
                "pending_credential_ref": None,
                "pending_credential_expires_at": None,
                "rotation_id": None,
                "rotation_idempotency_key": None,
                "activation_idempotency_key": None,
                "rotation_state": "none",
            }
        )

    def mark_revoked(self) -> None:
        identity = self.store.identity()
        if not identity:
            return
        for field in (
            "active_credential_ref",
            "pending_credential_ref",
            "previous_credential_ref",
        ):
            reference = identity.get(field)
            if reference:
                self.platform.secret_store.delete(str(reference))
        self.store.update_identity(
            {
                "revoked_at": self.clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "active_credential_ref": None,
                "pending_credential_ref": None,
                "previous_credential_ref": None,
                "rotation_state": "revoked",
            }
        )
