from __future__ import annotations

from wto_backend.audit import sanitize_metadata


def test_audit_metadata_allowlist_removes_secret_material() -> None:
    result = sanitize_metadata(
        {
            "session_id": "safe-id",
            "password": "do-not-store",
            "token_digest": "do-not-store",
            "authorization": "do-not-store",
            "unknown": "do-not-store",
        }
    )
    assert result == {"session_id": "safe-id"}
