from __future__ import annotations


def background_continuous_override(service_state: str) -> dict[str, object]:
    installed = service_state != "not_installed"
    running = service_state == "running"
    return {
        "technical_support": {"status": "supported", "reason": None},
        "implementation_status": {"status": "implemented", "reason": None},
        "permission_requirement": {
            "status": "required",
            "permissions": ["service.install"],
            "reason": None if installed else {"code": "permission_missing"},
        },
        "user_interaction": {
            "status": "conditional",
            "reason": None if installed else {"code": "user_interaction_required"},
        },
        "background_execution": {
            "status": "continuous" if running else "deferred",
            "reason": None if running else {"code": "blocked", "detail": service_state},
        },
        "provider": {
            "status": "available" if installed else "unavailable",
            "implementations": (
                [
                    {
                        "provider_id": "windows-service",
                        "provider_version": "1.0.0",
                        "method": "scm",
                    }
                ]
                if installed
                else []
            ),
            "reason": None if installed else {"code": "provider_unavailable"},
        },
        "limitations": {
            "status": "known",
            "max_concurrency": 1,
            "reason": {"code": "unknown", "detail": "Single installed service instance"},
        },
    }
