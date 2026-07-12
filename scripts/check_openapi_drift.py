from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute
from openapi_spec_validator import validate

from wto_backend.api.agent_schemas import (
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    CredentialMetadata,
    DesktopHeartbeatRequest,
    EnrollmentTokenCreateRequest,
    EnrollmentTokenResponse,
    MobilePresenceRequest,
    PresenceResponse,
    RotationActivateRequest,
    RotationActivateResponse,
    RotationCreateRequest,
    RotationCreateResponse,
)
from wto_backend.main import create_app

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "shared" / "contracts" / "openapi" / "openapi.json"
BUNDLED_CANDIDATES = (
    ROOT / "backend" / "src" / "wto_backend" / "contract_data" / "openapi-bundled.json",
    ROOT / "src" / "wto_backend" / "contract_data" / "openapi-bundled.json",
)
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
MODEL_OPERATIONS: dict[str, tuple[object | None, object]] = {
    "createEnrollmentToken": (EnrollmentTokenCreateRequest, EnrollmentTokenResponse),
    "createRecoveryEnrollmentToken": (None, EnrollmentTokenResponse),
    "registerAgent": (AgentRegistrationRequest, AgentRegistrationResponse),
    "listAgentCredentials": (None, list[CredentialMetadata]),
    "createAgentCredentialRotation": (RotationCreateRequest, RotationCreateResponse),
    "activateAgentCredentialRotation": (
        RotationActivateRequest,
        RotationActivateResponse,
    ),
    "publishCapabilityManifest": (dict[str, Any], dict[str, Any]),
    "desktopHeartbeat": (DesktopHeartbeatRequest, PresenceResponse),
    "mobilePresence": (MobilePresenceRequest, PresenceResponse),
}


def canonical_operations(document: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (path, method.upper())
        for path, item in document["paths"].items()
        for method in item
        if method in HTTP_METHODS
    }


def main() -> None:
    document = json.loads(CANONICAL.read_text(encoding="utf-8"))
    bundled_path = next((path for path in BUNDLED_CANDIDATES if path.exists()), None)
    if bundled_path is None:
        raise SystemExit("Bundled canonical OpenAPI is missing")
    bundled = json.loads(bundled_path.read_text(encoding="utf-8"))
    validate(bundled)
    runtime = {
        (route.path, method)
        for route in create_app().routes
        if isinstance(route, APIRoute) and route.include_in_schema
        for method in route.methods
        if method in {item.upper() for item in HTTP_METHODS}
    }
    expected = canonical_operations(document)
    if runtime != expected:
        missing = sorted(expected - runtime)
        extra = sorted(runtime - expected)
        raise SystemExit(f"OpenAPI route drift: missing={missing}, extra={extra}")
    schemes = document["components"]["securitySchemes"]
    required_schemes = {
        "UserBearerAuth",
        "AgentBearerAuth",
        "AgentPendingCredentialAuth",
    }
    if not required_schemes.issubset(schemes):
        raise SystemExit("OpenAPI security scheme drift")
    runtime_by_key = {
        (route.path, method): route
        for route in create_app().routes
        if isinstance(route, APIRoute) and route.include_in_schema
        for method in route.methods
        if method in {item.upper() for item in HTTP_METHODS}
    }
    for path, item in document["paths"].items():
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            if "responses" not in operation:
                raise SystemExit(f"{method.upper()} {path}: responses missing")
            route = runtime_by_key.get((path, method.upper()))
            if route is None:
                raise SystemExit(f"{method.upper()} {path}: runtime operation missing")
            success_status = str(route.status_code or 200)
            if success_status not in operation["responses"]:
                raise SystemExit(
                    f"{method.upper()} {path}: runtime status {success_status} missing"
                )
            if operation["operationId"] in MODEL_OPERATIONS:
                expected_request, expected_response = MODEL_OPERATIONS[operation["operationId"]]
                runtime_request = route.body_field.type_ if route.body_field else None
                if runtime_request != expected_request:
                    raise SystemExit(f"{method.upper()} {path}: runtime request model drift")
                if route.response_model != expected_response:
                    raise SystemExit(f"{method.upper()} {path}: runtime response model drift")
            security = operation.get("security", [])
            security_names = {name for requirement in security for name in requirement}
            header_refs = {
                parameter["$ref"].rsplit("/", 1)[-1]
                for parameter in operation.get("parameters", [])
                if "$ref" in parameter
                and document["components"]["parameters"]
                .get(parameter["$ref"].rsplit("/", 1)[-1], {})
                .get("in")
                == "header"
            }
            if security_names & {"AgentBearerAuth", "AgentPendingCredentialAuth"}:
                required_agent_headers = {
                    "AgentTimestamp",
                    "AgentNonce",
                    "AgentProtocol",
                    "CorrelationIdRequest",
                }
                if not required_agent_headers.issubset(header_refs):
                    raise SystemExit(f"{method.upper()} {path}: agent header drift")
            if "IdempotencyKey" in header_refs and "requestBody" not in operation:
                raise SystemExit(f"{method.upper()} {path}: idempotency without request payload")
            for code, response in operation["responses"].items():
                if (
                    code.startswith(("4", "5"))
                    and response.get("$ref") != "#/components/responses/Error"
                ):
                    raise SystemExit(f"{method.upper()} {path} {code}: ErrorEnvelope ref missing")
    print(f"OpenAPI runtime drift check passed for {len(expected)} operations.")


if __name__ == "__main__":
    main()
