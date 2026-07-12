from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from wto_backend.logging import correlation_id_context
from wto_backend.services.errors import DomainError

logger = logging.getLogger(__name__)


def error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    correlation_id = correlation_id_context.get() or "unavailable"
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details,
                "correlation_id": correlation_id,
            }
        },
        headers=headers,
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, error: StarletteHTTPException) -> JSONResponse:
        messages = {
            404: ("resource_not_found", "The requested resource was not found."),
            405: ("method_not_allowed", "The HTTP method is not allowed."),
        }
        code, message = messages.get(
            error.status_code, ("http_error", "The request could not be completed.")
        )
        return error_response(status_code=error.status_code, code=code, message=message)

    @app.exception_handler(DomainError)
    async def domain_error(_: Request, error: DomainError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if error.status_code == 401 else None
        return error_response(
            status_code=error.status_code, code=error.code, message=error.message, headers=headers
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, error: RequestValidationError) -> JSONResponse:
        details = [
            {"location": [str(item) for item in entry["loc"]], "type": entry["type"]}
            for entry in error.errors()
        ]
        return error_response(
            status_code=422,
            code="request_validation_failed",
            message="The request is invalid.",
            details=details,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, error: Exception) -> JSONResponse:
        logger.error("Unhandled API error", exc_info=(type(error), error, error.__traceback__))
        return error_response(
            status_code=500,
            code="internal_error",
            message="An unexpected error occurred.",
        )
