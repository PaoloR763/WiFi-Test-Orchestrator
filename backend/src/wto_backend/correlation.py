from __future__ import annotations

import logging
import re
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from wto_backend.logging import correlation_id_context

CORRELATION_HEADER = "X-Correlation-ID"
CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

logger = logging.getLogger(__name__)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get(CORRELATION_HEADER)
        correlation_id = supplied or str(uuid4())
        if supplied is not None and CORRELATION_ID_PATTERN.fullmatch(supplied) is None:
            safe_id = str(uuid4())
            token = correlation_id_context.set(safe_id)
            try:
                logger.warning("Rejected invalid client correlation ID")
                return JSONResponse(
                    status_code=400,
                    content={
                        "schema_version": "1.0.0",
                        "error": {
                            "code": "invalid_correlation_id",
                            "message": (
                                "X-Correlation-ID must match " "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
                            ),
                            "details": None,
                            "correlation_id": safe_id,
                        },
                    },
                    headers={CORRELATION_HEADER: safe_id},
                )
            finally:
                correlation_id_context.reset(token)

        token = correlation_id_context.set(correlation_id)
        try:
            response = await call_next(request)
            response.headers[CORRELATION_HEADER] = correlation_id
            logger.info("HTTP request completed")
            return response
        finally:
            correlation_id_context.reset(token)
