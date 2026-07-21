package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.domain.enrollment.BackendEnrollmentAcceptance
import com.wifitestorchestrator.agent.domain.identity.CorrelationId

sealed interface EnrollmentResult {
    class Accepted(
        val acceptance: BackendEnrollmentAcceptance,
        val correlationId: CorrelationId,
    ) : EnrollmentResult {
        override fun toString(): String =
            "EnrollmentResult.Accepted(acceptance=<redacted>, correlationId=<redacted>)"
    }

    class Rejected(
        val reason: EnrollmentRejectionReason,
        val statusCode: Int,
        val correlationId: CorrelationId,
    ) : EnrollmentResult {
        override fun toString(): String =
            "EnrollmentResult.Rejected(" +
                "reason=$reason, statusCode=$statusCode, correlationId=<redacted>)"
    }

    data class Failed(val reason: EnrollmentFailureReason) : EnrollmentResult
}

enum class EnrollmentRejectionReason {
    AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED,
    CONFLICT,
    REQUEST_TOO_LARGE,
    CONTRACT_REJECTED,
    RATE_LIMITED,
    SERVICE_UNAVAILABLE,
}

enum class EnrollmentFailureReason {
    INVALID_LOCAL_REQUEST,
    INVALID_ENDPOINT,
    REDIRECT,
    UNEXPECTED_STATUS,
    INVALID_CONTENT_TYPE,
    EMPTY_BODY,
    RESPONSE_TOO_LARGE,
    MALFORMED_JSON,
    INVALID_RESPONSE_SHAPE,
    INVALID_RESPONSE_SEMANTICS,
    MISSING_CORRELATION,
    CORRELATION_MISMATCH,
    DNS,
    TLS,
    CONNECTION,
    TIMEOUT,
    CANCELLED,
    INCOMPLETE_RESPONSE,
    IO,
}
