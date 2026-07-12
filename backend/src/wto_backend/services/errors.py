class DomainError(Exception):
    code = "domain_error"
    message = "The operation could not be completed."
    status_code = 400


class InvalidCredentialsError(DomainError):
    code = "invalid_credentials"
    message = "Authentication failed."
    status_code = 401


class InvalidSessionError(DomainError):
    code = "invalid_session"
    message = "The session is no longer valid."
    status_code = 401


class PermissionDeniedError(DomainError):
    code = "permission_denied"
    message = "The operation is not permitted."
    status_code = 403


class ResourceNotFoundError(DomainError):
    code = "resource_not_found"
    message = "The requested resource was not found."
    status_code = 404


class ConflictError(DomainError):
    code = "resource_conflict"
    message = "The operation conflicts with current state."
    status_code = 409


class LastAdministratorError(ConflictError):
    code = "last_administrator_required"
    message = "At least one active administrator must remain."


class RateLimitedError(DomainError):
    code = "login_rate_limited"
    message = "Too many authentication attempts."
    status_code = 429


class DependencyUnavailableError(DomainError):
    code = "dependency_unavailable"
    message = "A required service is temporarily unavailable."
    status_code = 503


class AgentAuthenticationError(DomainError):
    code = "agent_authentication_failed"
    message = "Agent authentication failed."
    status_code = 401


class ProtocolVersionError(DomainError):
    code = "protocol_version_unsupported"
    message = "The agent protocol version is not supported."
    status_code = 426


class RequestClockSkewError(DomainError):
    code = "request_clock_skew"
    message = "The request timestamp is outside the accepted window."
    status_code = 401


class NonceReplayError(DomainError):
    code = "agent_authentication_failed"
    message = "Agent authentication failed."
    status_code = 401


class IdempotencyConflictError(ConflictError):
    code = "idempotency_key_reused"
    message = "The idempotency key was already used with a different request."


class IdempotencyInProgressError(ConflictError):
    code = "idempotency_in_progress"
    message = "The idempotent operation is still in progress."


class SecretReplayExpiredError(ConflictError):
    code = "secret_replay_expired"
    message = "The one-time secret replay window has expired."


class SequenceConflictError(ConflictError):
    code = "sequence_conflict"
    message = "The sequence conflicts with previously accepted presence."


class EnrollmentFailedError(DomainError):
    code = "enrollment_failed"
    message = "Agent enrollment failed."
    status_code = 401


class PayloadTooLargeError(DomainError):
    code = "payload_too_large"
    message = "The request body exceeds the allowed size."
    status_code = 413


class AgentRateLimitedDomainError(DomainError):
    code = "agent_rate_limited"
    message = "Too many agent requests."
    status_code = 429
