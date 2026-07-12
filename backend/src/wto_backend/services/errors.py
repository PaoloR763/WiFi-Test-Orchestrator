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
