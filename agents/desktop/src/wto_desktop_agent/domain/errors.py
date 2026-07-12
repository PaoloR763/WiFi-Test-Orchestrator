class AgentError(Exception):
    """Base error whose message must never contain secret material."""


class SecureStoreUnavailableError(AgentError):
    pass


class IdentityNotEnrolledError(AgentError):
    pass


class DuplicateConflictError(AgentError):
    pass


class StateConflictError(AgentError):
    pass


class PluginUnavailableError(AgentError):
    pass


class TransportError(AgentError):
    pass
