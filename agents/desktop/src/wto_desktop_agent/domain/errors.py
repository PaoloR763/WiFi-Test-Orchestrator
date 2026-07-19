class AgentError(Exception):
    """Base error whose message must never contain secret material."""


class SecureStoreUnavailableError(AgentError):
    pass


class MutationCommitIndeterminateError(SecureStoreUnavailableError):
    """A secret mutation may be durable and must not be retried automatically."""

    code = "mutation_commit_indeterminate"

    def __init__(self) -> None:
        super().__init__(self.code)


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
