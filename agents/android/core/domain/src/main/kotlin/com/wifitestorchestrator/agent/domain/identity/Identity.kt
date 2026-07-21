package com.wifitestorchestrator.agent.domain.identity

/** The stable identity of this local application installation. */
data class LocalInstallationIdentity(val installationId: InstallationId)

/** The agent and device assignment issued by the backend. */
data class BackendAgentIdentity(
    val agentId: AgentId,
    val deviceId: DeviceId,
)

sealed interface IdentityState {
    data object Absent : IdentityState

    data class LocalOnly(val localIdentity: LocalInstallationIdentity) : IdentityState

    data class Assigned(
        val localIdentity: LocalInstallationIdentity,
        val backendIdentity: BackendAgentIdentity,
    ) : IdentityState
}

/*
 * Recovery may preserve a backend assignment while associating a different local installation.
 * C02B represents the identities independently and does not execute that recovery flow.
 */
