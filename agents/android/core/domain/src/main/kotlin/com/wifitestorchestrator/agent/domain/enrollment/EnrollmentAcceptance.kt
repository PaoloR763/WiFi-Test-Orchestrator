package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant

/**
 * A backend acceptance already validated by a future boundary.
 *
 * This fact does not imply local persistence, successful credential authentication, durable
 * enrollment, recovery, retry behavior, or any particular HTTP status.
 */
class BackendEnrollmentAcceptance(
    val localIdentity: LocalInstallationIdentity,
    val backendIdentity: BackendAgentIdentity,
    val deliveredCredential: DeliveredCredential,
    val serverReceivedAt: Instant,
    val protocolVersion: ProtocolVersion,
) {
    override fun toString(): String =
        "BackendEnrollmentAcceptance(" +
            "localIdentity=$localIdentity, " +
            "backendIdentity=$backendIdentity, " +
            "deliveredCredential=<redacted>, " +
            "serverReceivedAt=$serverReceivedAt, " +
            "protocolVersion=$protocolVersion)"
}
