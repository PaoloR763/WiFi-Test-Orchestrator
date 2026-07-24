package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant

/**
 * The non-secret facts and already-protected credential that C06 may persist.
 *
 * This boundary deliberately accepts neither an enrollment token nor a plaintext credential.
 */
class ProtectedEnrollmentWrite(
    val expectedLocalIdentity: LocalInstallationIdentity,
    val expectedServerConfiguration: ServerConfiguration,
    val backendIdentity: BackendAgentIdentity,
    val protocolVersion: ProtocolVersion,
    val serverReceivedAt: Instant,
    val credentialMetadata: CredentialMetadata,
    val protectedCredential: ProtectedCredentialEnvelope,
) {
    override fun toString(): String = "ProtectedEnrollmentWrite(<redacted>)"
}

/**
 * A compatible durable enrollment reconstructed from all three related Room tables.
 *
 * The encrypted envelope keeps its own defensive-copy contract. This type intentionally is not a
 * data class so callers cannot obtain a generated copy operation for the envelope.
 */
class StoredProtectedEnrollment(
    val localIdentity: LocalInstallationIdentity,
    val serverConfiguration: ServerConfiguration,
    val backendIdentity: BackendAgentIdentity,
    val protocolVersion: ProtocolVersion,
    val serverReceivedAt: Instant,
    val credentialMetadata: CredentialMetadata,
    val protectedCredential: ProtectedCredentialEnvelope,
) {
    override fun toString(): String = "StoredProtectedEnrollment(<redacted>)"
}

sealed interface ProtectedEnrollmentPreflightResult {
    /** Local installation and server configuration are valid; no durable enrollment exists. */
    data object Absent : ProtectedEnrollmentPreflightResult

    class Compatible(val enrollment: StoredProtectedEnrollment) :
        ProtectedEnrollmentPreflightResult {
        override fun toString(): String =
            "ProtectedEnrollmentPreflightResult.Compatible(<redacted>)"
    }

    /** The expected installation or server does not match the authoritative local state. */
    data object Conflict : ProtectedEnrollmentPreflightResult

    /** Enrollment cannot start until both C04 singleton rows exist. */
    data object LocalStateIncomplete : ProtectedEnrollmentPreflightResult

    data object Corrupt : ProtectedEnrollmentPreflightResult

    data object Unsupported : ProtectedEnrollmentPreflightResult

    data class Failure(val error: LocalPersistenceError) :
        ProtectedEnrollmentPreflightResult
}

sealed interface ReadProtectedEnrollmentResult {
    data object Absent : ReadProtectedEnrollmentResult

    class Compatible(val enrollment: StoredProtectedEnrollment) :
        ReadProtectedEnrollmentResult {
        override fun toString(): String =
            "ReadProtectedEnrollmentResult.Compatible(<redacted>)"
    }

    data object Corrupt : ReadProtectedEnrollmentResult

    data object Unsupported : ReadProtectedEnrollmentResult

    data class Failure(val error: LocalPersistenceError) :
        ReadProtectedEnrollmentResult
}

sealed interface PersistProtectedEnrollmentResult {
    data object Written : PersistProtectedEnrollmentResult

    data object ExistingEquivalent : PersistProtectedEnrollmentResult

    data object Replaced : PersistProtectedEnrollmentResult

    data object Conflict : PersistProtectedEnrollmentResult

    data object Rollback : PersistProtectedEnrollmentResult

    data object PendingRejected : PersistProtectedEnrollmentResult

    data object InvalidCandidate : PersistProtectedEnrollmentResult

    data object Corrupt : PersistProtectedEnrollmentResult

    data object Unsupported : PersistProtectedEnrollmentResult

    data class Failure(val error: LocalPersistenceError) :
        PersistProtectedEnrollmentResult
}
