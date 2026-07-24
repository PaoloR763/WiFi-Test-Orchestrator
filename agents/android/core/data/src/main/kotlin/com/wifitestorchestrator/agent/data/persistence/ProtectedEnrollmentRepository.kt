package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity

interface ProtectedEnrollmentRepository {
    /**
     * Authoritatively checks the local installation, server configuration, and durable
     * enrollment in one SQLite transaction.
     */
    suspend fun preflight(
        expectedLocalIdentity: LocalInstallationIdentity,
        expectedServerConfiguration: ServerConfiguration,
    ): ProtectedEnrollmentPreflightResult

    suspend fun read(): ReadProtectedEnrollmentResult

    suspend fun persist(write: ProtectedEnrollmentWrite): PersistProtectedEnrollmentResult
}
