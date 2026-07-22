package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.time.Instant

interface LocalStateRepository {
    suspend fun readLocalState(): ReadLocalStateResult

    suspend fun ensureLocalInstallation(
        localIdentity: LocalInstallationIdentity,
        createdAt: Instant,
    ): EnsureLocalInstallationResult

    suspend fun initializeLocalState(
        localIdentity: LocalInstallationIdentity,
        serverConfiguration: ServerConfiguration,
        installationCreatedAt: Instant,
        serverConfigurationUpdatedAt: Instant,
    ): InitializeLocalStateResult

    suspend fun setServerConfiguration(
        serverConfiguration: ServerConfiguration,
        updatedAt: Instant,
    ): SetServerConfigurationResult
}
