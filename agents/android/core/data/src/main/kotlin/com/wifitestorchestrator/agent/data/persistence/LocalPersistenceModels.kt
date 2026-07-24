package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.time.Instant

data class StoredLocalInstallation(
    val localIdentity: LocalInstallationIdentity,
    val createdAt: Instant,
)

data class StoredServerConfiguration(
    val configuration: ServerConfiguration,
    val updatedAt: Instant,
)

sealed interface ReadLocalStateResult {
    data object Absent : ReadLocalStateResult

    data class InstallationOnly(
        val installation: StoredLocalInstallation,
    ) : ReadLocalStateResult

    data class Configured(
        val installation: StoredLocalInstallation,
        val serverConfiguration: StoredServerConfiguration,
    ) : ReadLocalStateResult

    data class Failure(val error: LocalPersistenceError) : ReadLocalStateResult
}

sealed interface EnsureLocalInstallationResult {
    data object Created : EnsureLocalInstallationResult

    data object Existing : EnsureLocalInstallationResult

    data object Conflict : EnsureLocalInstallationResult

    data class Failure(val error: LocalPersistenceError) : EnsureLocalInstallationResult
}

sealed interface InitializeLocalStateResult {
    data object Created : InitializeLocalStateResult

    data object ExistingEquivalent : InitializeLocalStateResult

    data object Conflict : InitializeLocalStateResult

    data class Failure(val error: LocalPersistenceError) : InitializeLocalStateResult
}

sealed interface SetServerConfigurationResult {
    data object Created : SetServerConfigurationResult

    data object Updated : SetServerConfigurationResult

    data object Unchanged : SetServerConfigurationResult

    data object Conflict : SetServerConfigurationResult

    data object Corrupt : SetServerConfigurationResult

    data object Unsupported : SetServerConfigurationResult

    data class Failure(val error: LocalPersistenceError) : SetServerConfigurationResult
}
