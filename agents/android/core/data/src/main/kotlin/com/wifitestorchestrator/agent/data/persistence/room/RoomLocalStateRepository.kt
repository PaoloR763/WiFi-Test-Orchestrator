package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.withTransaction
import com.wifitestorchestrator.agent.data.persistence.EnsureLocalInstallationResult
import com.wifitestorchestrator.agent.data.persistence.InitializeLocalStateResult
import com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError
import com.wifitestorchestrator.agent.data.persistence.LocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.ReadLocalStateResult
import com.wifitestorchestrator.agent.data.persistence.SetServerConfigurationResult
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.time.Instant

internal fun interface WtoAgentDatabaseProvider {
    fun get(): WtoAgentDatabase
}

internal class RoomLocalStateRepository(
    private val databaseProvider: WtoAgentDatabaseProvider,
) : LocalStateRepository {
    override suspend fun readLocalState(): ReadLocalStateResult =
        when (
            val execution =
                executeStorageOperation {
                    databaseProvider.get().localStateDao().readLocalStateRows().toMappedLocalState()
                }
        ) {
            is StorageExecution.Success -> execution.value.toReadResult()
            is StorageExecution.Failure -> ReadLocalStateResult.Failure(execution.error)
        }

    override suspend fun ensureLocalInstallation(
        localIdentity: LocalInstallationIdentity,
        createdAt: Instant,
    ): EnsureLocalInstallationResult =
        when (
            val execution =
                executeStorageOperation {
                    val database = databaseProvider.get()
                    database.withTransaction {
                        val dao = database.localStateDao()
                        val before = dao.readLocalStateRows().toMappedLocalState()
                        when (before) {
                            MappedLocalState.Absent -> {
                                val inserted = dao.insertInstallation(localIdentity.toEntity(createdAt))
                                val after = dao.readLocalStateRows().toMappedLocalState()
                                classifyEnsuredInstallation(after, localIdentity, inserted != -1L)
                            }
                            is MappedLocalState.InstallationOnly ->
                                classifyExistingInstallation(before.installation.localIdentity, localIdentity)
                            is MappedLocalState.Configured ->
                                classifyExistingInstallation(before.installation.localIdentity, localIdentity)
                            MappedLocalState.Incomplete ->
                                EnsureLocalInstallationResult.Failure(
                                    LocalPersistenceError.STATE_INCOMPLETE,
                                )
                        }
                    }
                }
        ) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure -> EnsureLocalInstallationResult.Failure(execution.error)
        }

    override suspend fun initializeLocalState(
        localIdentity: LocalInstallationIdentity,
        serverConfiguration: ServerConfiguration,
        installationCreatedAt: Instant,
        serverConfigurationUpdatedAt: Instant,
    ): InitializeLocalStateResult =
        when (
            val execution =
                executeStorageOperation {
                    val database = databaseProvider.get()
                    database.withTransaction {
                        initializeInsideTransaction(
                            database = database,
                            localIdentity = localIdentity,
                            serverConfiguration = serverConfiguration,
                            installationCreatedAt = installationCreatedAt,
                            serverConfigurationUpdatedAt = serverConfigurationUpdatedAt,
                        )
                    }
                }
        ) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure -> InitializeLocalStateResult.Failure(execution.error)
        }

    override suspend fun setServerConfiguration(
        serverConfiguration: ServerConfiguration,
        updatedAt: Instant,
    ): SetServerConfigurationResult =
        when (
            val execution =
                executeStorageOperation {
                    val database = databaseProvider.get()
                    database.withTransaction {
                        val dao = database.localStateDao()
                        when (val current = dao.readLocalStateRows().toMappedLocalState()) {
                            MappedLocalState.Absent ->
                                SetServerConfigurationResult.Failure(
                                    LocalPersistenceError.STATE_INCOMPLETE,
                                )
                            is MappedLocalState.InstallationOnly -> {
                                dao.insertServerConfiguration(serverConfiguration.toEntity(updatedAt))
                                SetServerConfigurationResult.Created
                            }
                            is MappedLocalState.Configured -> {
                                if (current.serverConfiguration.configuration == serverConfiguration) {
                                    SetServerConfigurationResult.Unchanged
                                } else {
                                    val updated =
                                        dao.updateServerConfiguration(
                                            serverConfiguration.toEntity(updatedAt),
                                        )
                                    if (updated == 1) {
                                        SetServerConfigurationResult.Updated
                                    } else {
                                        SetServerConfigurationResult.Failure(
                                            LocalPersistenceError.STATE_INCOMPLETE,
                                        )
                                    }
                                }
                            }
                            MappedLocalState.Incomplete ->
                                SetServerConfigurationResult.Failure(
                                    LocalPersistenceError.STATE_INCOMPLETE,
                                )
                        }
                    }
                }
        ) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure -> SetServerConfigurationResult.Failure(execution.error)
        }

    private suspend fun initializeInsideTransaction(
        database: WtoAgentDatabase,
        localIdentity: LocalInstallationIdentity,
        serverConfiguration: ServerConfiguration,
        installationCreatedAt: Instant,
        serverConfigurationUpdatedAt: Instant,
    ): InitializeLocalStateResult {
        val dao = database.localStateDao()
        var created = false
        when (val current = dao.readLocalStateRows().toMappedLocalState()) {
            MappedLocalState.Absent -> {
                val inserted = dao.insertInstallation(localIdentity.toEntity(installationCreatedAt))
                created = inserted != -1L
            }
            is MappedLocalState.InstallationOnly -> {
                if (current.installation.localIdentity != localIdentity) {
                    return InitializeLocalStateResult.Conflict
                }
            }
            is MappedLocalState.Configured ->
                return classifyConfiguredInitialization(
                    current = current,
                    localIdentity = localIdentity,
                    serverConfiguration = serverConfiguration,
                )
            MappedLocalState.Incomplete ->
                return InitializeLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE)
        }

        val afterInstallation = dao.readLocalStateRows().toMappedLocalState()
        val installation =
            when (afterInstallation) {
                is MappedLocalState.InstallationOnly -> afterInstallation.installation
                is MappedLocalState.Configured -> afterInstallation.installation
                MappedLocalState.Absent,
                MappedLocalState.Incomplete,
                -> return InitializeLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE)
            }
        if (installation.localIdentity != localIdentity) {
            return InitializeLocalStateResult.Conflict
        }
        if (afterInstallation is MappedLocalState.Configured) {
            return classifyConfiguredInitialization(
                current = afterInstallation,
                localIdentity = localIdentity,
                serverConfiguration = serverConfiguration,
            )
        }
        dao.insertServerConfiguration(serverConfiguration.toEntity(serverConfigurationUpdatedAt))
        created = true
        return if (created) {
            InitializeLocalStateResult.Created
        } else {
            InitializeLocalStateResult.ExistingEquivalent
        }
    }

    private fun classifyConfiguredInitialization(
        current: MappedLocalState.Configured,
        localIdentity: LocalInstallationIdentity,
        serverConfiguration: ServerConfiguration,
    ): InitializeLocalStateResult =
        if (
            current.installation.localIdentity == localIdentity &&
            current.serverConfiguration.configuration == serverConfiguration
        ) {
            InitializeLocalStateResult.ExistingEquivalent
        } else {
            InitializeLocalStateResult.Conflict
        }
}

private fun MappedLocalState.toReadResult(): ReadLocalStateResult =
    when (this) {
        MappedLocalState.Absent -> ReadLocalStateResult.Absent
        is MappedLocalState.InstallationOnly ->
            ReadLocalStateResult.InstallationOnly(installation)
        is MappedLocalState.Configured ->
            ReadLocalStateResult.Configured(installation, serverConfiguration)
        MappedLocalState.Incomplete ->
            ReadLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE)
    }

private fun classifyExistingInstallation(
    existing: LocalInstallationIdentity,
    candidate: LocalInstallationIdentity,
): EnsureLocalInstallationResult =
    if (existing == candidate) {
        EnsureLocalInstallationResult.Existing
    } else {
        EnsureLocalInstallationResult.Conflict
    }

private fun classifyEnsuredInstallation(
    state: MappedLocalState,
    candidate: LocalInstallationIdentity,
    inserted: Boolean,
): EnsureLocalInstallationResult {
    val storedIdentity =
        when (state) {
            is MappedLocalState.InstallationOnly -> state.installation.localIdentity
            is MappedLocalState.Configured -> state.installation.localIdentity
            MappedLocalState.Absent,
            MappedLocalState.Incomplete,
            -> return EnsureLocalInstallationResult.Failure(LocalPersistenceError.STATE_INCOMPLETE)
        }
    if (storedIdentity != candidate) return EnsureLocalInstallationResult.Conflict
    return if (inserted) {
        EnsureLocalInstallationResult.Created
    } else {
        EnsureLocalInstallationResult.Existing
    }
}
