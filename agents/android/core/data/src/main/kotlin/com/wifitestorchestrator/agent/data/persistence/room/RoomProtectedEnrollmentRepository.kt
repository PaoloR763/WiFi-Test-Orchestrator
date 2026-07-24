package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.withTransaction
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentRepository
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.ReadProtectedEnrollmentResult
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity

internal class RoomProtectedEnrollmentRepository(
    private val databaseProvider: WtoAgentDatabaseProvider,
) : ProtectedEnrollmentRepository {
    override suspend fun preflight(
        expectedLocalIdentity: LocalInstallationIdentity,
        expectedServerConfiguration: ServerConfiguration,
    ): ProtectedEnrollmentPreflightResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    preflightInsideTransaction(
                        database = database,
                        expectedLocalIdentity = expectedLocalIdentity,
                        expectedServerConfiguration = expectedServerConfiguration,
                    )
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                ProtectedEnrollmentPreflightResult.Failure(execution.error)
        }
    }

    override suspend fun read(): ReadProtectedEnrollmentResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction { readInsideTransaction(database) }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                ReadProtectedEnrollmentResult.Failure(execution.error)
        }
    }

    override suspend fun persist(
        write: ProtectedEnrollmentWrite,
    ): PersistProtectedEnrollmentResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    persistInsideTransaction(database = database, write = write)
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                PersistProtectedEnrollmentResult.Failure(execution.error)
        }
    }

    private suspend fun preflightInsideTransaction(
        database: WtoAgentDatabase,
        expectedLocalIdentity: LocalInstallationIdentity,
        expectedServerConfiguration: ServerConfiguration,
    ): ProtectedEnrollmentPreflightResult {
        val state = database.readEnrollmentState()
        return when (val enrollment = state.enrollment) {
            MappedProtectedEnrollment.Corrupt ->
                ProtectedEnrollmentPreflightResult.Corrupt
            MappedProtectedEnrollment.Unsupported ->
                ProtectedEnrollmentPreflightResult.Unsupported
            MappedProtectedEnrollment.Absent ->
                classifyAbsentPreflight(
                    localState = state.localState,
                    expectedLocalIdentity = expectedLocalIdentity,
                    expectedServerConfiguration = expectedServerConfiguration,
                )
            is MappedProtectedEnrollment.Compatible -> {
                val configured =
                    state.localState as? MappedLocalState.Configured
                        ?: return ProtectedEnrollmentPreflightResult.Corrupt
                if (
                    configured.matches(
                        expectedLocalIdentity,
                        expectedServerConfiguration,
                    )
                ) {
                    ProtectedEnrollmentPreflightResult.Compatible(enrollment.enrollment)
                } else {
                    ProtectedEnrollmentPreflightResult.Conflict
                }
            }
        }
    }

    private suspend fun readInsideTransaction(
        database: WtoAgentDatabase,
    ): ReadProtectedEnrollmentResult {
        val state = database.readEnrollmentState()
        if (state.localState == MappedLocalState.Incomplete) {
            return ReadProtectedEnrollmentResult.Corrupt
        }
        return when (val enrollment = state.enrollment) {
            MappedProtectedEnrollment.Absent -> ReadProtectedEnrollmentResult.Absent
            is MappedProtectedEnrollment.Compatible ->
                ReadProtectedEnrollmentResult.Compatible(enrollment.enrollment)
            MappedProtectedEnrollment.Corrupt -> ReadProtectedEnrollmentResult.Corrupt
            MappedProtectedEnrollment.Unsupported -> ReadProtectedEnrollmentResult.Unsupported
        }
    }

    private suspend fun persistInsideTransaction(
        database: WtoAgentDatabase,
        write: ProtectedEnrollmentWrite,
    ): PersistProtectedEnrollmentResult {
        val state = database.readEnrollmentState()
        when (state.enrollment) {
            MappedProtectedEnrollment.Corrupt ->
                return PersistProtectedEnrollmentResult.Corrupt
            MappedProtectedEnrollment.Unsupported ->
                return PersistProtectedEnrollmentResult.Unsupported
            MappedProtectedEnrollment.Absent,
            is MappedProtectedEnrollment.Compatible,
            -> Unit
        }
        if (state.localState == MappedLocalState.Incomplete) {
            return PersistProtectedEnrollmentResult.Corrupt
        }
        val configured =
            state.localState as? MappedLocalState.Configured
                ?: return PersistProtectedEnrollmentResult.Conflict
        if (
            !configured.matches(
                write.expectedLocalIdentity,
                write.expectedServerConfiguration,
            )
        ) {
            return PersistProtectedEnrollmentResult.Conflict
        }

        return when (val candidate = write.toMappedWrite()) {
            MappedProtectedEnrollmentWrite.Pending ->
                PersistProtectedEnrollmentResult.PendingRejected
            MappedProtectedEnrollmentWrite.Invalid ->
                PersistProtectedEnrollmentResult.InvalidCandidate
            is MappedProtectedEnrollmentWrite.Active ->
                try {
                    persistActive(
                        database = database,
                        current = state.enrollment,
                        candidate = candidate.entity,
                    )
                } finally {
                    candidate.entity.clearEnvelopeCopies()
                }
        }
    }

    private suspend fun persistActive(
        database: WtoAgentDatabase,
        current: MappedProtectedEnrollment,
        candidate: ProtectedEnrollmentEntity,
    ): PersistProtectedEnrollmentResult {
        val dao = database.protectedEnrollmentDao()
        return when (current) {
            MappedProtectedEnrollment.Absent -> {
                val inserted = dao.insert(candidate)
                if (inserted != LOCAL_STATE_SINGLETON_ID) throw StorageCorruptionException()
                database.verifyExactEnrollment(candidate)
                PersistProtectedEnrollmentResult.Written
            }
            is MappedProtectedEnrollment.Compatible ->
                persistAgainstExisting(database, current.entity, candidate)
            MappedProtectedEnrollment.Corrupt ->
                PersistProtectedEnrollmentResult.Corrupt
            MappedProtectedEnrollment.Unsupported ->
                PersistProtectedEnrollmentResult.Unsupported
        }
    }

    private suspend fun persistAgainstExisting(
        database: WtoAgentDatabase,
        existing: ProtectedEnrollmentEntity,
        candidate: ProtectedEnrollmentEntity,
    ): PersistProtectedEnrollmentResult {
        if (existing.credentialId == candidate.credentialId) {
            if (existing.credentialVersion != candidate.credentialVersion) {
                return PersistProtectedEnrollmentResult.Conflict
            }
            if (!existing.hasEquivalentMetadata(candidate)) {
                return PersistProtectedEnrollmentResult.Conflict
            }
            database.verifyExactEnrollment(existing)
            return PersistProtectedEnrollmentResult.ExistingEquivalent
        }
        if (existing.credentialVersion == candidate.credentialVersion) {
            return PersistProtectedEnrollmentResult.Conflict
        }
        if (candidate.credentialVersion < existing.credentialVersion) {
            return PersistProtectedEnrollmentResult.Rollback
        }
        if (!existing.hasSameBackendIdentity(candidate)) {
            return PersistProtectedEnrollmentResult.Conflict
        }

        val updated = database.protectedEnrollmentDao().update(candidate)
        if (updated != 1) throw StorageCorruptionException()
        database.verifyExactEnrollment(candidate)
        return PersistProtectedEnrollmentResult.Replaced
    }
}

private data class EnrollmentState(
    val localState: MappedLocalState,
    val enrollment: MappedProtectedEnrollment,
)

private suspend fun WtoAgentDatabase.readEnrollmentState(): EnrollmentState {
    val localState = localStateDao().readLocalStateRows().toMappedLocalState()
    val enrollment = mapProtectedEnrollment(localState, observeProtectedEnrollmentRows())
    return EnrollmentState(localState = localState, enrollment = enrollment)
}

private suspend fun WtoAgentDatabase.verifyExactEnrollment(
    expected: ProtectedEnrollmentEntity,
) {
    val state = readEnrollmentState()
    val compatible =
        state.enrollment as? MappedProtectedEnrollment.Compatible
            ?: throw StorageCorruptionException()
    if (!compatible.entity.isByteIdenticalTo(expected)) {
        throw StorageCorruptionException()
    }
}

private fun classifyAbsentPreflight(
    localState: MappedLocalState,
    expectedLocalIdentity: LocalInstallationIdentity,
    expectedServerConfiguration: ServerConfiguration,
): ProtectedEnrollmentPreflightResult =
    when (localState) {
        MappedLocalState.Absent,
        is MappedLocalState.InstallationOnly,
        -> ProtectedEnrollmentPreflightResult.LocalStateIncomplete
        is MappedLocalState.Configured ->
            if (localState.matches(expectedLocalIdentity, expectedServerConfiguration)) {
                ProtectedEnrollmentPreflightResult.Absent
            } else {
                ProtectedEnrollmentPreflightResult.Conflict
            }
        MappedLocalState.Incomplete -> ProtectedEnrollmentPreflightResult.Corrupt
    }

private fun MappedLocalState.Configured.matches(
    expectedLocalIdentity: LocalInstallationIdentity,
    expectedServerConfiguration: ServerConfiguration,
): Boolean =
    installation.localIdentity == expectedLocalIdentity &&
        serverConfiguration.configuration == expectedServerConfiguration
