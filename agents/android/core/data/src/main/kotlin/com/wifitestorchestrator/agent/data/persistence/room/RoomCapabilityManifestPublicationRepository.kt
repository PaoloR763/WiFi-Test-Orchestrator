package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.withTransaction
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestAcknowledgement
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestCodec
import com.wifitestorchestrator.agent.data.capability.EnrollmentBindingFingerprint
import com.wifitestorchestrator.agent.data.capability.FrozenCapabilityManifest
import com.wifitestorchestrator.agent.data.capability.Sha256Value
import com.wifitestorchestrator.agent.data.persistence.AcceptCapabilityManifestResult
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestCredentialUse
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationState
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestSendContext
import com.wifitestorchestrator.agent.data.persistence.CapabilityPublicationPreflightResult
import com.wifitestorchestrator.agent.data.persistence.CapabilityPublicationReservationExpectation
import com.wifitestorchestrator.agent.data.persistence.EnrolledCapabilityPublicationContext
import com.wifitestorchestrator.agent.data.persistence.RevalidateCapabilityManifestResult
import com.wifitestorchestrator.agent.data.persistence.ReserveCapabilityManifestResult
import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import com.wifitestorchestrator.agent.domain.enrollment.CredentialUsability
import java.time.Instant

internal class RoomCapabilityManifestPublicationRepository(
    private val databaseProvider: WtoAgentDatabaseProvider,
    private val codec: CapabilityManifestCodec = CapabilityManifestCodec(),
) : CapabilityManifestPublicationRepository {
    override suspend fun preflight(): CapabilityPublicationPreflightResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    when (val state = database.readPublicationAggregate()) {
                        PublicationAggregate.NotEnrolled ->
                            CapabilityPublicationPreflightResult.NotEnrolled
                        PublicationAggregate.Corrupt ->
                            CapabilityPublicationPreflightResult.Corrupt
                        PublicationAggregate.Unsupported ->
                            CapabilityPublicationPreflightResult.Unsupported
                        is PublicationAggregate.Enrolled ->
                            CapabilityPublicationPreflightResult.Enrolled(
                                EnrolledCapabilityPublicationContext(
                                    enrollment = state.enrollment,
                                    enrollmentIdentityFingerprint = state.binding,
                                    publicationState = state.publicationState,
                                ),
                            )
                    }
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                CapabilityPublicationPreflightResult.Failure(execution.error)
        }
    }

    override suspend fun reserve(
        expectation: CapabilityPublicationReservationExpectation,
        manifest: FrozenCapabilityManifest,
    ): ReserveCapabilityManifestResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    reserveInsideTransaction(database, expectation, manifest)
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                ReserveCapabilityManifestResult.Failure(execution.error)
        }
    }

    override suspend fun revalidateForSend(
        enrollmentIdentityFingerprint: Sha256Value,
        pending: FrozenCapabilityManifest,
        now: Instant,
    ): RevalidateCapabilityManifestResult {
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    when (val state = database.readPublicationAggregate()) {
                        PublicationAggregate.NotEnrolled ->
                            RevalidateCapabilityManifestResult.NotEnrolled
                        PublicationAggregate.Corrupt ->
                            RevalidateCapabilityManifestResult.Corrupt
                        PublicationAggregate.Unsupported ->
                            RevalidateCapabilityManifestResult.Unsupported
                        is PublicationAggregate.Enrolled -> {
                            if (!state.binding.contentEquals(enrollmentIdentityFingerprint)) {
                                RevalidateCapabilityManifestResult.EnrollmentChanged
                            } else {
                                val storedPending =
                                    (state.publicationState as? CapabilityManifestPublicationState.Stored)
                                        ?.pending
                                when {
                                    storedPending == null ||
                                        !storedPending.isByteIdenticalTo(pending) ->
                                        RevalidateCapabilityManifestResult.PendingChanged
                                    state.enrollment.credentialMetadata.usabilityAt(now) !=
                                        CredentialUsability.Usable ->
                                        RevalidateCapabilityManifestResult.CredentialUnusable
                                    else ->
                                        RevalidateCapabilityManifestResult.Ready(
                                            CapabilityManifestSendContext(
                                                enrollment = state.enrollment,
                                                pending = storedPending,
                                            ),
                                        )
                                }
                            }
                        }
                    }
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                RevalidateCapabilityManifestResult.Failure(execution.error)
        }
    }

    override suspend fun accept(
        enrollmentIdentityFingerprint: Sha256Value,
        pending: FrozenCapabilityManifest,
        credentialUse: CapabilityManifestCredentialUse,
        acknowledgement: CapabilityManifestAcknowledgement,
        now: Instant,
    ): AcceptCapabilityManifestResult {
        if (
            acknowledgement.manifestId != pending.manifestId ||
            !acknowledgement.manifestDigest.contentEquals(pending.canonicalDigest)
        ) {
            return AcceptCapabilityManifestResult.PendingChanged
        }
        val execution =
            executeStorageOperation {
                val database = databaseProvider.get()
                database.withTransaction {
                    acceptInsideTransaction(
                        database = database,
                        expectedBinding = enrollmentIdentityFingerprint,
                        expectedPending = pending,
                        credentialUse = credentialUse,
                        acknowledgement = acknowledgement,
                        now = now,
                    )
                }
            }
        return when (execution) {
            is StorageExecution.Success -> execution.value
            is StorageExecution.Failure ->
                AcceptCapabilityManifestResult.Failure(execution.error)
        }
    }

    private suspend fun reserveInsideTransaction(
        database: WtoAgentDatabase,
        expectation: CapabilityPublicationReservationExpectation,
        manifest: FrozenCapabilityManifest,
    ): ReserveCapabilityManifestResult {
        val aggregate = database.readPublicationAggregate()
        val enrolled =
            aggregate as? PublicationAggregate.Enrolled
                ?: return aggregate.toReservationFailure()
        if (
            !enrolled.binding.contentEquals(expectation.enrollmentIdentityFingerprint) ||
            enrolled.enrollment.credentialMetadata.credentialId != expectation.credentialId ||
            enrolled.enrollment.credentialMetadata.version.value != expectation.credentialVersion
        ) {
            return ReserveCapabilityManifestResult.EnrollmentChanged
        }
        val currentAccepted =
            (enrolled.publicationState as? CapabilityManifestPublicationState.Stored)?.accepted
        if (
            currentAccepted?.manifest?.manifestId != expectation.expectedAcceptedManifestId ||
            currentAccepted?.manifest?.manifestSequence != expectation.expectedAcceptedSequence
        ) {
            return ReserveCapabilityManifestResult.StateChanged
        }
        val current =
            when (val mapped = enrolled.mappedPublication) {
                MappedCapabilityManifestPublication.Empty -> null
                MappedCapabilityManifestPublication.Corrupt ->
                    return ReserveCapabilityManifestResult.Corrupt
                is MappedCapabilityManifestPublication.Valid -> mapped
            }
        if (current?.state?.pending != null) {
            return ReserveCapabilityManifestResult.PendingAlreadyExists
        }
        if (current?.state?.sequenceExhausted == true) {
            return ReserveCapabilityManifestResult.SequenceExhausted
        }
        val expectedSequence = current?.state?.nextManifestSequence ?: 0L
        if (manifest.manifestSequence != expectedSequence) {
            return ReserveCapabilityManifestResult.StateChanged
        }
        val validated =
            codec.validateCurrentReservation(
                canonicalPayload = manifest.copyCanonicalPayload(),
                canonicalDigest = manifest.canonicalDigest,
                semanticFingerprint = manifest.semanticFingerprint,
                expectedAgentId = enrolled.enrollment.backendIdentity.agentId,
                expectedManifestId = manifest.manifestId,
                expectedSequence = manifest.manifestSequence,
            )
        if (validated == null || !validated.isByteIdenticalTo(manifest)) {
            return ReserveCapabilityManifestResult.Corrupt
        }

        val candidate =
            current?.entity?.withPending(manifest)
                ?: newPendingPublicationEntity(enrolled.binding, manifest)
        val dao = database.capabilityManifestPublicationDao()
        if (current == null) {
            if (dao.insert(candidate) != LOCAL_STATE_SINGLETON_ID) {
                throw StorageCorruptionException()
            }
        } else if (dao.update(candidate) != 1) {
            throw StorageCorruptionException()
        }
        val reread = database.readPublicationAggregate() as? PublicationAggregate.Enrolled
            ?: throw StorageCorruptionException()
        val persisted =
            (reread.mappedPublication as? MappedCapabilityManifestPublication.Valid)
                ?: throw StorageCorruptionException()
        if (
            !persisted.entity.isByteIdenticalTo(candidate) ||
            persisted.state.pending?.isByteIdenticalTo(manifest) != true
        ) {
            throw StorageCorruptionException()
        }
        return ReserveCapabilityManifestResult.Reserved
    }

    private suspend fun acceptInsideTransaction(
        database: WtoAgentDatabase,
        expectedBinding: Sha256Value,
        expectedPending: FrozenCapabilityManifest,
        credentialUse: CapabilityManifestCredentialUse,
        acknowledgement: CapabilityManifestAcknowledgement,
        now: Instant,
    ): AcceptCapabilityManifestResult {
        val aggregate = database.readPublicationAggregate()
        val enrolled =
            aggregate as? PublicationAggregate.Enrolled
                ?: return aggregate.toAcceptanceFailure()
        if (!enrolled.binding.contentEquals(expectedBinding)) {
            return AcceptCapabilityManifestResult.EnrollmentChanged
        }
        val mapped =
            enrolled.mappedPublication as? MappedCapabilityManifestPublication.Valid
                ?: return AcceptCapabilityManifestResult.PendingChanged
        if (mapped.state.pending?.isByteIdenticalTo(expectedPending) != true) {
            return AcceptCapabilityManifestResult.PendingChanged
        }
        val metadata = enrolled.enrollment.credentialMetadata
        if (
            metadata.credentialId != credentialUse.credentialId ||
            metadata.version.value != credentialUse.credentialVersion
        ) {
            return AcceptCapabilityManifestResult.CredentialChanged
        }
        if (metadata.usabilityAt(now) != CredentialUsability.Usable) {
            return AcceptCapabilityManifestResult.CredentialUnusable
        }

        val candidate = mapped.entity.acceptPending(acknowledgement.serverReceivedAt)
        if (database.capabilityManifestPublicationDao().update(candidate) != 1) {
            throw StorageCorruptionException()
        }
        val reread = database.readPublicationAggregate() as? PublicationAggregate.Enrolled
            ?: throw StorageCorruptionException()
        val persisted =
            reread.mappedPublication as? MappedCapabilityManifestPublication.Valid
                ?: throw StorageCorruptionException()
        if (
            !persisted.entity.isByteIdenticalTo(candidate) ||
            persisted.state.pending != null ||
            persisted.state.accepted?.manifest?.isByteIdenticalTo(expectedPending) != true ||
            persisted.state.accepted.serverReceivedAt != acknowledgement.serverReceivedAt
        ) {
            throw StorageCorruptionException()
        }
        return AcceptCapabilityManifestResult.Accepted
    }

    private suspend fun WtoAgentDatabase.readPublicationAggregate(): PublicationAggregate {
        val localState = localStateDao().readLocalStateRows().toMappedLocalState()
        val enrollment = mapProtectedEnrollment(localState, observeProtectedEnrollmentRows())
        val observedPublication = observeCapabilityManifestPublication()
        return when (enrollment) {
            MappedProtectedEnrollment.Absent ->
                if (observedPublication == ObservedCapabilityManifestPublication.Absent) {
                    PublicationAggregate.NotEnrolled
                } else {
                    PublicationAggregate.Corrupt
                }
            MappedProtectedEnrollment.Corrupt -> PublicationAggregate.Corrupt
            MappedProtectedEnrollment.Unsupported -> PublicationAggregate.Unsupported
            is MappedProtectedEnrollment.Compatible -> {
                val mapped =
                    mapCapabilityManifestPublication(
                        enrollment = enrollment.enrollment,
                        observed = observedPublication,
                        codec = codec,
                    )
                if (mapped == MappedCapabilityManifestPublication.Corrupt) {
                    PublicationAggregate.Corrupt
                } else {
                    val binding =
                        EnrollmentBindingFingerprint.compute(enrollment.enrollment)
                            ?: return PublicationAggregate.Corrupt
                    val state =
                        when (mapped) {
                            MappedCapabilityManifestPublication.Empty ->
                                CapabilityManifestPublicationState.Empty
                            MappedCapabilityManifestPublication.Corrupt ->
                                return PublicationAggregate.Corrupt
                            is MappedCapabilityManifestPublication.Valid -> mapped.state
                        }
                    PublicationAggregate.Enrolled(
                        enrollment = enrollment.enrollment,
                        binding = binding,
                        publicationState = state,
                        mappedPublication = mapped,
                    )
                }
            }
        }
    }
}

private sealed interface PublicationAggregate {
    data object NotEnrolled : PublicationAggregate

    data object Corrupt : PublicationAggregate

    data object Unsupported : PublicationAggregate

    class Enrolled(
        val enrollment: StoredProtectedEnrollment,
        val binding: Sha256Value,
        val publicationState: CapabilityManifestPublicationState,
        val mappedPublication: MappedCapabilityManifestPublication,
    ) : PublicationAggregate {
        override fun toString(): String = "PublicationAggregate.Enrolled(<redacted>)"
    }
}

private fun PublicationAggregate.toReservationFailure(): ReserveCapabilityManifestResult =
    when (this) {
        PublicationAggregate.NotEnrolled ->
            ReserveCapabilityManifestResult.EnrollmentChanged
        PublicationAggregate.Corrupt -> ReserveCapabilityManifestResult.Corrupt
        PublicationAggregate.Unsupported -> ReserveCapabilityManifestResult.Unsupported
        is PublicationAggregate.Enrolled -> error("Enrolled is not a failure")
    }

private fun PublicationAggregate.toAcceptanceFailure(): AcceptCapabilityManifestResult =
    when (this) {
        PublicationAggregate.NotEnrolled ->
            AcceptCapabilityManifestResult.EnrollmentChanged
        PublicationAggregate.Corrupt -> AcceptCapabilityManifestResult.Corrupt
        PublicationAggregate.Unsupported -> AcceptCapabilityManifestResult.Unsupported
        is PublicationAggregate.Enrolled -> error("Enrolled is not a failure")
    }
