package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.data.capability.CapabilityManifestAcknowledgement
import com.wifitestorchestrator.agent.data.capability.FrozenCapabilityManifest
import com.wifitestorchestrator.agent.data.capability.Sha256Value
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.time.Instant

sealed interface CapabilityManifestPublicationState {
    data object Empty : CapabilityManifestPublicationState

    class Stored(
        val enrollmentIdentityFingerprint: Sha256Value,
        val nextManifestSequence: Long,
        val sequenceExhausted: Boolean,
        val accepted: AcceptedCapabilityManifest?,
        val pending: FrozenCapabilityManifest?,
    ) : CapabilityManifestPublicationState {
        override fun toString(): String =
            "CapabilityManifestPublicationState.Stored(<redacted>)"
    }
}

class AcceptedCapabilityManifest(
    val manifest: FrozenCapabilityManifest,
    val serverReceivedAt: Instant,
) {
    override fun toString(): String = "AcceptedCapabilityManifest(<redacted>)"
}

class EnrolledCapabilityPublicationContext(
    val enrollment: StoredProtectedEnrollment,
    val enrollmentIdentityFingerprint: Sha256Value,
    val publicationState: CapabilityManifestPublicationState,
) {
    override fun toString(): String = "EnrolledCapabilityPublicationContext(<redacted>)"
}

sealed interface CapabilityPublicationPreflightResult {
    data object NotEnrolled : CapabilityPublicationPreflightResult

    class Enrolled(val context: EnrolledCapabilityPublicationContext) :
        CapabilityPublicationPreflightResult {
        override fun toString(): String =
            "CapabilityPublicationPreflightResult.Enrolled(<redacted>)"
    }

    data object Corrupt : CapabilityPublicationPreflightResult

    data object Unsupported : CapabilityPublicationPreflightResult

    data class Failure(val error: LocalPersistenceError) :
        CapabilityPublicationPreflightResult
}

data class CapabilityPublicationReservationExpectation(
    val enrollmentIdentityFingerprint: Sha256Value,
    val credentialId: CredentialId,
    val credentialVersion: Int,
    val expectedAcceptedManifestId: String?,
    val expectedAcceptedSequence: Long?,
)

sealed interface ReserveCapabilityManifestResult {
    data object Reserved : ReserveCapabilityManifestResult

    data object PendingAlreadyExists : ReserveCapabilityManifestResult

    data object EnrollmentChanged : ReserveCapabilityManifestResult

    data object StateChanged : ReserveCapabilityManifestResult

    data object SequenceExhausted : ReserveCapabilityManifestResult

    data object Corrupt : ReserveCapabilityManifestResult

    data object Unsupported : ReserveCapabilityManifestResult

    data class Failure(val error: LocalPersistenceError) :
        ReserveCapabilityManifestResult
}

class CapabilityManifestSendContext(
    val enrollment: StoredProtectedEnrollment,
    val pending: FrozenCapabilityManifest,
) {
    override fun toString(): String = "CapabilityManifestSendContext(<redacted>)"
}

sealed interface RevalidateCapabilityManifestResult {
    class Ready(val context: CapabilityManifestSendContext) :
        RevalidateCapabilityManifestResult {
        override fun toString(): String =
            "RevalidateCapabilityManifestResult.Ready(<redacted>)"
    }

    data object NotEnrolled : RevalidateCapabilityManifestResult

    data object EnrollmentChanged : RevalidateCapabilityManifestResult

    data object PendingChanged : RevalidateCapabilityManifestResult

    data object CredentialUnusable : RevalidateCapabilityManifestResult

    data object Corrupt : RevalidateCapabilityManifestResult

    data object Unsupported : RevalidateCapabilityManifestResult

    data class Failure(val error: LocalPersistenceError) :
        RevalidateCapabilityManifestResult
}

data class CapabilityManifestCredentialUse(
    val credentialId: CredentialId,
    val credentialVersion: Int,
)

sealed interface AcceptCapabilityManifestResult {
    data object Accepted : AcceptCapabilityManifestResult

    data object EnrollmentChanged : AcceptCapabilityManifestResult

    data object PendingChanged : AcceptCapabilityManifestResult

    data object CredentialChanged : AcceptCapabilityManifestResult

    data object CredentialUnusable : AcceptCapabilityManifestResult

    data object Corrupt : AcceptCapabilityManifestResult

    data object Unsupported : AcceptCapabilityManifestResult

    data class Failure(val error: LocalPersistenceError) :
        AcceptCapabilityManifestResult
}

interface CapabilityManifestPublicationRepository {
    suspend fun preflight(): CapabilityPublicationPreflightResult

    suspend fun reserve(
        expectation: CapabilityPublicationReservationExpectation,
        manifest: FrozenCapabilityManifest,
    ): ReserveCapabilityManifestResult

    suspend fun revalidateForSend(
        enrollmentIdentityFingerprint: Sha256Value,
        pending: FrozenCapabilityManifest,
        now: Instant,
    ): RevalidateCapabilityManifestResult

    suspend fun accept(
        enrollmentIdentityFingerprint: Sha256Value,
        pending: FrozenCapabilityManifest,
        credentialUse: CapabilityManifestCredentialUse,
        acknowledgement: CapabilityManifestAcknowledgement,
        now: Instant,
    ): AcceptCapabilityManifestResult
}
