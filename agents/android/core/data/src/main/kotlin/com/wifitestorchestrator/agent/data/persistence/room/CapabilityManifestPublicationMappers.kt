package com.wifitestorchestrator.agent.data.persistence.room

import com.wifitestorchestrator.agent.data.capability.CapabilityManifestCodec
import com.wifitestorchestrator.agent.data.capability.FrozenCapabilityManifest
import com.wifitestorchestrator.agent.data.capability.Sha256Value
import com.wifitestorchestrator.agent.data.persistence.AcceptedCapabilityManifest
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationState
import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import java.time.DateTimeException
import java.time.Instant

internal sealed interface MappedCapabilityManifestPublication {
    data object Empty : MappedCapabilityManifestPublication

    class Valid(
        val state: CapabilityManifestPublicationState.Stored,
        val entity: CapabilityManifestPublicationEntity,
    ) : MappedCapabilityManifestPublication {
        override fun toString(): String =
            "MappedCapabilityManifestPublication.Valid(<redacted>)"
    }

    data object Corrupt : MappedCapabilityManifestPublication
}

internal fun mapCapabilityManifestPublication(
    enrollment: StoredProtectedEnrollment,
    observed: ObservedCapabilityManifestPublication,
    codec: CapabilityManifestCodec,
): MappedCapabilityManifestPublication {
    return when (observed) {
        ObservedCapabilityManifestPublication.Absent ->
            MappedCapabilityManifestPublication.Empty
        ObservedCapabilityManifestPublication.Corrupt ->
            MappedCapabilityManifestPublication.Corrupt
        is ObservedCapabilityManifestPublication.Valid ->
            observed.entity.toMapped(enrollment, codec)
    }
}

internal fun CapabilityManifestPublicationEntity.isByteIdenticalTo(
    other: CapabilityManifestPublicationEntity,
): Boolean =
    singletonId == other.singletonId &&
        enrollmentIdentityFingerprint.contentEquals(other.enrollmentIdentityFingerprint) &&
        nextManifestSequence == other.nextManifestSequence &&
        sequenceExhausted == other.sequenceExhausted &&
        acceptedManifestId == other.acceptedManifestId &&
        acceptedManifestSequence == other.acceptedManifestSequence &&
        acceptedManifestDigest.contentEqualsNullable(other.acceptedManifestDigest) &&
        acceptedServerReceivedAtEpochSeconds == other.acceptedServerReceivedAtEpochSeconds &&
        acceptedServerReceivedAtNanoseconds == other.acceptedServerReceivedAtNanoseconds &&
        acceptedSemanticFingerprint.contentEqualsNullable(other.acceptedSemanticFingerprint) &&
        acceptedCanonicalPayload.contentEqualsNullable(other.acceptedCanonicalPayload) &&
        pendingManifestId == other.pendingManifestId &&
        pendingManifestSequence == other.pendingManifestSequence &&
        pendingGeneratedAtEpochSeconds == other.pendingGeneratedAtEpochSeconds &&
        pendingGeneratedAtNanoseconds == other.pendingGeneratedAtNanoseconds &&
        pendingCanonicalPayload.contentEqualsNullable(other.pendingCanonicalPayload) &&
        pendingCanonicalDigest.contentEqualsNullable(other.pendingCanonicalDigest) &&
        pendingSemanticFingerprint.contentEqualsNullable(other.pendingSemanticFingerprint)

internal fun newPendingPublicationEntity(
    enrollmentIdentityFingerprint: Sha256Value,
    pending: FrozenCapabilityManifest,
): CapabilityManifestPublicationEntity =
    CapabilityManifestPublicationEntity(
        singletonId = LOCAL_STATE_SINGLETON_ID,
        enrollmentIdentityFingerprint = enrollmentIdentityFingerprint.copyBytes(),
        nextManifestSequence = pending.nextSequenceOrSentinel(),
        sequenceExhausted = pending.exhaustionFlag(),
        acceptedManifestId = null,
        acceptedManifestSequence = null,
        acceptedManifestDigest = null,
        acceptedServerReceivedAtEpochSeconds = null,
        acceptedServerReceivedAtNanoseconds = null,
        acceptedSemanticFingerprint = null,
        acceptedCanonicalPayload = null,
        pendingManifestId = pending.manifestId,
        pendingManifestSequence = pending.manifestSequence,
        pendingGeneratedAtEpochSeconds = pending.generatedAt.epochSecond,
        pendingGeneratedAtNanoseconds = pending.generatedAt.nano.toLong(),
        pendingCanonicalPayload = pending.copyCanonicalPayload(),
        pendingCanonicalDigest = pending.canonicalDigest.copyBytes(),
        pendingSemanticFingerprint = pending.semanticFingerprint.copyBytes(),
    )

internal fun CapabilityManifestPublicationEntity.withPending(
    pending: FrozenCapabilityManifest,
): CapabilityManifestPublicationEntity =
    copy(
        nextManifestSequence = pending.nextSequenceOrSentinel(),
        sequenceExhausted = pending.exhaustionFlag(),
        pendingManifestId = pending.manifestId,
        pendingManifestSequence = pending.manifestSequence,
        pendingGeneratedAtEpochSeconds = pending.generatedAt.epochSecond,
        pendingGeneratedAtNanoseconds = pending.generatedAt.nano.toLong(),
        pendingCanonicalPayload = pending.copyCanonicalPayload(),
        pendingCanonicalDigest = pending.canonicalDigest.copyBytes(),
        pendingSemanticFingerprint = pending.semanticFingerprint.copyBytes(),
    )

internal fun CapabilityManifestPublicationEntity.acceptPending(
    serverReceivedAt: Instant,
): CapabilityManifestPublicationEntity =
    copy(
        acceptedManifestId = pendingManifestId,
        acceptedManifestSequence = pendingManifestSequence,
        acceptedManifestDigest = pendingCanonicalDigest?.copyOf(),
        acceptedServerReceivedAtEpochSeconds = serverReceivedAt.epochSecond,
        acceptedServerReceivedAtNanoseconds = serverReceivedAt.nano.toLong(),
        acceptedSemanticFingerprint = pendingSemanticFingerprint?.copyOf(),
        acceptedCanonicalPayload = pendingCanonicalPayload?.copyOf(),
        pendingManifestId = null,
        pendingManifestSequence = null,
        pendingGeneratedAtEpochSeconds = null,
        pendingGeneratedAtNanoseconds = null,
        pendingCanonicalPayload = null,
        pendingCanonicalDigest = null,
        pendingSemanticFingerprint = null,
    )

private fun CapabilityManifestPublicationEntity.toMapped(
    enrollment: StoredProtectedEnrollment,
    codec: CapabilityManifestCodec,
): MappedCapabilityManifestPublication {
    if (
        singletonId != LOCAL_STATE_SINGLETON_ID ||
        nextManifestSequence < 0L ||
        sequenceExhausted !in 0L..1L
    ) {
        return MappedCapabilityManifestPublication.Corrupt
    }
    val storedBinding =
        Sha256Value.from(enrollmentIdentityFingerprint)
            ?: return MappedCapabilityManifestPublication.Corrupt
    val expectedBinding =
        com.wifitestorchestrator.agent.data.capability.EnrollmentBindingFingerprint
            .compute(enrollment)
            ?: return MappedCapabilityManifestPublication.Corrupt
    if (!storedBinding.contentEquals(expectedBinding)) {
        return MappedCapabilityManifestPublication.Corrupt
    }

    val acceptedPresent = acceptedManifestId != null
    val pendingPresent = pendingManifestId != null
    if (!acceptedTupleComplete(acceptedPresent) || !pendingTupleComplete(pendingPresent)) {
        return MappedCapabilityManifestPublication.Corrupt
    }
    if (!acceptedPresent && !pendingPresent) {
        return MappedCapabilityManifestPublication.Corrupt
    }

    val accepted =
        if (acceptedPresent) {
            mapAccepted(enrollment, codec)
                ?: return MappedCapabilityManifestPublication.Corrupt
        } else {
            null
        }
    val pending =
        if (pendingPresent) {
            mapPending(enrollment, codec)
                ?: return MappedCapabilityManifestPublication.Corrupt
        } else {
            null
        }
    if (!validSequenceRelationship(accepted?.manifest, pending)) {
        return MappedCapabilityManifestPublication.Corrupt
    }
    val highest = pending?.manifestSequence ?: accepted?.manifest?.manifestSequence
        ?: return MappedCapabilityManifestPublication.Corrupt
    val expectedExhausted = highest == Long.MAX_VALUE
    val expectedNext = if (expectedExhausted) Long.MAX_VALUE else highest + 1L
    if (
        sequenceExhausted == 1L != expectedExhausted ||
        nextManifestSequence != expectedNext
    ) {
        return MappedCapabilityManifestPublication.Corrupt
    }

    return MappedCapabilityManifestPublication.Valid(
        state =
            CapabilityManifestPublicationState.Stored(
                enrollmentIdentityFingerprint = storedBinding,
                nextManifestSequence = nextManifestSequence,
                sequenceExhausted = expectedExhausted,
                accepted = accepted,
                pending = pending,
            ),
        entity = this,
    )
}

private fun CapabilityManifestPublicationEntity.mapAccepted(
    enrollment: StoredProtectedEnrollment,
    codec: CapabilityManifestCodec,
): AcceptedCapabilityManifest? {
    val digest = Sha256Value.from(acceptedManifestDigest ?: return null) ?: return null
    val fingerprint =
        Sha256Value.from(acceptedSemanticFingerprint ?: return null) ?: return null
    val payload = acceptedCanonicalPayload ?: return null
    val manifest =
        codec.validatePersisted(
            canonicalPayload = payload,
            canonicalDigest = digest,
            semanticFingerprint = fingerprint,
            expectedAgentId = enrollment.backendIdentity.agentId,
            expectedManifestId = acceptedManifestId ?: return null,
            expectedSequence = acceptedManifestSequence ?: return null,
        ) ?: return null
    val serverReceivedAt =
        instantOrNull(
            acceptedServerReceivedAtEpochSeconds ?: return null,
            acceptedServerReceivedAtNanoseconds ?: return null,
        ) ?: return null
    return AcceptedCapabilityManifest(manifest, serverReceivedAt)
}

private fun CapabilityManifestPublicationEntity.mapPending(
    enrollment: StoredProtectedEnrollment,
    codec: CapabilityManifestCodec,
): FrozenCapabilityManifest? {
    val digest = Sha256Value.from(pendingCanonicalDigest ?: return null) ?: return null
    val fingerprint =
        Sha256Value.from(pendingSemanticFingerprint ?: return null) ?: return null
    val payload = pendingCanonicalPayload ?: return null
    val generatedAt =
        instantOrNull(
            pendingGeneratedAtEpochSeconds ?: return null,
            pendingGeneratedAtNanoseconds ?: return null,
        ) ?: return null
    val manifest =
        codec.validatePersisted(
            canonicalPayload = payload,
            canonicalDigest = digest,
            semanticFingerprint = fingerprint,
            expectedAgentId = enrollment.backendIdentity.agentId,
            expectedManifestId = pendingManifestId ?: return null,
            expectedSequence = pendingManifestSequence ?: return null,
        ) ?: return null
    return manifest.takeIf { it.generatedAt == generatedAt }
}

private fun CapabilityManifestPublicationEntity.acceptedTupleComplete(
    present: Boolean,
): Boolean =
    listOf(
        acceptedManifestId,
        acceptedManifestSequence,
        acceptedManifestDigest,
        acceptedServerReceivedAtEpochSeconds,
        acceptedServerReceivedAtNanoseconds,
        acceptedSemanticFingerprint,
        acceptedCanonicalPayload,
    ).all { (it != null) == present }

private fun CapabilityManifestPublicationEntity.pendingTupleComplete(
    present: Boolean,
): Boolean =
    listOf(
        pendingManifestId,
        pendingManifestSequence,
        pendingGeneratedAtEpochSeconds,
        pendingGeneratedAtNanoseconds,
        pendingCanonicalPayload,
        pendingCanonicalDigest,
        pendingSemanticFingerprint,
    ).all { (it != null) == present }

private fun validSequenceRelationship(
    accepted: FrozenCapabilityManifest?,
    pending: FrozenCapabilityManifest?,
): Boolean =
    when {
        accepted == null && pending != null -> pending.manifestSequence == 0L
        accepted != null && pending == null -> true
        accepted != null && pending != null ->
            accepted.manifestSequence < Long.MAX_VALUE &&
                pending.manifestSequence == accepted.manifestSequence + 1L
        else -> false
    }

private fun FrozenCapabilityManifest.nextSequenceOrSentinel(): Long =
    if (manifestSequence == Long.MAX_VALUE) Long.MAX_VALUE else manifestSequence + 1L

private fun FrozenCapabilityManifest.exhaustionFlag(): Long =
    if (manifestSequence == Long.MAX_VALUE) 1L else 0L

private fun instantOrNull(
    epochSeconds: Long,
    nanoseconds: Long,
): Instant? {
    if (nanoseconds !in 0L..999_999_999L) return null
    return try {
        Instant.ofEpochSecond(epochSeconds, nanoseconds)
    } catch (_: DateTimeException) {
        null
    }
}

private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
    when {
        this == null || other == null -> this == null && other == null
        else -> contentEquals(other)
    }
