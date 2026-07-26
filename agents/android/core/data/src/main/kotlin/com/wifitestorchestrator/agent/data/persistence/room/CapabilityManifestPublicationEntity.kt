package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey

@Entity(
    tableName = "capability_manifest_publication",
    foreignKeys = [
        ForeignKey(
            entity = ProtectedEnrollmentEntity::class,
            parentColumns = ["singleton_id"],
            childColumns = ["singleton_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.NO_ACTION,
        ),
    ],
)
internal data class CapabilityManifestPublicationEntity(
    @PrimaryKey
    @ColumnInfo(name = "singleton_id")
    val singletonId: Long,
    @ColumnInfo(name = "enrollment_identity_fingerprint", typeAffinity = ColumnInfo.BLOB)
    val enrollmentIdentityFingerprint: ByteArray,
    @ColumnInfo(name = "next_manifest_sequence")
    val nextManifestSequence: Long,
    @ColumnInfo(name = "sequence_exhausted")
    val sequenceExhausted: Long,
    @ColumnInfo(name = "accepted_manifest_id")
    val acceptedManifestId: String?,
    @ColumnInfo(name = "accepted_manifest_sequence")
    val acceptedManifestSequence: Long?,
    @ColumnInfo(name = "accepted_manifest_digest", typeAffinity = ColumnInfo.BLOB)
    val acceptedManifestDigest: ByteArray?,
    @ColumnInfo(name = "accepted_server_received_at_epoch_seconds")
    val acceptedServerReceivedAtEpochSeconds: Long?,
    @ColumnInfo(name = "accepted_server_received_at_nanoseconds")
    val acceptedServerReceivedAtNanoseconds: Long?,
    @ColumnInfo(name = "accepted_semantic_fingerprint", typeAffinity = ColumnInfo.BLOB)
    val acceptedSemanticFingerprint: ByteArray?,
    @ColumnInfo(name = "accepted_canonical_payload", typeAffinity = ColumnInfo.BLOB)
    val acceptedCanonicalPayload: ByteArray?,
    @ColumnInfo(name = "pending_manifest_id")
    val pendingManifestId: String?,
    @ColumnInfo(name = "pending_manifest_sequence")
    val pendingManifestSequence: Long?,
    @ColumnInfo(name = "pending_generated_at_epoch_seconds")
    val pendingGeneratedAtEpochSeconds: Long?,
    @ColumnInfo(name = "pending_generated_at_nanoseconds")
    val pendingGeneratedAtNanoseconds: Long?,
    @ColumnInfo(name = "pending_canonical_payload", typeAffinity = ColumnInfo.BLOB)
    val pendingCanonicalPayload: ByteArray?,
    @ColumnInfo(name = "pending_canonical_digest", typeAffinity = ColumnInfo.BLOB)
    val pendingCanonicalDigest: ByteArray?,
    @ColumnInfo(name = "pending_semantic_fingerprint", typeAffinity = ColumnInfo.BLOB)
    val pendingSemanticFingerprint: ByteArray?,
) {
    override fun toString(): String = "CapabilityManifestPublicationEntity(<redacted>)"
}
