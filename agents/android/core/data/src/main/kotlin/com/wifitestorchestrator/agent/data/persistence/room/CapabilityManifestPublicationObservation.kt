package com.wifitestorchestrator.agent.data.persistence.room

import android.database.Cursor

internal sealed interface ObservedCapabilityManifestPublication {
    data object Corrupt : ObservedCapabilityManifestPublication

    data object Absent : ObservedCapabilityManifestPublication

    class Valid(val entity: CapabilityManifestPublicationEntity) :
        ObservedCapabilityManifestPublication {
        override fun toString(): String =
            "ObservedCapabilityManifestPublication.Valid(<redacted>)"
    }
}

/**
 * Validates SQLite storage classes and BLOB lengths before any potentially coercing getter.
 *
 * Both queries execute inside the caller's Room transaction. The second query is never issued for
 * a malformed or oversized row, so an attacker-controlled payload above the C08 bound is not
 * materialized.
 */
internal fun WtoAgentDatabase.observeCapabilityManifestPublication():
    ObservedCapabilityManifestPublication {
    val metadata =
        openHelper.writableDatabase.query(METADATA_QUERY).use(::readMetadata)
            ?: return ObservedCapabilityManifestPublication.Corrupt
    if (metadata.absent) return ObservedCapabilityManifestPublication.Absent
    val cursor = openHelper.writableDatabase.query(VALUE_QUERY)
    return cursor.use { readValues(it, metadata) }
}

private data class PublicationMetadata(
    val absent: Boolean,
    val acceptedPresent: Boolean,
    val pendingPresent: Boolean,
)

private fun readMetadata(cursor: Cursor): PublicationMetadata? {
    if (cursor.count == 0) return PublicationMetadata(true, false, false)
    if (
        cursor.count != 1 ||
        cursor.columnCount != METADATA_COLUMN_NAMES.size ||
        !cursor.columnNames.contentEquals(METADATA_COLUMN_NAMES) ||
        !cursor.moveToFirst()
    ) {
        return null
    }
    repeat(STORED_COLUMN_COUNT) { index ->
        if (cursor.getType(index) != Cursor.FIELD_TYPE_STRING) return null
    }
    val storageClasses = List(STORED_COLUMN_COUNT) { cursor.getString(it) }
    val acceptedPresent = storageClasses[ACCEPTED_FIRST_INDEX] != "null"
    val pendingPresent = storageClasses[PENDING_FIRST_INDEX] != "null"
    if (!matchesStorageClasses(storageClasses, acceptedPresent, pendingPresent)) return null

    val expectedLengths =
        mapOf(
            ENROLLMENT_FINGERPRINT_LENGTH_INDEX to SHA256_SIZE,
            ACCEPTED_DIGEST_LENGTH_INDEX to if (acceptedPresent) SHA256_SIZE else null,
            ACCEPTED_FINGERPRINT_LENGTH_INDEX to if (acceptedPresent) SHA256_SIZE else null,
            ACCEPTED_PAYLOAD_LENGTH_INDEX to if (acceptedPresent) PAYLOAD_RANGE else null,
            PENDING_PAYLOAD_LENGTH_INDEX to if (pendingPresent) PAYLOAD_RANGE else null,
            PENDING_DIGEST_LENGTH_INDEX to if (pendingPresent) SHA256_SIZE else null,
            PENDING_FINGERPRINT_LENGTH_INDEX to if (pendingPresent) SHA256_SIZE else null,
        )
    expectedLengths.forEach { (index, expected) ->
        if (expected == null) {
            if (cursor.getType(index) != Cursor.FIELD_TYPE_NULL) return null
        } else {
            if (cursor.getType(index) != Cursor.FIELD_TYPE_INTEGER) return null
            if (cursor.getLong(index) !in expected) return null
        }
    }
    return PublicationMetadata(false, acceptedPresent, pendingPresent)
}

private fun matchesStorageClasses(
    actual: List<String>,
    acceptedPresent: Boolean,
    pendingPresent: Boolean,
): Boolean {
    val expected =
        listOf(
            "integer",
            "blob",
            "integer",
            "integer",
        ) +
            (
                if (acceptedPresent) {
                    ACCEPTED_STORAGE_CLASSES
                } else {
                    List(ACCEPTED_COLUMN_COUNT) { "null" }
                }
            ) +
            (
                if (pendingPresent) {
                    PENDING_STORAGE_CLASSES
                } else {
                    List(PENDING_COLUMN_COUNT) { "null" }
                }
            )
    return actual == expected
}

private fun readValues(
    cursor: Cursor,
    metadata: PublicationMetadata,
): ObservedCapabilityManifestPublication {
    if (
        cursor.count != 1 ||
        cursor.columnCount != VALUE_COLUMN_NAMES.size ||
        !cursor.columnNames.contentEquals(VALUE_COLUMN_NAMES) ||
        !cursor.moveToFirst()
    ) {
        return ObservedCapabilityManifestPublication.Corrupt
    }
    val expectedTypes =
        intArrayOf(
            Cursor.FIELD_TYPE_INTEGER,
            Cursor.FIELD_TYPE_BLOB,
            Cursor.FIELD_TYPE_INTEGER,
            Cursor.FIELD_TYPE_INTEGER,
        ) +
            if (metadata.acceptedPresent) {
                ACCEPTED_CURSOR_TYPES
            } else {
                IntArray(ACCEPTED_COLUMN_COUNT) { Cursor.FIELD_TYPE_NULL }
            } +
            if (metadata.pendingPresent) {
                PENDING_CURSOR_TYPES
            } else {
                IntArray(PENDING_COLUMN_COUNT) { Cursor.FIELD_TYPE_NULL }
            }
    expectedTypes.forEachIndexed { index, expected ->
        if (cursor.getType(index) != expected) {
            return ObservedCapabilityManifestPublication.Corrupt
        }
    }

    return ObservedCapabilityManifestPublication.Valid(
        CapabilityManifestPublicationEntity(
            singletonId = cursor.getLong(0),
            enrollmentIdentityFingerprint = cursor.getBlob(1),
            nextManifestSequence = cursor.getLong(2),
            sequenceExhausted = cursor.getLong(3),
            acceptedManifestId = cursor.stringOrNull(4),
            acceptedManifestSequence = cursor.longOrNull(5),
            acceptedManifestDigest = cursor.blobOrNull(6),
            acceptedServerReceivedAtEpochSeconds = cursor.longOrNull(7),
            acceptedServerReceivedAtNanoseconds = cursor.longOrNull(8),
            acceptedSemanticFingerprint = cursor.blobOrNull(9),
            acceptedCanonicalPayload = cursor.blobOrNull(10),
            pendingManifestId = cursor.stringOrNull(11),
            pendingManifestSequence = cursor.longOrNull(12),
            pendingGeneratedAtEpochSeconds = cursor.longOrNull(13),
            pendingGeneratedAtNanoseconds = cursor.longOrNull(14),
            pendingCanonicalPayload = cursor.blobOrNull(15),
            pendingCanonicalDigest = cursor.blobOrNull(16),
            pendingSemanticFingerprint = cursor.blobOrNull(17),
        ),
    )
}

private fun Cursor.stringOrNull(index: Int): String? =
    if (getType(index) == Cursor.FIELD_TYPE_NULL) null else getString(index)

private fun Cursor.longOrNull(index: Int): Long? =
    if (getType(index) == Cursor.FIELD_TYPE_NULL) null else getLong(index)

private fun Cursor.blobOrNull(index: Int): ByteArray? =
    if (getType(index) == Cursor.FIELD_TYPE_NULL) null else getBlob(index)

private const val STORED_COLUMN_COUNT = 18
private const val ACCEPTED_FIRST_INDEX = 4
private const val ACCEPTED_COLUMN_COUNT = 7
private const val PENDING_FIRST_INDEX = 11
private const val PENDING_COLUMN_COUNT = 7
private const val LENGTH_FIRST_INDEX = STORED_COLUMN_COUNT
private const val ENROLLMENT_FINGERPRINT_LENGTH_INDEX = LENGTH_FIRST_INDEX
private const val ACCEPTED_DIGEST_LENGTH_INDEX = LENGTH_FIRST_INDEX + 1
private const val ACCEPTED_FINGERPRINT_LENGTH_INDEX = LENGTH_FIRST_INDEX + 2
private const val ACCEPTED_PAYLOAD_LENGTH_INDEX = LENGTH_FIRST_INDEX + 3
private const val PENDING_PAYLOAD_LENGTH_INDEX = LENGTH_FIRST_INDEX + 4
private const val PENDING_DIGEST_LENGTH_INDEX = LENGTH_FIRST_INDEX + 5
private const val PENDING_FINGERPRINT_LENGTH_INDEX = LENGTH_FIRST_INDEX + 6
private val SHA256_SIZE = 32L..32L
private val PAYLOAD_RANGE = 1L..262_144L

private val ACCEPTED_STORAGE_CLASSES =
    listOf("text", "integer", "blob", "integer", "integer", "blob", "blob")
private val PENDING_STORAGE_CLASSES =
    listOf("text", "integer", "integer", "integer", "blob", "blob", "blob")
private val ACCEPTED_CURSOR_TYPES =
    intArrayOf(
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_BLOB,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_BLOB,
        Cursor.FIELD_TYPE_BLOB,
    )
private val PENDING_CURSOR_TYPES =
    intArrayOf(
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_BLOB,
        Cursor.FIELD_TYPE_BLOB,
        Cursor.FIELD_TYPE_BLOB,
    )

private val STORED_COLUMNS =
    listOf(
        "singleton_id",
        "enrollment_identity_fingerprint",
        "next_manifest_sequence",
        "sequence_exhausted",
        "accepted_manifest_id",
        "accepted_manifest_sequence",
        "accepted_manifest_digest",
        "accepted_server_received_at_epoch_seconds",
        "accepted_server_received_at_nanoseconds",
        "accepted_semantic_fingerprint",
        "accepted_canonical_payload",
        "pending_manifest_id",
        "pending_manifest_sequence",
        "pending_generated_at_epoch_seconds",
        "pending_generated_at_nanoseconds",
        "pending_canonical_payload",
        "pending_canonical_digest",
        "pending_semantic_fingerprint",
    )

private val METADATA_COLUMN_NAMES =
    (STORED_COLUMNS.map { "storage_class_$it" } +
        listOf(
            "length_enrollment_identity_fingerprint",
            "length_accepted_manifest_digest",
            "length_accepted_semantic_fingerprint",
            "length_accepted_canonical_payload",
            "length_pending_canonical_payload",
            "length_pending_canonical_digest",
            "length_pending_semantic_fingerprint",
        )).toTypedArray()

private val VALUE_COLUMN_NAMES =
    STORED_COLUMNS.map { "value_$it" }.toTypedArray()

private val METADATA_QUERY =
    """
    SELECT
        ${STORED_COLUMNS.joinToString(",\n        ") { "typeof($it) AS storage_class_$it" }},
        CASE WHEN typeof(enrollment_identity_fingerprint) = 'blob'
            THEN length(enrollment_identity_fingerprint) END
            AS length_enrollment_identity_fingerprint,
        CASE WHEN typeof(accepted_manifest_digest) = 'blob'
            THEN length(accepted_manifest_digest) END AS length_accepted_manifest_digest,
        CASE WHEN typeof(accepted_semantic_fingerprint) = 'blob'
            THEN length(accepted_semantic_fingerprint) END
            AS length_accepted_semantic_fingerprint,
        CASE WHEN typeof(accepted_canonical_payload) = 'blob'
            THEN length(accepted_canonical_payload) END AS length_accepted_canonical_payload,
        CASE WHEN typeof(pending_canonical_payload) = 'blob'
            THEN length(pending_canonical_payload) END AS length_pending_canonical_payload,
        CASE WHEN typeof(pending_canonical_digest) = 'blob'
            THEN length(pending_canonical_digest) END AS length_pending_canonical_digest,
        CASE WHEN typeof(pending_semantic_fingerprint) = 'blob'
            THEN length(pending_semantic_fingerprint) END
            AS length_pending_semantic_fingerprint
    FROM capability_manifest_publication
    ORDER BY singleton_id
    """.trimIndent()

private val VALUE_QUERY =
    """
    SELECT
        CASE WHEN typeof(singleton_id) = 'integer' THEN singleton_id END
            AS value_singleton_id,
        CASE WHEN typeof(enrollment_identity_fingerprint) = 'blob'
            AND length(enrollment_identity_fingerprint) = 32
            THEN enrollment_identity_fingerprint END
            AS value_enrollment_identity_fingerprint,
        CASE WHEN typeof(next_manifest_sequence) = 'integer'
            THEN next_manifest_sequence END AS value_next_manifest_sequence,
        CASE WHEN typeof(sequence_exhausted) = 'integer'
            THEN sequence_exhausted END AS value_sequence_exhausted,
        CASE WHEN typeof(accepted_manifest_id) = 'text'
            THEN accepted_manifest_id END AS value_accepted_manifest_id,
        CASE WHEN typeof(accepted_manifest_sequence) = 'integer'
            THEN accepted_manifest_sequence END AS value_accepted_manifest_sequence,
        CASE WHEN typeof(accepted_manifest_digest) = 'blob'
            AND length(accepted_manifest_digest) = 32
            THEN accepted_manifest_digest END AS value_accepted_manifest_digest,
        CASE WHEN typeof(accepted_server_received_at_epoch_seconds) = 'integer'
            THEN accepted_server_received_at_epoch_seconds END
            AS value_accepted_server_received_at_epoch_seconds,
        CASE WHEN typeof(accepted_server_received_at_nanoseconds) = 'integer'
            THEN accepted_server_received_at_nanoseconds END
            AS value_accepted_server_received_at_nanoseconds,
        CASE WHEN typeof(accepted_semantic_fingerprint) = 'blob'
            AND length(accepted_semantic_fingerprint) = 32
            THEN accepted_semantic_fingerprint END AS value_accepted_semantic_fingerprint,
        CASE WHEN typeof(accepted_canonical_payload) = 'blob'
            AND length(accepted_canonical_payload) BETWEEN 1 AND 262144
            THEN accepted_canonical_payload END AS value_accepted_canonical_payload,
        CASE WHEN typeof(pending_manifest_id) = 'text'
            THEN pending_manifest_id END AS value_pending_manifest_id,
        CASE WHEN typeof(pending_manifest_sequence) = 'integer'
            THEN pending_manifest_sequence END AS value_pending_manifest_sequence,
        CASE WHEN typeof(pending_generated_at_epoch_seconds) = 'integer'
            THEN pending_generated_at_epoch_seconds END
            AS value_pending_generated_at_epoch_seconds,
        CASE WHEN typeof(pending_generated_at_nanoseconds) = 'integer'
            THEN pending_generated_at_nanoseconds END
            AS value_pending_generated_at_nanoseconds,
        CASE WHEN typeof(pending_canonical_payload) = 'blob'
            AND length(pending_canonical_payload) BETWEEN 1 AND 262144
            THEN pending_canonical_payload END AS value_pending_canonical_payload,
        CASE WHEN typeof(pending_canonical_digest) = 'blob'
            AND length(pending_canonical_digest) = 32
            THEN pending_canonical_digest END AS value_pending_canonical_digest,
        CASE WHEN typeof(pending_semantic_fingerprint) = 'blob'
            AND length(pending_semantic_fingerprint) = 32
            THEN pending_semantic_fingerprint END AS value_pending_semantic_fingerprint
    FROM capability_manifest_publication
    ORDER BY singleton_id
    """.trimIndent()
