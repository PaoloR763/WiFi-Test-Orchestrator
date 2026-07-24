package com.wifitestorchestrator.agent.data.persistence.room

import android.database.Cursor
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Update

@Dao
internal interface ProtectedEnrollmentDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: ProtectedEnrollmentEntity): Long

    @Update(onConflict = OnConflictStrategy.ABORT)
    suspend fun update(entity: ProtectedEnrollmentEntity): Int
}

internal sealed interface ObservedProtectedEnrollmentRows {
    data object Corrupt : ObservedProtectedEnrollmentRows

    class Valid(val rows: List<ProtectedEnrollmentEntity>) : ObservedProtectedEnrollmentRows {
        override fun toString(): String = "ObservedProtectedEnrollmentRows.Valid(<redacted>)"
    }
}

/**
 * Observes storage classes, bounded BLOB lengths, and values in one SQLite statement.
 *
 * The value projections return NULL for a mismatched storage class. BLOB values are additionally
 * projected only when their declared length is inside the generic safety bound, so a corrupt large
 * value is never materialized before validation.
 */
internal fun WtoAgentDatabase.observeProtectedEnrollmentRows(): ObservedProtectedEnrollmentRows {
    val cursor = openHelper.writableDatabase.query(PROTECTED_ENROLLMENT_OBSERVATION_QUERY)
    return cursor.use(::readObservedProtectedEnrollmentRows)
}

private fun readObservedProtectedEnrollmentRows(
    cursor: Cursor,
): ObservedProtectedEnrollmentRows {
    if (
        cursor.columnCount != OBSERVATION_COLUMN_NAMES.size ||
        !cursor.columnNames.contentEquals(OBSERVATION_COLUMN_NAMES)
    ) {
        return ObservedProtectedEnrollmentRows.Corrupt
    }
    if (cursor.count == 0) return ObservedProtectedEnrollmentRows.Valid(emptyList())
    if (cursor.count != 1 || !cursor.moveToFirst()) {
        return ObservedProtectedEnrollmentRows.Corrupt
    }

    EXPECTED_STORAGE_CLASSES.forEachIndexed { index, expected ->
        if (
            cursor.getType(index) != Cursor.FIELD_TYPE_STRING ||
            cursor.getString(index) != expected
        ) {
            return ObservedProtectedEnrollmentRows.Corrupt
        }
    }

    if (
        cursor.getType(NONCE_LENGTH_INDEX) != Cursor.FIELD_TYPE_INTEGER ||
        cursor.getType(SEALED_CREDENTIAL_LENGTH_INDEX) != Cursor.FIELD_TYPE_INTEGER
    ) {
        return ObservedProtectedEnrollmentRows.Corrupt
    }
    val nonceLength = cursor.getLong(NONCE_LENGTH_INDEX)
    val sealedCredentialLength = cursor.getLong(SEALED_CREDENTIAL_LENGTH_INDEX)
    if (
        nonceLength !in 1L..MAX_GENERIC_NONCE_SIZE_BYTES.toLong() ||
        sealedCredentialLength !in 1L..MAX_GENERIC_CIPHERTEXT_SIZE_BYTES.toLong()
    ) {
        return ObservedProtectedEnrollmentRows.Corrupt
    }

    EXPECTED_VALUE_CURSOR_TYPES.forEachIndexed { offset, expected ->
        if (cursor.getType(FIRST_VALUE_INDEX + offset) != expected) {
            return ObservedProtectedEnrollmentRows.Corrupt
        }
    }

    val nonce = cursor.getBlob(NONCE_VALUE_INDEX)
    val sealedCredential = cursor.getBlob(SEALED_CREDENTIAL_VALUE_INDEX)
    if (
        nonce.size.toLong() != nonceLength ||
        sealedCredential.size.toLong() != sealedCredentialLength
    ) {
        return ObservedProtectedEnrollmentRows.Corrupt
    }

    return ObservedProtectedEnrollmentRows.Valid(
        listOf(
            ProtectedEnrollmentEntity(
                singletonId = cursor.getLong(FIRST_VALUE_INDEX),
                installationId = cursor.getString(FIRST_VALUE_INDEX + 1),
                serverBaseUrl = cursor.getString(FIRST_VALUE_INDEX + 2),
                agentId = cursor.getString(FIRST_VALUE_INDEX + 3),
                deviceId = cursor.getString(FIRST_VALUE_INDEX + 4),
                protocolVersion = cursor.getString(FIRST_VALUE_INDEX + 5),
                serverReceivedAtEpochSeconds = cursor.getLong(FIRST_VALUE_INDEX + 6),
                serverReceivedAtNanoseconds = cursor.getLong(FIRST_VALUE_INDEX + 7),
                credentialId = cursor.getString(FIRST_VALUE_INDEX + 8),
                credentialVersion = cursor.getLong(FIRST_VALUE_INDEX + 9),
                issuedAtEpochSeconds = cursor.getLong(FIRST_VALUE_INDEX + 10),
                issuedAtNanoseconds = cursor.getLong(FIRST_VALUE_INDEX + 11),
                expiresAtEpochSeconds = cursor.getLong(FIRST_VALUE_INDEX + 12),
                expiresAtNanoseconds = cursor.getLong(FIRST_VALUE_INDEX + 13),
                credentialDeliveryState = cursor.getString(FIRST_VALUE_INDEX + 14),
                cryptoVersion = cursor.getLong(FIRST_VALUE_INDEX + 15),
                keyAlias = cursor.getString(FIRST_VALUE_INDEX + 16),
                nonce = nonce,
                sealedCredential = sealedCredential,
            ),
        ),
    )
}

internal const val MAX_GENERIC_NONCE_SIZE_BYTES = 64
internal const val MAX_GENERIC_CIPHERTEXT_SIZE_BYTES = 4_096

private const val STORED_COLUMN_COUNT = 19
private const val NONCE_LENGTH_INDEX = STORED_COLUMN_COUNT
private const val SEALED_CREDENTIAL_LENGTH_INDEX = STORED_COLUMN_COUNT + 1
private const val FIRST_VALUE_INDEX = STORED_COLUMN_COUNT + 2
private const val NONCE_VALUE_INDEX = FIRST_VALUE_INDEX + 17
private const val SEALED_CREDENTIAL_VALUE_INDEX = FIRST_VALUE_INDEX + 18

private val EXPECTED_STORAGE_CLASSES =
    arrayOf(
        "integer",
        "text",
        "text",
        "text",
        "text",
        "text",
        "integer",
        "integer",
        "text",
        "integer",
        "integer",
        "integer",
        "integer",
        "integer",
        "text",
        "integer",
        "text",
        "blob",
        "blob",
    )

private val EXPECTED_VALUE_CURSOR_TYPES =
    intArrayOf(
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_INTEGER,
        Cursor.FIELD_TYPE_STRING,
        Cursor.FIELD_TYPE_BLOB,
        Cursor.FIELD_TYPE_BLOB,
    )

private val OBSERVATION_COLUMN_NAMES =
    arrayOf(
        "storage_class_singleton_id",
        "storage_class_installation_id",
        "storage_class_server_base_url",
        "storage_class_agent_id",
        "storage_class_device_id",
        "storage_class_protocol_version",
        "storage_class_server_received_at_epoch_seconds",
        "storage_class_server_received_at_nanoseconds",
        "storage_class_credential_id",
        "storage_class_credential_version",
        "storage_class_issued_at_epoch_seconds",
        "storage_class_issued_at_nanoseconds",
        "storage_class_expires_at_epoch_seconds",
        "storage_class_expires_at_nanoseconds",
        "storage_class_credential_delivery_state",
        "storage_class_crypto_version",
        "storage_class_key_alias",
        "storage_class_nonce",
        "storage_class_sealed_credential",
        "nonce_length",
        "sealed_credential_length",
        "value_singleton_id",
        "value_installation_id",
        "value_server_base_url",
        "value_agent_id",
        "value_device_id",
        "value_protocol_version",
        "value_server_received_at_epoch_seconds",
        "value_server_received_at_nanoseconds",
        "value_credential_id",
        "value_credential_version",
        "value_issued_at_epoch_seconds",
        "value_issued_at_nanoseconds",
        "value_expires_at_epoch_seconds",
        "value_expires_at_nanoseconds",
        "value_credential_delivery_state",
        "value_crypto_version",
        "value_key_alias",
        "value_nonce",
        "value_sealed_credential",
    )

private const val PROTECTED_ENROLLMENT_OBSERVATION_QUERY =
    """
    SELECT
        typeof(singleton_id) AS storage_class_singleton_id,
        typeof(installation_id) AS storage_class_installation_id,
        typeof(server_base_url) AS storage_class_server_base_url,
        typeof(agent_id) AS storage_class_agent_id,
        typeof(device_id) AS storage_class_device_id,
        typeof(protocol_version) AS storage_class_protocol_version,
        typeof(server_received_at_epoch_seconds)
            AS storage_class_server_received_at_epoch_seconds,
        typeof(server_received_at_nanoseconds) AS storage_class_server_received_at_nanoseconds,
        typeof(credential_id) AS storage_class_credential_id,
        typeof(credential_version) AS storage_class_credential_version,
        typeof(issued_at_epoch_seconds) AS storage_class_issued_at_epoch_seconds,
        typeof(issued_at_nanoseconds) AS storage_class_issued_at_nanoseconds,
        typeof(expires_at_epoch_seconds) AS storage_class_expires_at_epoch_seconds,
        typeof(expires_at_nanoseconds) AS storage_class_expires_at_nanoseconds,
        typeof(credential_delivery_state) AS storage_class_credential_delivery_state,
        typeof(crypto_version) AS storage_class_crypto_version,
        typeof(key_alias) AS storage_class_key_alias,
        typeof(nonce) AS storage_class_nonce,
        typeof(sealed_credential) AS storage_class_sealed_credential,
        length(nonce) AS nonce_length,
        length(sealed_credential) AS sealed_credential_length,
        CASE WHEN typeof(singleton_id) = 'integer' THEN singleton_id END
            AS value_singleton_id,
        CASE WHEN typeof(installation_id) = 'text' THEN installation_id END
            AS value_installation_id,
        CASE WHEN typeof(server_base_url) = 'text' THEN server_base_url END
            AS value_server_base_url,
        CASE WHEN typeof(agent_id) = 'text' THEN agent_id END AS value_agent_id,
        CASE WHEN typeof(device_id) = 'text' THEN device_id END AS value_device_id,
        CASE WHEN typeof(protocol_version) = 'text' THEN protocol_version END
            AS value_protocol_version,
        CASE
            WHEN typeof(server_received_at_epoch_seconds) = 'integer'
            THEN server_received_at_epoch_seconds
        END AS value_server_received_at_epoch_seconds,
        CASE
            WHEN typeof(server_received_at_nanoseconds) = 'integer'
            THEN server_received_at_nanoseconds
        END AS value_server_received_at_nanoseconds,
        CASE WHEN typeof(credential_id) = 'text' THEN credential_id END
            AS value_credential_id,
        CASE WHEN typeof(credential_version) = 'integer' THEN credential_version END
            AS value_credential_version,
        CASE
            WHEN typeof(issued_at_epoch_seconds) = 'integer'
            THEN issued_at_epoch_seconds
        END AS value_issued_at_epoch_seconds,
        CASE WHEN typeof(issued_at_nanoseconds) = 'integer' THEN issued_at_nanoseconds END
            AS value_issued_at_nanoseconds,
        CASE
            WHEN typeof(expires_at_epoch_seconds) = 'integer'
            THEN expires_at_epoch_seconds
        END AS value_expires_at_epoch_seconds,
        CASE WHEN typeof(expires_at_nanoseconds) = 'integer' THEN expires_at_nanoseconds END
            AS value_expires_at_nanoseconds,
        CASE
            WHEN typeof(credential_delivery_state) = 'text'
            THEN credential_delivery_state
        END AS value_credential_delivery_state,
        CASE WHEN typeof(crypto_version) = 'integer' THEN crypto_version END
            AS value_crypto_version,
        CASE WHEN typeof(key_alias) = 'text' THEN key_alias END AS value_key_alias,
        CASE
            WHEN typeof(nonce) = 'blob' AND length(nonce) BETWEEN 1 AND 64
            THEN nonce
        END AS value_nonce,
        CASE
            WHEN typeof(sealed_credential) = 'blob'
                AND length(sealed_credential) BETWEEN 1 AND 4096
            THEN sealed_credential
        END AS value_sealed_credential
    FROM protected_enrollment
    ORDER BY singleton_id
    """
