package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

internal object CapabilityManifestPublicationSchema {
    const val TABLE_NAME: String = "capability_manifest_publication"

    val CREATE_TABLE_SQL: String =
        """
        CREATE TABLE IF NOT EXISTS `capability_manifest_publication` (
            `singleton_id` INTEGER NOT NULL,
            `enrollment_identity_fingerprint` BLOB NOT NULL,
            `next_manifest_sequence` INTEGER NOT NULL,
            `sequence_exhausted` INTEGER NOT NULL,
            `accepted_manifest_id` TEXT,
            `accepted_manifest_sequence` INTEGER,
            `accepted_manifest_digest` BLOB,
            `accepted_server_received_at_epoch_seconds` INTEGER,
            `accepted_server_received_at_nanoseconds` INTEGER,
            `accepted_semantic_fingerprint` BLOB,
            `accepted_canonical_payload` BLOB,
            `pending_manifest_id` TEXT,
            `pending_manifest_sequence` INTEGER,
            `pending_generated_at_epoch_seconds` INTEGER,
            `pending_generated_at_nanoseconds` INTEGER,
            `pending_canonical_payload` BLOB,
            `pending_canonical_digest` BLOB,
            `pending_semantic_fingerprint` BLOB,
            PRIMARY KEY(`singleton_id`),
            FOREIGN KEY(`singleton_id`) REFERENCES `protected_enrollment`(`singleton_id`)
                ON UPDATE NO ACTION ON DELETE RESTRICT
        )
        """.trimIndent()

    private const val INSERT_TRIGGER = "capability_manifest_publication_guard_insert"
    private const val UPDATE_TRIGGER = "capability_manifest_publication_guard_update"
    private const val MAX_SEQUENCE = Long.MAX_VALUE

    val GUARD_SQL: List<String> =
        listOf(
            triggerSql(INSERT_TRIGGER, "INSERT"),
            triggerSql(UPDATE_TRIGGER, "UPDATE"),
        )

    fun installGuards(database: SupportSQLiteDatabase) {
        GUARD_SQL.forEach(database::execSQL)
    }

    fun validateGuardsReadOnly(database: SupportSQLiteDatabase) {
        val observed = mutableMapOf<String, String>()
        database
            .query(
                "SELECT name, sql FROM sqlite_master " +
                    "WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
                arrayOf(TABLE_NAME),
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    if (
                        cursor.getType(0) != android.database.Cursor.FIELD_TYPE_STRING ||
                        cursor.getType(1) != android.database.Cursor.FIELD_TYPE_STRING
                    ) {
                        throw IllegalStateException()
                    }
                    observed[cursor.getString(0)] = normalizeSql(cursor.getString(1))
                }
            }
        val expected =
            mapOf(
                INSERT_TRIGGER to normalizeSql(GUARD_SQL[0]),
                UPDATE_TRIGGER to normalizeSql(GUARD_SQL[1]),
            )
        if (observed != expected) throw IllegalStateException()
        database
            .query("PRAGMA foreign_key_check(`$TABLE_NAME`)")
            .use { cursor -> if (cursor.count != 0) throw IllegalStateException() }
    }

    val CALLBACK: RoomDatabase.Callback =
        object : RoomDatabase.Callback() {
            override fun onCreate(db: SupportSQLiteDatabase) {
                installGuards(db)
            }

            override fun onOpen(db: SupportSQLiteDatabase) {
                validateGuardsReadOnly(db)
            }
        }

    private fun triggerSql(name: String, operation: String): String =
        """
        CREATE TRIGGER IF NOT EXISTS `$name`
        BEFORE $operation ON `$TABLE_NAME`
        FOR EACH ROW
        WHEN NOT (
            typeof(NEW.singleton_id) = 'integer'
            AND NEW.singleton_id = 1
            AND typeof(NEW.enrollment_identity_fingerprint) = 'blob'
            AND length(NEW.enrollment_identity_fingerprint) = 32
            AND typeof(NEW.next_manifest_sequence) = 'integer'
            AND NEW.next_manifest_sequence BETWEEN 0 AND $MAX_SEQUENCE
            AND typeof(NEW.sequence_exhausted) = 'integer'
            AND NEW.sequence_exhausted IN (0, 1)
            AND (
                (
                    NEW.accepted_manifest_id IS NULL
                    AND NEW.accepted_manifest_sequence IS NULL
                    AND NEW.accepted_manifest_digest IS NULL
                    AND NEW.accepted_server_received_at_epoch_seconds IS NULL
                    AND NEW.accepted_server_received_at_nanoseconds IS NULL
                    AND NEW.accepted_semantic_fingerprint IS NULL
                    AND NEW.accepted_canonical_payload IS NULL
                )
                OR
                (
                    typeof(NEW.accepted_manifest_id) = 'text'
                    AND length(NEW.accepted_manifest_id) = 36
                    AND lower(NEW.accepted_manifest_id) = NEW.accepted_manifest_id
                    AND typeof(NEW.accepted_manifest_sequence) = 'integer'
                    AND NEW.accepted_manifest_sequence BETWEEN 0 AND $MAX_SEQUENCE
                    AND typeof(NEW.accepted_manifest_digest) = 'blob'
                    AND length(NEW.accepted_manifest_digest) = 32
                    AND typeof(NEW.accepted_server_received_at_epoch_seconds) = 'integer'
                    AND typeof(NEW.accepted_server_received_at_nanoseconds) = 'integer'
                    AND NEW.accepted_server_received_at_nanoseconds BETWEEN 0 AND 999999999
                    AND typeof(NEW.accepted_semantic_fingerprint) = 'blob'
                    AND length(NEW.accepted_semantic_fingerprint) = 32
                    AND typeof(NEW.accepted_canonical_payload) = 'blob'
                    AND length(NEW.accepted_canonical_payload) BETWEEN 1 AND 262144
                )
            )
            AND (
                (
                    NEW.pending_manifest_id IS NULL
                    AND NEW.pending_manifest_sequence IS NULL
                    AND NEW.pending_generated_at_epoch_seconds IS NULL
                    AND NEW.pending_generated_at_nanoseconds IS NULL
                    AND NEW.pending_canonical_payload IS NULL
                    AND NEW.pending_canonical_digest IS NULL
                    AND NEW.pending_semantic_fingerprint IS NULL
                )
                OR
                (
                    typeof(NEW.pending_manifest_id) = 'text'
                    AND length(NEW.pending_manifest_id) = 36
                    AND lower(NEW.pending_manifest_id) = NEW.pending_manifest_id
                    AND typeof(NEW.pending_manifest_sequence) = 'integer'
                    AND NEW.pending_manifest_sequence BETWEEN 0 AND $MAX_SEQUENCE
                    AND typeof(NEW.pending_generated_at_epoch_seconds) = 'integer'
                    AND typeof(NEW.pending_generated_at_nanoseconds) = 'integer'
                    AND NEW.pending_generated_at_nanoseconds BETWEEN 0 AND 999999999
                    AND typeof(NEW.pending_canonical_payload) = 'blob'
                    AND length(NEW.pending_canonical_payload) BETWEEN 1 AND 262144
                    AND typeof(NEW.pending_canonical_digest) = 'blob'
                    AND length(NEW.pending_canonical_digest) = 32
                    AND typeof(NEW.pending_semantic_fingerprint) = 'blob'
                    AND length(NEW.pending_semantic_fingerprint) = 32
                )
            )
            AND NOT (
                NEW.accepted_manifest_id IS NULL
                AND NEW.pending_manifest_id IS NULL
            )
            AND (
                (
                    NEW.accepted_manifest_id IS NULL
                    AND NEW.pending_manifest_sequence = 0
                )
                OR
                (
                    NEW.pending_manifest_id IS NULL
                    AND NEW.accepted_manifest_id IS NOT NULL
                )
                OR
                (
                    NEW.accepted_manifest_sequence < $MAX_SEQUENCE
                    AND NEW.pending_manifest_sequence = NEW.accepted_manifest_sequence + 1
                )
            )
            AND (
                (
                    NEW.sequence_exhausted = 0
                    AND COALESCE(
                        NEW.pending_manifest_sequence,
                        NEW.accepted_manifest_sequence
                    ) < $MAX_SEQUENCE
                    AND NEW.next_manifest_sequence = COALESCE(
                        NEW.pending_manifest_sequence,
                        NEW.accepted_manifest_sequence
                    ) + 1
                )
                OR
                (
                    NEW.sequence_exhausted = 1
                    AND COALESCE(
                        NEW.pending_manifest_sequence,
                        NEW.accepted_manifest_sequence
                    ) = $MAX_SEQUENCE
                    AND NEW.next_manifest_sequence = $MAX_SEQUENCE
                )
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'capability_manifest_publication_invalid');
        END
        """.trimIndent()

    private fun normalizeSql(raw: String): String =
        raw
            .replace(Regex("\\s+"), " ")
            .replace(" IF NOT EXISTS ", " ", ignoreCase = true)
            .trim()
            .lowercase()
}
