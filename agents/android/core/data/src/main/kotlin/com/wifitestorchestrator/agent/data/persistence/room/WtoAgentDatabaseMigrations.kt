package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

internal object WtoAgentDatabaseMigrations {
    val MIGRATION_1_2: Migration =
        object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `protected_enrollment` (
                        `singleton_id` INTEGER NOT NULL,
                        `installation_id` TEXT NOT NULL,
                        `server_base_url` TEXT NOT NULL,
                        `agent_id` TEXT NOT NULL,
                        `device_id` TEXT NOT NULL,
                        `protocol_version` TEXT NOT NULL,
                        `server_received_at_epoch_seconds` INTEGER NOT NULL,
                        `server_received_at_nanoseconds` INTEGER NOT NULL,
                        `credential_id` TEXT NOT NULL,
                        `credential_version` INTEGER NOT NULL,
                        `issued_at_epoch_seconds` INTEGER NOT NULL,
                        `issued_at_nanoseconds` INTEGER NOT NULL,
                        `expires_at_epoch_seconds` INTEGER NOT NULL,
                        `expires_at_nanoseconds` INTEGER NOT NULL,
                        `credential_delivery_state` TEXT NOT NULL,
                        `crypto_version` INTEGER NOT NULL,
                        `key_alias` TEXT NOT NULL,
                        `nonce` BLOB NOT NULL,
                        `sealed_credential` BLOB NOT NULL,
                        PRIMARY KEY(`singleton_id`),
                        FOREIGN KEY(`singleton_id`) REFERENCES `local_installation`(`singleton_id`)
                            ON UPDATE NO ACTION ON DELETE RESTRICT,
                        FOREIGN KEY(`singleton_id`) REFERENCES `server_configuration`(`singleton_id`)
                            ON UPDATE NO ACTION ON DELETE RESTRICT
                    )
                    """.trimIndent(),
                )
            }
        }

    val ALL: Array<Migration> = arrayOf(MIGRATION_1_2)
}
