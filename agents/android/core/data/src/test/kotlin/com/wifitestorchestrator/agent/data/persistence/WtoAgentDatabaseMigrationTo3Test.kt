package com.wifitestorchestrator.agent.data.persistence

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.platform.app.InstrumentationRegistry
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseMigrations
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class WtoAgentDatabaseMigrationTo3Test : RoomPersistenceTestBase() {
    @get:Rule
    val migrationHelper =
        MigrationTestHelper(
            InstrumentationRegistry.getInstrumentation(),
            WtoAgentDatabase::class.java,
        )

    @Test
    fun `exported v1 opens through 1 to 2 to 3 without false publication backfill`() {
        withMigratedDatabase(1) { database ->
            assertV3Shape(database)
            assertEquals(
                0L,
                scalarLong(database, "SELECT COUNT(*) FROM capability_manifest_publication"),
            )
        }
    }

    @Test
    fun `exported v2 opens through 2 to 3 without false publication backfill`() {
        withMigratedDatabase(2) { database ->
            assertV3Shape(database)
            assertEquals(
                0L,
                scalarLong(database, "SELECT COUNT(*) FROM capability_manifest_publication"),
            )
        }
    }

    @Test
    fun `migration installs the same fail closed guards used by fresh v3`() {
        withMigratedDatabase(2) { database ->
            assertFails {
                database.execSQL(
                    """
                    INSERT INTO capability_manifest_publication (
                        singleton_id,
                        enrollment_identity_fingerprint,
                        next_manifest_sequence,
                        sequence_exhausted
                    ) VALUES (1, zeroblob(32), 0, 0)
                    """.trimIndent(),
                )
            }
        }
    }

    private fun withMigratedDatabase(
        version: Int,
        block: (SupportSQLiteDatabase) -> Unit,
    ) {
        val name = newDatabaseName("migration-to-3")
        context.deleteDatabase(name)
        val path = context.getDatabasePath(name).absolutePath
        try {
            migrationHelper.createDatabase(path, version).close()
            val migrations =
                if (version == 1) {
                    arrayOf(
                        WtoAgentDatabaseMigrations.MIGRATION_1_2,
                        WtoAgentDatabaseMigrations.MIGRATION_2_3,
                    )
                } else {
                    arrayOf(WtoAgentDatabaseMigrations.MIGRATION_2_3)
                }
            migrationHelper
                .runMigrationsAndValidate(path, 3, true, *migrations)
                .use(block)
        } finally {
            context.deleteDatabase(name)
        }
    }

    private fun assertV3Shape(database: SupportSQLiteDatabase) {
        assertEquals(3L, scalarLong(database, "PRAGMA user_version"))
        assertEquals(
            1L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM sqlite_master " +
                    "WHERE type = 'table' AND name = 'capability_manifest_publication'",
            ),
        )
        assertEquals(
            2L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM sqlite_master " +
                    "WHERE type = 'trigger' AND tbl_name = 'capability_manifest_publication'",
            ),
        )
        assertEquals(
            1,
            database.query("PRAGMA foreign_key_list(capability_manifest_publication)").use {
                it.count
            },
        )
        val foreignKey =
            database.query("PRAGMA foreign_key_list(capability_manifest_publication)").use {
                assertTrue(it.moveToFirst())
                listOf(
                    it.getString(it.getColumnIndexOrThrow("table")),
                    it.getString(it.getColumnIndexOrThrow("on_update")),
                    it.getString(it.getColumnIndexOrThrow("on_delete")),
                )
            }
        assertEquals(listOf("protected_enrollment", "NO ACTION", "RESTRICT"), foreignKey)
    }

    private fun scalarLong(
        database: SupportSQLiteDatabase,
        query: String,
    ): Long =
        database.query(query).use {
            assertTrue(it.moveToFirst())
            it.getLong(0)
        }
}
