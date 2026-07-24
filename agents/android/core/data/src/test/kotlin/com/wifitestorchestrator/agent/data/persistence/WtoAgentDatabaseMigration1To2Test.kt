package com.wifitestorchestrator.agent.data.persistence

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.platform.app.InstrumentationRegistry
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseMigrations
import java.io.File
import java.time.Instant
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class WtoAgentDatabaseMigration1To2Test : RoomPersistenceTestBase() {
    @get:Rule
    val migrationHelper =
        MigrationTestHelper(
            InstrumentationRegistry.getInstrumentation(),
            WtoAgentDatabase::class.java,
        )

    @Test
    fun `empty exported v1 migrates to v2 with an empty protected enrollment table`() {
        withMigratedV1(newDatabaseName("migration-empty")) { database ->
            assertEquals(2L, scalarLong(database, "PRAGMA user_version"))
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM protected_enrollment"))
            assertEquals(
                3L,
                scalarLong(
                    database,
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' " +
                        "AND name IN (" +
                        "'local_installation', 'server_configuration', " +
                        "'protected_enrollment')",
                ),
            )
        }
    }

    @Test
    fun `exported v1 installation row is preserved exactly`() {
        withMigratedV1(
            name = newDatabaseName("migration-installation"),
            includeInstallation = true,
        ) { database ->
            assertInstallationRow(database)
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM server_configuration"))
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM protected_enrollment"))
        }
    }

    @Test
    fun `adversarial exported v1 server-only row is preserved without backfill`() {
        withMigratedV1(
            name = newDatabaseName("migration-server-only"),
            includeServer = true,
        ) { database ->
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM local_installation"))
            assertServerRow(database)
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM protected_enrollment"))
        }
    }

    @Test
    fun `exported v1 installation and server rows migrate with exact values`() {
        withMigratedV1(
            name = newDatabaseName("migration-configured"),
            includeInstallation = true,
            includeServer = true,
        ) { database ->
            assertInstallationRow(database)
            assertServerRow(database)
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM protected_enrollment"))
        }
    }

    @Test
    fun `migration validates final v2 shape FKs and absence of backfill`() {
        withMigratedV1(
            name = newDatabaseName("migration-shape"),
            includeInstallation = true,
            includeServer = true,
        ) { database ->
            val protectedSql =
                scalarString(
                    database,
                    "SELECT sql FROM sqlite_master WHERE type = 'table' " +
                        "AND name = 'protected_enrollment'",
                ).lowercase()
            assertEquals(
                0L,
                scalarLong(
                    database,
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' " +
                        "AND tbl_name = 'protected_enrollment'",
                ),
            )
            assertEquals(2, rowCount(database, "PRAGMA foreign_key_list(protected_enrollment)"))
            assertEquals(2, "foreign key".toRegex().findAll(protectedSql).count())
            assertTrue("check" !in protectedSql)
            assertEquals(0L, scalarLong(database, "SELECT COUNT(*) FROM protected_enrollment"))
        }
    }

    @Test
    fun `current migration source passes best effort maintenance hygiene checks`() {
        val projectDir =
            File(requireNotNull(System.getProperty("wto.android.data.projectDir")))
        val sourceFile =
            File(
                projectDir,
                "src/test/kotlin/com/wifitestorchestrator/agent/data/persistence/" +
                    "WtoAgentDatabaseMigration1To2Test.kt",
            )
        assertTrue(sourceFile.isFile)
        assertEquals(
            emptySet(),
            MigrationTestBestEffortMaintenanceGuard.findDirectFormViolations(
                sourceFile.readText(),
            ),
        )

        val directFormsCoveredByMaintenanceGuard =
            mapOf(
                "identity-hash-literal" to
                    ("val duplicated = \"" + "ab".repeat(16) + "\""),
                "room-metadata-reference" to
                    (
                        "database.execSQL(\"INSERT INTO room_" +
                            "master_table VALUES (42, ?)\")"
                    ),
                "identity-hash-reference" to
                    (
                        "database.execSQL(\"UPDATE metadata SET identity_" +
                            "hash = ?\")"
                    ),
                "manual-local-installation-ddl" to
                    (
                        "database.execSQL(\"CREATE TABLE local_" +
                            "installation (singleton_id INTEGER)\")"
                    ),
                "manual-server-configuration-ddl" to
                    (
                        "database.execSQL(\"CREATE TABLE server_" +
                            "configuration (singleton_id INTEGER)\")"
                    ),
                "manual-v1-index-ddl" to
                    (
                        "database.execSQL(\"CREATE INDEX idx_local_state ON local_" +
                            "installation (singleton_id)\")"
                    ),
                "manual-user-version-write" to
                    ("database.execSQL(\"PRAGMA user_version " + "= 2\")"),
            )
        directFormsCoveredByMaintenanceGuard.forEach { (expectedViolation, sample) ->
            assertTrue(
                expectedViolation in
                    MigrationTestBestEffortMaintenanceGuard.findDirectFormViolations(sample),
                "Best-effort maintenance guard did not detect direct form $expectedViolation",
            )
        }

        val dynamicAssetRead =
            """
            val exportedSchema = instrumentation.context.assets
                .open("schemas/com.example.Database/2.json")
                .bufferedReader()
                .readText()
            """.trimIndent()
        assertEquals(
            emptySet(),
            MigrationTestBestEffortMaintenanceGuard.findDirectFormViolations(dynamicAssetRead),
        )
    }

    private fun withMigratedV1(
        name: String,
        includeInstallation: Boolean = false,
        includeServer: Boolean = false,
        block: (SupportSQLiteDatabase) -> Unit,
    ) {
        context.deleteDatabase(name)
        val databasePath = context.getDatabasePath(name).absolutePath
        try {
            migrationHelper.createDatabase(databasePath, 1).use { database ->
                database.execSQL("PRAGMA foreign_keys = OFF")
                if (includeInstallation) {
                    database.execSQL(
                        "INSERT INTO local_installation VALUES (?, ?, ?, ?)",
                        arrayOf<Any?>(
                            1L,
                            FIRST_INSTALLATION_ID,
                            INSTALLATION_CREATED_AT.epochSecond,
                            INSTALLATION_CREATED_AT.nano.toLong(),
                        ),
                    )
                }
                if (includeServer) {
                    database.execSQL(
                        "INSERT INTO server_configuration VALUES (?, ?, ?, ?)",
                        arrayOf<Any?>(
                            1L,
                            FIRST_SERVER_URL,
                            SERVER_UPDATED_AT.epochSecond,
                            SERVER_UPDATED_AT.nano.toLong(),
                        ),
                    )
                }
            }

            migrationHelper
                .runMigrationsAndValidate(
                    databasePath,
                    2,
                    true,
                    WtoAgentDatabaseMigrations.MIGRATION_1_2,
                ).use(block)
        } finally {
            context.deleteDatabase(name)
        }
    }

    private fun assertInstallationRow(database: SupportSQLiteDatabase) {
        val row =
            database
                .query(
                    "SELECT singleton_id, installation_id, " +
                        "created_at_epoch_seconds, created_at_nanoseconds " +
                        "FROM local_installation",
                ).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    listOf(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getLong(2),
                        cursor.getLong(3),
                    )
                }
        assertEquals(
            listOf(
                1L,
                FIRST_INSTALLATION_ID,
                INSTALLATION_CREATED_AT.epochSecond,
                INSTALLATION_CREATED_AT.nano.toLong(),
            ),
            row,
        )
    }

    private fun assertServerRow(database: SupportSQLiteDatabase) {
        val row =
            database
                .query(
                    "SELECT singleton_id, base_url, updated_at_epoch_seconds, " +
                        "updated_at_nanoseconds FROM server_configuration",
                ).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    listOf(
                        cursor.getLong(0),
                        cursor.getString(1),
                        cursor.getLong(2),
                        cursor.getLong(3),
                    )
                }
        assertEquals(
            listOf(
                1L,
                FIRST_SERVER_URL,
                SERVER_UPDATED_AT.epochSecond,
                SERVER_UPDATED_AT.nano.toLong(),
            ),
            row,
        )
    }

    private fun scalarLong(
        database: SupportSQLiteDatabase,
        query: String,
    ): Long =
        database.query(query).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun scalarString(
        database: SupportSQLiteDatabase,
        query: String,
    ): String =
        database.query(query).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getString(0)
        }

    private fun rowCount(
        database: SupportSQLiteDatabase,
        query: String,
    ): Int =
        database.query(query).use { cursor ->
            cursor.count
        }

    private companion object {
        val INSTALLATION_CREATED_AT: Instant =
            Instant.parse("2026-07-21T12:00:00.123456789Z")
        val SERVER_UPDATED_AT: Instant =
            Instant.parse("2026-07-21T12:01:00.987654321Z")
    }
}

/**
 * Best-effort maintenance hygiene for direct, contiguous source forms.
 *
 * This is intentionally not a Kotlin parser or a security boundary. It does not evaluate
 * constants, concatenations, interpolation, generated code, or deliberately modified checks;
 * review must still confirm that the migration fixture starts from the exported Room schema.
 */
private object MigrationTestBestEffortMaintenanceGuard {
    private val identityHashLiteral =
        Regex("""(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])""")
    private val localInstallationDdl =
        Regex(
            """(?is)\bcreate\s+table\b.{0,400}\blocal_installation\b""",
        )
    private val serverConfigurationDdl =
        Regex(
            """(?is)\bcreate\s+table\b.{0,400}\bserver_configuration\b""",
        )
    private val v1IndexDdl =
        Regex(
            """(?is)\bcreate\s+(?:unique\s+)?index\b.{0,400}""" +
                """\b(?:local_installation|server_configuration)\b""",
        )
    private val manualUserVersion =
        Regex("""(?is)\bpragma\s+user_version\s*=""")

    fun findDirectFormViolations(source: String): Set<String> =
        buildSet {
            if (identityHashLiteral.containsMatchIn(source)) {
                add("identity-hash-literal")
            }
            if (source.contains("room_" + "master_table", ignoreCase = true)) {
                add("room-metadata-reference")
            }
            if (source.contains("identity_" + "hash", ignoreCase = true)) {
                add("identity-hash-reference")
            }
            if (localInstallationDdl.containsMatchIn(source)) {
                add("manual-local-installation-ddl")
            }
            if (serverConfigurationDdl.containsMatchIn(source)) {
                add("manual-server-configuration-ddl")
            }
            if (v1IndexDdl.containsMatchIn(source)) {
                add("manual-v1-index-ddl")
            }
            if (manualUserVersion.containsMatchIn(source)) {
                add("manual-user-version-write")
            }
        }
}
