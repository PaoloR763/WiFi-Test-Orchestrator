package com.wifitestorchestrator.agent.data.persistence

import android.database.sqlite.SQLiteDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import com.wifitestorchestrator.agent.data.persistence.room.FailClosedCallback
import com.wifitestorchestrator.agent.data.persistence.room.StorageMigrationMissingException
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributes
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class WtoAgentDatabaseTest : RoomPersistenceTestBase() {
    @Test
    fun `fresh v3 database is created under no backup with WAL and foreign keys`() = runTest {
        val name = newDatabaseName("wto-fresh")
        val database = openDatabase(name)

        assertEquals(ReadLocalStateResult.Absent, repository(database).readLocalState())

        val expectedFile = databaseFile(name)
        assertTrue(expectedFile.isFile)
        assertEquals(
            context.noBackupFilesDir.canonicalFile,
            requireNotNull(expectedFile.parentFile).canonicalFile,
        )
        assertProductFilesConfined(name)
        assertEquals("wal", scalarString(database, "PRAGMA journal_mode").lowercase())
        assertEquals(1L, scalarLong(database, "PRAGMA foreign_keys"))
        assertEquals(3L, scalarLong(database, "PRAGMA user_version"))
        assertEquals(
            "fc6ae10689d928ae79814722274f529e",
            scalarString(
                database,
                "SELECT identity_hash FROM room_master_table WHERE id = 42",
            ),
        )
        assertEquals(
            2L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' " +
                    "AND tbl_name = 'capability_manifest_publication'",
            ),
        )
    }

    @Test
    fun `main thread access remains prohibited`() {
        val database = openDatabase()

        assertFailsWith<IllegalStateException> {
            database.assertNotMainThread()
        }
    }

    @Test
    fun `higher schema version is rejected and main file is preserved`() = runTest {
        val name = newDatabaseName("wto-downgrade")
        val first = openDatabase(name)
        repository(first).readLocalState()
        first.close()
        val file = databaseFile(name)
        setUserVersion(file, 4)
        val beforeKey = fileKey(file)
        val beforeLength = file.length()

        val result = repository(reopenDatabase(name)).readLocalState()

        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.SCHEMA_INCOMPATIBLE),
            result,
        )
        assertTrue(file.isFile)
        assertEquals(beforeLength, file.length())
        assertStableFileKey(beforeKey, fileKey(file))
        assertEquals(4, readUserVersion(file))
    }

    @Test
    fun `identity hash mismatch is rejected without recreation`() = runTest {
        val name = newDatabaseName("wto-schema-mismatch")
        val first = openDatabase(name)
        repository(first).readLocalState()
        first.close()
        val file = databaseFile(name)
        updateIdentityHash(file)
        val beforeKey = fileKey(file)
        val beforeLength = file.length()

        val result = repository(reopenDatabase(name)).readLocalState()

        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.SCHEMA_INCOMPATIBLE),
            result,
        )
        assertTrue(file.isFile)
        assertEquals(beforeLength, file.length())
        assertStableFileKey(beforeKey, fileKey(file))
    }

    @Test
    fun `corrupt database remains fail closed across repeated and independent access`() = runTest {
        val name = newDatabaseName("wto-corrupt")
        val first = openDatabase(name)
        assertEquals(
            InitializeLocalStateResult.Created,
            repository(first).initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = Instant.parse("2026-07-21T12:00:00.123456789Z"),
                serverConfigurationUpdatedAt = Instant.parse("2026-07-21T12:01:00.987654321Z"),
            ),
        )
        first.close()
        val file = databaseFile(name)
        corruptHeader(file)
        val evidence =
            CorruptedFileEvidence(
                length = file.length(),
                header = readHeader(file),
                fileKey = fileKey(file),
            )
        assertCorruptedDatabasePreserved(name, evidence)

        val failedRepository = repository(reopenDatabase(name))
        repeat(2) {
            assertCorruptedDatabasePreserved(name, evidence)
            val sidecarsBefore = captureExistingSidecars(name)
            assertEquals(
                ReadLocalStateResult.Failure(LocalPersistenceError.CORRUPTION),
                failedRepository.readLocalState(),
            )
            assertCorruptedDatabasePreserved(name, evidence)
            assertExistingSidecarsPreserved(sidecarsBefore)
        }

        val independentRepository = repository(reopenDatabase(name))
        assertCorruptedDatabasePreserved(name, evidence)
        val sidecarsBeforeIndependentAttempt = captureExistingSidecars(name)
        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.CORRUPTION),
            independentRepository.readLocalState(),
        )
        assertCorruptedDatabasePreserved(name, evidence)
        assertExistingSidecarsPreserved(sidecarsBeforeIndependentAttempt)
    }

    @Test
    fun `missing migration callback is classified without raw cause`() {
        val database = openDatabase()
        val callback =
            FailClosedCallback(
                delegate =
                    object : SupportSQLiteOpenHelper.Callback(2) {
                        override fun onCreate(db: SupportSQLiteDatabase) = Unit

                        override fun onUpgrade(
                            db: SupportSQLiteDatabase,
                            oldVersion: Int,
                            newVersion: Int,
                        ) {
                            throw IllegalStateException("untrusted diagnostic")
                        }
                    },
                corruptionState = AtomicBoolean(false),
            )

        val failure =
            assertFailsWith<StorageMigrationMissingException> {
                callback.onUpgrade(database.openHelper.writableDatabase, 1, 2)
            }

        assertTrue(failure.message == null)
        assertTrue(failure.cause == null)
        assertTrue(failure.stackTrace.isEmpty())
    }

    private fun scalarString(database: WtoAgentDatabase, query: String): String =
        database.openHelper.writableDatabase.query(query).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getString(0)
        }

    private fun scalarLong(database: WtoAgentDatabase, query: String): Long =
        database.openHelper.writableDatabase.query(query).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private fun setUserVersion(file: java.io.File, version: Int) {
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
            database.execSQL("PRAGMA user_version = $version")
        }
    }

    private fun readUserVersion(file: java.io.File): Int =
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { database ->
            database.rawQuery("PRAGMA user_version", null).use { cursor ->
                assertTrue(cursor.moveToFirst())
                cursor.getInt(0)
            }
        }

    private fun updateIdentityHash(file: java.io.File) {
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
            database.execSQL(
                "UPDATE room_master_table SET identity_hash = 'invalid_identity' WHERE id = 42",
            )
        }
    }

    private fun corruptHeader(file: java.io.File) {
        val replacement = "corrupt-wto-data".toByteArray(StandardCharsets.US_ASCII)
        RandomAccessFile(file, "rw").use { randomAccess ->
            randomAccess.seek(0)
            randomAccess.write(replacement)
            randomAccess.fd.sync()
        }
    }

    private fun readHeader(file: java.io.File): ByteArray =
        RandomAccessFile(file, "r").use { randomAccess ->
            ByteArray(16).also(randomAccess::readFully)
        }

    private fun fileKey(file: java.io.File): Any? =
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java).fileKey()

    private fun assertStableFileKey(before: Any?, after: Any?) {
        if (before != null || after != null) {
            assertNotNull(before)
            assertEquals(before, after)
        }
    }

    private fun assertCorruptedDatabasePreserved(
        name: String,
        evidence: CorruptedFileEvidence,
    ) {
        val file = databaseFile(name)
        assertTrue(file.isFile)
        assertEquals(evidence.length, file.length())
        assertEquals(evidence.header.toList(), readHeader(file).toList())
        assertNotEquals("SQLite format 3\u0000", String(readHeader(file), StandardCharsets.US_ASCII))
        assertStableFileKey(evidence.fileKey, fileKey(file))
        assertProductFilesConfined(name)
    }

    private fun assertProductFilesConfined(name: String) {
        val expectedParent = context.noBackupFilesDir.canonicalFile
        productFileNames(name).forEach { fileName ->
            val noBackupFile = File(context.noBackupFilesDir, fileName)
            if (noBackupFile.exists()) {
                assertEquals(expectedParent, requireNotNull(noBackupFile.parentFile).canonicalFile)
            }
        }

        val standardMain = context.getDatabasePath(name)
        val standardParent = requireNotNull(standardMain.parentFile)
        productFileNames(name).forEach { fileName ->
            assertTrue(!File(standardParent, fileName).exists())
        }
    }

    private fun productFileNames(name: String): List<String> =
        listOf(name, "$name-wal", "$name-shm", "$name-journal")

    private fun captureExistingSidecars(name: String): List<SidecarEvidence> =
        listOf("$name-wal", "$name-shm", "$name-journal")
            .map { fileName -> File(context.noBackupFilesDir, fileName) }
            .filter(File::exists)
            .map { file ->
                SidecarEvidence(
                    file = file.canonicalFile,
                    fileKey = fileKey(file),
                )
            }

    private fun assertExistingSidecarsPreserved(sidecars: List<SidecarEvidence>) {
        sidecars.forEach { evidence ->
            assertTrue(evidence.file.isFile)
            assertEquals(
                context.noBackupFilesDir.canonicalFile,
                requireNotNull(evidence.file.parentFile).canonicalFile,
            )
            assertStableFileKey(evidence.fileKey, fileKey(evidence.file))
        }
    }

    private data class CorruptedFileEvidence(
        val length: Long,
        val header: ByteArray,
        val fileKey: Any?,
    )

    private data class SidecarEvidence(
        val file: File,
        val fileKey: Any?,
    )
}
