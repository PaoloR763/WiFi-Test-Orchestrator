package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.data.persistence.room.ProcessRoomDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import java.io.File
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class AndroidLocalPersistenceFactoryTest : RoomPersistenceTestBase() {
    @After
    fun closeProcessDatabase() {
        ProcessRoomDatabaseProvider.closeForTestsOrMaintenance()
        removeTestDatabaseFiles(WtoAgentDatabase.DATABASE_NAME)
        removeStandardProductDatabaseFiles()
    }

    @Test
    fun `factory and repository construction perform no database IO`() {
        ProcessRoomDatabaseProvider.closeForTestsOrMaintenance()
        removeTestDatabaseFiles(WtoAgentDatabase.DATABASE_NAME)
        removeStandardProductDatabaseFiles()
        val before = productStorageSnapshot()
        assertTrue(before.productEntries.isEmpty())

        val factory = AndroidLocalPersistenceFactory(context)
        assertEquals(before, productStorageSnapshot())
        factory.create()
        factory.createProtectedEnrollmentRepository()

        assertEquals(before, productStorageSnapshot())
    }

    @Test
    fun `first operation opens the fixed database under no backup`() = runTest {
        ProcessRoomDatabaseProvider.closeForTestsOrMaintenance()
        removeTestDatabaseFiles(WtoAgentDatabase.DATABASE_NAME)
        val repository = AndroidLocalPersistenceFactory(context).create()

        assertEquals(ReadLocalStateResult.Absent, repository.readLocalState())

        val file = databaseFile(WtoAgentDatabase.DATABASE_NAME)
        assertTrue(file.isFile)
        assertEquals(
            context.noBackupFilesDir.canonicalFile,
            requireNotNull(file.parentFile).canonicalFile,
        )
        assertProductFilesConfined()
    }

    @Test
    fun `multiple factories publish one process database instance`() = runTest {
        ProcessRoomDatabaseProvider.closeForTestsOrMaintenance()
        removeTestDatabaseFiles(WtoAgentDatabase.DATABASE_NAME)
        val firstRepository = AndroidLocalPersistenceFactory(context).create()
        val secondRepository = AndroidLocalPersistenceFactory(context).create()

        val results =
            listOf(firstRepository, secondRepository)
                .map { repository ->
                    async {
                        repository.ensureLocalInstallation(
                            localIdentity(),
                            java.time.Instant.parse("2026-07-21T12:00:00.123456789Z"),
                        )
                    }
                }
                .awaitAll()

        assertEquals(1, results.count { it == EnsureLocalInstallationResult.Created })
        assertEquals(1, results.count { it == EnsureLocalInstallationResult.Existing })
        assertSame(
            ProcessRoomDatabaseProvider.get(context),
            ProcessRoomDatabaseProvider.get(context),
        )
    }

    @Test
    fun `public repository API does not expose close`() {
        val methodNames =
            listOf(
                LocalStateRepository::class.java,
                ProtectedEnrollmentRepository::class.java,
            ).flatMap { type -> type.methods.map { it.name } }
                .toSet()

        assertFalse("close" in methodNames)
    }

    @Test
    fun `factory memoizes both repository ports without composing enrollment`() {
        val factory = AndroidLocalPersistenceFactory(context)

        assertSame(factory.create(), factory.create())
        assertSame(
            factory.createProtectedEnrollmentRepository(),
            factory.createProtectedEnrollmentRepository(),
        )
    }

    private fun assertProductFilesConfined() {
        val expectedParent = context.noBackupFilesDir.canonicalFile
        productFileNames().forEach { fileName ->
            val noBackupFile = File(context.noBackupFilesDir, fileName)
            if (noBackupFile.exists()) {
                assertEquals(expectedParent, requireNotNull(noBackupFile.parentFile).canonicalFile)
            }
        }

        val standardParent = requireNotNull(context.getDatabasePath(WtoAgentDatabase.DATABASE_NAME).parentFile)
        productFileNames().forEach { fileName ->
            assertFalse(File(standardParent, fileName).exists())
        }
    }

    private fun productStorageSnapshot(): ProductStorageSnapshot {
        val standardParent = requireNotNull(context.getDatabasePath(WtoAgentDatabase.DATABASE_NAME).parentFile)
        val productEntries =
            listOf(context.noBackupFilesDir, standardParent)
                .flatMap { parent -> productFileNames().map { fileName -> File(parent, fileName) } }
                .filter(File::exists)
                .map { it.canonicalPath }
                .toSet()
        return ProductStorageSnapshot(
            productEntries = productEntries,
            standardDirectoryExists = standardParent.exists(),
        )
    }

    private fun removeStandardProductDatabaseFiles() {
        val standardParent = requireNotNull(context.getDatabasePath(WtoAgentDatabase.DATABASE_NAME).parentFile)
        productFileNames().forEach { fileName ->
            try {
                File(standardParent, fileName).delete()
            } catch (_: SecurityException) {
                // Cleanup remains scoped to the product database namespace.
            }
        }
    }

    private fun productFileNames(): List<String> {
        val name = WtoAgentDatabase.DATABASE_NAME
        return listOf(name, "$name-wal", "$name-shm", "$name-journal")
    }

    private data class ProductStorageSnapshot(
        val productEntries: Set<String>,
        val standardDirectoryExists: Boolean,
    )
}
