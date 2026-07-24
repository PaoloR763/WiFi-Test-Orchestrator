package com.wifitestorchestrator.agent.data.persistence

import android.database.sqlite.SQLiteConstraintException
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import com.wifitestorchestrator.agent.data.persistence.room.LOCAL_STATE_SINGLETON_ID
import com.wifitestorchestrator.agent.data.persistence.room.LocalInstallationEntity
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.room.ServerConfigurationEntity
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.toEntity
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

@RunWith(RobolectricTestRunner::class)
internal class RoomLocalStateRepositoryTest : RoomPersistenceTestBase() {
    private val createdAt = Instant.parse("2026-07-21T10:00:00.123456789Z")
    private val updatedAt = Instant.parse("2026-07-21T10:01:00.987654321Z")

    @Test
    fun `read returns Absent for a fresh database`() = runTest {
        val result = repository(openDatabase()).readLocalState()

        assertEquals(ReadLocalStateResult.Absent, result)
    }

    @Test
    fun `ensure creates and rereads a local installation`() = runTest {
        val repository = repository(openDatabase())

        assertEquals(
            EnsureLocalInstallationResult.Created,
            repository.ensureLocalInstallation(localIdentity(), createdAt),
        )
        val read = assertIs<ReadLocalStateResult.InstallationOnly>(repository.readLocalState())
        assertEquals(localIdentity(), read.installation.localIdentity)
        assertEquals(createdAt, read.installation.createdAt)
    }

    @Test
    fun `ensure is idempotent for the same installation`() = runTest {
        val repository = repository(openDatabase())
        repository.ensureLocalInstallation(localIdentity(), createdAt)

        val result = repository.ensureLocalInstallation(localIdentity(), updatedAt)

        assertEquals(EnsureLocalInstallationResult.Existing, result)
        val read = assertIs<ReadLocalStateResult.InstallationOnly>(repository.readLocalState())
        assertEquals(createdAt, read.installation.createdAt)
    }

    @Test
    fun `ensure conflicts with a different installation without overwrite`() = runTest {
        val repository = repository(openDatabase())
        repository.ensureLocalInstallation(localIdentity(), createdAt)

        val result =
            repository.ensureLocalInstallation(localIdentity(SECOND_INSTALLATION_ID), updatedAt)

        assertEquals(EnsureLocalInstallationResult.Conflict, result)
        val read = assertIs<ReadLocalStateResult.InstallationOnly>(repository.readLocalState())
        assertEquals(localIdentity(), read.installation.localIdentity)
        assertEquals(createdAt, read.installation.createdAt)
    }

    @Test
    fun `initialize creates installation and configuration atomically`() = runTest {
        val repository = repository(openDatabase())

        val result =
            repository.initializeLocalState(
                localIdentity = localIdentity(),
                serverConfiguration = serverConfiguration(),
                installationCreatedAt = createdAt,
                serverConfigurationUpdatedAt = updatedAt,
            )

        assertEquals(InitializeLocalStateResult.Created, result)
        val read = assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
        assertEquals(localIdentity(), read.installation.localIdentity)
        assertEquals(createdAt, read.installation.createdAt)
        assertEquals(serverConfiguration(), read.serverConfiguration.configuration)
        assertEquals(updatedAt, read.serverConfiguration.updatedAt)
    }

    @Test
    fun `initialize completes an existing installation`() = runTest {
        val repository = repository(openDatabase())
        repository.ensureLocalInstallation(localIdentity(), createdAt)

        val result =
            repository.initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = updatedAt,
                serverConfigurationUpdatedAt = updatedAt,
            )

        assertEquals(InitializeLocalStateResult.Created, result)
        assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
    }

    @Test
    fun `initialize returns ExistingEquivalent without changing timestamps`() = runTest {
        val repository = repository(openDatabase())
        repository.initializeLocalState(
            localIdentity(),
            serverConfiguration(),
            installationCreatedAt = createdAt,
            serverConfigurationUpdatedAt = updatedAt,
        )

        val result =
            repository.initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = Instant.EPOCH,
                serverConfigurationUpdatedAt = Instant.EPOCH,
            )

        assertEquals(InitializeLocalStateResult.ExistingEquivalent, result)
        val read = assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
        assertEquals(createdAt, read.installation.createdAt)
        assertEquals(updatedAt, read.serverConfiguration.updatedAt)
    }

    @Test
    fun `initialize conflicts with a different installation`() = runTest {
        val repository = repository(openDatabase())
        repository.ensureLocalInstallation(localIdentity(), createdAt)

        val result =
            repository.initializeLocalState(
                localIdentity(SECOND_INSTALLATION_ID),
                serverConfiguration(),
                installationCreatedAt = updatedAt,
                serverConfigurationUpdatedAt = updatedAt,
            )

        assertEquals(InitializeLocalStateResult.Conflict, result)
    }

    @Test
    fun `initialize conflicts with a different existing server`() = runTest {
        val repository = repository(openDatabase())
        repository.initializeLocalState(
            localIdentity(),
            serverConfiguration(),
            installationCreatedAt = createdAt,
            serverConfigurationUpdatedAt = updatedAt,
        )

        val result =
            repository.initializeLocalState(
                localIdentity(),
                serverConfiguration(SECOND_SERVER_URL),
                installationCreatedAt = createdAt,
                serverConfigurationUpdatedAt = updatedAt,
            )

        assertEquals(InitializeLocalStateResult.Conflict, result)
    }

    @Test
    fun `set server requires an installation`() = runTest {
        val repository = repository(openDatabase())

        val result = repository.setServerConfiguration(serverConfiguration(), updatedAt)

        assertEquals(
            SetServerConfigurationResult.Failure(LocalPersistenceError.STATE_INCOMPLETE),
            result,
        )
        assertEquals(ReadLocalStateResult.Absent, repository.readLocalState())
    }

    @Test
    fun `set server creates configuration after installation`() = runTest {
        val repository = repository(openDatabase())
        repository.ensureLocalInstallation(localIdentity(), createdAt)

        val result = repository.setServerConfiguration(serverConfiguration(), updatedAt)

        assertEquals(SetServerConfigurationResult.Created, result)
        assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
    }

    @Test
    fun `set server returns Unchanged and preserves timestamp`() = runTest {
        val repository = repository(openDatabase())
        repository.initializeLocalState(
            localIdentity(),
            serverConfiguration(),
            installationCreatedAt = createdAt,
            serverConfigurationUpdatedAt = updatedAt,
        )

        val result =
            repository.setServerConfiguration(serverConfiguration(), Instant.EPOCH)

        assertEquals(SetServerConfigurationResult.Unchanged, result)
        val read = assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
        assertEquals(updatedAt, read.serverConfiguration.updatedAt)
    }

    @Test
    fun `set server updates explicitly without replacing installation`() = runTest {
        val repository = repository(openDatabase())
        repository.initializeLocalState(
            localIdentity(),
            serverConfiguration(),
            installationCreatedAt = createdAt,
            serverConfigurationUpdatedAt = updatedAt,
        )
        val replacementTime = Instant.parse("2026-07-21T11:00:00.000000001Z")

        val result =
            repository.setServerConfiguration(
                serverConfiguration(SECOND_SERVER_URL),
                replacementTime,
            )

        assertEquals(SetServerConfigurationResult.Updated, result)
        val read = assertIs<ReadLocalStateResult.Configured>(repository.readLocalState())
        assertEquals(localIdentity(), read.installation.localIdentity)
        assertEquals(createdAt, read.installation.createdAt)
        assertEquals(serverConfiguration(SECOND_SERVER_URL), read.serverConfiguration.configuration)
        assertEquals(replacementTime, read.serverConfiguration.updatedAt)
    }

    @Test
    fun `foreign key rejects configuration without installation`() = runTest {
        val database = openDatabase()

        assertFailsWith<SQLiteConstraintException> {
            database.localStateDao().insertServerConfiguration(serverConfiguration().toEntity(updatedAt))
        }
    }

    @Test
    fun `set server preserves C04 incomplete result when no enrollment exists`() = runTest {
        val database = openDatabase()
        val sqliteDatabase = database.openHelper.writableDatabase
        withCleanupPreservingPrimaryFailure(
            cleanup = { sqliteDatabase.execSQL("PRAGMA foreign_keys = ON") },
        ) {
            sqliteDatabase.execSQL("PRAGMA foreign_keys = OFF")
            insertRawServerConfiguration(database)
        }

        val result =
            repository(database).setServerConfiguration(
                serverConfiguration(SECOND_SERVER_URL),
                Instant.EPOCH,
            )

        assertEquals(
            SetServerConfigurationResult.Failure(LocalPersistenceError.STATE_INCOMPLETE),
            result,
        )
        assertRawServerConfigurationRow(database)
        assertTrue(database.readProtectedEnrollmentEntitiesForTest().isEmpty())
    }

    @Test
    fun `invalid singleton row is read fail closed`() = runTest {
        val database = openDatabase()
        database.localStateDao().insertInstallation(
            localIdentity().toEntity(createdAt).copy(singletonId = 2),
        )

        val result = repository(database).readLocalState()

        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE),
            result,
        )
    }

    @Test
    fun `raw 64 bit local singleton congruent to one is read fail closed`() = runTest {
        val database = openDatabase()
        val rawSingletonId = 4_294_967_297L
        insertRawInstallation(
            database = database,
            singletonId = rawSingletonId,
            nanoseconds = createdAt.nano.toLong(),
        )
        assertRawInstallationRow(
            database = database,
            expectedSingletonId = rawSingletonId,
            expectedNanoseconds = createdAt.nano.toLong(),
        )

        assertStateIncomplete(database)
    }

    @Test
    fun `raw local nanoseconds congruent to zero are read fail closed`() = runTest {
        val database = openDatabase()
        val rawNanoseconds = 4_294_967_296L
        insertRawInstallation(database = database, nanoseconds = rawNanoseconds)
        assertRawInstallationRow(database = database, expectedNanoseconds = rawNanoseconds)

        assertStateIncomplete(database)
    }

    @Test
    fun `raw local nanoseconds congruent to upper boundary are read fail closed`() = runTest {
        val database = openDatabase()
        val rawNanoseconds = 5_294_967_295L
        insertRawInstallation(database = database, nanoseconds = rawNanoseconds)
        assertRawInstallationRow(database = database, expectedNanoseconds = rawNanoseconds)

        assertStateIncomplete(database)
    }

    @Test
    fun `raw server nanoseconds congruent to zero are read fail closed`() = runTest {
        val database = openDatabase()
        val rawNanoseconds = 4_294_967_296L
        insertRawInstallation(database = database)
        insertRawServerConfiguration(database = database, nanoseconds = rawNanoseconds)
        assertRawInstallationRow(database)
        assertRawServerConfigurationRow(database = database, expectedNanoseconds = rawNanoseconds)

        assertStateIncomplete(database)
    }

    @Test
    fun `raw server nanoseconds congruent to upper boundary are read fail closed`() = runTest {
        val database = openDatabase()
        val rawNanoseconds = 5_294_967_295L
        insertRawInstallation(database = database)
        insertRawServerConfiguration(database = database, nanoseconds = rawNanoseconds)
        assertRawInstallationRow(database)
        assertRawServerConfigurationRow(database = database, expectedNanoseconds = rawNanoseconds)

        assertStateIncomplete(database)
    }

    @Test
    fun `raw 64 bit server singleton congruent to one is read fail closed`() = runTest {
        val database = openDatabase()
        val rawSingletonId = 4_294_967_297L
        insertRawInstallation(database = database)
        assertRawInstallationRow(database)
        val sqliteDatabase = database.openHelper.writableDatabase
        assertFalse(sqliteDatabase.inTransaction())
        assertForeignKeysState(sqliteDatabase, expectedState = 1L)
        withCleanupPreservingPrimaryFailure(
            cleanup = { sqliteDatabase.execSQL("PRAGMA foreign_keys = ON") },
        ) {
            sqliteDatabase.execSQL("PRAGMA foreign_keys = OFF")
            assertForeignKeysState(sqliteDatabase, expectedState = 0L)
            insertRawServerConfiguration(database = database, singletonId = rawSingletonId)
            assertRawServerConfigurationRow(
                database = database,
                expectedSingletonId = rawSingletonId,
            )
        }
        assertForeignKeysState(sqliteDatabase, expectedState = 1L)

        assertStateIncomplete(database)
    }

    @Test
    fun `cleanup preserves primary failure and propagates cleanup only failure`() {
        val primaryFailure = AssertionError("primary failure")
        val cleanupFailure = IllegalStateException("cleanup failure")

        val observedPrimary = assertFailsWith<AssertionError> {
            withCleanupPreservingPrimaryFailure(
                cleanup = { throw cleanupFailure },
                block = { throw primaryFailure },
            )
        }
        assertSame(primaryFailure, observedPrimary)
        assertEquals(1, observedPrimary.suppressed.size)
        assertSame(cleanupFailure, observedPrimary.suppressed.single())

        val cleanupOnlyFailure = IllegalArgumentException("cleanup only failure")
        val observedCleanup = assertFailsWith<IllegalArgumentException> {
            withCleanupPreservingPrimaryFailure(
                cleanup = { throw cleanupOnlyFailure },
                block = {},
            )
        }
        assertSame(cleanupOnlyFailure, observedCleanup)

        val sharedFailure = IllegalStateException("shared failure")
        val observedShared = assertFailsWith<IllegalStateException> {
            withCleanupPreservingPrimaryFailure(
                cleanup = { throw sharedFailure },
                block = { throw sharedFailure },
            )
        }
        assertSame(sharedFailure, observedShared)
        assertTrue(observedShared.suppressed.isEmpty())
    }

    @Test
    fun `multiple installation rows are read fail closed`() = runTest {
        val database = openDatabase()
        val dao = database.localStateDao()
        dao.insertInstallation(localIdentity().toEntity(createdAt))
        dao.insertInstallation(
            localIdentity(SECOND_INSTALLATION_ID).toEntity(updatedAt).copy(singletonId = 2),
        )

        val result = repository(database).readLocalState()

        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE),
            result,
        )
    }

    @Test
    fun `invalid stored URL is read fail closed and not exposed`() = runTest {
        val database = openDatabase()
        val dao = database.localStateDao()
        dao.insertInstallation(localIdentity().toEntity(createdAt))
        dao.insertServerConfiguration(
            ServerConfigurationEntity(
                singletonId = LOCAL_STATE_SINGLETON_ID,
                baseUrl = "http://invalid.local/",
                updatedAtEpochSeconds = updatedAt.epochSecond,
                updatedAtNanoseconds = updatedAt.nano.toLong(),
            ),
        )

        val result = repository(database).readLocalState()

        assertEquals(
            ReadLocalStateResult.Failure(LocalPersistenceError.STATE_INCOMPLETE),
            result,
        )
        assertTrue(result.toString().contains("STATE_INCOMPLETE"))
        assertTrue(!result.toString().contains("invalid.local"))
    }

    @Test
    fun `concurrent identical ensure has one creator and one durable row`() = runTest {
        val repository = repository(openDatabase())

        val results =
            (1..8)
                .map {
                    async(Dispatchers.Default) {
                        repository.ensureLocalInstallation(localIdentity(), createdAt)
                    }
                }
                .awaitAll()

        assertEquals(1, results.count { it == EnsureLocalInstallationResult.Created })
        assertEquals(7, results.count { it == EnsureLocalInstallationResult.Existing })
        assertIs<ReadLocalStateResult.InstallationOnly>(repository.readLocalState())
    }

    @Test
    fun `concurrent different ensure preserves one winner without overwrite`() = runTest {
        val repository = repository(openDatabase())

        val results =
            listOf(localIdentity(), localIdentity(SECOND_INSTALLATION_ID))
                .map { identity ->
                    async(Dispatchers.Default) {
                        repository.ensureLocalInstallation(identity, createdAt)
                    }
                }
                .awaitAll()

        assertEquals(1, results.count { it == EnsureLocalInstallationResult.Created })
        assertEquals(1, results.count { it == EnsureLocalInstallationResult.Conflict })
        assertIs<ReadLocalStateResult.InstallationOnly>(repository.readLocalState())
    }

    @Test
    fun `transaction rolls back installation when configuration insert fails`() = runTest {
        val database = openDatabase()
        val dao = database.localStateDao()
        try {
            database.withTransaction {
                dao.insertInstallation(localIdentity().toEntity(createdAt))
                dao.insertServerConfiguration(
                    serverConfiguration().toEntity(updatedAt).copy(singletonId = 2),
                )
            }
            fail("The foreign-key violation must abort the transaction.")
        } catch (_: SQLiteConstraintException) {
            // Expected: verify the durable state below.
        }

        assertEquals(ReadLocalStateResult.Absent, repository(database).readLocalState())
    }

    @Test
    fun `transaction cancellation propagates and rolls back`() = runTest {
        val database = openDatabase()
        val dao = database.localStateDao()
        val inserted = CompletableDeferred<Unit>()
        val waitForever = CompletableDeferred<Unit>()
        val job =
            launch(Dispatchers.Default) {
                database.withTransaction {
                    dao.insertInstallation(localIdentity().toEntity(createdAt))
                    inserted.complete(Unit)
                    waitForever.await()
                }
            }
        inserted.await()

        job.cancelAndJoin()

        assertTrue(job.isCancelled)
        assertEquals(ReadLocalStateResult.Absent, repository(database).readLocalState())
    }

    @Test
    fun `repository does not translate cancellation into Failure`() = runTest {
        val repository =
            RoomLocalStateRepository(
                WtoAgentDatabaseProvider { throw CancellationException() },
            )

        assertFailsWith<CancellationException> {
            repository.readLocalState()
        }
    }

    @Test
    fun `committed state survives close and reopen`() = runTest {
        val name = newDatabaseName("wto-reopen")
        val firstDatabase = openDatabase(name)
        val firstRepository = repository(firstDatabase)
        firstRepository.initializeLocalState(
            localIdentity(),
            serverConfiguration(),
            installationCreatedAt = createdAt,
            serverConfigurationUpdatedAt = updatedAt,
        )
        firstDatabase.close()

        val reopenedRepository = repository(reopenDatabase(name))

        val read = assertIs<ReadLocalStateResult.Configured>(reopenedRepository.readLocalState())
        assertEquals(localIdentity(), read.installation.localIdentity)
        assertEquals(serverConfiguration(), read.serverConfiguration.configuration)
    }

    @Test
    fun `constraint violation is mapped without raw database information`() = runTest {
        val database = openDatabase()
        val repository = repository(database)
        database.localStateDao().insertInstallation(
            LocalInstallationEntity(
                singletonId = LOCAL_STATE_SINGLETON_ID,
                installationId = FIRST_INSTALLATION_ID,
                createdAtEpochSeconds = createdAt.epochSecond,
                createdAtNanoseconds = createdAt.nano.toLong(),
            ),
        )

        val result = repository.ensureLocalInstallation(localIdentity(), createdAt)

        assertEquals(EnsureLocalInstallationResult.Existing, result)
    }

    private fun insertRawInstallation(
        database: WtoAgentDatabase,
        singletonId: Long = LOCAL_STATE_SINGLETON_ID,
        nanoseconds: Long = createdAt.nano.toLong(),
    ) {
        database.openHelper.writableDatabase.execSQL(
            INSERT_RAW_LOCAL_INSTALLATION_SQL,
            arrayOf<Any?>(singletonId, FIRST_INSTALLATION_ID, createdAt.epochSecond, nanoseconds),
        )
    }

    private fun insertRawServerConfiguration(
        database: WtoAgentDatabase,
        singletonId: Long = LOCAL_STATE_SINGLETON_ID,
        nanoseconds: Long = updatedAt.nano.toLong(),
    ) {
        database.openHelper.writableDatabase.execSQL(
            INSERT_RAW_SERVER_CONFIGURATION_SQL,
            arrayOf<Any?>(singletonId, FIRST_SERVER_URL, updatedAt.epochSecond, nanoseconds),
        )
    }

    private fun assertRawInstallationRow(
        database: WtoAgentDatabase,
        expectedSingletonId: Long = LOCAL_STATE_SINGLETON_ID,
        expectedNanoseconds: Long = createdAt.nano.toLong(),
    ) {
        database.openHelper.writableDatabase.query(SELECT_RAW_LOCAL_INSTALLATION_SQL).use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            val singletonIdColumn = cursor.getColumnIndexOrThrow("singleton_id")
            val installationIdColumn = cursor.getColumnIndexOrThrow("installation_id")
            val epochSecondsColumn = cursor.getColumnIndexOrThrow("created_at_epoch_seconds")
            val nanosecondsColumn = cursor.getColumnIndexOrThrow("created_at_nanoseconds")
            val singletonTypeColumn = cursor.getColumnIndexOrThrow("singleton_id_type")
            val epochSecondsTypeColumn = cursor.getColumnIndexOrThrow("epoch_seconds_type")
            val nanosecondsTypeColumn = cursor.getColumnIndexOrThrow("nanoseconds_type")

            assertEquals(expectedSingletonId, cursor.getLong(singletonIdColumn))
            assertEquals(FIRST_INSTALLATION_ID, cursor.getString(installationIdColumn))
            assertEquals(createdAt.epochSecond, cursor.getLong(epochSecondsColumn))
            assertEquals(expectedNanoseconds, cursor.getLong(nanosecondsColumn))
            assertEquals("integer", cursor.getString(singletonTypeColumn))
            assertEquals("integer", cursor.getString(epochSecondsTypeColumn))
            assertEquals("integer", cursor.getString(nanosecondsTypeColumn))
            assertFalse(cursor.moveToNext())
        }
    }

    private fun assertRawServerConfigurationRow(
        database: WtoAgentDatabase,
        expectedSingletonId: Long = LOCAL_STATE_SINGLETON_ID,
        expectedNanoseconds: Long = updatedAt.nano.toLong(),
    ) {
        database.openHelper.writableDatabase.query(SELECT_RAW_SERVER_CONFIGURATION_SQL).use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            val singletonIdColumn = cursor.getColumnIndexOrThrow("singleton_id")
            val baseUrlColumn = cursor.getColumnIndexOrThrow("base_url")
            val epochSecondsColumn = cursor.getColumnIndexOrThrow("updated_at_epoch_seconds")
            val nanosecondsColumn = cursor.getColumnIndexOrThrow("updated_at_nanoseconds")
            val singletonTypeColumn = cursor.getColumnIndexOrThrow("singleton_id_type")
            val epochSecondsTypeColumn = cursor.getColumnIndexOrThrow("epoch_seconds_type")
            val nanosecondsTypeColumn = cursor.getColumnIndexOrThrow("nanoseconds_type")

            assertEquals(expectedSingletonId, cursor.getLong(singletonIdColumn))
            assertEquals(FIRST_SERVER_URL, cursor.getString(baseUrlColumn))
            assertEquals(updatedAt.epochSecond, cursor.getLong(epochSecondsColumn))
            assertEquals(expectedNanoseconds, cursor.getLong(nanosecondsColumn))
            assertEquals("integer", cursor.getString(singletonTypeColumn))
            assertEquals("integer", cursor.getString(epochSecondsTypeColumn))
            assertEquals("integer", cursor.getString(nanosecondsTypeColumn))
            assertFalse(cursor.moveToNext())
        }
    }

    private fun assertForeignKeysState(
        database: SupportSQLiteDatabase,
        expectedState: Long,
    ) {
        database.query("PRAGMA foreign_keys").use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            assertEquals(expectedState, cursor.getLong(0))
            assertFalse(cursor.moveToNext())
        }
    }

    private fun <T> withCleanupPreservingPrimaryFailure(
        cleanup: () -> Unit,
        block: () -> T,
    ): T {
        var primaryFailure: Throwable? = null
        try {
            return block()
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                cleanup()
            } catch (cleanupFailure: Throwable) {
                val failure = primaryFailure
                if (failure == null) {
                    throw cleanupFailure
                }
                if (failure !== cleanupFailure) {
                    failure.addSuppressed(cleanupFailure)
                }
            }
        }
    }

    private suspend fun assertStateIncomplete(database: WtoAgentDatabase) {
        val failure = assertIs<ReadLocalStateResult.Failure>(repository(database).readLocalState())
        assertEquals(LocalPersistenceError.STATE_INCOMPLETE, failure.error)
    }

    private companion object {
        const val INSERT_RAW_LOCAL_INSTALLATION_SQL =
            "INSERT INTO local_installation " +
                "(singleton_id, installation_id, created_at_epoch_seconds, " +
                "created_at_nanoseconds) VALUES (?, ?, ?, ?)"

        const val INSERT_RAW_SERVER_CONFIGURATION_SQL =
            "INSERT INTO server_configuration " +
                "(singleton_id, base_url, updated_at_epoch_seconds, " +
                "updated_at_nanoseconds) VALUES (?, ?, ?, ?)"

        const val SELECT_RAW_LOCAL_INSTALLATION_SQL =
            "SELECT singleton_id, installation_id, created_at_epoch_seconds, " +
                "created_at_nanoseconds, typeof(singleton_id) AS singleton_id_type, " +
                "typeof(created_at_epoch_seconds) AS epoch_seconds_type, " +
                "typeof(created_at_nanoseconds) AS nanoseconds_type " +
                "FROM local_installation ORDER BY singleton_id"

        const val SELECT_RAW_SERVER_CONFIGURATION_SQL =
            "SELECT singleton_id, base_url, updated_at_epoch_seconds, " +
                "updated_at_nanoseconds, typeof(singleton_id) AS singleton_id_type, " +
                "typeof(updated_at_epoch_seconds) AS epoch_seconds_type, " +
                "typeof(updated_at_nanoseconds) AS nanoseconds_type " +
                "FROM server_configuration ORDER BY singleton_id"
    }
}
