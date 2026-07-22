package com.wifitestorchestrator.agent.data.persistence

import android.database.sqlite.SQLiteCantOpenDatabaseException
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabaseCorruptException
import android.database.sqlite.SQLiteDatabaseLockedException
import android.database.sqlite.SQLiteDiskIOException
import android.database.sqlite.SQLiteException
import android.database.sqlite.SQLiteFullException
import android.database.sqlite.SQLiteTableLockedException
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.room.StorageCorruptionException
import com.wifitestorchestrator.agent.data.persistence.room.StorageInitializationException
import com.wifitestorchestrator.agent.data.persistence.room.StorageMigrationMissingException
import com.wifitestorchestrator.agent.data.persistence.room.StorageSchemaIncompatibleException
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.rethrowCancellationIfPresent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame

@RunWith(RobolectricTestRunner::class)
internal class PersistenceFailureMapperTest {
    @Test
    fun `internal storage boundaries map to closed errors`() = runTest {
        val cases =
            listOf(
                StorageInitializationException() to LocalPersistenceError.INITIALIZATION_FAILED,
                StorageCorruptionException() to LocalPersistenceError.CORRUPTION,
                StorageSchemaIncompatibleException() to LocalPersistenceError.SCHEMA_INCOMPATIBLE,
                StorageMigrationMissingException() to LocalPersistenceError.MIGRATION_MISSING,
            )

        cases.forEach { (failure, expected) ->
            assertEquals(ReadLocalStateResult.Failure(expected), resultFor(failure))
        }
    }

    @Test
    fun `SQLite failures map without exposing their diagnostics`() = runTest {
        val diagnostic = "untrusted path SELECT https://invalid.local/"
        val cases =
            listOf(
                SQLiteConstraintException(diagnostic) to LocalPersistenceError.CONSTRAINT_VIOLATION,
                SQLiteDatabaseCorruptException(diagnostic) to LocalPersistenceError.CORRUPTION,
                SQLiteDatabaseLockedException(diagnostic) to
                    LocalPersistenceError.DATABASE_BUSY_OR_LOCKED,
                SQLiteTableLockedException(diagnostic) to
                    LocalPersistenceError.DATABASE_BUSY_OR_LOCKED,
                SQLiteDiskIOException(diagnostic) to LocalPersistenceError.IO,
                SQLiteFullException(diagnostic) to LocalPersistenceError.IO,
                SQLiteCantOpenDatabaseException(diagnostic) to LocalPersistenceError.IO,
                SQLiteException(diagnostic) to LocalPersistenceError.UNKNOWN,
            )

        cases.forEach { (failure, expected) ->
            val result = resultFor(failure)
            assertEquals(ReadLocalStateResult.Failure(expected), result)
            assertFalse(diagnostic in result.toString())
        }
    }

    @Test
    fun `programming failures are not translated into storage state`() = runTest {
        assertFailsWith<IllegalArgumentException> {
            resultFor(IllegalArgumentException("programming failure"))
        }
    }

    @Test
    fun `direct cancellation propagates without translation`() = runTest {
        val cancellation = CancellationException()

        val thrown =
            assertFailsWith<CancellationException> {
                resultFor(cancellation)
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `SQLite wrapper propagates its cancellation cause`() = runTest {
        val cancellation = CancellationException()
        val wrapper = SQLiteException("untrusted wrapper", cancellation)

        val thrown =
            assertFailsWith<CancellationException> {
                resultFor(wrapper)
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `illegal state wrapper propagates its cancellation cause`() = runTest {
        val cancellation = CancellationException()
        val wrapper = IllegalStateException("untrusted wrapper", cancellation)

        val thrown =
            assertFailsWith<CancellationException> {
                resultFor(wrapper)
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `multiple wrapper levels propagate the original cancellation`() = runTest {
        val cancellation = CancellationException()
        val wrapper =
            SQLiteException(
                "untrusted outer wrapper",
                IllegalStateException("untrusted middle wrapper", cancellation),
            )

        val thrown =
            assertFailsWith<CancellationException> {
                resultFor(wrapper)
            }

        assertSame(cancellation, thrown)
    }

    @Test(timeout = 1_000L)
    fun `cyclic cause chain terminates without inventing cancellation`() {
        val first = IllegalStateException("first untrusted wrapper")
        val second = IllegalStateException("second untrusted wrapper")
        first.initCause(second)
        second.initCause(first)

        first.rethrowCancellationIfPresent()
    }

    @Test
    fun `fatal errors are not translated into storage state`() = runTest {
        assertFailsWith<AssertionError> {
            resultFor(AssertionError("fatal programming error"))
        }
    }

    private suspend fun resultFor(failure: Throwable): ReadLocalStateResult =
        RoomLocalStateRepository(
            WtoAgentDatabaseProvider { throw failure },
        ).readLocalState()
}
