package com.wifitestorchestrator.agent.data.persistence.room

import android.database.sqlite.SQLiteCantOpenDatabaseException
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabaseCorruptException
import android.database.sqlite.SQLiteDatabaseLockedException
import android.database.sqlite.SQLiteDiskIOException
import android.database.sqlite.SQLiteException
import android.database.sqlite.SQLiteFullException
import android.database.sqlite.SQLiteTableLockedException
import com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError
import java.util.IdentityHashMap
import kotlinx.coroutines.CancellationException

internal sealed interface StorageExecution<out T> {
    data class Success<T>(val value: T) : StorageExecution<T>

    data class Failure(val error: LocalPersistenceError) : StorageExecution<Nothing>
}

internal suspend fun <T> executeStorageOperation(
    block: suspend () -> T,
): StorageExecution<T> =
    try {
        StorageExecution.Success(block())
    } catch (failure: Exception) {
        failure.rethrowCancellationIfPresent()
        when (failure) {
            is StorageInitializationException ->
                StorageExecution.Failure(LocalPersistenceError.INITIALIZATION_FAILED)
            is StorageCorruptionException ->
                StorageExecution.Failure(LocalPersistenceError.CORRUPTION)
            is StorageSchemaIncompatibleException ->
                StorageExecution.Failure(LocalPersistenceError.SCHEMA_INCOMPATIBLE)
            is StorageMigrationMissingException ->
                StorageExecution.Failure(LocalPersistenceError.MIGRATION_MISSING)
            is SQLiteConstraintException ->
                StorageExecution.Failure(LocalPersistenceError.CONSTRAINT_VIOLATION)
            is SQLiteDatabaseCorruptException ->
                StorageExecution.Failure(LocalPersistenceError.CORRUPTION)
            is SQLiteDatabaseLockedException,
            is SQLiteTableLockedException,
            -> StorageExecution.Failure(LocalPersistenceError.DATABASE_BUSY_OR_LOCKED)
            is SQLiteDiskIOException,
            is SQLiteFullException,
            is SQLiteCantOpenDatabaseException,
            -> StorageExecution.Failure(LocalPersistenceError.IO)
            is SQLiteException -> StorageExecution.Failure(LocalPersistenceError.UNKNOWN)
            else -> throw failure
        }
    }

internal fun Throwable.rethrowCancellationIfPresent() {
    val visited = IdentityHashMap<Throwable, Unit>()
    var current: Throwable? = this
    while (current != null && visited.put(current, Unit) == null) {
        if (current is CancellationException) throw current
        current = current.cause
    }
}
