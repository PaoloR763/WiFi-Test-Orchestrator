package com.wifitestorchestrator.agent.data.persistence.room

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import java.util.concurrent.atomic.AtomicBoolean

internal class FailClosedRoomOpenHelperFactory(
    private val delegateFactory: SupportSQLiteOpenHelper.Factory =
        FrameworkSQLiteOpenHelperFactory(),
) : SupportSQLiteOpenHelper.Factory {
    override fun create(
        configuration: SupportSQLiteOpenHelper.Configuration,
    ): SupportSQLiteOpenHelper {
        val name = configuration.name ?: throw StorageInitializationException()
        val applicationContext =
            configuration.context.applicationContext ?: throw StorageInitializationException()
        try {
            val noBackupDirectory = applicationContext.noBackupFilesDir
            if (!noBackupDirectory.isDirectory && !noBackupDirectory.mkdirs()) {
                throw StorageInitializationException()
            }
        } catch (failure: SecurityException) {
            failure.rethrowCancellationIfPresent()
            throw StorageInitializationException()
        }
        val corruptionState = AtomicBoolean(false)
        val failClosedCallback =
            FailClosedCallback(
                delegate = configuration.callback,
                corruptionState = corruptionState,
            )
        val failClosedConfiguration =
            SupportSQLiteOpenHelper.Configuration.builder(applicationContext)
                .name(name)
                .callback(failClosedCallback)
                .noBackupDirectory(true)
                .allowDataLossOnRecovery(false)
                .build()
        return FailClosedSupportSQLiteOpenHelper(
            delegate = delegateFactory.create(failClosedConfiguration),
            corruptionState = corruptionState,
        )
    }
}

internal class FailClosedCallback(
    private val delegate: SupportSQLiteOpenHelper.Callback,
    private val corruptionState: AtomicBoolean,
) : SupportSQLiteOpenHelper.Callback(delegate.version) {
    override fun onConfigure(db: SupportSQLiteDatabase) {
        delegate.onConfigure(db)
    }

    override fun onCreate(db: SupportSQLiteDatabase) {
        delegate.onCreate(db)
    }

    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
        try {
            delegate.onUpgrade(db, oldVersion, newVersion)
        } catch (failure: IllegalStateException) {
            failure.rethrowCancellationIfPresent()
            throw StorageMigrationMissingException()
        }
    }

    override fun onDowngrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
        throw StorageSchemaIncompatibleException()
    }

    override fun onOpen(db: SupportSQLiteDatabase) {
        try {
            delegate.onOpen(db)
        } catch (failure: IllegalStateException) {
            failure.rethrowCancellationIfPresent()
            throw StorageSchemaIncompatibleException()
        }
    }

    override fun onCorruption(db: SupportSQLiteDatabase) {
        corruptionState.set(true)
        try {
            db.close()
        } catch (failure: Exception) {
            failure.rethrowCancellationIfPresent()
            // The operation still fails closed; no path, SQL, or exception is retained.
        }
        throw StorageCorruptionException()
    }
}

private class FailClosedSupportSQLiteOpenHelper(
    private val delegate: SupportSQLiteOpenHelper,
    private val corruptionState: AtomicBoolean,
) : SupportSQLiteOpenHelper {
    override val databaseName: String?
        get() = delegate.databaseName

    override val readableDatabase: SupportSQLiteDatabase
        get() = openFailClosed { delegate.readableDatabase }

    override val writableDatabase: SupportSQLiteDatabase
        get() = openFailClosed { delegate.writableDatabase }

    override fun setWriteAheadLoggingEnabled(enabled: Boolean) {
        delegate.setWriteAheadLoggingEnabled(enabled)
    }

    override fun close() {
        delegate.close()
    }

    private inline fun openFailClosed(open: () -> SupportSQLiteDatabase): SupportSQLiteDatabase {
        if (corruptionState.get()) throw StorageCorruptionException()
        val database = open()
        if (corruptionState.get()) {
            try {
                database.close()
            } catch (failure: Exception) {
                failure.rethrowCancellationIfPresent()
                // Preserve the original fail-closed classification.
            }
            try {
                delegate.close()
            } catch (failure: Exception) {
                failure.rethrowCancellationIfPresent()
                // Preserve the original fail-closed classification.
            }
            throw StorageCorruptionException()
        }
        return database
    }
}
