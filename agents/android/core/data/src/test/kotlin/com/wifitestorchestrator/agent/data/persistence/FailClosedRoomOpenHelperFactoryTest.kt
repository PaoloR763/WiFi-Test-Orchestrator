package com.wifitestorchestrator.agent.data.persistence

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import com.wifitestorchestrator.agent.data.persistence.room.FailClosedCallback
import com.wifitestorchestrator.agent.data.persistence.room.FailClosedRoomOpenHelperFactory
import com.wifitestorchestrator.agent.data.persistence.room.StorageInitializationException
import com.wifitestorchestrator.agent.data.persistence.room.StorageMigrationMissingException
import com.wifitestorchestrator.agent.data.persistence.room.StorageSchemaIncompatibleException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class FailClosedRoomOpenHelperFactoryTest : RoomPersistenceTestBase() {
    @Test
    fun `factory forces no backup and disables data loss recovery`() {
        val recordingFactory = RecordingFactory()
        val original =
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name("captured.db")
                .callback(NoOpCallback())
                .noBackupDirectory(false)
                .allowDataLossOnRecovery(true)
                .build()

        FailClosedRoomOpenHelperFactory(recordingFactory).create(original)

        assertTrue(recordingFactory.configuration.useNoBackupDirectory)
        assertFalse(recordingFactory.configuration.allowDataLossOnRecovery)
        assertEquals(context.applicationContext, recordingFactory.configuration.context)
        assertEquals("captured.db", recordingFactory.configuration.name)
    }

    @Test
    fun `factory rejects an in memory name instead of falling back to another location`() {
        val original =
            SupportSQLiteOpenHelper.Configuration(
                context = context,
                name = null,
                callback = NoOpCallback(),
                useNoBackupDirectory = false,
                allowDataLossOnRecovery = false,
            )

        assertFailsWith<StorageInitializationException> {
            FailClosedRoomOpenHelperFactory(RecordingFactory()).create(original)
        }
    }

    @Test
    fun `direct cancellation from onOpen propagates unchanged`() {
        val cancellation = CancellationException()
        val callback = failClosedCallback(openFailure = cancellation)

        val thrown =
            assertFailsWith<CancellationException> {
                callback.onOpen(openDatabase().openHelper.writableDatabase)
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `direct cancellation from onUpgrade propagates unchanged`() {
        val cancellation = CancellationException()
        val callback = failClosedCallback(upgradeFailure = cancellation)

        val thrown =
            assertFailsWith<CancellationException> {
                callback.onUpgrade(openDatabase().openHelper.writableDatabase, 1, 2)
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `nested cancellation from callbacks propagates the original cause`() {
        val openCancellation = CancellationException()
        val upgradeCancellation = CancellationException()
        val database = openDatabase().openHelper.writableDatabase
        val openCallback =
            failClosedCallback(
                openFailure =
                    IllegalStateException(
                        "untrusted open wrapper",
                        RuntimeException("untrusted middle wrapper", openCancellation),
                    ),
            )
        val upgradeCallback =
            failClosedCallback(
                upgradeFailure =
                    IllegalStateException("untrusted upgrade wrapper", upgradeCancellation),
            )

        val openThrown =
            assertFailsWith<CancellationException> {
                openCallback.onOpen(database)
            }
        val upgradeThrown =
            assertFailsWith<CancellationException> {
                upgradeCallback.onUpgrade(database, 1, 2)
            }

        assertSame(openCancellation, openThrown)
        assertSame(upgradeCancellation, upgradeThrown)
    }

    @Test
    fun `non cancellation callback failures retain their storage classifications`() {
        val database = openDatabase().openHelper.writableDatabase
        val openCallback =
            failClosedCallback(openFailure = IllegalStateException("untrusted open diagnostic"))
        val upgradeCallback =
            failClosedCallback(
                upgradeFailure = IllegalStateException("untrusted upgrade diagnostic"),
            )

        assertFailsWith<StorageSchemaIncompatibleException> {
            openCallback.onOpen(database)
        }
        assertFailsWith<StorageMigrationMissingException> {
            upgradeCallback.onUpgrade(database, 1, 2)
        }
    }

    private fun failClosedCallback(
        openFailure: RuntimeException? = null,
        upgradeFailure: RuntimeException? = null,
    ): FailClosedCallback =
        FailClosedCallback(
            delegate = ThrowingCallback(openFailure, upgradeFailure),
            corruptionState = AtomicBoolean(false),
        )

    private class RecordingFactory : SupportSQLiteOpenHelper.Factory {
        lateinit var configuration: SupportSQLiteOpenHelper.Configuration

        override fun create(
            configuration: SupportSQLiteOpenHelper.Configuration,
        ): SupportSQLiteOpenHelper {
            this.configuration = configuration
            return NoOpOpenHelper(configuration.name)
        }
    }

    private class NoOpOpenHelper(
        override val databaseName: String?,
    ) : SupportSQLiteOpenHelper {
        override val readableDatabase: SupportSQLiteDatabase
            get() = error("Not opened by this configuration-only test.")
        override val writableDatabase: SupportSQLiteDatabase
            get() = error("Not opened by this configuration-only test.")

        override fun setWriteAheadLoggingEnabled(enabled: Boolean) = Unit

        override fun close() = Unit
    }

    private class NoOpCallback : SupportSQLiteOpenHelper.Callback(1) {
        override fun onCreate(db: SupportSQLiteDatabase) = Unit

        override fun onUpgrade(
            db: SupportSQLiteDatabase,
            oldVersion: Int,
            newVersion: Int,
        ) = Unit
    }

    private class ThrowingCallback(
        private val openFailure: RuntimeException?,
        private val upgradeFailure: RuntimeException?,
    ) : SupportSQLiteOpenHelper.Callback(1) {
        override fun onCreate(db: SupportSQLiteDatabase) = Unit

        override fun onUpgrade(
            db: SupportSQLiteDatabase,
            oldVersion: Int,
            newVersion: Int,
        ) {
            upgradeFailure?.let { throw it }
        }

        override fun onOpen(db: SupportSQLiteDatabase) {
            openFailure?.let { throw it }
        }
    }
}
