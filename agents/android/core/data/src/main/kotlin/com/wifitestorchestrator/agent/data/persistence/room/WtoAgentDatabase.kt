package com.wifitestorchestrator.agent.data.persistence.room

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        LocalInstallationEntity::class,
        ServerConfigurationEntity::class,
        ProtectedEnrollmentEntity::class,
        CapabilityManifestPublicationEntity::class,
    ],
    version = 3,
    exportSchema = true,
)
internal abstract class WtoAgentDatabase : RoomDatabase() {
    internal abstract fun localStateDao(): LocalStateDao

    internal abstract fun protectedEnrollmentDao(): ProtectedEnrollmentDao

    internal abstract fun capabilityManifestPublicationDao(): CapabilityManifestPublicationDao

    companion object {
        internal const val DATABASE_NAME = "wto-agent.db"

        internal fun build(
            context: Context,
            databaseName: String = DATABASE_NAME,
        ): WtoAgentDatabase {
            val applicationContext =
                context.applicationContext ?: throw StorageInitializationException()
            return Room.databaseBuilder(
                applicationContext,
                WtoAgentDatabase::class.java,
                databaseName,
            )
                .openHelperFactory(FailClosedRoomOpenHelperFactory())
                .addMigrations(*WtoAgentDatabaseMigrations.ALL)
                .addCallback(CapabilityManifestPublicationSchema.CALLBACK)
                .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                .build()
        }
    }
}
