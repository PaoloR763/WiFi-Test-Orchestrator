package com.wifitestorchestrator.agent.data.persistence.room

import android.content.Context

internal object ProcessRoomDatabaseProvider {
    private val lock = Any()

    @Volatile
    private var database: WtoAgentDatabase? = null

    fun get(context: Context): WtoAgentDatabase {
        database?.let { return it }
        return synchronized(lock) {
            database?.let { return@synchronized it }
            val applicationContext =
                context.applicationContext ?: throw StorageInitializationException()
            WtoAgentDatabase.build(applicationContext).also { database = it }
        }
    }

    internal fun closeForTestsOrMaintenance() {
        synchronized(lock) {
            database?.close()
            database = null
        }
    }
}
