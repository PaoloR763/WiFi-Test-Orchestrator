package com.wifitestorchestrator.agent.data.persistence

import android.content.Context
import com.wifitestorchestrator.agent.data.persistence.room.ProcessRoomDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository

class AndroidLocalPersistenceFactory(context: Context) {
    private val applicationContext: Context =
        requireNotNull(context.applicationContext) {
            "An application context is required to configure local persistence."
        }

    private val repository: LocalStateRepository by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        RoomLocalStateRepository {
            ProcessRoomDatabaseProvider.get(applicationContext)
        }
    }

    fun create(): LocalStateRepository = repository
}
