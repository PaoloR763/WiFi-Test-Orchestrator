package com.wifitestorchestrator.agent.data.persistence

import android.content.Context
import com.wifitestorchestrator.agent.data.persistence.room.ProcessRoomDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.RoomCapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.room.RoomProtectedEnrollmentRepository

class AndroidLocalPersistenceFactory(context: Context) {
    private val applicationContext: Context =
        requireNotNull(context.applicationContext) {
            "An application context is required to configure local persistence."
        }

    private val localStateRepository: LocalStateRepository by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        RoomLocalStateRepository {
            ProcessRoomDatabaseProvider.get(applicationContext)
        }
    }

    private val protectedEnrollmentRepository: ProtectedEnrollmentRepository by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            RoomProtectedEnrollmentRepository {
                ProcessRoomDatabaseProvider.get(applicationContext)
            }
        }

    private val capabilityManifestPublicationRepository:
        CapabilityManifestPublicationRepository by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            RoomCapabilityManifestPublicationRepository(
                databaseProvider = {
                    ProcessRoomDatabaseProvider.get(applicationContext)
                },
            )
        }

    fun create(): LocalStateRepository = localStateRepository

    fun createProtectedEnrollmentRepository(): ProtectedEnrollmentRepository =
        protectedEnrollmentRepository

    fun createCapabilityManifestPublicationRepository():
        CapabilityManifestPublicationRepository =
        capabilityManifestPublicationRepository
}
