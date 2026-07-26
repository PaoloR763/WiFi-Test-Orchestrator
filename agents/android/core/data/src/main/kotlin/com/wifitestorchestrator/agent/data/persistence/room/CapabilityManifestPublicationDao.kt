package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Update

@Dao
internal interface CapabilityManifestPublicationDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: CapabilityManifestPublicationEntity): Long

    @Update(onConflict = OnConflictStrategy.ABORT)
    suspend fun update(entity: CapabilityManifestPublicationEntity): Int
}
