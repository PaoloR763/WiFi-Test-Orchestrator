package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update

internal data class LocalStateRows(
    val installations: List<LocalInstallationEntity>,
    val serverConfigurations: List<ServerConfigurationEntity>,
)

@Dao
internal interface LocalStateDao {
    @Query("SELECT * FROM local_installation ORDER BY singleton_id")
    suspend fun readInstallations(): List<LocalInstallationEntity>

    @Query("SELECT * FROM server_configuration ORDER BY singleton_id")
    suspend fun readServerConfigurations(): List<ServerConfigurationEntity>

    @Transaction
    suspend fun readLocalStateRows(): LocalStateRows =
        LocalStateRows(
            installations = readInstallations(),
            serverConfigurations = readServerConfigurations(),
        )

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertInstallation(entity: LocalInstallationEntity): Long

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertServerConfiguration(entity: ServerConfigurationEntity): Long

    @Update(onConflict = OnConflictStrategy.ABORT)
    suspend fun updateServerConfiguration(entity: ServerConfigurationEntity): Int
}
