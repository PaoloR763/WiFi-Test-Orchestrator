package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey

@Entity(
    tableName = "server_configuration",
    foreignKeys = [
        ForeignKey(
            entity = LocalInstallationEntity::class,
            parentColumns = ["singleton_id"],
            childColumns = ["singleton_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.NO_ACTION,
        ),
    ],
)
internal data class ServerConfigurationEntity(
    @PrimaryKey
    @ColumnInfo(name = "singleton_id")
    val singletonId: Long,
    @ColumnInfo(name = "base_url")
    val baseUrl: String,
    @ColumnInfo(name = "updated_at_epoch_seconds")
    val updatedAtEpochSeconds: Long,
    @ColumnInfo(name = "updated_at_nanoseconds")
    val updatedAtNanoseconds: Long,
)
