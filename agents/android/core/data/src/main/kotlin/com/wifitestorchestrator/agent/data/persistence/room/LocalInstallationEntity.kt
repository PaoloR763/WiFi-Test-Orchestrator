package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "local_installation",
    indices = [Index(value = ["installation_id"], unique = true)],
)
internal data class LocalInstallationEntity(
    @PrimaryKey
    @ColumnInfo(name = "singleton_id")
    val singletonId: Long,
    @ColumnInfo(name = "installation_id")
    val installationId: String,
    @ColumnInfo(name = "created_at_epoch_seconds")
    val createdAtEpochSeconds: Long,
    @ColumnInfo(name = "created_at_nanoseconds")
    val createdAtNanoseconds: Long,
)
