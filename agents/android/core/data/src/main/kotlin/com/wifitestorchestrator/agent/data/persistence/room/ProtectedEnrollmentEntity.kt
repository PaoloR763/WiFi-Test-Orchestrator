package com.wifitestorchestrator.agent.data.persistence.room

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey

@Entity(
    tableName = "protected_enrollment",
    foreignKeys = [
        ForeignKey(
            entity = LocalInstallationEntity::class,
            parentColumns = ["singleton_id"],
            childColumns = ["singleton_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.NO_ACTION,
        ),
        ForeignKey(
            entity = ServerConfigurationEntity::class,
            parentColumns = ["singleton_id"],
            childColumns = ["singleton_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.NO_ACTION,
        ),
    ],
)
internal data class ProtectedEnrollmentEntity(
    @PrimaryKey
    @ColumnInfo(name = "singleton_id")
    val singletonId: Long,
    @ColumnInfo(name = "installation_id")
    val installationId: String,
    @ColumnInfo(name = "server_base_url")
    val serverBaseUrl: String,
    @ColumnInfo(name = "agent_id")
    val agentId: String,
    @ColumnInfo(name = "device_id")
    val deviceId: String,
    @ColumnInfo(name = "protocol_version")
    val protocolVersion: String,
    @ColumnInfo(name = "server_received_at_epoch_seconds")
    val serverReceivedAtEpochSeconds: Long,
    @ColumnInfo(name = "server_received_at_nanoseconds")
    val serverReceivedAtNanoseconds: Long,
    @ColumnInfo(name = "credential_id")
    val credentialId: String,
    @ColumnInfo(name = "credential_version")
    val credentialVersion: Long,
    @ColumnInfo(name = "issued_at_epoch_seconds")
    val issuedAtEpochSeconds: Long,
    @ColumnInfo(name = "issued_at_nanoseconds")
    val issuedAtNanoseconds: Long,
    @ColumnInfo(name = "expires_at_epoch_seconds")
    val expiresAtEpochSeconds: Long,
    @ColumnInfo(name = "expires_at_nanoseconds")
    val expiresAtNanoseconds: Long,
    @ColumnInfo(name = "credential_delivery_state")
    val credentialDeliveryState: String,
    @ColumnInfo(name = "crypto_version")
    val cryptoVersion: Long,
    @ColumnInfo(name = "key_alias")
    val keyAlias: String,
    @ColumnInfo(name = "nonce", typeAffinity = ColumnInfo.BLOB)
    val nonce: ByteArray,
    @ColumnInfo(name = "sealed_credential", typeAffinity = ColumnInfo.BLOB)
    val sealedCredential: ByteArray,
) {
    override fun toString(): String = "ProtectedEnrollmentEntity(<redacted>)"
}
