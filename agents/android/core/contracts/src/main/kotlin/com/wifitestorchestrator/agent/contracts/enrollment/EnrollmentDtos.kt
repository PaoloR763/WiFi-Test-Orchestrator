package com.wifitestorchestrator.agent.contracts.enrollment

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class AgentRegistrationRequestDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("idempotency_key")
    val idempotencyKey: String,
    @SerialName("enrollment_token")
    val enrollmentToken: String,
    @SerialName("installation_id")
    val installationId: String,
    @SerialName("display_name")
    val displayName: String,
    @SerialName("platform")
    val platform: AgentPlatformDto,
    @SerialName("platform_version")
    val platformVersion: String,
    @SerialName("agent_version")
    val agentVersion: String,
    @SerialName("protocol_min_version")
    val protocolMinVersion: String,
    @SerialName("protocol_max_version")
    val protocolMaxVersion: String,
    @SerialName("agent_reported_at")
    val agentReportedAt: String,
) {
    override fun toString(): String =
        "AgentRegistrationRequestDto(" +
            "schemaVersion=$schemaVersion, " +
            "idempotencyKey=$idempotencyKey, " +
            "enrollmentToken=<redacted>, " +
            "installationId=$installationId, " +
            "displayName=$displayName, " +
            "platform=$platform, " +
            "platformVersion=$platformVersion, " +
            "agentVersion=$agentVersion, " +
            "protocolMinVersion=$protocolMinVersion, " +
            "protocolMaxVersion=$protocolMaxVersion, " +
            "agentReportedAt=$agentReportedAt)"
}

@Serializable
class AgentRegistrationResponseDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("device_id")
    val deviceId: String,
    @SerialName("agent_id")
    val agentId: String,
    @SerialName("protocol_version")
    val protocolVersion: String,
    @SerialName("server_received_at")
    val serverReceivedAt: String,
    @SerialName("credential")
    val credential: AgentCredentialDto,
) {
    override fun toString(): String =
        "AgentRegistrationResponseDto(" +
            "schemaVersion=$schemaVersion, " +
            "deviceId=$deviceId, " +
            "agentId=$agentId, " +
            "protocolVersion=$protocolVersion, " +
            "serverReceivedAt=$serverReceivedAt, " +
            "credential=<redacted>)"
}

@Serializable
class AgentCredentialDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("credential_id")
    val credentialId: String,
    @SerialName("credential_version")
    val credentialVersion: Int,
    @SerialName("credential")
    val credential: String,
    @SerialName("issued_at")
    val issuedAt: String,
    @SerialName("expires_at")
    val expiresAt: String,
    @SerialName("state")
    val state: CredentialDeliveryStateDto,
) {
    override fun toString(): String =
        "AgentCredentialDto(" +
            "schemaVersion=$schemaVersion, " +
            "credentialId=$credentialId, " +
            "credentialVersion=$credentialVersion, " +
            "credential=<redacted>, " +
            "issuedAt=$issuedAt, " +
            "expiresAt=$expiresAt, " +
            "state=$state)"
}

@Serializable
enum class AgentPlatformDto {
    @SerialName("simulated")
    SIMULATED,

    @SerialName("windows")
    WINDOWS,

    @SerialName("linux")
    LINUX,

    @SerialName("android")
    ANDROID,

    @SerialName("ios")
    IOS,
}

@Serializable
enum class CredentialDeliveryStateDto {
    @SerialName("active")
    ACTIVE,

    @SerialName("pending")
    PENDING,
}
