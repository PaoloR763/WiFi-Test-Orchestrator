package com.wifitestorchestrator.agent.contracts.capability

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CapabilityManifestDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("manifest_id")
    val manifestId: String,
    @SerialName("manifest_sequence")
    val manifestSequence: Long,
    @SerialName("agent_id")
    val agentId: String,
    @SerialName("agent_version")
    val agentVersion: String,
    val platform: String,
    @SerialName("platform_version")
    val platformVersion: String,
    @SerialName("protocol_version")
    val protocolVersion: String,
    @SerialName("capability_catalog_version")
    val capabilityCatalogVersion: String,
    @SerialName("generated_at")
    val generatedAt: String,
    val capabilities: List<CapabilityDto>,
)

@Serializable
data class CapabilityDto(
    val id: String,
    val version: String,
    @SerialName("technical_support")
    val technicalSupport: TechnicalSupportDto,
    @SerialName("implementation_status")
    val implementationStatus: ImplementationStatusDto,
    @SerialName("permission_requirement")
    val permissionRequirement: PermissionRequirementDto,
    @SerialName("user_interaction")
    val userInteraction: UserInteractionDto,
    @SerialName("background_execution")
    val backgroundExecution: BackgroundExecutionDto,
    val provider: ProviderDto,
    val limitations: LimitationsDto,
)

@Serializable
data class CapabilityReasonDto(
    val code: CapabilityReasonCodeDto,
    val detail: String? = null,
)

@Serializable
data class TechnicalSupportDto(
    val status: TechnicalSupportStatusDto,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class ImplementationStatusDto(
    val status: ImplementationStatusValueDto,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class PermissionRequirementDto(
    val status: PermissionRequirementStatusDto,
    val permissions: List<String>,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class UserInteractionDto(
    val status: UserInteractionStatusDto,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class BackgroundExecutionDto(
    val status: BackgroundExecutionStatusDto,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class ProviderDto(
    val status: ProviderStatusDto,
    val implementations: List<ProviderImplementationDto>,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class ProviderImplementationDto(
    @SerialName("provider_id")
    val providerId: String,
    @SerialName("provider_version")
    val providerVersion: String,
    val method: String,
)

@Serializable
data class LimitationsDto(
    val status: LimitationsStatusDto,
    @SerialName("max_duration_seconds")
    val maxDurationSeconds: Long? = null,
    @SerialName("max_throughput_bps")
    val maxThroughputBps: Long? = null,
    @SerialName("max_payload_bytes")
    val maxPayloadBytes: Long? = null,
    @SerialName("max_concurrency")
    val maxConcurrency: Int? = null,
    @SerialName("max_streams")
    val maxStreams: Int? = null,
    val reason: CapabilityReasonDto?,
)

@Serializable
data class CapabilityManifestAcceptedDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("manifest_id")
    val manifestId: String,
    @SerialName("manifest_digest")
    val manifestDigest: String,
    @SerialName("server_received_at")
    val serverReceivedAt: String,
)

@Serializable
enum class TechnicalSupportStatusDto {
    @SerialName("supported")
    SUPPORTED,

    @SerialName("conditional")
    CONDITIONAL,

    @SerialName("unsupported")
    UNSUPPORTED,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class ImplementationStatusValueDto {
    @SerialName("implemented")
    IMPLEMENTED,

    @SerialName("partial")
    PARTIAL,

    @SerialName("planned")
    PLANNED,

    @SerialName("not_implemented")
    NOT_IMPLEMENTED,

    @SerialName("excluded")
    EXCLUDED,

    @SerialName("unknown")
    UNKNOWN,
}

@Serializable
enum class PermissionRequirementStatusDto {
    @SerialName("none")
    NONE,

    @SerialName("required")
    REQUIRED,

    @SerialName("conditional")
    CONDITIONAL,

    @SerialName("denied")
    DENIED,

    @SerialName("restricted")
    RESTRICTED,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class UserInteractionStatusDto {
    @SerialName("none")
    NONE,

    @SerialName("required")
    REQUIRED,

    @SerialName("conditional")
    CONDITIONAL,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class BackgroundExecutionStatusDto {
    @SerialName("continuous")
    CONTINUOUS,

    @SerialName("bounded")
    BOUNDED,

    @SerialName("foreground_only")
    FOREGROUND_ONLY,

    @SerialName("deferred")
    DEFERRED,

    @SerialName("not_supported")
    NOT_SUPPORTED,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class ProviderStatusDto {
    @SerialName("available")
    AVAILABLE,

    @SerialName("unavailable")
    UNAVAILABLE,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class LimitationsStatusDto {
    @SerialName("known")
    KNOWN,

    @SerialName("unknown")
    UNKNOWN,

    @SerialName("not_applicable")
    NOT_APPLICABLE,
}

@Serializable
enum class CapabilityReasonCodeDto {
    @SerialName("not_implemented")
    NOT_IMPLEMENTED,

    @SerialName("not_exposed_by_platform")
    NOT_EXPOSED_BY_PLATFORM,

    @SerialName("permission_missing")
    PERMISSION_MISSING,

    @SerialName("user_interaction_required")
    USER_INTERACTION_REQUIRED,

    @SerialName("lifecycle_restricted")
    LIFECYCLE_RESTRICTED,

    @SerialName("provider_unavailable")
    PROVIDER_UNAVAILABLE,

    @SerialName("not_applicable")
    NOT_APPLICABLE,

    @SerialName("unknown")
    UNKNOWN,
}
