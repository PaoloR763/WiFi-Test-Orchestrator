package com.wifitestorchestrator.agent.domain.capability

enum class TechnicalSupportStatus {
    SUPPORTED,
    CONDITIONAL,
    UNSUPPORTED,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class ImplementationStatus {
    IMPLEMENTED,
    PARTIAL,
    PLANNED,
    NOT_IMPLEMENTED,
    EXCLUDED,
    UNKNOWN,
}

enum class PermissionRequirementStatus {
    NONE,
    REQUIRED,
    CONDITIONAL,
    DENIED,
    RESTRICTED,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class UserInteractionStatus {
    NONE,
    REQUIRED,
    CONDITIONAL,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class BackgroundExecutionStatus {
    CONTINUOUS,
    BOUNDED,
    FOREGROUND_ONLY,
    DEFERRED,
    NOT_SUPPORTED,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class ProviderStatus {
    AVAILABLE,
    UNAVAILABLE,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class LimitationsStatus {
    KNOWN,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class CapabilityReasonCode {
    NOT_IMPLEMENTED,
    NOT_EXPOSED_BY_PLATFORM,
    PERMISSION_MISSING,
    USER_INTERACTION_REQUIRED,
    LIFECYCLE_RESTRICTED,
    PROVIDER_UNAVAILABLE,
    NOT_APPLICABLE,
    UNKNOWN,
}

data class CapabilityReason(val code: CapabilityReasonCode)

data class TechnicalSupport(
    val status: TechnicalSupportStatus,
    val reason: CapabilityReason?,
)

data class CapabilityImplementation(
    val status: ImplementationStatus,
    val reason: CapabilityReason?,
)

data class PermissionRequirement(
    val status: PermissionRequirementStatus,
    val permissions: List<String>,
    val reason: CapabilityReason?,
)

data class UserInteraction(
    val status: UserInteractionStatus,
    val reason: CapabilityReason?,
)

data class BackgroundExecution(
    val status: BackgroundExecutionStatus,
    val reason: CapabilityReason?,
)

data class CapabilityProvider(
    val status: ProviderStatus,
    val implementations: List<ProviderImplementation>,
    val reason: CapabilityReason?,
)

data class ProviderImplementation(
    val providerId: String,
    val providerVersion: String,
    val method: String,
)

data class CapabilityLimitations(
    val status: LimitationsStatus,
    val maxDurationSeconds: Long?,
    val maxThroughputBps: Long?,
    val maxPayloadBytes: Long?,
    val maxConcurrency: Int?,
    val maxStreams: Int?,
    val reason: CapabilityReason?,
)

data class AndroidCapability(
    val id: String,
    val version: String,
    val technicalSupport: TechnicalSupport,
    val implementationStatus: CapabilityImplementation,
    val permissionRequirement: PermissionRequirement,
    val userInteraction: UserInteraction,
    val backgroundExecution: BackgroundExecution,
    val provider: CapabilityProvider,
    val limitations: CapabilityLimitations,
)

data class AndroidCapabilitySnapshot(
    val platformVersion: String,
    val capabilities: List<AndroidCapability>,
)

sealed interface AndroidCapabilitySnapshotResult {
    data class Built(val snapshot: AndroidCapabilitySnapshot) :
        AndroidCapabilitySnapshotResult

    data object InvalidPlatformVersion : AndroidCapabilitySnapshotResult
}
