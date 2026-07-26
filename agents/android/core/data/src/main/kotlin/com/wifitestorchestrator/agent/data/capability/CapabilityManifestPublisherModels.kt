package com.wifitestorchestrator.agent.data.capability

interface CapabilityManifestPublisher {
    suspend fun publish(): CapabilityManifestPublicationResult
}

sealed interface CapabilityManifestPublicationResult {
    data class Published(
        val manifestId: String,
        val manifestSequence: Long,
    ) : CapabilityManifestPublicationResult

    data class AlreadyCurrent(
        val manifestId: String,
        val manifestSequence: Long,
    ) : CapabilityManifestPublicationResult

    data object NotEnrolled : CapabilityManifestPublicationResult

    data class PendingRetry(
        val manifestId: String,
        val manifestSequence: Long,
        val reason: PendingRetryReason,
    ) : CapabilityManifestPublicationResult

    data object SequenceExhausted : CapabilityManifestPublicationResult

    data class Blocked(val reason: CapabilityManifestBlockedReason) :
        CapabilityManifestPublicationResult

    data object CancelledBeforeStart : CapabilityManifestPublicationResult

    data class CancelledPending(
        val manifestId: String,
        val manifestSequence: Long,
    ) : CapabilityManifestPublicationResult
}

enum class PendingRetryReason {
    AMBIGUOUS_TRANSPORT,
    RATE_LIMITED,
    SERVICE_UNAVAILABLE,
}

enum class CapabilityManifestBlockedReason {
    INVALID_PLATFORM_VERSION,
    INVALID_LOCAL_SNAPSHOT,
    LOCAL_PERSISTENCE,
    CORRUPT_LOCAL_STATE,
    UNSUPPORTED_LOCAL_STATE,
    ENROLLMENT_CHANGED,
    PENDING_CHANGED,
    CREDENTIAL_UNUSABLE,
    CREDENTIAL_PROTECTION,
    INVALID_ENDPOINT,
    INVALID_HTTP_FACTS,
    AUTHENTICATION,
    CONFLICT,
    LOCAL_CONTRACT,
    PROTOCOL_INCOMPATIBLE,
    REDIRECT,
    UNEXPECTED_STATUS,
    INVALID_ACKNOWLEDGEMENT,
    ACCEPTANCE_COMMIT,
}
