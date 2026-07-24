package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant

enum class EnrollmentInvocationIntent {
    INITIAL,
    MANUAL_SAME_LIVE_ATTEMPT_ONLY,
}

enum class RetryDisposition {
    NONE,
    MANUAL_SAME_LIVE_ATTEMPT_ONLY,
    MANUAL_AFTER_INTERVENTION,
}

enum class RemoteDisposition {
    NOT_ATTEMPTED,
    KNOWN_REJECTED,
    KNOWN_TRANSIENT_FAILURE,
    OUTCOME_UNRESOLVED,
    ACCEPTED,
}

enum class PersistenceDisposition {
    NOT_ATTEMPTED,
    NEWLY_WRITTEN,
    EXISTING_EQUIVALENT,
    REPLACED,
    RECONCILED_AFTER_FAILURE,
    NOT_DURABLE,
    DURABILITY_UNKNOWN,
    DURABILITY_CONFLICT,
}

enum class DurabilityEvidence {
    NONE,
    AUTHORITATIVE_PREFLIGHT,
    TRANSACTION_CONFIRMED,
    AUTHORITATIVE_RECONCILIATION,
    ABSENT_AFTER_FAILURE,
    CONFLICTING_AFTER_FAILURE,
    UNKNOWN_AFTER_FAILURE,
}

enum class EnrollmentSuccessKind {
    NEWLY_WRITTEN,
    EXISTING_EQUIVALENT,
    REPLACED,
    RECONCILED_AFTER_FAILURE,
}

enum class EnrollmentAnomaly {
    UNEXPECTED_DURABLE_REPLACEMENT,
}

enum class MissingPreconditionReason {
    LOCAL_STATE_INCOMPLETE,
}

enum class InvalidConfigurationReason {
    INVALID_LOCAL_REQUEST,
    INVALID_ENDPOINT,
    CALL_CREATION_FAILED,
}

enum class LocalStateBlockedReason {
    IDENTITY_OR_SERVER_CONFLICT,
    CORRUPT,
    UNSUPPORTED,
    PREFLIGHT_INITIALIZATION_FAILED,
    PREFLIGHT_STATE_INCOMPLETE,
    PREFLIGHT_STATE_CONFLICT,
    PREFLIGHT_CONSTRAINT_VIOLATION,
    PREFLIGHT_IO,
    PREFLIGHT_DATABASE_BUSY_OR_LOCKED,
    PREFLIGHT_CORRUPTION,
    PREFLIGHT_SCHEMA_INCOMPATIBLE,
    PREFLIGHT_MIGRATION_MISSING,
    PREFLIGHT_UNKNOWN,
    MANUAL_RETRY_REQUIRES_SAME_LIVE_ATTEMPT,
    RETRY_REQUIRES_MANUAL_INTENT,
    PREVIOUS_REMOTE_OUTCOME_UNRESOLVED,
    PREVIOUS_REMOTE_ACCEPTED_NOT_DURABLE,
}

enum class KeyIncompatibleReason {
    MISSING_FOR_DURABLE_ENROLLMENT,
    INCOMPATIBLE_FOR_DURABLE_ENROLLMENT,
    INCOMPATIBLE_DURING_PREPARATION,
}

enum class PlatformFailureReason {
    KEY_MISSING,
    KEY_INCOMPATIBLE,
    KEY_INVALIDATED,
    KEY_PERMANENTLY_INVALIDATED,
    KEYSTORE_TEMPORARILY_UNAVAILABLE,
    DEVICE_LOCKED,
    PROVIDER_FAILURE,
    MALFORMED_ENVELOPE,
    INVALID_NONCE,
    UNSUPPORTED_CRYPTO_VERSION,
    UNKNOWN_KEY_ALIAS,
    AUTHENTICATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    ADAPTER_EXCEPTION,
}

enum class RemoteRejectedReason {
    AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED,
    CONFLICT,
    REQUEST_TOO_LARGE,
    CONTRACT_REJECTED,
    RATE_LIMITED,
    SERVICE_UNAVAILABLE,
}

enum class KnownTransientFailureReason {
    DNS,
    CONNECTION,
}

enum class RemoteOutcomeAmbiguousReason {
    TLS,
    TIMEOUT,
    TRANSPORT_CANCELLED,
    INCOMPLETE_RESPONSE,
    IO,
}

enum class ResponseIncompatibleReason {
    REDIRECT,
    UNEXPECTED_STATUS,
    INVALID_CONTENT_TYPE,
    EMPTY_BODY,
    RESPONSE_TOO_LARGE,
    MALFORMED_JSON,
    INVALID_RESPONSE_SHAPE,
    INVALID_RESPONSE_SEMANTICS,
    MISSING_CORRELATION,
    CORRELATION_MISMATCH,
    DEFENSIVE_ACCEPTANCE_VALIDATION_FAILED,
}

enum class ProtectionFailureReason {
    KEY_MISSING,
    KEY_INCOMPATIBLE,
    KEY_INVALIDATED,
    KEY_PERMANENTLY_INVALIDATED,
    KEYSTORE_TEMPORARILY_UNAVAILABLE,
    DEVICE_LOCKED,
    PROVIDER_FAILURE,
    MALFORMED_ENVELOPE,
    INVALID_NONCE,
    UNSUPPORTED_CRYPTO_VERSION,
    UNKNOWN_KEY_ALIAS,
    AUTHENTICATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    ADAPTER_EXCEPTION,
    ENVELOPE_METADATA_MISMATCH,
}

enum class PersistenceFailureReason {
    CONFLICT,
    ROLLBACK,
    PENDING_REJECTED,
    INVALID_CANDIDATE,
    CORRUPT,
    UNSUPPORTED,
    INITIALIZATION_FAILED,
    STATE_INCOMPLETE,
    STATE_CONFLICT,
    CONSTRAINT_VIOLATION,
    IO,
    DATABASE_BUSY_OR_LOCKED,
    CORRUPTION,
    SCHEMA_INCOMPATIBLE,
    MIGRATION_MISSING,
    UNKNOWN,
    ADAPTER_EXCEPTION,
    RECONCILIATION_ABSENT,
    RECONCILIATION_NOT_EQUIVALENT,
    RECONCILIATION_CORRUPT,
    RECONCILIATION_UNSUPPORTED,
    RECONCILIATION_FAILED,
}

/**
 * Non-secret enrollment facts safe to return to a future application boundary.
 *
 * This receipt contains neither an enrollment token, plaintext credential, protected envelope,
 * nonce, ciphertext, nor AAD.
 */
class EnrollmentReceipt(
    val backendIdentity: BackendAgentIdentity,
    val protocolVersion: ProtocolVersion,
    val serverReceivedAt: Instant,
    val credentialMetadata: CredentialMetadata,
) {
    override fun toString(): String = "EnrollmentReceipt(<redacted>)"
}

sealed interface EnrollmentCoordinatorResult {
    val retryDisposition: RetryDisposition
    val remoteDisposition: RemoteDisposition
    val persistenceDisposition: PersistenceDisposition
    val durabilityEvidence: DurabilityEvidence
}

class Enrolled(
    val kind: EnrollmentSuccessKind,
    val receipt: EnrollmentReceipt,
    val anomaly: EnrollmentAnomaly?,
    override val persistenceDisposition: PersistenceDisposition,
    override val durabilityEvidence: DurabilityEvidence,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition = RetryDisposition.NONE
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.ACCEPTED

    override fun toString(): String = "Enrolled(<redacted>)"
}

class AlreadyEnrolled(
    val receipt: EnrollmentReceipt,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition = RetryDisposition.NONE
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.NOT_ATTEMPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence =
        DurabilityEvidence.AUTHORITATIVE_PREFLIGHT

    override fun toString(): String = "AlreadyEnrolled(<redacted>)"
}

class MissingPrecondition(
    val reason: MissingPreconditionReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_AFTER_INTERVENTION
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.NOT_ATTEMPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "MissingPrecondition(reason=$reason)"
}

class InvalidConfiguration(
    val reason: InvalidConfigurationReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_AFTER_INTERVENTION
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.NOT_ATTEMPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "InvalidConfiguration(reason=$reason)"
}

class LocalStateBlocked(
    val reason: LocalStateBlockedReason,
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_AFTER_INTERVENTION,
) : EnrollmentCoordinatorResult {
    override val remoteDisposition: RemoteDisposition =
        when (reason) {
            LocalStateBlockedReason.PREVIOUS_REMOTE_OUTCOME_UNRESOLVED ->
                RemoteDisposition.OUTCOME_UNRESOLVED
            LocalStateBlockedReason.PREVIOUS_REMOTE_ACCEPTED_NOT_DURABLE ->
                RemoteDisposition.ACCEPTED
            else -> RemoteDisposition.NOT_ATTEMPTED
        }
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "LocalStateBlocked(reason=$reason)"
}

class KeyIncompatible(
    val reason: KeyIncompatibleReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_AFTER_INTERVENTION
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.NOT_ATTEMPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "KeyIncompatible(reason=$reason)"
}

class PlatformFailure(
    val reason: PlatformFailureReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.NOT_ATTEMPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "PlatformFailure(reason=$reason)"
}

class RemoteRejected(
    val reason: RemoteRejectedReason,
    val statusCode: Int,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.KNOWN_REJECTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String =
        "RemoteRejected(reason=$reason, statusCode=$statusCode)"
}

class KnownTransientFailure(
    val reason: KnownTransientFailureReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition =
        RemoteDisposition.KNOWN_TRANSIENT_FAILURE
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "KnownTransientFailure(reason=$reason)"
}

class RemoteOutcomeAmbiguous(
    val reason: RemoteOutcomeAmbiguousReason,
    val statusCode: Int?,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.OUTCOME_UNRESOLVED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String =
        "RemoteOutcomeAmbiguous(reason=$reason, statusCode=$statusCode)"
}

class ResponseIncompatible(
    val reason: ResponseIncompatibleReason,
    val statusCode: Int?,
    override val remoteDisposition: RemoteDisposition =
        RemoteDisposition.OUTCOME_UNRESOLVED,
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_ATTEMPTED,
    override val durabilityEvidence: DurabilityEvidence =
        DurabilityEvidence.NONE,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY

    override fun toString(): String =
        "ResponseIncompatible(reason=$reason, statusCode=$statusCode)"
}

class ProtectionFailure(
    val reason: ProtectionFailureReason,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.ACCEPTED
    override val persistenceDisposition: PersistenceDisposition =
        PersistenceDisposition.NOT_DURABLE
    override val durabilityEvidence: DurabilityEvidence = DurabilityEvidence.NONE

    override fun toString(): String = "ProtectionFailure(reason=$reason)"
}

class PersistenceFailure(
    val reason: PersistenceFailureReason,
    override val persistenceDisposition: PersistenceDisposition,
    override val durabilityEvidence: DurabilityEvidence,
) : EnrollmentCoordinatorResult {
    override val retryDisposition: RetryDisposition =
        RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    override val remoteDisposition: RemoteDisposition = RemoteDisposition.ACCEPTED

    override fun toString(): String = "PersistenceFailure(reason=$reason)"
}
