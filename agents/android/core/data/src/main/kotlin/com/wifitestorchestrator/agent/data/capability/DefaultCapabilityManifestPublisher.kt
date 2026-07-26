package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestContract
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestEndpoint
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpClient
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpCommand
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpResult
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestRejection
import com.wifitestorchestrator.agent.data.capability.http.OkHttpCapabilityManifestClient
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentHttpClientPolicy
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentWireTimestamp
import com.wifitestorchestrator.agent.data.persistence.AcceptCapabilityManifestResult
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestCredentialUse
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationState
import com.wifitestorchestrator.agent.data.persistence.CapabilityPublicationPreflightResult
import com.wifitestorchestrator.agent.data.persistence.CapabilityPublicationReservationExpectation
import com.wifitestorchestrator.agent.data.persistence.EnrolledCapabilityPublicationContext
import com.wifitestorchestrator.agent.data.persistence.RevalidateCapabilityManifestResult
import com.wifitestorchestrator.agent.data.persistence.ReserveCapabilityManifestResult
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityCatalog
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFactsProvider
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshotResult
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

object CapabilityManifestPublisherFactory {
    fun create(
        repository: CapabilityManifestPublicationRepository,
        credentialProtector: CredentialProtector,
        factsProvider: AndroidCapabilityFactsProvider,
        agentVersion: AgentVersion,
    ): CapabilityManifestPublisher =
        DefaultCapabilityManifestPublisher(
            repository = repository,
            credentialProtector = credentialProtector,
            factsProvider = factsProvider,
            agentVersion = agentVersion,
            httpClient =
                OkHttpCapabilityManifestClient(EnrollmentHttpClientPolicy.shared),
            ioDispatcher = Dispatchers.IO,
            manifestClock = SystemCapabilityManifestClock,
            requestClock = SystemCapabilityManifestClock,
            uuidSource = SystemCapabilityManifestUuidSource,
            randomSource = SecureCapabilityManifestRandomSource(),
            correlationSource = SystemCapabilityManifestCorrelationSource,
            processMutex = ProcessCapabilityManifestPublicationGuard.mutex,
        )
}

internal object ProcessCapabilityManifestPublicationGuard {
    val mutex = Mutex()
}

internal class DefaultCapabilityManifestPublisher(
    private val repository: CapabilityManifestPublicationRepository,
    private val credentialProtector: CredentialProtector,
    private val factsProvider: AndroidCapabilityFactsProvider,
    private val agentVersion: AgentVersion,
    private val httpClient: CapabilityManifestHttpClient,
    private val ioDispatcher: CoroutineDispatcher,
    private val manifestClock: CapabilityManifestClock,
    private val requestClock: CapabilityManifestClock,
    private val uuidSource: CapabilityManifestUuidSource,
    private val randomSource: CapabilityManifestRandomSource,
    private val correlationSource: CapabilityManifestCorrelationSource,
    private val processMutex: Mutex,
    private val codec: CapabilityManifestCodec = CapabilityManifestCodec(),
) : CapabilityManifestPublisher {
    override suspend fun publish(): CapabilityManifestPublicationResult {
        if (!currentCoroutineContext().isActive) {
            return CapabilityManifestPublicationResult.CancelledBeforeStart
        }
        return try {
            processMutex.withLock { publishLocked() }
        } catch (cancellation: CancellationException) {
            throw cancellation
        }
    }

    private suspend fun publishLocked(): CapabilityManifestPublicationResult {
        currentCoroutineContext().ensureActive()
        val context =
            when (val preflight = repository.preflight()) {
                CapabilityPublicationPreflightResult.NotEnrolled ->
                    return CapabilityManifestPublicationResult.NotEnrolled
                CapabilityPublicationPreflightResult.Corrupt ->
                    return blocked(CapabilityManifestBlockedReason.CORRUPT_LOCAL_STATE)
                CapabilityPublicationPreflightResult.Unsupported ->
                    return blocked(CapabilityManifestBlockedReason.UNSUPPORTED_LOCAL_STATE)
                is CapabilityPublicationPreflightResult.Failure ->
                    return blocked(CapabilityManifestBlockedReason.LOCAL_PERSISTENCE)
                is CapabilityPublicationPreflightResult.Enrolled -> preflight.context
            }
        val pending =
            when (val state = context.publicationState) {
                CapabilityManifestPublicationState.Empty ->
                    reserveSnapshot(context, accepted = null)
                is CapabilityManifestPublicationState.Stored -> {
                    state.pending?.let(SnapshotPreparation::Ready)
                        ?: reserveSnapshot(context, state.accepted)
                }
            }
        if (pending is SnapshotPreparation.Terminal) return pending.result
        return publishPending(
            enrollmentContext = context,
            pending = (pending as SnapshotPreparation.Ready).manifest,
        )
    }

    private suspend fun reserveSnapshot(
        context: EnrolledCapabilityPublicationContext,
        accepted: com.wifitestorchestrator.agent.data.persistence.AcceptedCapabilityManifest?,
    ): SnapshotPreparation {
        val snapshot =
            when (val built = AndroidCapabilityCatalog.build(factsProvider.observe())) {
                AndroidCapabilitySnapshotResult.InvalidPlatformVersion ->
                    return terminal(CapabilityManifestBlockedReason.INVALID_PLATFORM_VERSION)
                is AndroidCapabilitySnapshotResult.Built -> built.snapshot
            }
        val semantic =
            CapabilityManifestSemanticInput(
                agentId = context.enrollment.backendIdentity.agentId,
                agentVersion = agentVersion,
                protocolVersion = context.enrollment.protocolVersion,
                snapshot = snapshot,
            )
        val fingerprint =
            codec.semanticFingerprint(semantic)
                ?: return terminal(CapabilityManifestBlockedReason.INVALID_LOCAL_SNAPSHOT)
        if (accepted?.manifest?.semanticFingerprint?.contentEquals(fingerprint) == true) {
            return SnapshotPreparation.Terminal(
                CapabilityManifestPublicationResult.AlreadyCurrent(
                    manifestId = accepted.manifest.manifestId,
                    manifestSequence = accepted.manifest.manifestSequence,
                ),
            )
        }

        val storedState =
            context.publicationState as? CapabilityManifestPublicationState.Stored
        if (storedState?.sequenceExhausted == true) {
            return SnapshotPreparation.Terminal(
                CapabilityManifestPublicationResult.SequenceExhausted,
            )
        }
        val sequence = storedState?.nextManifestSequence ?: 0L
        val manifestId = uuidSource.next()
        val generatedAt = manifestClock.now()
        val frozen =
            when (
                val result =
                    codec.freeze(
                        input = semantic,
                        manifestId = manifestId,
                        manifestSequence = sequence,
                        generatedAt = generatedAt,
                    )
            ) {
                CapabilityManifestFreezeResult.Invalid ->
                    return terminal(CapabilityManifestBlockedReason.INVALID_LOCAL_SNAPSHOT)
                is CapabilityManifestFreezeResult.Frozen -> result.manifest
            }
        val reservation =
            repository.reserve(
                expectation =
                    CapabilityPublicationReservationExpectation(
                        enrollmentIdentityFingerprint =
                            context.enrollmentIdentityFingerprint,
                        credentialId = context.enrollment.credentialMetadata.credentialId,
                        credentialVersion =
                            context.enrollment.credentialMetadata.version.value,
                        expectedAcceptedManifestId = accepted?.manifest?.manifestId,
                        expectedAcceptedSequence = accepted?.manifest?.manifestSequence,
                    ),
                manifest = frozen,
            )
        return when (reservation) {
            ReserveCapabilityManifestResult.Reserved -> SnapshotPreparation.Ready(frozen)
            ReserveCapabilityManifestResult.SequenceExhausted ->
                SnapshotPreparation.Terminal(
                    CapabilityManifestPublicationResult.SequenceExhausted,
                )
            ReserveCapabilityManifestResult.EnrollmentChanged ->
                terminal(CapabilityManifestBlockedReason.ENROLLMENT_CHANGED)
            ReserveCapabilityManifestResult.PendingAlreadyExists,
            ReserveCapabilityManifestResult.StateChanged,
            -> terminal(CapabilityManifestBlockedReason.PENDING_CHANGED)
            ReserveCapabilityManifestResult.Corrupt ->
                terminal(CapabilityManifestBlockedReason.CORRUPT_LOCAL_STATE)
            ReserveCapabilityManifestResult.Unsupported ->
                terminal(CapabilityManifestBlockedReason.UNSUPPORTED_LOCAL_STATE)
            is ReserveCapabilityManifestResult.Failure ->
                terminal(CapabilityManifestBlockedReason.LOCAL_PERSISTENCE)
        }
    }

    private suspend fun publishPending(
        enrollmentContext: EnrolledCapabilityPublicationContext,
        pending: FrozenCapabilityManifest,
    ): CapabilityManifestPublicationResult {
        val attemptTime = requestClock.now()
        val sendContext =
            when (
                val validation =
                    repository.revalidateForSend(
                        enrollmentIdentityFingerprint =
                            enrollmentContext.enrollmentIdentityFingerprint,
                        pending = pending,
                        now = attemptTime,
                    )
            ) {
                RevalidateCapabilityManifestResult.NotEnrolled ->
                    return CapabilityManifestPublicationResult.NotEnrolled
                RevalidateCapabilityManifestResult.EnrollmentChanged ->
                    return blocked(CapabilityManifestBlockedReason.ENROLLMENT_CHANGED)
                RevalidateCapabilityManifestResult.PendingChanged ->
                    return blocked(CapabilityManifestBlockedReason.PENDING_CHANGED)
                RevalidateCapabilityManifestResult.CredentialUnusable ->
                    return blocked(CapabilityManifestBlockedReason.CREDENTIAL_UNUSABLE)
                RevalidateCapabilityManifestResult.Corrupt ->
                    return blocked(CapabilityManifestBlockedReason.CORRUPT_LOCAL_STATE)
                RevalidateCapabilityManifestResult.Unsupported ->
                    return blocked(CapabilityManifestBlockedReason.UNSUPPORTED_LOCAL_STATE)
                is RevalidateCapabilityManifestResult.Failure ->
                    return blocked(CapabilityManifestBlockedReason.LOCAL_PERSISTENCE)
                is RevalidateCapabilityManifestResult.Ready -> validation.context
            }
        val endpoint =
            CapabilityManifestEndpoint.build(sendContext.enrollment.serverConfiguration)
                ?: return blocked(CapabilityManifestBlockedReason.INVALID_ENDPOINT)
        val timestamp =
            EnrollmentWireTimestamp.render(attemptTime)
                ?: return blocked(CapabilityManifestBlockedReason.INVALID_HTTP_FACTS)
        val nonceBytes = randomSource.nextBytes(NONCE_SIZE_BYTES)
        if (nonceBytes.size != NONCE_SIZE_BYTES) {
            return blocked(CapabilityManifestBlockedReason.INVALID_HTTP_FACTS)
        }
        val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes)
        if (!NONCE_PATTERN.matches(nonce)) {
            return blocked(CapabilityManifestBlockedReason.INVALID_HTTP_FACTS)
        }
        val correlationId = correlationSource.next()
        if (CorrelationId.parse(correlationId) !is com.wifitestorchestrator.agent.domain.error.Valid) {
            return blocked(CapabilityManifestBlockedReason.INVALID_HTTP_FACTS)
        }
        val command =
            CapabilityManifestHttpCommand(
                endpointUrl = endpoint,
                expectedManifestId = pending.manifestId,
                canonicalPayload = pending.copyCanonicalPayload(),
                timestamp = timestamp,
                nonce = nonce,
                correlationId = correlationId,
            )
        val execution =
            executeWithProtectedCredential(
                protector = credentialProtector,
                envelope = sendContext.enrollment.protectedCredential,
                httpClient = httpClient,
                command = command,
                dispatcher = ioDispatcher,
            )
        val credentialUse =
            CapabilityManifestCredentialUse(
                credentialId = sendContext.enrollment.credentialMetadata.credentialId,
                credentialVersion = sendContext.enrollment.credentialMetadata.version.value,
            )
        return when (execution) {
            is CredentialScopedExecutionResult.ProtectionFailure ->
                blocked(CapabilityManifestBlockedReason.CREDENTIAL_PROTECTION)
            is CredentialScopedExecutionResult.Completed ->
                handleHttpResult(
                    enrollmentContext = enrollmentContext,
                    pending = pending,
                    credentialUse = credentialUse,
                    result = execution.result,
                    cancellation = null,
                )
            is CredentialScopedExecutionResult.AcceptedAfterCancellation ->
                handleAccepted(
                    enrollmentContext = enrollmentContext,
                    pending = pending,
                    credentialUse = credentialUse,
                    result = execution.result,
                    cancellation = execution.cancellation,
                )
        }
    }

    private suspend fun handleHttpResult(
        enrollmentContext: EnrolledCapabilityPublicationContext,
        pending: FrozenCapabilityManifest,
        credentialUse: CapabilityManifestCredentialUse,
        result: CapabilityManifestHttpResult,
        cancellation: CancellationException?,
    ): CapabilityManifestPublicationResult =
        when (result) {
            is CapabilityManifestHttpResult.Accepted ->
                handleAccepted(
                    enrollmentContext,
                    pending,
                    credentialUse,
                    result,
                    cancellation,
                )
            is CapabilityManifestHttpResult.Ambiguous ->
                pendingRetry(pending, PendingRetryReason.AMBIGUOUS_TRANSPORT)
            is CapabilityManifestHttpResult.InvalidAcknowledgement ->
                blocked(CapabilityManifestBlockedReason.INVALID_ACKNOWLEDGEMENT)
            CapabilityManifestHttpResult.InvalidLocalRequest ->
                blocked(CapabilityManifestBlockedReason.LOCAL_CONTRACT)
            CapabilityManifestHttpResult.Cancelled ->
                CapabilityManifestPublicationResult.CancelledPending(
                    pending.manifestId,
                    pending.manifestSequence,
                )
            is CapabilityManifestHttpResult.Rejected ->
                mapRejection(pending, result.reason)
        }

    private suspend fun handleAccepted(
        enrollmentContext: EnrolledCapabilityPublicationContext,
        pending: FrozenCapabilityManifest,
        credentialUse: CapabilityManifestCredentialUse,
        result: CapabilityManifestHttpResult.Accepted,
        cancellation: CancellationException?,
    ): CapabilityManifestPublicationResult {
        val commit =
            try {
                withContext(NonCancellable) {
                    repository.accept(
                        enrollmentIdentityFingerprint =
                            enrollmentContext.enrollmentIdentityFingerprint,
                        pending = pending,
                        credentialUse = credentialUse,
                        acknowledgement = result.acknowledgement,
                        now = requestClock.now(),
                    )
                }
            } catch (failure: Throwable) {
                if (cancellation != null) {
                    if (failure !== cancellation) cancellation.addSuppressed(failure)
                    throw cancellation
                }
                throw failure
            }
        if (cancellation != null) {
            if (commit != AcceptCapabilityManifestResult.Accepted) {
                cancellation.addSuppressed(AcceptanceCommitFailure())
            }
            throw cancellation
        }
        currentCoroutineContext().ensureActive()
        return when (commit) {
            AcceptCapabilityManifestResult.Accepted ->
                CapabilityManifestPublicationResult.Published(
                    pending.manifestId,
                    pending.manifestSequence,
                )
            AcceptCapabilityManifestResult.EnrollmentChanged ->
                blocked(CapabilityManifestBlockedReason.ENROLLMENT_CHANGED)
            AcceptCapabilityManifestResult.PendingChanged ->
                blocked(CapabilityManifestBlockedReason.PENDING_CHANGED)
            AcceptCapabilityManifestResult.CredentialChanged ->
                blocked(CapabilityManifestBlockedReason.ENROLLMENT_CHANGED)
            AcceptCapabilityManifestResult.CredentialUnusable ->
                blocked(CapabilityManifestBlockedReason.CREDENTIAL_UNUSABLE)
            AcceptCapabilityManifestResult.Corrupt ->
                blocked(CapabilityManifestBlockedReason.CORRUPT_LOCAL_STATE)
            AcceptCapabilityManifestResult.Unsupported ->
                blocked(CapabilityManifestBlockedReason.UNSUPPORTED_LOCAL_STATE)
            is AcceptCapabilityManifestResult.Failure ->
                blocked(CapabilityManifestBlockedReason.ACCEPTANCE_COMMIT)
        }
    }

    private fun mapRejection(
        pending: FrozenCapabilityManifest,
        rejection: CapabilityManifestRejection,
    ): CapabilityManifestPublicationResult =
        when (rejection) {
            CapabilityManifestRejection.AUTHENTICATION_BLOCKED ->
                blocked(CapabilityManifestBlockedReason.AUTHENTICATION)
            CapabilityManifestRejection.CONFLICT ->
                blocked(CapabilityManifestBlockedReason.CONFLICT)
            CapabilityManifestRejection.REQUEST_TOO_LARGE ->
                blocked(CapabilityManifestBlockedReason.LOCAL_CONTRACT)
            CapabilityManifestRejection.CONTRACT_INCOMPATIBLE ->
                blocked(CapabilityManifestBlockedReason.PROTOCOL_INCOMPATIBLE)
            CapabilityManifestRejection.RATE_LIMITED ->
                pendingRetry(pending, PendingRetryReason.RATE_LIMITED)
            CapabilityManifestRejection.SERVICE_UNAVAILABLE ->
                pendingRetry(pending, PendingRetryReason.SERVICE_UNAVAILABLE)
            CapabilityManifestRejection.REDIRECT ->
                blocked(CapabilityManifestBlockedReason.REDIRECT)
            CapabilityManifestRejection.UNEXPECTED_STATUS ->
                blocked(CapabilityManifestBlockedReason.UNEXPECTED_STATUS)
        }

    private fun pendingRetry(
        pending: FrozenCapabilityManifest,
        reason: PendingRetryReason,
    ): CapabilityManifestPublicationResult.PendingRetry =
        CapabilityManifestPublicationResult.PendingRetry(
            manifestId = pending.manifestId,
            manifestSequence = pending.manifestSequence,
            reason = reason,
        )

    private fun terminal(reason: CapabilityManifestBlockedReason): SnapshotPreparation.Terminal =
        SnapshotPreparation.Terminal(blocked(reason))

    private fun blocked(
        reason: CapabilityManifestBlockedReason,
    ): CapabilityManifestPublicationResult.Blocked =
        CapabilityManifestPublicationResult.Blocked(reason)
}

private sealed interface SnapshotPreparation {
    data class Ready(val manifest: FrozenCapabilityManifest) : SnapshotPreparation

    data class Terminal(val result: CapabilityManifestPublicationResult) :
        SnapshotPreparation
}

private class AcceptanceCommitFailure :
    RuntimeException("Capability manifest acknowledgement commit failed (<redacted>).") {
    override fun fillInStackTrace(): Throwable = this
}

private const val NONCE_SIZE_BYTES = 16
private val NONCE_PATTERN = Regex("[A-Za-z0-9_-]{22}")
