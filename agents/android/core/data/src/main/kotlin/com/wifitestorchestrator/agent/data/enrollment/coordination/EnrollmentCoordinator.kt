package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentClient
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentFailureReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentRejectionReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentRepository
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.ReadProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeValidation
import com.wifitestorchestrator.agent.domain.enrollment.BackendEnrollmentAcceptance
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

interface EnrollmentCoordinator {
    /**
     * Performs no automatic remote retry. Cancellation is propagated as [CancellationException].
     */
    suspend fun enroll(
        attempt: EnrollmentAttempt,
        intent: EnrollmentInvocationIntent = EnrollmentInvocationIntent.INITIAL,
    ): EnrollmentCoordinatorResult
}

object EnrollmentCoordinatorFactory {
    fun create(
        enrollmentClient: EnrollmentClient,
        protectedEnrollmentRepository: ProtectedEnrollmentRepository,
        credentialProtector: CredentialProtector,
    ): EnrollmentCoordinator =
        DefaultEnrollmentCoordinator(
            enrollmentClient = enrollmentClient,
            protectedEnrollmentRepository = protectedEnrollmentRepository,
            credentialProtector = credentialProtector,
            blockingDispatcher = Dispatchers.IO,
            processGuard = ProductionProcessEnrollmentGuard.shared,
        )

    internal fun createForTesting(
        enrollmentClient: EnrollmentClient,
        protectedEnrollmentRepository: ProtectedEnrollmentRepository,
        credentialProtector: CredentialProtector,
        blockingDispatcher: CoroutineDispatcher,
        processGuard: ProcessEnrollmentGuard,
    ): EnrollmentCoordinator =
        DefaultEnrollmentCoordinator(
            enrollmentClient = enrollmentClient,
            protectedEnrollmentRepository = protectedEnrollmentRepository,
            credentialProtector = credentialProtector,
            blockingDispatcher = blockingDispatcher,
            processGuard = processGuard,
        )
}

private class DefaultEnrollmentCoordinator(
    private val enrollmentClient: EnrollmentClient,
    private val protectedEnrollmentRepository: ProtectedEnrollmentRepository,
    private val credentialProtector: CredentialProtector,
    private val blockingDispatcher: CoroutineDispatcher,
    private val processGuard: ProcessEnrollmentGuard,
) : EnrollmentCoordinator {
    override suspend fun enroll(
        attempt: EnrollmentAttempt,
        intent: EnrollmentInvocationIntent,
    ): EnrollmentCoordinatorResult =
        processGuard.withLock {
            coordinateLocked(attempt = attempt, intent = intent)
        }

    private suspend fun coordinateLocked(
        attempt: EnrollmentAttempt,
        intent: EnrollmentInvocationIntent,
    ): EnrollmentCoordinatorResult {
        val remoteTracker = RemoteExecutionTracker()
        val durable = AtomicBoolean(false)
        try {
            val preflight =
                try {
                    protectedEnrollmentRepository.preflight(
                        expectedLocalIdentity = attempt.expectedLocalIdentity,
                        expectedServerConfiguration = attempt.expectedServerConfiguration,
                    )
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (fatal: Error) {
                    throw fatal
                } catch (_: Exception) {
                    return LocalStateBlocked(
                        reason = LocalStateBlockedReason.PREFLIGHT_UNKNOWN,
                    )
                }

            when (preflight) {
                is ProtectedEnrollmentPreflightResult.Compatible ->
                    return handleCompatiblePreflight(preflight.enrollment)
                ProtectedEnrollmentPreflightResult.Absent -> Unit
                ProtectedEnrollmentPreflightResult.Conflict ->
                    return LocalStateBlocked(
                        LocalStateBlockedReason.IDENTITY_OR_SERVER_CONFLICT,
                    )
                ProtectedEnrollmentPreflightResult.LocalStateIncomplete ->
                    return MissingPrecondition(
                        MissingPreconditionReason.LOCAL_STATE_INCOMPLETE,
                    )
                ProtectedEnrollmentPreflightResult.Corrupt ->
                    return LocalStateBlocked(LocalStateBlockedReason.CORRUPT)
                ProtectedEnrollmentPreflightResult.Unsupported ->
                    return LocalStateBlocked(LocalStateBlockedReason.UNSUPPORTED)
                is ProtectedEnrollmentPreflightResult.Failure ->
                    return LocalStateBlocked(preflight.error.toPreflightReason())
            }

            when (val authorization = processGuard.authorize(attempt.attemptId, intent)) {
                ProcessEnrollmentAuthorization.Allowed -> Unit
                is ProcessEnrollmentAuthorization.Blocked ->
                    return LocalStateBlocked(
                        reason = authorization.reason,
                        retryDisposition =
                            RetryDisposition.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
                    )
            }

            when (val preparation = prepareKey()) {
                CredentialProtectionPreparation.Created,
                CredentialProtectionPreparation.AlreadyCompatible,
                -> Unit
                is CredentialProtectionPreparation.Failure ->
                    return preparation.error.toPreparationFailure()
            }

            currentCoroutineContext().ensureActive()
            val call =
                try {
                    enrollmentClient.newCall(attempt.command)
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (fatal: Error) {
                    throw fatal
                } catch (_: Exception) {
                    return InvalidConfiguration(
                        InvalidConfigurationReason.CALL_CREATION_FAILED,
                    )
                }
            currentCoroutineContext().ensureActive()

            val remoteResult =
                try {
                    awaitEnrollmentCall(
                        call = call,
                        dispatcher = blockingDispatcher,
                        tracker = remoteTracker,
                    )
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (fatal: Error) {
                    throw fatal
                } catch (_: Exception) {
                    if (remoteTracker.snapshot() == RemoteExecutionExposure.NOT_STARTED) {
                        return PlatformFailure(PlatformFailureReason.ADAPTER_EXCEPTION)
                    }
                    processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                    return RemoteOutcomeAmbiguous(
                        reason = RemoteOutcomeAmbiguousReason.IO,
                        statusCode = null,
                    )
                }

            return when (remoteResult) {
                is EnrollmentResult.Accepted ->
                    handleAccepted(
                        attempt = attempt,
                        accepted = remoteResult,
                        durable = durable,
                    )
                is EnrollmentResult.Rejected ->
                    RemoteRejected(
                        reason = remoteResult.reason.toCoordinatorReason(),
                        statusCode = remoteResult.statusCode,
                    )
                is EnrollmentResult.Failed ->
                    handleTransportFailure(
                        attempt = attempt,
                        reason = remoteResult.reason,
                    )
            }
        } catch (failure: Throwable) {
            if (!durable.get()) {
                when (remoteTracker.snapshot()) {
                    RemoteExecutionExposure.NOT_STARTED -> Unit
                    RemoteExecutionExposure.STARTED ->
                        processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                    RemoteExecutionExposure.ACCEPTED ->
                        processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                }
            }
            throw failure
        }
    }

    private suspend fun handleCompatiblePreflight(
        enrollment: StoredProtectedEnrollment,
    ): EnrollmentCoordinatorResult {
        processGuard.resolveFromDurableEvidence()
        return when (val inspection = inspectKey()) {
            is CredentialProtectionInspection.Compatible ->
                AlreadyEnrolled(enrollment.toReceipt())
            CredentialProtectionInspection.Missing ->
                KeyIncompatible(
                    KeyIncompatibleReason.MISSING_FOR_DURABLE_ENROLLMENT,
                )
            CredentialProtectionInspection.Incompatible ->
                KeyIncompatible(
                    KeyIncompatibleReason.INCOMPATIBLE_FOR_DURABLE_ENROLLMENT,
                )
            is CredentialProtectionInspection.Unavailable ->
                PlatformFailure(inspection.error.toPlatformFailureReason())
        }
    }

    private suspend fun inspectKey(): CredentialProtectionInspection =
        try {
            withContext(blockingDispatcher) { credentialProtector.inspect() }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (fatal: Error) {
            throw fatal
        } catch (_: Exception) {
            CredentialProtectionInspection.Unavailable(
                CredentialProtectionError.PROVIDER_FAILURE,
            )
        }

    private suspend fun prepareKey(): CredentialProtectionPreparation =
        try {
            withContext(blockingDispatcher) { credentialProtector.prepare() }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (fatal: Error) {
            throw fatal
        } catch (_: Exception) {
            CredentialProtectionPreparation.Failure(
                CredentialProtectionError.PROVIDER_FAILURE,
            )
        }

    private suspend fun handleAccepted(
        attempt: EnrollmentAttempt,
        accepted: EnrollmentResult.Accepted,
        durable: AtomicBoolean,
    ): EnrollmentCoordinatorResult {
        val acceptance = accepted.acceptance
        if (!accepted.isValidFor(attempt)) {
            processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
            return ResponseIncompatible(
                reason =
                    ResponseIncompatibleReason.DEFENSIVE_ACCEPTANCE_VALIDATION_FAILED,
                statusCode = 201,
                remoteDisposition = RemoteDisposition.ACCEPTED,
                persistenceDisposition = PersistenceDisposition.NOT_DURABLE,
                durabilityEvidence = DurabilityEvidence.NONE,
            )
        }
        val deliveredCredential = acceptance.deliveredCredential
        val metadata = deliveredCredential.metadata
        val backendIdentity = acceptance.backendIdentity
        val protocolVersion = acceptance.protocolVersion
        val serverReceivedAt = acceptance.serverReceivedAt
        val receipt = acceptance.toReceipt()

        val protection =
            try {
                withContext(blockingDispatcher) {
                    credentialProtector.protect(deliveredCredential)
                }
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (fatal: Error) {
                throw fatal
            } catch (_: Exception) {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                return ProtectionFailure(ProtectionFailureReason.ADAPTER_EXCEPTION)
            }
        val envelope =
            when (protection) {
                is ProtectCredentialResult.Protected -> protection.envelope
                is ProtectCredentialResult.Failure -> {
                    processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                    return ProtectionFailure(protection.error.toProtectionFailureReason())
                }
            }
        if (
            envelope.validate() !is ProtectedCredentialEnvelopeValidation.Valid ||
            envelope.credentialId != metadata.credentialId ||
            envelope.credentialVersion != metadata.version
        ) {
            processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
            return ProtectionFailure(
                ProtectionFailureReason.ENVELOPE_METADATA_MISMATCH,
            )
        }

        val write =
            ProtectedEnrollmentWrite(
                expectedLocalIdentity = attempt.expectedLocalIdentity,
                expectedServerConfiguration = attempt.expectedServerConfiguration,
                backendIdentity = backendIdentity,
                protocolVersion = protocolVersion,
                serverReceivedAt = serverReceivedAt,
                credentialMetadata = metadata,
                protectedCredential = envelope,
            )
        val persistence =
            try {
                protectedEnrollmentRepository.persist(write)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (fatal: Error) {
                throw fatal
            } catch (_: Exception) {
                return reconcileAfterUncertainPersistence(
                    attempt = attempt,
                    candidate = write,
                    receipt = receipt,
                    initialFailure = PersistenceFailureReason.ADAPTER_EXCEPTION,
                    durable = durable,
                )
            }

        return when (persistence) {
            PersistProtectedEnrollmentResult.Written ->
                durableSuccess(
                    durable = durable,
                    kind = EnrollmentSuccessKind.NEWLY_WRITTEN,
                    receipt = receipt,
                    persistenceDisposition = PersistenceDisposition.NEWLY_WRITTEN,
                    anomaly = null,
                    evidence = DurabilityEvidence.TRANSACTION_CONFIRMED,
                )
            PersistProtectedEnrollmentResult.ExistingEquivalent ->
                durableSuccess(
                    durable = durable,
                    kind = EnrollmentSuccessKind.EXISTING_EQUIVALENT,
                    receipt = receipt,
                    persistenceDisposition =
                        PersistenceDisposition.EXISTING_EQUIVALENT,
                    anomaly = null,
                    evidence = DurabilityEvidence.TRANSACTION_CONFIRMED,
                )
            PersistProtectedEnrollmentResult.Replaced ->
                durableSuccess(
                    durable = durable,
                    kind = EnrollmentSuccessKind.REPLACED,
                    receipt = receipt,
                    persistenceDisposition = PersistenceDisposition.REPLACED,
                    anomaly = EnrollmentAnomaly.UNEXPECTED_DURABLE_REPLACEMENT,
                    evidence = DurabilityEvidence.TRANSACTION_CONFIRMED,
                )
            is PersistProtectedEnrollmentResult.Failure ->
                reconcileAfterUncertainPersistence(
                    attempt = attempt,
                    candidate = write,
                    receipt = receipt,
                    initialFailure = persistence.error.toPersistenceFailureReason(),
                    durable = durable,
                )
            PersistProtectedEnrollmentResult.Conflict ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.CONFLICT,
                )
            PersistProtectedEnrollmentResult.Rollback ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.ROLLBACK,
                )
            PersistProtectedEnrollmentResult.PendingRejected ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.PENDING_REJECTED,
                )
            PersistProtectedEnrollmentResult.InvalidCandidate ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.INVALID_CANDIDATE,
                )
            PersistProtectedEnrollmentResult.Corrupt ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.CORRUPT,
                )
            PersistProtectedEnrollmentResult.Unsupported ->
                definitivePersistenceFailure(
                    attempt,
                    PersistenceFailureReason.UNSUPPORTED,
                )
        }
    }

    private suspend fun durableSuccess(
        durable: AtomicBoolean,
        kind: EnrollmentSuccessKind,
        receipt: EnrollmentReceipt,
        persistenceDisposition: PersistenceDisposition,
        anomaly: EnrollmentAnomaly?,
        evidence: DurabilityEvidence,
    ): EnrollmentCoordinatorResult {
        durable.set(true)
        processGuard.resolveFromDurableEvidence()
        currentCoroutineContext().ensureActive()
        return Enrolled(
            kind = kind,
            receipt = receipt,
            anomaly = anomaly,
            persistenceDisposition = persistenceDisposition,
            durabilityEvidence = evidence,
        )
    }

    private fun definitivePersistenceFailure(
        attempt: EnrollmentAttempt,
        reason: PersistenceFailureReason,
    ): EnrollmentCoordinatorResult {
        processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
        return PersistenceFailure(
            reason = reason,
            persistenceDisposition = PersistenceDisposition.NOT_DURABLE,
            durabilityEvidence = DurabilityEvidence.NONE,
        )
    }

    private suspend fun reconcileAfterUncertainPersistence(
        attempt: EnrollmentAttempt,
        candidate: ProtectedEnrollmentWrite,
        receipt: EnrollmentReceipt,
        initialFailure: PersistenceFailureReason,
        durable: AtomicBoolean,
    ): EnrollmentCoordinatorResult {
        val read =
            try {
                protectedEnrollmentRepository.read()
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (fatal: Error) {
                throw fatal
            } catch (_: Exception) {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                return PersistenceFailure(
                    reason = PersistenceFailureReason.RECONCILIATION_FAILED,
                    persistenceDisposition =
                        PersistenceDisposition.DURABILITY_UNKNOWN,
                    durabilityEvidence = DurabilityEvidence.UNKNOWN_AFTER_FAILURE,
                )
            }
        return when (read) {
            is ReadProtectedEnrollmentResult.Compatible ->
                if (read.enrollment.isEquivalentTo(candidate)) {
                    durableSuccess(
                        durable = durable,
                        kind = EnrollmentSuccessKind.RECONCILED_AFTER_FAILURE,
                        receipt = receipt,
                        persistenceDisposition =
                            PersistenceDisposition.RECONCILED_AFTER_FAILURE,
                        anomaly = null,
                        evidence = DurabilityEvidence.AUTHORITATIVE_RECONCILIATION,
                    )
                } else {
                    processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                    PersistenceFailure(
                        reason =
                            PersistenceFailureReason.RECONCILIATION_NOT_EQUIVALENT,
                        persistenceDisposition =
                            PersistenceDisposition.DURABILITY_CONFLICT,
                        durabilityEvidence =
                            DurabilityEvidence.CONFLICTING_AFTER_FAILURE,
                    )
                }
            ReadProtectedEnrollmentResult.Absent -> {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                PersistenceFailure(
                    reason = PersistenceFailureReason.RECONCILIATION_ABSENT,
                    persistenceDisposition = PersistenceDisposition.NOT_DURABLE,
                    durabilityEvidence = DurabilityEvidence.ABSENT_AFTER_FAILURE,
                )
            }
            ReadProtectedEnrollmentResult.Corrupt -> {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                PersistenceFailure(
                    reason = PersistenceFailureReason.RECONCILIATION_CORRUPT,
                    persistenceDisposition =
                        PersistenceDisposition.DURABILITY_UNKNOWN,
                    durabilityEvidence = DurabilityEvidence.UNKNOWN_AFTER_FAILURE,
                )
            }
            ReadProtectedEnrollmentResult.Unsupported -> {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                PersistenceFailure(
                    reason = PersistenceFailureReason.RECONCILIATION_UNSUPPORTED,
                    persistenceDisposition =
                        PersistenceDisposition.DURABILITY_UNKNOWN,
                    durabilityEvidence = DurabilityEvidence.UNKNOWN_AFTER_FAILURE,
                )
            }
            is ReadProtectedEnrollmentResult.Failure -> {
                processGuard.markRemoteAcceptedNotDurable(attempt.attemptId)
                PersistenceFailure(
                    reason =
                        if (read.error.toPersistenceFailureReason() == initialFailure) {
                            initialFailure
                        } else {
                            PersistenceFailureReason.RECONCILIATION_FAILED
                        },
                    persistenceDisposition =
                        PersistenceDisposition.DURABILITY_UNKNOWN,
                    durabilityEvidence = DurabilityEvidence.UNKNOWN_AFTER_FAILURE,
                )
            }
        }
    }

    private fun handleTransportFailure(
        attempt: EnrollmentAttempt,
        reason: EnrollmentFailureReason,
    ): EnrollmentCoordinatorResult =
        when (reason) {
            EnrollmentFailureReason.INVALID_LOCAL_REQUEST ->
                InvalidConfiguration(InvalidConfigurationReason.INVALID_LOCAL_REQUEST)
            EnrollmentFailureReason.INVALID_ENDPOINT ->
                InvalidConfiguration(InvalidConfigurationReason.INVALID_ENDPOINT)
            EnrollmentFailureReason.DNS ->
                KnownTransientFailure(KnownTransientFailureReason.DNS)
            EnrollmentFailureReason.CONNECTION ->
                KnownTransientFailure(KnownTransientFailureReason.CONNECTION)
            EnrollmentFailureReason.TLS -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                RemoteOutcomeAmbiguous(RemoteOutcomeAmbiguousReason.TLS, null)
            }
            EnrollmentFailureReason.TIMEOUT -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                RemoteOutcomeAmbiguous(RemoteOutcomeAmbiguousReason.TIMEOUT, null)
            }
            EnrollmentFailureReason.CANCELLED -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                RemoteOutcomeAmbiguous(
                    RemoteOutcomeAmbiguousReason.TRANSPORT_CANCELLED,
                    null,
                )
            }
            EnrollmentFailureReason.INCOMPLETE_RESPONSE -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                RemoteOutcomeAmbiguous(
                    RemoteOutcomeAmbiguousReason.INCOMPLETE_RESPONSE,
                    null,
                )
            }
            EnrollmentFailureReason.IO -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                RemoteOutcomeAmbiguous(RemoteOutcomeAmbiguousReason.IO, null)
            }
            EnrollmentFailureReason.REDIRECT,
            EnrollmentFailureReason.UNEXPECTED_STATUS,
            EnrollmentFailureReason.INVALID_CONTENT_TYPE,
            EnrollmentFailureReason.EMPTY_BODY,
            EnrollmentFailureReason.RESPONSE_TOO_LARGE,
            EnrollmentFailureReason.MALFORMED_JSON,
            EnrollmentFailureReason.INVALID_RESPONSE_SHAPE,
            EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS,
            EnrollmentFailureReason.MISSING_CORRELATION,
            EnrollmentFailureReason.CORRELATION_MISMATCH,
            -> {
                processGuard.markRemoteOutcomeUnresolved(attempt.attemptId)
                ResponseIncompatible(
                    reason = reason.toResponseIncompatibleReason(),
                    statusCode = null,
                )
            }
        }
}

private fun EnrollmentResult.Accepted.isValidFor(attempt: EnrollmentAttempt): Boolean {
    val metadata = acceptance.deliveredCredential.metadata
    return correlationId == attempt.command.correlationId &&
        acceptance.localIdentity == attempt.expectedLocalIdentity &&
        acceptance.protocolVersion == ProtocolVersion.CURRENT &&
        metadata.deliveryState == CredentialDeliveryState.ACTIVE &&
        metadata.issuedAt <= acceptance.serverReceivedAt &&
        acceptance.serverReceivedAt < metadata.expiresAt
}

private fun StoredProtectedEnrollment.toReceipt(): EnrollmentReceipt =
    EnrollmentReceipt(
        backendIdentity = backendIdentity,
        protocolVersion = protocolVersion,
        serverReceivedAt = serverReceivedAt,
        credentialMetadata = credentialMetadata,
    )

private fun BackendEnrollmentAcceptance.toReceipt(): EnrollmentReceipt =
    EnrollmentReceipt(
        backendIdentity = backendIdentity,
        protocolVersion = protocolVersion,
        serverReceivedAt = serverReceivedAt,
        credentialMetadata = deliveredCredential.metadata,
    )

private fun StoredProtectedEnrollment.isEquivalentTo(
    candidate: ProtectedEnrollmentWrite,
): Boolean =
    localIdentity == candidate.expectedLocalIdentity &&
        serverConfiguration == candidate.expectedServerConfiguration &&
        backendIdentity == candidate.backendIdentity &&
        protocolVersion == candidate.protocolVersion &&
        serverReceivedAt == candidate.serverReceivedAt &&
        credentialMetadata == candidate.credentialMetadata &&
        protectedCredential.validate() is ProtectedCredentialEnvelopeValidation.Valid &&
        candidate.protectedCredential.validate() is ProtectedCredentialEnvelopeValidation.Valid &&
        protectedCredential.cryptoVersion == candidate.protectedCredential.cryptoVersion &&
        protectedCredential.keyAlias == candidate.protectedCredential.keyAlias &&
        protectedCredential.credentialId == candidate.protectedCredential.credentialId &&
        protectedCredential.credentialVersion ==
        candidate.protectedCredential.credentialVersion

private fun CredentialProtectionError.toPreparationFailure(): EnrollmentCoordinatorResult =
    if (this == CredentialProtectionError.KEY_INCOMPATIBLE) {
        KeyIncompatible(KeyIncompatibleReason.INCOMPATIBLE_DURING_PREPARATION)
    } else {
        PlatformFailure(toPlatformFailureReason())
    }

private fun CredentialProtectionError.toPlatformFailureReason(): PlatformFailureReason =
    PlatformFailureReason.valueOf(name)

private fun CredentialProtectionError.toProtectionFailureReason(): ProtectionFailureReason =
    ProtectionFailureReason.valueOf(name)

private fun EnrollmentRejectionReason.toCoordinatorReason(): RemoteRejectedReason =
    RemoteRejectedReason.valueOf(name)

private fun EnrollmentFailureReason.toResponseIncompatibleReason():
    ResponseIncompatibleReason = ResponseIncompatibleReason.valueOf(name)

private fun LocalPersistenceError.toPreflightReason(): LocalStateBlockedReason =
    LocalStateBlockedReason.valueOf("PREFLIGHT_$name")

private fun LocalPersistenceError.toPersistenceFailureReason():
    PersistenceFailureReason = PersistenceFailureReason.valueOf(name)
