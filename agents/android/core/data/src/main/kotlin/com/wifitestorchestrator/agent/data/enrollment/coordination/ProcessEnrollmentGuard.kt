package com.wifitestorchestrator.agent.data.enrollment.coordination

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Process-local serialization and ambiguity guard shared by every production coordinator.
 *
 * Its state is deliberately non-durable and contains only an opaque attempt identifier.
 */
internal class ProcessEnrollmentGuard {
    private val mutex = Mutex()

    @Volatile
    private var state: ProcessEnrollmentGuardState = ProcessEnrollmentGuardState.Open

    @Volatile
    private var lastAuthorizedAttemptId: EnrollmentAttemptId? = null

    suspend fun <T> withLock(block: suspend () -> T): T = mutex.withLock { block() }

    fun authorize(
        attemptId: EnrollmentAttemptId,
        intent: EnrollmentInvocationIntent,
    ): ProcessEnrollmentAuthorization =
        when (val current = state) {
            ProcessEnrollmentGuardState.Open ->
                authorizeOpenState(attemptId = attemptId, intent = intent)
            is ProcessEnrollmentGuardState.RemoteOutcomeUnresolved ->
                authorizeBlockedState(
                    storedAttemptId = current.attemptId,
                    presentedAttemptId = attemptId,
                    intent = intent,
                    blockedReason =
                        LocalStateBlockedReason.PREVIOUS_REMOTE_OUTCOME_UNRESOLVED,
                )
            is ProcessEnrollmentGuardState.RemoteAcceptedNotDurable ->
                authorizeBlockedState(
                    storedAttemptId = current.attemptId,
                    presentedAttemptId = attemptId,
                    intent = intent,
                    blockedReason =
                        LocalStateBlockedReason.PREVIOUS_REMOTE_ACCEPTED_NOT_DURABLE,
                )
        }

    fun markRemoteOutcomeUnresolved(attemptId: EnrollmentAttemptId) {
        lastAuthorizedAttemptId = attemptId
        state = ProcessEnrollmentGuardState.RemoteOutcomeUnresolved(attemptId)
    }

    fun markRemoteAcceptedNotDurable(attemptId: EnrollmentAttemptId) {
        lastAuthorizedAttemptId = attemptId
        state = ProcessEnrollmentGuardState.RemoteAcceptedNotDurable(attemptId)
    }

    fun resolveFromDurableEvidence() {
        state = ProcessEnrollmentGuardState.Open
        lastAuthorizedAttemptId = null
    }

    private fun authorizeOpenState(
        attemptId: EnrollmentAttemptId,
        intent: EnrollmentInvocationIntent,
    ): ProcessEnrollmentAuthorization =
        when (intent) {
            EnrollmentInvocationIntent.INITIAL ->
                if (lastAuthorizedAttemptId == attemptId) {
                    ProcessEnrollmentAuthorization.Blocked(
                        LocalStateBlockedReason.RETRY_REQUIRES_MANUAL_INTENT,
                    )
                } else {
                    lastAuthorizedAttemptId = attemptId
                    ProcessEnrollmentAuthorization.Allowed
                }
            EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY ->
                if (lastAuthorizedAttemptId == attemptId) {
                    ProcessEnrollmentAuthorization.Allowed
                } else {
                    ProcessEnrollmentAuthorization.Blocked(
                        LocalStateBlockedReason.MANUAL_RETRY_REQUIRES_SAME_LIVE_ATTEMPT,
                    )
                }
        }

    internal fun snapshot(): ProcessEnrollmentGuardState = state
}

internal sealed interface ProcessEnrollmentGuardState {
    data object Open : ProcessEnrollmentGuardState

    class RemoteOutcomeUnresolved(val attemptId: EnrollmentAttemptId) :
        ProcessEnrollmentGuardState {
        override fun toString(): String =
            "ProcessEnrollmentGuardState.RemoteOutcomeUnresolved(<redacted>)"
    }

    class RemoteAcceptedNotDurable(val attemptId: EnrollmentAttemptId) :
        ProcessEnrollmentGuardState {
        override fun toString(): String =
            "ProcessEnrollmentGuardState.RemoteAcceptedNotDurable(<redacted>)"
    }
}

internal sealed interface ProcessEnrollmentAuthorization {
    data object Allowed : ProcessEnrollmentAuthorization

    data class Blocked(val reason: LocalStateBlockedReason) :
        ProcessEnrollmentAuthorization
}

internal object ProductionProcessEnrollmentGuard {
    val shared: ProcessEnrollmentGuard = ProcessEnrollmentGuard()
}

private fun authorizeBlockedState(
    storedAttemptId: EnrollmentAttemptId,
    presentedAttemptId: EnrollmentAttemptId,
    intent: EnrollmentInvocationIntent,
    blockedReason: LocalStateBlockedReason,
): ProcessEnrollmentAuthorization =
    if (
        storedAttemptId == presentedAttemptId &&
        intent == EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY
    ) {
        ProcessEnrollmentAuthorization.Allowed
    } else {
        ProcessEnrollmentAuthorization.Blocked(blockedReason)
    }
