package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentCall
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal enum class RemoteExecutionExposure {
    NOT_STARTED,
    STARTED,
    ACCEPTED,
}

internal class RemoteExecutionTracker {
    private val exposure =
        AtomicReference(RemoteExecutionExposure.NOT_STARTED)

    fun markStarted() {
        exposure.compareAndSet(
            RemoteExecutionExposure.NOT_STARTED,
            RemoteExecutionExposure.STARTED,
        )
    }

    fun observe(result: EnrollmentResult) {
        if (result is EnrollmentResult.Accepted) {
            exposure.set(RemoteExecutionExposure.ACCEPTED)
        }
    }

    fun snapshot(): RemoteExecutionExposure = exposure.get()
}

private enum class EnrollmentCallExecutionState {
    QUEUED,
    RUNNING,
    CANCELLED_BEFORE_START,
    TERMINAL,
}

private class EnrollmentCallExecutionHandshake {
    private val state =
        AtomicReference(EnrollmentCallExecutionState.QUEUED)
    private val terminal = CompletableDeferred<Unit>()
    private val cancellationCleanupFailure =
        AtomicReference<EnrollmentCallCancellationFailure?>(null)

    fun tryStart(): Boolean =
        state.compareAndSet(
            EnrollmentCallExecutionState.QUEUED,
            EnrollmentCallExecutionState.RUNNING,
        )

    fun cancelBeforeStart() {
        state.compareAndSet(
            EnrollmentCallExecutionState.QUEUED,
            EnrollmentCallExecutionState.CANCELLED_BEFORE_START,
        )
    }

    fun publishRunningTerminal() {
        if (
            state.compareAndSet(
                EnrollmentCallExecutionState.RUNNING,
                EnrollmentCallExecutionState.TERMINAL,
            )
        ) {
            check(terminal.complete(Unit))
        }
    }

    fun publishCancelledBeforeStartTerminal() {
        if (
            state.compareAndSet(
                EnrollmentCallExecutionState.CANCELLED_BEFORE_START,
                EnrollmentCallExecutionState.TERMINAL,
            )
        ) {
            check(terminal.complete(Unit))
        }
    }

    fun publishDispatchFailureTerminal(): Boolean {
        while (true) {
            val current = state.get()
            when (current) {
                EnrollmentCallExecutionState.QUEUED,
                EnrollmentCallExecutionState.CANCELLED_BEFORE_START,
                -> {
                    if (
                        state.compareAndSet(
                            current,
                            EnrollmentCallExecutionState.TERMINAL,
                        )
                    ) {
                        check(terminal.complete(Unit))
                        return true
                    }
                }
                EnrollmentCallExecutionState.RUNNING,
                EnrollmentCallExecutionState.TERMINAL,
                -> return false
            }
        }
    }

    fun recordCancellationCleanupFailure() {
        cancellationCleanupFailure.compareAndSet(
            null,
            EnrollmentCallCancellationFailure(),
        )
    }

    suspend fun awaitRunningTerminalAfterCancellation() {
        while (true) {
            when (state.get()) {
                EnrollmentCallExecutionState.QUEUED -> {
                    if (
                        state.compareAndSet(
                            EnrollmentCallExecutionState.QUEUED,
                            EnrollmentCallExecutionState.CANCELLED_BEFORE_START,
                        )
                    ) {
                        return
                    }
                }
                EnrollmentCallExecutionState.RUNNING -> {
                    withContext(NonCancellable) {
                        terminal.await()
                    }
                    return
                }
                EnrollmentCallExecutionState.CANCELLED_BEFORE_START,
                EnrollmentCallExecutionState.TERMINAL,
                -> return
            }
        }
    }

    fun attachCleanupFailureTo(cancellation: CancellationException) {
        cancellationCleanupFailure.get()?.let(cancellation::addSuppressed)
    }
}

/**
 * Cancellable bridge for C03's single-shot blocking call.
 *
 * Cancellation is registered before dispatch. A canceled continuation cannot proceed into
 * protection or persistence, and [EnrollmentCall.cancel] is invoked at most once. Once execution
 * has started, cancellation waits for the blocking worker to become terminal before returning.
 */
internal suspend fun awaitEnrollmentCall(
    call: EnrollmentCall,
    dispatcher: CoroutineDispatcher,
    tracker: RemoteExecutionTracker,
): EnrollmentResult {
    val handshake = EnrollmentCallExecutionHandshake()
    try {
        return suspendCancellableCoroutine { continuation ->
            val cancellationForwarded = AtomicBoolean(false)
            val completionClaimed = AtomicBoolean(false)
            continuation.invokeOnCancellation {
                completionClaimed.compareAndSet(false, true)
                handshake.cancelBeforeStart()
                if (cancellationForwarded.compareAndSet(false, true)) {
                    try {
                        call.cancel()
                    } catch (_: Throwable) {
                        handshake.recordCancellationCleanupFailure()
                    }
                }
            }

            try {
                dispatcher.dispatch(
                    continuation.context,
                    Runnable {
                        if (!handshake.tryStart()) {
                            handshake.publishCancelledBeforeStartTerminal()
                            return@Runnable
                        }
                        val outcome: Result<EnrollmentResult> =
                            try {
                                tracker.markStarted()
                                val result = call.execute()
                                tracker.observe(result)
                                Result.success(result)
                            } catch (failure: Throwable) {
                                Result.failure(failure)
                            } finally {
                                handshake.publishRunningTerminal()
                            }
                        if (completionClaimed.compareAndSet(false, true)) {
                            continuation.resumeWith(outcome)
                        }
                    },
                )
            } catch (failure: Throwable) {
                if (
                    handshake.publishDispatchFailureTerminal() &&
                    completionClaimed.compareAndSet(false, true)
                ) {
                    continuation.resumeWith(Result.failure(failure))
                }
            }
        }
    } catch (cancellation: CancellationException) {
        handshake.awaitRunningTerminalAfterCancellation()
        handshake.attachCleanupFailureTo(cancellation)
        throw cancellation
    }
}

private class EnrollmentCallCancellationFailure :
    RuntimeException("EnrollmentCall cancellation cleanup failed (<redacted>).") {
    override fun fillInStackTrace(): Throwable = this
}
