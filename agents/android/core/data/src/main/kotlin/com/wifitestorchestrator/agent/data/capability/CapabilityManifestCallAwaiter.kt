package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpClient
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpCommand
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpResult
import com.wifitestorchestrator.agent.data.capability.http.CredentialScopedHttpCancellation
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.UseDecryptedCredentialResult
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

internal sealed interface CredentialScopedExecutionResult {
    data class Completed(val result: CapabilityManifestHttpResult) :
        CredentialScopedExecutionResult

    data class ProtectionFailure(val error: CredentialProtectionError) :
        CredentialScopedExecutionResult

    data class AcceptedAfterCancellation(
        val result: CapabilityManifestHttpResult.Accepted,
        val cancellation: CancellationException,
    ) : CredentialScopedExecutionResult
}

private enum class ExecutionState {
    QUEUED,
    RUNNING,
    CANCELLED_BEFORE_START,
    TERMINAL,
}

private class ExecutionHandshake {
    private val state = AtomicReference(ExecutionState.QUEUED)
    private val terminal = CompletableDeferred<Unit>()

    fun tryStart(): Boolean = state.compareAndSet(ExecutionState.QUEUED, ExecutionState.RUNNING)

    fun cancelBeforeStart() {
        state.compareAndSet(ExecutionState.QUEUED, ExecutionState.CANCELLED_BEFORE_START)
    }

    fun finishRunning() {
        if (state.compareAndSet(ExecutionState.RUNNING, ExecutionState.TERMINAL)) {
            terminal.complete(Unit)
        }
    }

    fun finishCancelledBeforeStart() {
        if (state.compareAndSet(ExecutionState.CANCELLED_BEFORE_START, ExecutionState.TERMINAL)) {
            terminal.complete(Unit)
        }
    }

    fun finishDispatchFailure(): Boolean {
        while (true) {
            val current = state.get()
            when (current) {
                ExecutionState.QUEUED,
                ExecutionState.CANCELLED_BEFORE_START,
                -> if (state.compareAndSet(current, ExecutionState.TERMINAL)) {
                    terminal.complete(Unit)
                    return true
                }
                ExecutionState.RUNNING,
                ExecutionState.TERMINAL,
                -> return false
            }
        }
    }

    suspend fun awaitTerminalAfterCancellation() {
        while (true) {
            when (state.get()) {
                ExecutionState.QUEUED -> {
                    if (state.compareAndSet(ExecutionState.QUEUED, ExecutionState.CANCELLED_BEFORE_START)) {
                        return
                    }
                }
                ExecutionState.RUNNING -> {
                    withContext(NonCancellable) { terminal.await() }
                    return
                }
                ExecutionState.CANCELLED_BEFORE_START,
                ExecutionState.TERMINAL,
                -> return
            }
        }
    }
}

internal suspend fun executeWithProtectedCredential(
    protector: CredentialProtector,
    envelope: ProtectedCredentialEnvelope,
    httpClient: CapabilityManifestHttpClient,
    command: CapabilityManifestHttpCommand,
    dispatcher: CoroutineDispatcher,
): CredentialScopedExecutionResult {
    val handshake = ExecutionHandshake()
    val cancellationRelay = CredentialScopedHttpCancellation()
    val terminalResult = AtomicReference<CredentialScopedExecutionResult?>(null)
    try {
        return suspendCancellableCoroutine { continuation ->
            val completionClaimed = AtomicBoolean(false)
            continuation.invokeOnCancellation {
                completionClaimed.compareAndSet(false, true)
                handshake.cancelBeforeStart()
                cancellationRelay.requestCancellation()
            }
            try {
                dispatcher.dispatch(
                    continuation.context,
                    Runnable {
                        if (!handshake.tryStart()) {
                            handshake.finishCancelledBeforeStart()
                            return@Runnable
                        }
                        val outcome =
                            try {
                                Result.success(
                                    executeCredentialCallback(
                                        protector = protector,
                                        envelope = envelope,
                                        httpClient = httpClient,
                                        command = command,
                                        cancellationRelay = cancellationRelay,
                                    ),
                                )
                            } catch (failure: Throwable) {
                                Result.failure(failure)
                            }
                        outcome.getOrNull()?.let(terminalResult::set)
                        handshake.finishRunning()
                        if (completionClaimed.compareAndSet(false, true)) {
                            continuation.resumeWith(outcome)
                        }
                    },
                )
            } catch (failure: Throwable) {
                if (
                    handshake.finishDispatchFailure() &&
                    completionClaimed.compareAndSet(false, true)
                ) {
                    continuation.resumeWith(Result.failure(failure))
                }
            }
        }
    } catch (cancellation: CancellationException) {
        handshake.awaitTerminalAfterCancellation()
        cancellationRelay.attachCleanupFailure(cancellation)
        val accepted =
            (terminalResult.get() as? CredentialScopedExecutionResult.Completed)
                ?.result as? CapabilityManifestHttpResult.Accepted
        if (accepted != null) {
            return CredentialScopedExecutionResult.AcceptedAfterCancellation(
                result = accepted,
                cancellation = cancellation,
            )
        }
        throw cancellation
    }
}

private fun executeCredentialCallback(
    protector: CredentialProtector,
    envelope: ProtectedCredentialEnvelope,
    httpClient: CapabilityManifestHttpClient,
    command: CapabilityManifestHttpCommand,
    cancellationRelay: CredentialScopedHttpCancellation,
): CredentialScopedExecutionResult {
    var httpResult: CapabilityManifestHttpResult? = null
    val decrypted =
        protector.useDecryptedCredential(envelope) { credential ->
            httpResult =
                httpClient.execute(
                    command = command,
                    credential = credential,
                    cancellation = cancellationRelay,
                )
        }
    return when (decrypted) {
        UseDecryptedCredentialResult.Used ->
            CredentialScopedExecutionResult.Completed(
                requireNotNull(httpResult) { "Credential callback completed without a result." },
            )
        is UseDecryptedCredentialResult.Failure ->
            CredentialScopedExecutionResult.ProtectionFailure(decrypted.error)
    }
}
