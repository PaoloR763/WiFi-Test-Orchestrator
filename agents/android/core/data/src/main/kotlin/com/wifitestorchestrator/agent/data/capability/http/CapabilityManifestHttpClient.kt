package com.wifitestorchestrator.agent.data.capability.http

import com.wifitestorchestrator.agent.data.capability.CapabilityManifestAcknowledgement
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class CapabilityManifestHttpCommand(
    val endpointUrl: String,
    val expectedManifestId: String,
    val canonicalPayload: ByteArray,
    val timestamp: String,
    val nonce: String,
    val correlationId: String,
) {
    override fun toString(): String = "CapabilityManifestHttpCommand(<redacted>)"
}

internal interface CapabilityManifestHttpClient {
    /**
     * Creates and executes the authenticated call synchronously.
     *
     * This method may only be invoked from inside CredentialProtector.useDecryptedCredential.
     */
    fun execute(
        command: CapabilityManifestHttpCommand,
        credential: AgentCredentialSecret,
        cancellation: CredentialScopedHttpCancellation,
    ): CapabilityManifestHttpResult
}

internal sealed interface CapabilityManifestHttpResult {
    data class Accepted(val acknowledgement: CapabilityManifestAcknowledgement) :
        CapabilityManifestHttpResult {
        override fun toString(): String =
            "CapabilityManifestHttpResult.Accepted(<redacted>)"
    }

    data class Rejected(val reason: CapabilityManifestRejection) :
        CapabilityManifestHttpResult

    data class Ambiguous(val reason: CapabilityManifestTransportFailure) :
        CapabilityManifestHttpResult

    data class InvalidAcknowledgement(val reason: InvalidAcknowledgementReason) :
        CapabilityManifestHttpResult

    data object Cancelled : CapabilityManifestHttpResult

    data object InvalidLocalRequest : CapabilityManifestHttpResult
}

internal enum class CapabilityManifestRejection {
    AUTHENTICATION_BLOCKED,
    CONFLICT,
    REQUEST_TOO_LARGE,
    CONTRACT_INCOMPATIBLE,
    RATE_LIMITED,
    SERVICE_UNAVAILABLE,
    REDIRECT,
    UNEXPECTED_STATUS,
}

internal enum class CapabilityManifestTransportFailure {
    DNS,
    TLS,
    TIMEOUT,
    CONNECTION,
    INCOMPLETE_RESPONSE,
    IO,
}

internal enum class InvalidAcknowledgementReason {
    CORRELATION,
    CONTENT_TYPE,
    BODY_TOO_LARGE,
    MALFORMED_JSON,
    DUPLICATE_KEY,
    UNKNOWN_OR_MISSING_FIELD,
    SCHEMA_VERSION,
    MANIFEST_ID,
    MANIFEST_DIGEST,
    SERVER_TIMESTAMP,
}

/**
 * Cancellation relay whose authenticated-call reference exists only while the credential callback
 * is active. [clear] removes that reference before the callback returns.
 */
internal class CredentialScopedHttpCancellation {
    private val requested = AtomicBoolean(false)
    private val forwarded = AtomicBoolean(false)
    private val cancelAction = AtomicReference<(() -> Unit)?>(null)
    private val cleanupFailure = AtomicReference<Throwable?>(null)

    fun register(action: () -> Unit) {
        check(cancelAction.compareAndSet(null, action))
        if (requested.get()) forwardAtMostOnce()
    }

    fun requestCancellation() {
        requested.set(true)
        forwardAtMostOnce()
    }

    fun isCancellationRequested(): Boolean = requested.get()

    fun clear() {
        cancelAction.set(null)
    }

    fun attachCleanupFailure(primary: Throwable) {
        cleanupFailure.get()?.let { cleanup ->
            if (cleanup !== primary) primary.addSuppressed(cleanup)
        }
    }

    private fun forwardAtMostOnce() {
        val action = cancelAction.get() ?: return
        if (!forwarded.compareAndSet(false, true)) return
        try {
            action()
        } catch (failure: Throwable) {
            cleanupFailure.compareAndSet(null, failure)
        }
    }
}
