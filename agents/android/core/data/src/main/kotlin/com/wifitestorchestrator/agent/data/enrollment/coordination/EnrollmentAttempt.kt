package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentCommand
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentCommandCreationResult
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentCommandFailure
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.enrollment.EnrollmentToken
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.IdempotencyKey
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.time.Instant
import java.util.UUID

/**
 * One validated, in-memory enrollment attempt.
 *
 * The caller owns this object for its entire lifetime. A manual retry must pass this exact object
 * back to the coordinator; C07 never refreshes its timestamp, token, idempotency key, correlation
 * ID, identity, server configuration, or payload.
 */
class EnrollmentAttempt private constructor(
    internal val command: EnrollmentCommand,
    internal val expectedLocalIdentity: LocalInstallationIdentity,
    internal val expectedServerConfiguration: ServerConfiguration,
    internal val attemptId: EnrollmentAttemptId,
) {
    override fun toString(): String = "EnrollmentAttempt(<redacted>)"

    companion object {
        fun create(
            serverConfiguration: ServerConfiguration?,
            localIdentity: LocalInstallationIdentity?,
            idempotencyKey: IdempotencyKey?,
            correlationId: CorrelationId?,
            enrollmentToken: EnrollmentToken?,
            displayName: String?,
            platformVersion: String?,
            agentVersion: AgentVersion?,
            agentReportedAt: Instant?,
        ): EnrollmentAttemptCreationResult =
            when (
                val command =
                    EnrollmentCommand.create(
                        serverConfiguration = serverConfiguration,
                        localIdentity = localIdentity,
                        idempotencyKey = idempotencyKey,
                        correlationId = correlationId,
                        enrollmentToken = enrollmentToken,
                        displayName = displayName,
                        platformVersion = platformVersion,
                        agentVersion = agentVersion,
                        agentReportedAt = agentReportedAt,
                    )
            ) {
                is EnrollmentCommandCreationResult.Ready ->
                    EnrollmentAttemptCreationResult.Ready(
                        EnrollmentAttempt(
                            command = command.command,
                            expectedLocalIdentity = requireNotNull(localIdentity),
                            expectedServerConfiguration = requireNotNull(serverConfiguration),
                            attemptId = EnrollmentAttemptId.create(),
                        ),
                    )
                is EnrollmentCommandCreationResult.Invalid ->
                    EnrollmentAttemptCreationResult.Invalid(command.reason.toAttemptFailure())
            }
    }
}

sealed interface EnrollmentAttemptCreationResult {
    class Ready(val attempt: EnrollmentAttempt) : EnrollmentAttemptCreationResult {
        override fun toString(): String =
            "EnrollmentAttemptCreationResult.Ready(<redacted>)"
    }

    data class Invalid(val reason: EnrollmentAttemptFailure) :
        EnrollmentAttemptCreationResult
}

enum class EnrollmentAttemptFailure {
    INVALID_LOCAL_REQUEST,
    INVALID_ENDPOINT,
}

internal class EnrollmentAttemptId private constructor(
    private val value: UUID,
) {
    override fun equals(other: Any?): Boolean =
        other is EnrollmentAttemptId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = "EnrollmentAttemptId(<opaque>)"

    companion object {
        fun create(): EnrollmentAttemptId = EnrollmentAttemptId(UUID.randomUUID())
    }
}

private fun EnrollmentCommandFailure.toAttemptFailure(): EnrollmentAttemptFailure =
    when (this) {
        EnrollmentCommandFailure.INVALID_LOCAL_REQUEST ->
            EnrollmentAttemptFailure.INVALID_LOCAL_REQUEST
        EnrollmentCommandFailure.INVALID_ENDPOINT -> EnrollmentAttemptFailure.INVALID_ENDPOINT
    }
