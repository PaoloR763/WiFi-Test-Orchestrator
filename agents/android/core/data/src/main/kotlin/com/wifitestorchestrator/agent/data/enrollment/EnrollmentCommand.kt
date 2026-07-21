package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.enrollment.EnrollmentToken
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.IdempotencyKey
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.time.Instant

private const val DISPLAY_NAME_MAX_CODE_POINTS = 128
private const val PLATFORM_VERSION_MAX_CODE_POINTS = 64

class EnrollmentCommand private constructor(
    internal val endpointUrl: String,
    internal val localIdentity: LocalInstallationIdentity,
    internal val idempotencyKey: IdempotencyKey,
    internal val correlationId: CorrelationId,
    internal val enrollmentToken: EnrollmentToken,
    internal val displayName: String,
    internal val platformVersion: String,
    internal val agentVersion: AgentVersion,
    internal val agentReportedAt: String,
) {
    override fun toString(): String = "EnrollmentCommand(<redacted>)"

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
        ): EnrollmentCommandCreationResult {
            if (
                serverConfiguration == null ||
                localIdentity == null ||
                idempotencyKey == null ||
                correlationId == null ||
                enrollmentToken == null ||
                displayName == null ||
                platformVersion == null ||
                agentVersion == null ||
                agentReportedAt == null
            ) {
                return EnrollmentCommandCreationResult.Invalid(
                    EnrollmentCommandFailure.INVALID_LOCAL_REQUEST,
                )
            }
            if (
                displayName.codePointLength() !in 1..DISPLAY_NAME_MAX_CODE_POINTS ||
                platformVersion.codePointLength() !in 1..PLATFORM_VERSION_MAX_CODE_POINTS
            ) {
                return EnrollmentCommandCreationResult.Invalid(
                    EnrollmentCommandFailure.INVALID_LOCAL_REQUEST,
                )
            }
            val renderedTimestamp =
                EnrollmentWireTimestamp.render(agentReportedAt)
                    ?: return EnrollmentCommandCreationResult.Invalid(
                        EnrollmentCommandFailure.INVALID_LOCAL_REQUEST,
                    )
            val endpointUrl =
                EnrollmentEndpoint.build(serverConfiguration)
                    ?: return EnrollmentCommandCreationResult.Invalid(
                        EnrollmentCommandFailure.INVALID_ENDPOINT,
                    )
            return EnrollmentCommandCreationResult.Ready(
                EnrollmentCommand(
                    endpointUrl = endpointUrl,
                    localIdentity = localIdentity,
                    idempotencyKey = idempotencyKey,
                    correlationId = correlationId,
                    enrollmentToken = enrollmentToken,
                    displayName = displayName,
                    platformVersion = platformVersion,
                    agentVersion = agentVersion,
                    agentReportedAt = renderedTimestamp,
                ),
            )
        }
    }
}

sealed interface EnrollmentCommandCreationResult {
    class Ready(val command: EnrollmentCommand) : EnrollmentCommandCreationResult {
        override fun toString(): String = "EnrollmentCommandCreationResult.Ready(<redacted>)"
    }

    data class Invalid(val reason: EnrollmentCommandFailure) : EnrollmentCommandCreationResult
}

enum class EnrollmentCommandFailure {
    INVALID_LOCAL_REQUEST,
    INVALID_ENDPOINT,
}

internal fun String.codePointLength(): Int = codePointCount(0, length)
